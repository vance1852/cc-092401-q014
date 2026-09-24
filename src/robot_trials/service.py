"""统计准入服务的领域用例。

权限模型：用户本身不携带角色，授权全部来自组织内的成员关系——
团队成员关系（operator/statistician/approver/auditor）按团队授予，同一用户
可以在不同团队拥有不同角色；组织角色（org_admin/org_auditor）按组织授予，
org_admin 只能维护团队与成员关系，org_auditor 跨团队只读。机器人、构建、
协议和批次都归属唯一的组织与团队，日常操作只能作用于操作人被授权团队的
对象；对无权可见的对象一律按“不存在”响应，避免通过存在性差异泄露其他
组织的数据。所有写操作把成员资格检查放在 BEGIN IMMEDIATE 事务内执行，
与成员变更串行化，杜绝“检查后被撤权仍写入”的窗口。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


TEAM_ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run", "report.read"},
    "approver": {"decision.write", "report.read"},
    "auditor": {"report.read", "audit.read"},
}

ORG_ROLE_PERMISSIONS = {
    "org_admin": {"team.write", "membership.write"},
    "org_auditor": {"report.read", "audit.read"},
}


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    # ------------------------------------------------------------------
    # 身份与授权
    # ------------------------------------------------------------------

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _membership_role(self, user_id: str, org_id: str, team_id: str) -> str | None:
        row = self.connection.execute(
            "SELECT role FROM memberships WHERE user_id=? AND org_id=? AND team_id=?",
            (user_id, org_id, team_id),
        ).fetchone()
        return None if row is None else row["role"]

    def _org_roles(self, user_id: str, org_id: str) -> set[str]:
        rows = self.connection.execute(
            "SELECT role FROM org_roles WHERE user_id=? AND org_id=?", (user_id, org_id)
        ).fetchall()
        return {row["role"] for row in rows}

    def _has_org_membership(self, user_id: str, org_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM memberships WHERE user_id=? AND org_id=? LIMIT 1", (user_id, org_id)
        ).fetchone()
        return row is not None

    def _can_read(self, user_id: str, org_id: str, team_id: str) -> bool:
        """团队成员或组织审计员可以读取对象；组织管理员不接触业务数据。"""

        if self._membership_role(user_id, org_id, team_id) is not None:
            return True
        return "org_auditor" in self._org_roles(user_id, org_id)

    def _require_team_role(self, user_id: str, org_id: str, team_id: str, not_found: str) -> str:
        """返回团队成员角色；非成员一律按对象不存在处理，避免泄露存在性。"""

        self._user(user_id)
        role = self._membership_role(user_id, org_id, team_id)
        if role is None:
            raise NotFound(not_found)
        return role

    @staticmethod
    def _require_permission(role: str, permission: str) -> None:
        if permission not in TEAM_ROLE_PERMISSIONS[role]:
            raise Forbidden(f"角色 {role} 无权执行 {permission}")

    def _require_scoped_permission(
        self, user_id: str, org_id: str, team_id: str, permission: str, not_found: str
    ) -> None:
        role = self._require_team_role(user_id, org_id, team_id, not_found)
        self._require_permission(role, permission)

    def _require_org_admin(self, actor_id: str, org_id: str) -> None:
        self._user(actor_id)
        org = self.connection.execute(
            "SELECT org_id FROM organizations WHERE org_id=?", (org_id,)
        ).fetchone()
        if org is None:
            raise NotFound("组织不存在")
        roles = self._org_roles(actor_id, org_id)
        if "org_admin" in roles:
            return
        if roles or self._has_org_membership(actor_id, org_id):
            raise Forbidden("需要组织管理员权限")
        raise NotFound("组织不存在")

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        row = self.connection.execute(
            "SELECT display_name FROM users WHERE user_id=?", (actor_id,)
        ).fetchone()
        actor_name = actor_id if row is None else row["display_name"]
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,actor_name,payload_json,"
            "created_at) VALUES(?,?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, actor_name, canonical_json(payload), self._now()),
        )

    # ------------------------------------------------------------------
    # 用户、组织、团队与成员关系
    # ------------------------------------------------------------------

    def create_user(self, user_id: str, display_name: str) -> dict[str, Any]:
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name) VALUES(?,?)",
                    (user_id.strip(), display_name.strip()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip()}

    def create_org(self, actor_id: str, org_id: str, name: str) -> dict[str, Any]:
        if not org_id.strip() or not name.strip():
            raise ValidationFailed("组织编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self._user(actor_id)
                self.connection.execute(
                    "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
                    (org_id.strip(), name.strip(), self._now()),
                )
                self.connection.execute(
                    "INSERT INTO org_roles(user_id,org_id,role,created_at) VALUES(?,?,?,?)",
                    (actor_id, org_id.strip(), "org_admin", self._now()),
                )
                self._audit("org", org_id.strip(), "org.created", actor_id, {"name": name.strip()})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"组织已存在: {org_id}") from exc
        return {"org_id": org_id.strip(), "name": name.strip()}

    def create_team(self, actor_id: str, org_id: str, team_id: str, name: str) -> dict[str, Any]:
        if not team_id.strip() or not name.strip():
            raise ValidationFailed("团队编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self._require_org_admin(actor_id, org_id)
                self.connection.execute(
                    "INSERT INTO teams(org_id,team_id,name,created_at) VALUES(?,?,?,?)",
                    (org_id, team_id.strip(), name.strip(), self._now()),
                )
                self._audit(
                    "team", f"{org_id}/{team_id.strip()}", "team.created", actor_id, {"name": name.strip()}
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"团队已存在: {team_id}") from exc
        return {"org_id": org_id, "team_id": team_id.strip()}

    def _grant_guard(self, actor_id: str, org_id: str, user_id: str) -> None:
        """组织管理员不能调整自己的授权，防止借此获得审批或读取权限。"""

        self._require_org_admin(actor_id, org_id)
        if user_id == actor_id:
            raise Forbidden("不能调整自己在组织内的授权")
        self._user(user_id)

    def grant_membership(
        self, actor_id: str, org_id: str, team_id: str, user_id: str, role: str
    ) -> dict[str, Any]:
        if role not in TEAM_ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        try:
            with transaction(self.connection, immediate=True):
                self._grant_guard(actor_id, org_id, user_id)
                team = self.connection.execute(
                    "SELECT team_id FROM teams WHERE org_id=? AND team_id=?", (org_id, team_id)
                ).fetchone()
                if team is None:
                    raise NotFound("团队不存在")
                self.connection.execute(
                    "INSERT INTO memberships(user_id,org_id,team_id,role,created_at) VALUES(?,?,?,?,?)",
                    (user_id, org_id, team_id, role, self._now()),
                )
                self._audit(
                    "membership", f"{org_id}/{team_id}/{user_id}", "membership.granted", actor_id,
                    {"role": role},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("成员关系已存在") from exc
        return {"user_id": user_id, "org_id": org_id, "team_id": team_id, "role": role}

    def revoke_membership(self, actor_id: str, org_id: str, team_id: str, user_id: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            self._grant_guard(actor_id, org_id, user_id)
            row = self.connection.execute(
                "SELECT role FROM memberships WHERE user_id=? AND org_id=? AND team_id=?",
                (user_id, org_id, team_id),
            ).fetchone()
            if row is None:
                raise NotFound("成员关系不存在")
            self.connection.execute(
                "DELETE FROM memberships WHERE user_id=? AND org_id=? AND team_id=?",
                (user_id, org_id, team_id),
            )
            self._audit(
                "membership", f"{org_id}/{team_id}/{user_id}", "membership.revoked", actor_id,
                {"role": row["role"]},
            )
        return {"user_id": user_id, "org_id": org_id, "team_id": team_id, "revoked": True}

    def grant_org_role(self, actor_id: str, org_id: str, user_id: str, role: str) -> dict[str, Any]:
        if role not in ORG_ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知组织角色: {role}")
        try:
            with transaction(self.connection, immediate=True):
                self._grant_guard(actor_id, org_id, user_id)
                self.connection.execute(
                    "INSERT INTO org_roles(user_id,org_id,role,created_at) VALUES(?,?,?,?)",
                    (user_id, org_id, role, self._now()),
                )
                self._audit("org", org_id, "org_role.granted", actor_id, {"user_id": user_id, "role": role})
        except sqlite3.IntegrityError as exc:
            raise Conflict("组织角色已存在") from exc
        return {"user_id": user_id, "org_id": org_id, "role": role}

    def revoke_org_role(self, actor_id: str, org_id: str, user_id: str, role: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            self._grant_guard(actor_id, org_id, user_id)
            cursor = self.connection.execute(
                "DELETE FROM org_roles WHERE user_id=? AND org_id=? AND role=?", (user_id, org_id, role)
            )
            if cursor.rowcount != 1:
                raise NotFound("组织角色不存在")
            self._audit("org", org_id, "org_role.revoked", actor_id, {"user_id": user_id, "role": role})
        return {"user_id": user_id, "org_id": org_id, "role": role, "revoked": True}

    def list_memberships(self, actor_id: str, org_id: str) -> dict[str, Any]:
        self._user(actor_id)
        org = self.connection.execute(
            "SELECT org_id FROM organizations WHERE org_id=?", (org_id,)
        ).fetchone()
        if org is None:
            raise NotFound("组织不存在")
        roles = self._org_roles(actor_id, org_id)
        if not roles & {"org_admin", "org_auditor"}:
            if roles or self._has_org_membership(actor_id, org_id):
                raise Forbidden("需要组织管理员或组织审计员权限")
            raise NotFound("组织不存在")
        memberships = self.connection.execute(
            "SELECT m.user_id,m.org_id,m.team_id,m.role,m.created_at,u.display_name "
            "FROM memberships m JOIN users u ON u.user_id=m.user_id "
            "WHERE m.org_id=? ORDER BY m.team_id,m.user_id",
            (org_id,),
        ).fetchall()
        org_roles = self.connection.execute(
            "SELECT r.user_id,r.role,r.created_at,u.display_name "
            "FROM org_roles r JOIN users u ON u.user_id=r.user_id "
            "WHERE r.org_id=? ORDER BY r.user_id,r.role",
            (org_id,),
        ).fetchall()
        return {
            "memberships": [dict(row) for row in memberships],
            "org_roles": [dict(row) for row in org_roles],
        }

    # ------------------------------------------------------------------
    # 目录：机器人、构建、协议
    # ------------------------------------------------------------------

    def register_robot(
        self, actor_id: str, org_id: str, team_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        try:
            with transaction(self.connection, immediate=True):
                team = self.connection.execute(
                    "SELECT team_id FROM teams WHERE org_id=? AND team_id=?", (org_id, team_id)
                ).fetchone()
                if team is None:
                    raise NotFound("团队不存在")
                self._require_scoped_permission(actor_id, org_id, team_id, "catalog.write", "团队不存在")
                self.connection.execute(
                    "INSERT INTO robots(robot_id,org_id,team_id,model_name,vendor,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (robot_id, org_id, team_id, model_name, vendor, self._now()),
                )
                self._audit(
                    "robot", robot_id, "robot.registered", actor_id,
                    {"org_id": org_id, "team_id": team_id, "model_name": model_name},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"机器人已存在: {robot_id}") from exc
        return {"robot_id": robot_id, "org_id": org_id, "team_id": team_id,
                "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, robot_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                robot = self.connection.execute(
                    "SELECT * FROM robots WHERE robot_id=?", (robot_id,)
                ).fetchone()
                if robot is None:
                    raise NotFound("机器人不存在")
                self._require_scoped_permission(
                    actor_id, robot["org_id"], robot["team_id"], "catalog.write", "机器人不存在"
                )
                self.connection.execute(
                    "INSERT INTO builds(build_id,org_id,team_id,robot_id,version,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (build_id, robot["org_id"], robot["team_id"], robot_id, version,
                     content_sha256.lower(), self._now()),
                )
                self._audit(
                    "build", build_id, "build.registered", actor_id,
                    {"org_id": robot["org_id"], "team_id": robot["team_id"],
                     "robot_id": robot_id, "version": version},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "robot_id": robot_id, "version": version}

    def publish_protocol(
        self, actor_id: str, org_id: str, team_id: str, raw: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                team = self.connection.execute(
                    "SELECT team_id FROM teams WHERE org_id=? AND team_id=?", (org_id, team_id)
                ).fetchone()
                if team is None:
                    raise NotFound("团队不存在")
                self._require_scoped_permission(actor_id, org_id, team_id, "protocol.publish", "团队不存在")
                self.connection.execute(
                    "INSERT INTO protocol_catalog(org_id,team_id,protocol_id,version,title,task_family,"
                    "canonical_json,content_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (org_id, team_id, protocol.protocol_id, protocol.version, protocol.title,
                     protocol.task_family, text, digest, self._now()),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit(
                    "protocol", identity, "protocol.published", actor_id,
                    {"org_id": org_id, "team_id": team_id, "sha256": digest},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, org_id: str, team_id: str, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog "
            "WHERE org_id=? AND team_id=? AND protocol_id=? AND version=?",
            (org_id, team_id, protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    # ------------------------------------------------------------------
    # 批次生命周期
    # ------------------------------------------------------------------

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        try:
            with transaction(self.connection, immediate=True):
                build = self.connection.execute(
                    "SELECT * FROM builds WHERE build_id=?", (build_id,)
                ).fetchone()
                if build is None:
                    raise NotFound("构建不存在")
                org_id, team_id = build["org_id"], build["team_id"]
                self._require_scoped_permission(actor_id, org_id, team_id, "batch.create", "构建不存在")
                protocol_row = self.connection.execute(
                    "SELECT 1 FROM protocol_catalog WHERE org_id=? AND team_id=? AND protocol_id=? AND version=?",
                    (org_id, team_id, protocol_id, protocol_version),
                ).fetchone()
                if protocol_row is None:
                    other = self.connection.execute(
                        "SELECT org_id,team_id FROM protocol_catalog WHERE protocol_id=? AND version=?",
                        (protocol_id, protocol_version),
                    ).fetchone()
                    if other is not None and self._can_read(actor_id, other["org_id"], other["team_id"]):
                        raise ValidationFailed("协议与构建不属于同一团队，拒绝跨组织或跨团队引用")
                    raise NotFound("协议版本不存在")
                self.connection.execute(
                    "INSERT INTO batches(batch_id,org_id,team_id,protocol_id,protocol_version,build_id,"
                    "state,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (batch_id, org_id, team_id, protocol_id, protocol_version, build_id, "draft",
                     actor_id, self._now()),
                )
                self._audit(
                    "batch", batch_id, "batch.created", actor_id,
                    {"org_id": org_id, "team_id": team_id, "build_id": build_id},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突") from exc
        return dict(self._batch_row(batch_id))

    def _batch_row(self, batch_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return row

    def get_batch(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        self._user(actor_id)
        batch = self._batch_row(batch_id)
        if not self._can_read(actor_id, batch["org_id"], batch["team_id"]):
            raise NotFound("批次不存在")
        return dict(batch)

    def list_batches(
        self, actor_id: str, org_id: str | None = None, team_id: str | None = None
    ) -> dict[str, Any]:
        self._user(actor_id)
        memberships = self.connection.execute(
            "SELECT org_id,team_id FROM memberships WHERE user_id=?", (actor_id,)
        ).fetchall()
        auditor_orgs = self.connection.execute(
            "SELECT org_id FROM org_roles WHERE user_id=? AND role='org_auditor'", (actor_id,)
        ).fetchall()
        clauses: list[str] = []
        params: list[str] = []
        for row in memberships:
            clauses.append("(org_id=? AND team_id=?)")
            params.extend((row["org_id"], row["team_id"]))
        for row in auditor_orgs:
            clauses.append("org_id=?")
            params.append(row["org_id"])
        if not clauses:
            return {"batches": []}
        sql = "SELECT * FROM batches WHERE (" + " OR ".join(clauses) + ")"
        if org_id is not None:
            sql += " AND org_id=?"
            params.append(org_id)
        if team_id is not None:
            sql += " AND team_id=?"
            params.append(team_id)
        sql += " ORDER BY created_at,batch_id"
        rows = self.connection.execute(sql, params).fetchall()
        return {"batches": [dict(row) for row in rows]}

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            batch = self._batch_row(batch_id)
            self._require_scoped_permission(
                actor_id, batch["org_id"], batch["team_id"], "batch.start", "批次不存在"
            )
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return dict(self._batch_row(batch_id))

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("观测数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        with transaction(self.connection, immediate=True):
            batch = self._batch_row(batch_id)
            self._require_scoped_permission(
                actor_id, batch["org_id"], batch["team_id"], "observation.import", "批次不存在"
            )
            existing = self._idempotent_response(scope, idempotency_key, request_digest)
            if existing is not None:
                return existing
            if batch["state"] != "running":
                raise InvalidState("只有运行中的批次可以导入观测")
            protocol, _ = self._protocol(
                batch["org_id"], batch["team_id"], batch["protocol_id"], batch["protocol_version"]
            )
            build = self.connection.execute(
                "SELECT robot_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()
            parsed: list[Observation] = []
            for raw in rows:
                try:
                    item = Observation.from_dict(raw, protocol)
                except ValidationError as exc:
                    raise ValidationFailed(str(exc)) from exc
                if item.robot_id != build["robot_id"]:
                    raise ValidationFailed("观测机器人与批次构建不一致")
                parsed.append(item)
            response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
            try:
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,"
                        "observed_at,metrics_json,content_sha256,imported_by,imported_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.robot_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("来源行重复或幂等键并发冲突") from exc
            self._audit("batch", batch_id, "observations.imported", actor_id, response)
            return response

    # ------------------------------------------------------------------
    # 排除申请
    # ------------------------------------------------------------------

    def _observation_scope(self, observation_id: int, not_found: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT o.observation_id,o.batch_id,b.org_id,b.team_id FROM observations o "
            "JOIN batches b ON b.batch_id=o.batch_id WHERE o.observation_id=?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise NotFound(not_found)
        return row

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            observation = self._observation_scope(observation_id, "观测不存在")
            self._require_scoped_permission(
                actor_id, observation["org_id"], observation["team_id"], "exclusion.request", "观测不存在"
            )
            try:
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("该观测已有待处理或生效排除") from exc
            exclusion_id = cursor.lastrowid
            self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def _exclusion_scope(self, exclusion_id: int, not_found: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT e.*,o.batch_id,b.org_id,b.team_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id "
            "JOIN batches b ON b.batch_id=o.batch_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound(not_found)
        return row

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            row = self._exclusion_scope(exclusion_id, "排除申请不存在")
            self._require_scoped_permission(
                actor_id, row["org_id"], row["team_id"], "exclusion.review", "排除申请不存在"
            )
            if row["status"] != "pending":
                raise InvalidState("排除申请已经处理")
            if row["requested_by"] == actor_id:
                raise Forbidden("申请人不能复核自己的排除申请")
            status = "approved" if approve else "rejected"
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            row = self._exclusion_scope(exclusion_id, "排除记录不存在")
            self._require_scoped_permission(
                actor_id, row["org_id"], row["team_id"], "exclusion.revoke", "排除记录不存在"
            )
            if row["status"] != "approved":
                raise InvalidState("只有已批准的排除可以撤销")
            if row["requested_by"] != actor_id:
                raise Forbidden("只有原申请人可以撤销排除")
            batch = self._batch_row(row["batch_id"])
            if batch["state"] != "running":
                raise InvalidState("批次封存后不能改变排除状态")
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    # ------------------------------------------------------------------
    # 封存、分析任务与审批
    # ------------------------------------------------------------------

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            batch = self._batch_row(batch_id)
            self._require_scoped_permission(
                actor_id, batch["org_id"], batch["team_id"], "batch.seal", "批次不存在"
            )
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return dict(self._batch_row(batch_id))

    def claim_job(
        self, actor_id: str, org_id: str, team_id: str, worker_id: str, lease_seconds: int = 60
    ) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            team = self.connection.execute(
                "SELECT team_id FROM teams WHERE org_id=? AND team_id=?", (org_id, team_id)
            ).fetchone()
            if team is None:
                raise NotFound("团队不存在")
            self._require_scoped_permission(actor_id, org_id, team_id, "analysis.run", "团队不存在")
            row = self.connection.execute(
                "SELECT j.job_id FROM analysis_jobs j JOIN batches b ON b.batch_id=j.batch_id "
                "WHERE b.org_id=? AND b.team_id=? AND "
                "((j.state='queued' AND j.available_at<=?) OR (j.state='leased' AND j.lease_expires_at<=?)) "
                "ORDER BY j.available_at,j.job_id LIMIT 1",
                (org_id, team_id, now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,"
                "lease_expires_at=?,updated_at=? WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id=row["robot_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self._batch_row(job["batch_id"])
        org_id, team_id = batch["org_id"], batch["team_id"]
        self._require_scoped_permission(statistician_id, org_id, team_id, "analysis.run", "分析任务不存在")
        protocol, protocol_digest = self._protocol(
            org_id, team_id, batch["protocol_id"], batch["protocol_version"]
        )
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            # 事务内复核成员资格，避免分析计算期间被撤权后仍写入。
            self._require_scoped_permission(statistician_id, org_id, team_id, "analysis.run", "分析任务不存在")
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed,"
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL,"
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知准入决定")
        try:
            with transaction(self.connection, immediate=True):
                batch = self._batch_row(batch_id)
                self._require_scoped_permission(
                    actor_id, batch["org_id"], batch["team_id"], "decision.write", "批次不存在"
                )
                analysis_row = self.connection.execute(
                    "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
                ).fetchone()
                if analysis_row is None:
                    raise NotFound("分析版本不存在")
                if analysis_row["created_by"] == actor_id:
                    raise Forbidden("统计负责人不能批准自己的分析")
                if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
                    raise InvalidState("分析不是批次当前可审批版本")
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        self._user(actor_id)
        batch = self._batch_row(batch_id)
        org_id, team_id = batch["org_id"], batch["team_id"]
        role = self._membership_role(actor_id, org_id, team_id)
        org_roles = self._org_roles(actor_id, org_id)
        if role is None and "org_auditor" not in org_roles:
            raise NotFound("批次不存在")
        allowed = "org_auditor" in org_roles or (
            role is not None and "report.read" in TEAM_ROLE_PERMISSIONS[role]
        )
        if not allowed:
            raise Forbidden("当前角色不能读取完整报告")
        protocol, protocol_digest = self._protocol(
            org_id, team_id, batch["protocol_id"], batch["protocol_version"]
        )
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,actor_name,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": dict(batch),
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
