"""统计准入服务的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Callable, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


TEAM_ROLES = ("operator", "statistician", "approver", "auditor")
ORG_ROLES = ("org_admin", "org_auditor")

ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {
        "protocol.publish", "batch.seal", "exclusion.review", "analysis.run", "report.read",
    },
    "approver": {"decision.write", "report.read"},
    "auditor": {"report.read", "audit.read"},
}


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        # 测试钩子：在 IMMEDIATE 事务内完成成员校验后回调，用于验证并发撤权不可穿透。
        self.permission_barrier: Callable[[], None] | None = None
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _barrier(self) -> None:
        if self.permission_barrier is not None:
            self.permission_barrier()

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        actor_role: str,
        payload: Mapping[str, Any],
        *,
        org_id: str | None = None,
        team_id: str | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,actor_role,"
            "org_id,team_id,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, actor_role,
             org_id, team_id, canonical_json(payload), self._now()),
        )

    # ------------------------------------------------------------------ 建档

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

    def set_user_active(self, actor_id: str, org_id: str, user_id: str, active: bool) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            self._require_org_role(actor_id, org_id, "org_admin")
            if self.connection.execute(
                "SELECT 1 FROM memberships WHERE user_id=? AND org_id=?", (user_id, org_id)
            ).fetchone() is None:
                raise NotFound("用户不存在或不属于该组织")
            cursor = self.connection.execute(
                "UPDATE users SET active=? WHERE user_id=?", (1 if active else 0, user_id)
            )
            if cursor.rowcount != 1:
                raise NotFound(f"用户不存在: {user_id}")
        return {"user_id": user_id, "active": active}

    def create_organization(
        self, org_id: str, display_name: str, admin_user_id: str, admin_display_name: str | None = None
    ) -> dict[str, Any]:
        if not org_id.strip() or not display_name.strip() or not admin_user_id.strip():
            raise ValidationFailed("组织编号、名称和首任管理员不能为空")
        try:
            with transaction(self.connection, immediate=True):
                if admin_display_name is not None:
                    self.connection.execute(
                        "INSERT INTO users(user_id,display_name) VALUES(?,?) ON CONFLICT(user_id) DO NOTHING",
                        (admin_user_id.strip(), admin_display_name.strip()),
                    )
                elif self.connection.execute(
                    "SELECT 1 FROM users WHERE user_id=?", (admin_user_id.strip(),)
                ).fetchone() is None:
                    raise NotFound(f"用户不存在: {admin_user_id}")
                self.connection.execute(
                    "INSERT INTO organizations(org_id,display_name,created_at) VALUES(?,?,?)",
                    (org_id.strip(), display_name.strip(), self._now()),
                )
                self.connection.execute(
                    "INSERT INTO memberships(user_id,org_id,team_id,role,granted_at) VALUES(?,?,NULL,?,?)",
                    (admin_user_id.strip(), org_id.strip(), "org_admin", self._now()),
                )
                self._audit("organization", org_id.strip(), "organization.created",
                            admin_user_id.strip(), "org_admin", {"display_name": display_name.strip()},
                            org_id=org_id.strip())
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"组织已存在或参数冲突: {org_id}") from exc
        return {"org_id": org_id.strip(), "admin_user_id": admin_user_id.strip()}

    def create_team(self, actor_id: str, org_id: str, team_id: str, display_name: str) -> dict[str, Any]:
        if not team_id.strip() or not display_name.strip():
            raise ValidationFailed("团队编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self._require_org_role(actor_id, org_id, "org_admin")
                self.connection.execute(
                    "INSERT INTO teams(team_id,org_id,display_name,created_at) VALUES(?,?,?,?)",
                    (team_id.strip(), org_id, display_name.strip(), self._now()),
                )
                self._audit("team", team_id.strip(), "team.created", actor_id, "org_admin",
                            {"org_id": org_id, "display_name": display_name.strip()}, org_id=org_id)
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"团队已存在: {team_id}") from exc
        return {"org_id": org_id, "team_id": team_id.strip()}

    def grant_membership(
        self, actor_id: str, user_id: str, org_id: str, team_id: str | None, role: str
    ) -> dict[str, Any]:
        if role in TEAM_ROLES:
            if not team_id:
                raise ValidationFailed(f"角色 {role} 必须授予到具体团队")
            scope_type, scope_id = "team", team_id
        elif role in ORG_ROLES:
            if team_id:
                raise ValidationFailed(f"角色 {role} 是组织级角色，不能绑定团队")
            team_id = None
            scope_type, scope_id = "organization", org_id
        else:
            raise ValidationFailed(f"未知角色: {role}")
        try:
            with transaction(self.connection, immediate=True):
                self._require_org_role(actor_id, org_id, "org_admin")
                if self.connection.execute(
                    "SELECT 1 FROM users WHERE user_id=? AND active=1", (user_id,)
                ).fetchone() is None:
                    raise NotFound(f"用户不存在或已停用: {user_id}")
                if self.connection.execute(
                    "SELECT 1 FROM organizations WHERE org_id=?", (org_id,)
                ).fetchone() is None:
                    raise NotFound("组织不存在")
                if scope_type == "team" and self.connection.execute(
                    "SELECT 1 FROM teams WHERE org_id=? AND team_id=?", (org_id, team_id)
                ).fetchone() is None:
                    raise NotFound("团队不存在")
                self.connection.execute(
                    "INSERT INTO memberships(user_id,org_id,team_id,role,granted_at) VALUES(?,?,?,?,?)",
                    (user_id, org_id, team_id, role, self._now()),
                )
                self._audit(scope_type, scope_id, "membership.granted", actor_id, "org_admin",
                            {"user_id": user_id, "role": role}, org_id=org_id, team_id=team_id)
        except sqlite3.IntegrityError as exc:
            raise Conflict("成员关系已经存在（同一团队每用户只能有一个角色）") from exc
        return {"user_id": user_id, "org_id": org_id, "team_id": team_id, "role": role}

    def revoke_membership(
        self, actor_id: str, user_id: str, org_id: str, team_id: str | None, role: str
    ) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            self._require_org_role(actor_id, org_id, "org_admin")
            cursor = self.connection.execute(
                "DELETE FROM memberships WHERE user_id=? AND org_id=? AND "
                "(team_id IS ? OR team_id=?) AND role=?",
                (user_id, org_id, team_id, team_id, role),
            )
            if cursor.rowcount != 1:
                raise NotFound("成员关系不存在")
            if role == "org_admin" and self.connection.execute(
                "SELECT count(*) FROM memberships WHERE org_id=? AND role='org_admin'", (org_id,)
            ).fetchone()[0] == 0:
                raise InvalidState("不能撤销组织的最后一名组织管理员")
            self._audit(
                "team" if team_id is not None else "organization",
                team_id if team_id is not None else org_id,
                "membership.revoked", actor_id, "org_admin",
                {"user_id": user_id, "role": role}, org_id=org_id, team_id=team_id,
            )
        return {"user_id": user_id, "org_id": org_id, "team_id": team_id, "role": role, "active": False}

    # ------------------------------------------------------------- 权限辅助

    def _require_org_role(self, user_id: str, org_id: str, role: str) -> None:
        """事务内调用：校验组织级角色；用户/组织不可见时一律按不存在处理。"""
        row = self.connection.execute(
            "SELECT m.role FROM memberships m JOIN users u ON u.user_id=m.user_id "
            "WHERE m.user_id=? AND m.org_id=? AND m.team_id IS NULL AND u.active=1",
            (user_id, org_id),
        ).fetchone()
        if row is None:
            raise NotFound("组织不存在")
        if row["role"] != role:
            raise Forbidden(f"需要组织角色 {role}")

    def _team_role(self, user_id: str, org_id: str, team_id: str) -> str | None:
        """事务内调用：返回用户在该团队的当前角色，无成员关系返回 None。"""
        row = self.connection.execute(
            "SELECT m.role FROM memberships m JOIN users u ON u.user_id=m.user_id "
            "WHERE m.user_id=? AND m.org_id=? AND m.team_id=? AND u.active=1",
            (user_id, org_id, team_id),
        ).fetchone()
        return None if row is None else row["role"]

    def _is_org_auditor(self, user_id: str, org_id: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM memberships m JOIN users u ON u.user_id=m.user_id "
            "WHERE m.user_id=? AND m.org_id=? AND m.role='org_auditor' AND m.team_id IS NULL AND u.active=1",
            (user_id, org_id),
        ).fetchone() is not None

    def _authorize_scope(self, user_id: str, org_id: str, team_id: str, permission: str) -> str:
        """事务内调用：权限检查 -> 并发屏障 -> 成员关系二次确认。

        保证成员关系在首次读取后、写入前被撤销（并发撤权）时写操作被拒绝。
        """
        role = self._team_role(user_id, org_id, team_id)
        if role is None:
            raise NotFound("对象不存在或当前用户无权访问")
        if permission not in ROLE_PERMISSIONS[role]:
            raise Forbidden(f"角色 {role} 无权执行 {permission}")
        self._barrier()
        current = self._team_role(user_id, org_id, team_id)
        if current is None:
            raise NotFound("对象不存在或当前用户无权访问")
        if current != role or permission not in ROLE_PERMISSIONS[current]:
            raise Forbidden("成员关系在操作过程中发生变化")
        return role

    # 裸业务编号在复合键下可能落在多个团队，统一通过调用方可见范围解析。
    _VISIBLE_SQL = """
        SELECT * FROM {table} t WHERE t.{id_col}=? AND (
            EXISTS (
                SELECT 1 FROM memberships m JOIN users u ON u.user_id=m.user_id
                WHERE m.user_id=? AND m.team_id IS NOT NULL AND u.active=1
                AND m.org_id=t.org_id AND m.team_id=t.team_id
            )
            OR EXISTS (
                SELECT 1 FROM memberships m JOIN users u ON u.user_id=m.user_id
                WHERE m.user_id=? AND m.role='org_auditor' AND m.team_id IS NULL AND u.active=1
                AND m.org_id=t.org_id
            )
        )
    """

    def _resolve_visible(self, table: str, id_col: str, value: Any, actor_id: str) -> sqlite3.Row:
        rows = self.connection.execute(
            self._VISIBLE_SQL.format(table=table, id_col=id_col),
            (value, actor_id, actor_id),
        ).fetchall()
        if not rows:
            label = {"batches": "批次", "robots": "机器人", "builds": "构建"}.get(table, "对象")
            raise NotFound(f"{label}不存在")
        if len(rows) > 1:
            raise Conflict("编号在可见范围内不唯一，请通过组织与团队定位")
        return rows[0]

    def _resolve_batch_for_write(
        self, actor_id: str, batch_id: str, permission: str
    ) -> tuple[sqlite3.Row, str]:
        """通过团队成员关系解析批次并校验权限（组织审计员只读，不会命中此路径）。"""
        rows = self.connection.execute(
            "SELECT b.*, m.role AS actor_role FROM batches b "
            "JOIN memberships m ON m.org_id=b.org_id AND m.team_id=b.team_id AND m.team_id IS NOT NULL "
            "JOIN users u ON u.user_id=m.user_id AND u.active=1 "
            "WHERE m.user_id=? AND b.batch_id=?",
            (actor_id, batch_id),
        ).fetchall()
        if not rows:
            raise NotFound("批次不存在")
        if len(rows) > 1:
            raise Conflict("批次编号在可见范围内不唯一，请通过组织与团队定位")
        row = rows[0]
        role = row["actor_role"]
        if permission not in ROLE_PERMISSIONS[role]:
            raise Forbidden(f"角色 {role} 无权执行 {permission}")
        self._barrier()
        current = self.connection.execute(
            "SELECT b.*, m.role AS actor_role FROM batches b "
            "JOIN memberships m ON m.org_id=b.org_id AND m.team_id=b.team_id AND m.team_id IS NOT NULL "
            "JOIN users u ON u.user_id=m.user_id AND u.active=1 "
            "WHERE m.user_id=? AND b.batch_id=?",
            (actor_id, batch_id),
        ).fetchall()
        if not current:
            raise NotFound("批次不存在")
        if len(current) > 1 or current[0]["actor_role"] != role:
            raise Forbidden("成员关系在操作过程中发生变化")
        return current[0], role

    def _visible_scopes(self, user_id: str) -> tuple[set[tuple[str, str]], set[str]]:
        """返回 (可见团队集合, 组织审计员可见的组织集合)。"""
        teams = {
            (row["org_id"], row["team_id"])
            for row in self.connection.execute(
                "SELECT m.org_id,m.team_id FROM memberships m JOIN users u ON u.user_id=m.user_id "
                "WHERE m.user_id=? AND m.team_id IS NOT NULL AND u.active=1",
                (user_id,),
            )
        }
        auditor_orgs = {
            row["org_id"]
            for row in self.connection.execute(
                "SELECT m.org_id FROM memberships m JOIN users u ON u.user_id=m.user_id "
                "WHERE m.user_id=? AND m.role='org_auditor' AND m.team_id IS NULL AND u.active=1",
                (user_id,),
            )
        }
        return teams, auditor_orgs

    def _list_scoped(
        self, table: str, user_id: str, org_id: str | None, team_id: str | None
    ) -> list[dict[str, Any]]:
        teams, auditor_orgs = self._visible_scopes(user_id)
        if not teams and not auditor_orgs:
            return []
        if team_id is not None and org_id is None:
            raise ValidationFailed("按团队过滤时必须同时提供 org_id")
        if org_id is not None and org_id not in auditor_orgs and not any(
            org == org_id for org, _ in teams
        ):
            # 无权组织不泄露存在性，统一返回空集合
            return []
        if team_id is not None and (org_id, team_id) not in teams and org_id not in auditor_orgs:
            return []
        clauses: list[str] = []
        parameters: list[Any] = []
        if teams:
            pair_clause = " OR ".join("(org_id=? AND team_id=?)" for _ in teams)
            clauses.append(f"({pair_clause})")
            for org, team in sorted(teams):
                parameters.extend((org, team))
        if auditor_orgs:
            placeholders = ",".join("?" for _ in auditor_orgs)
            clauses.append(f"org_id IN ({placeholders})")
            parameters.extend(sorted(auditor_orgs))
        sql = f"SELECT * FROM {table} WHERE ({' OR '.join(clauses)})"
        if org_id is not None:
            sql += " AND org_id=?"
            parameters.append(org_id)
        if team_id is not None:
            sql += " AND team_id=?"
            parameters.append(team_id)
        sql += " ORDER BY org_id,team_id"
        return [dict(row) for row in self.connection.execute(sql, parameters).fetchall()]

    # ------------------------------------------------------------- 业务目录

    def register_robot(
        self, actor_id: str, org_id: str, team_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            role = self._authorize_scope(actor_id, org_id, team_id, "catalog.write")
            try:
                self.connection.execute(
                    "INSERT INTO robots(robot_id,org_id,team_id,model_name,vendor,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (robot_id, org_id, team_id, model_name, vendor, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict(f"机器人已存在: {robot_id}") from exc
            self._audit("robot", robot_id, "robot.registered", actor_id, role,
                        {"model_name": model_name}, org_id=org_id, team_id=team_id)
        return {"robot_id": robot_id, "org_id": org_id, "team_id": team_id,
                "model_name": model_name, "vendor": vendor}

    def register_build(
        self,
        actor_id: str,
        org_id: str,
        team_id: str,
        build_id: str,
        robot_id: str,
        version: str,
        content_sha256: str,
    ) -> dict[str, Any]:
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        with transaction(self.connection, immediate=True):
            role = self._authorize_scope(actor_id, org_id, team_id, "catalog.write")
            robot = self.connection.execute(
                "SELECT 1 FROM robots WHERE org_id=? AND team_id=? AND robot_id=?",
                (org_id, team_id, robot_id),
            ).fetchone()
            if robot is None:
                raise ValidationFailed("引用的机器人不存在或不属于当前组织与团队")
            try:
                self.connection.execute(
                    "INSERT INTO builds(build_id,org_id,team_id,robot_id,version,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (build_id, org_id, team_id, robot_id, version, content_sha256.lower(), self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("构建编号、版本或摘要冲突") from exc
            self._audit("build", build_id, "build.registered", actor_id, role,
                        {"robot_id": robot_id, "version": version}, org_id=org_id, team_id=team_id)
        return {"build_id": build_id, "org_id": org_id, "team_id": team_id,
                "robot_id": robot_id, "version": version}

    def publish_protocol(
        self, actor_id: str, org_id: str, team_id: str, raw: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        with transaction(self.connection, immediate=True):
            role = self._authorize_scope(actor_id, org_id, team_id, "protocol.publish")
            try:
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,org_id,team_id,title,task_family,"
                    "canonical_json,content_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id, protocol.version, org_id, team_id,
                        protocol.title, protocol.task_family, text, digest, self._now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("协议版本或内容摘要已经存在") from exc
            identity = f"{protocol.protocol_id}@{protocol.version}"
            self._audit("protocol", identity, "protocol.published", actor_id, role,
                        {"sha256": digest}, org_id=org_id, team_id=team_id)
        return {"protocol_id": protocol.protocol_id, "version": protocol.version,
                "org_id": org_id, "team_id": team_id, "sha256": digest}

    def _protocol_scoped(
        self, org_id: str, team_id: str, protocol_id: str, version: int
    ) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog "
            "WHERE org_id=? AND team_id=? AND protocol_id=? AND version=?",
            (org_id, team_id, protocol_id, version),
        ).fetchone()
        if row is None:
            raise ValidationFailed("引用的协议版本不存在或不属于当前组织与团队")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    # ---------------------------------------------------------------- 批次

    def create_batch(
        self,
        actor_id: str,
        org_id: str,
        team_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            role = self._authorize_scope(actor_id, org_id, team_id, "batch.create")
            self._protocol_scoped(org_id, team_id, protocol_id, protocol_version)
            build = self.connection.execute(
                "SELECT 1 FROM builds WHERE org_id=? AND team_id=? AND build_id=?",
                (org_id, team_id, build_id),
            ).fetchone()
            if build is None:
                raise ValidationFailed("引用的构建不存在或不属于当前组织与团队")
            try:
                self.connection.execute(
                    "INSERT INTO batches(batch_id,org_id,team_id,protocol_id,protocol_version,build_id,"
                    "state,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (batch_id, org_id, team_id, protocol_id, protocol_version, build_id,
                     "draft", actor_id, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("批次编号冲突或引用不存在") from exc
            self._audit("batch", batch_id, "batch.created", actor_id, role,
                        {"build_id": build_id}, org_id=org_id, team_id=team_id)
        return {
            "batch_id": batch_id, "org_id": org_id, "team_id": team_id,
            "protocol_id": protocol_id, "protocol_version": protocol_version,
            "build_id": build_id, "state": "draft", "revision": 1,
            "created_by": actor_id,
        }

    def get_batch(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        with transaction(self.connection):
            return dict(self._resolve_visible("batches", "batch_id", batch_id, actor_id))

    def list_batches(
        self, actor_id: str, org_id: str | None = None, team_id: str | None = None
    ) -> list[dict[str, Any]]:
        with transaction(self.connection):
            return self._list_scoped("batches", actor_id, org_id, team_id)

    def list_robots(
        self, actor_id: str, org_id: str | None = None, team_id: str | None = None
    ) -> list[dict[str, Any]]:
        with transaction(self.connection):
            return self._list_scoped("robots", actor_id, org_id, team_id)

    def list_builds(
        self, actor_id: str, org_id: str | None = None, team_id: str | None = None
    ) -> list[dict[str, Any]]:
        with transaction(self.connection):
            return self._list_scoped("builds", actor_id, org_id, team_id)

    def list_protocols(
        self, actor_id: str, org_id: str | None = None, team_id: str | None = None
    ) -> list[dict[str, Any]]:
        with transaction(self.connection):
            rows = self._list_scoped("protocol_catalog", actor_id, org_id, team_id)
        for row in rows:
            row.pop("canonical_json", None)
        return rows

    def get_robot(self, actor_id: str, robot_id: str) -> dict[str, Any]:
        with transaction(self.connection):
            return dict(self._resolve_visible("robots", "robot_id", robot_id, actor_id))

    def get_build(self, actor_id: str, build_id: str) -> dict[str, Any]:
        with transaction(self.connection):
            return dict(self._resolve_visible("builds", "build_id", build_id, actor_id))

    def get_protocol(
        self, actor_id: str, org_id: str, team_id: str, protocol_id: str, version: int
    ) -> dict[str, Any]:
        with transaction(self.connection):
            row = self.connection.execute(
                "SELECT * FROM protocol_catalog "
                "WHERE org_id=? AND team_id=? AND protocol_id=? AND version=?",
                (org_id, team_id, protocol_id, version),
            ).fetchone()
            if row is None:
                raise NotFound("协议版本不存在")
            if self._team_role(actor_id, row["org_id"], row["team_id"]) is None and not self._is_org_auditor(
                actor_id, row["org_id"]
            ):
                raise NotFound("协议版本不存在")
            data = dict(row)
            data.pop("canonical_json", None)
            return data

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            batch, role = self._resolve_batch_for_write(actor_id, batch_id, "batch.start")
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE org_id=? AND team_id=? AND batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch["org_id"], batch["team_id"], batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, role,
                        {"from_revision": expected_revision},
                        org_id=batch["org_id"], team_id=batch["team_id"])
        return dict(self.connection.execute(
            "SELECT * FROM batches WHERE org_id=? AND team_id=? AND batch_id=?",
            (batch["org_id"], batch["team_id"], batch_id),
        ).fetchone())

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
        with transaction(self.connection, immediate=True):
            # 鉴权必须先于一切业务校验：无权用户不能通过错误差异推断批次/协议状态
            batch, role = self._resolve_batch_for_write(actor_id, batch_id, "observation.import")
            org_id, team_id = batch["org_id"], batch["team_id"]
            # 幂等键作用域包含组织/团队/批次，禁止跨范围碰撞
            scope = f"observations:{org_id}:{team_id}:{batch_id}"
            existing = self._idempotent_response(scope, idempotency_key, request_digest)
            if existing is not None:
                return existing
            if batch["state"] != "running":
                raise InvalidState("只有运行中的批次可以导入观测")
            protocol, _ = self._protocol_scoped(
                org_id, team_id, batch["protocol_id"], batch["protocol_version"]
            )
            build_robot = self.connection.execute(
                "SELECT robot_id FROM builds WHERE org_id=? AND team_id=? AND build_id=?",
                (org_id, team_id, batch["build_id"]),
            ).fetchone()
            if build_robot is None:
                raise InvalidState("批次构建已失效")
            parsed: list[Observation] = []
            for raw in rows:
                try:
                    item = Observation.from_dict(raw, protocol)
                except ValidationError as exc:
                    raise ValidationFailed(str(exc)) from exc
                if item.robot_id != build_robot["robot_id"]:
                    raise ValidationFailed("观测机器人与批次构建不一致")
                parsed.append(item)
            response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
            try:
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(org_id,team_id,batch_id,source_batch,source_row,robot_id,"
                        "stratum_key,observed_at,metrics_json,content_sha256,imported_by,imported_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            org_id,
                            team_id,
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
                self._audit("batch", batch_id, "observations.imported", actor_id, role, response,
                            org_id=org_id, team_id=team_id)
            except sqlite3.IntegrityError as exc:
                raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def _observation_scope(self, observation_id: int) -> sqlite3.Row:
        return self.connection.execute(
            "SELECT observation_id,org_id,team_id,batch_id FROM observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            observation = self._observation_scope(observation_id)
            if observation is None:
                raise NotFound("观测不存在")
            role = self._authorize_scope(
                actor_id, observation["org_id"], observation["team_id"], "exclusion.request"
            )
            try:
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(org_id,observation_id,status,reason,"
                    "requested_by,requested_at) VALUES(?,?,?,?,?,?)",
                    (observation["org_id"], observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
            except sqlite3.IntegrityError as exc:
                raise Conflict("该观测已有待处理或生效排除") from exc
            self._audit("observation", str(observation_id), "exclusion.requested", actor_id, role,
                        {"reason": reason},
                        org_id=observation["org_id"], team_id=observation["team_id"])
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def _exclusion_scope(self, exclusion_id: int) -> sqlite3.Row:
        return self.connection.execute(
            "SELECT e.*,o.org_id,o.team_id,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id AND o.org_id=e.org_id "
            "WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            row = self._exclusion_scope(exclusion_id)
            if row is None:
                raise NotFound("排除申请不存在")
            role = self._authorize_scope(actor_id, row["org_id"], row["team_id"], "exclusion.review")
            if row["status"] != "pending":
                raise InvalidState("排除申请已经处理")
            if row["requested_by"] == actor_id:
                raise Forbidden("申请人不能复核自己的排除申请")
            status = "approved" if approve else "rejected"
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, role,
                        {"note": note}, org_id=row["org_id"], team_id=row["team_id"])
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            row = self._exclusion_scope(exclusion_id)
            if row is None:
                raise NotFound("排除记录不存在")
            role = self._authorize_scope(actor_id, row["org_id"], row["team_id"], "exclusion.revoke")
            if row["status"] != "approved":
                raise InvalidState("只有已批准的排除可以撤销")
            if row["requested_by"] != actor_id:
                raise Forbidden("只有原申请人可以撤销排除")
            if self.connection.execute(
                "SELECT state FROM batches WHERE org_id=? AND team_id=? AND batch_id=?",
                (row["org_id"], row["team_id"], row["batch_id"]),
            ).fetchone()["state"] != "running":
                raise InvalidState("批次封存后不能改变排除状态")
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit("observation", str(row["observation_id"]), "exclusion.revoked", actor_id, role,
                        {"exclusion_id": exclusion_id, "reason": reason},
                        org_id=row["org_id"], team_id=row["team_id"])
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        with transaction(self.connection, immediate=True):
            batch, role = self._resolve_batch_for_write(actor_id, batch_id, "batch.seal")
            org_id, team_id = batch["org_id"], batch["team_id"]
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e "
                "JOIN observations o ON o.observation_id=e.observation_id AND o.org_id=e.org_id "
                "WHERE o.org_id=? AND o.team_id=? AND o.batch_id=? AND e.status='pending'",
                (org_id, team_id, batch_id),
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE org_id=? AND team_id=? AND batch_id=? AND state='running' AND revision=?",
                (self._now(), org_id, team_id, batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(org_id,team_id,batch_id,batch_revision,state,"
                "available_at,created_at,updated_at) VALUES(?,?,?,?, 'queued', ?,?,?)",
                (org_id, team_id, batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, role, {"revision": new_revision},
                        org_id=org_id, team_id=team_id)
        return dict(self.connection.execute(
            "SELECT * FROM batches WHERE org_id=? AND team_id=? AND batch_id=?",
            (org_id, team_id, batch_id),
        ).fetchone())

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,"
                "updated_at=? WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)
            ).fetchone()
        return dict(claimed)

    def _analysis_observations(
        self, org_id: str, team_id: str, batch_id: str, protocol: Protocol
    ) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e "
            "ON e.observation_id=o.observation_id AND e.org_id=o.org_id AND e.status='approved' "
            "WHERE o.org_id=? AND o.team_id=? AND o.batch_id=? ORDER BY o.observation_id",
            (org_id, team_id, batch_id),
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
        # 读事务内先确认统计负责人对任务批次所在团队的成员关系，再透露任务是否存在/租约状态
        with transaction(self.connection):
            job = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise NotFound("分析任务不存在")
            role = self._team_role(statistician_id, job["org_id"], job["team_id"])
            if role is None:
                # 与任务不存在使用同一错误，避免跨组织枚举任务编号
                raise NotFound("分析任务不存在")
            if "analysis.run" not in ROLE_PERMISSIONS[role]:
                raise Forbidden(f"角色 {role} 无权执行 analysis.run")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        org_id, team_id, batch_id = job["org_id"], job["team_id"], job["batch_id"]
        batch = self.connection.execute(
            "SELECT * FROM batches WHERE org_id=? AND team_id=? AND batch_id=?",
            (org_id, team_id, batch_id),
        ).fetchone()
        protocol, protocol_digest = self._protocol_scoped(
            org_id, team_id, batch["protocol_id"], batch["protocol_version"]
        )
        observations = self._analysis_observations(org_id, team_id, batch_id, protocol)
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
            # 团队角色在写事务内复核，防止任务运行期间成员关系被变更后仍落库
            role = self._authorize_scope(statistician_id, org_id, team_id, "analysis.run")
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses "
                "WHERE org_id=? AND team_id=? AND batch_id=? AND batch_revision=? AND input_sha256=?",
                (org_id, team_id, batch_id, job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(org_id,team_id,batch_id,batch_revision,protocol_sha256,"
                    "input_sha256,algorithm_version,seed,result_json,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        org_id, team_id, batch_id, job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id,
                        self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' "
                "WHERE org_id=? AND team_id=? AND batch_id=? AND state IN ('sealed','analyzing')",
                (org_id, team_id, batch_id),
            )
            self._audit("batch", batch_id, "analysis.completed", statistician_id, role,
                        {"analysis_id": analysis_id, "input_sha256": input_digest},
                        org_id=org_id, team_id=team_id)
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
        with transaction(self.connection, immediate=True):
            # 组织管理员即便管理成员关系，也没有团队审批角色，此处一律按不可见处理
            batch, role = self._resolve_batch_for_write(actor_id, batch_id, "decision.write")
            org_id, team_id = batch["org_id"], batch["team_id"]
            analysis_row = self.connection.execute(
                "SELECT * FROM analyses WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
            if (
                analysis_row is None
                or analysis_row["org_id"] != org_id
                or analysis_row["team_id"] != team_id
                or analysis_row["batch_id"] != batch_id
            ):
                raise NotFound("分析版本不存在")
            if analysis_row["created_by"] == actor_id:
                raise Forbidden("统计负责人不能批准自己的分析")
            if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
                raise InvalidState("分析不是批次当前可审批版本")
            try:
                now = self._now()
                cursor = self.connection.execute(
                    "INSERT INTO decisions(org_id,team_id,batch_id,analysis_id,decision,reason,"
                    "decided_by,decided_at) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS ("
                    "SELECT 1 FROM memberships m JOIN users u ON u.user_id=m.user_id "
                    "WHERE m.user_id=? AND m.org_id=? AND m.team_id=? "
                    "AND m.role='approver' AND u.active=1)",
                    (org_id, team_id, batch_id, analysis_id, decision, reason, actor_id, now,
                     actor_id, org_id, team_id),
                )
                if cursor.rowcount != 1:
                    raise Forbidden("审批权限在事务过程中被撤销")
                self.connection.execute(
                    "UPDATE batches SET state='decided' WHERE org_id=? AND team_id=? AND batch_id=?",
                    (org_id, team_id, batch_id),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("该分析版本已经形成决定") from exc
            self._audit("batch", batch_id, "decision.recorded", actor_id, role,
                        {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                        org_id=org_id, team_id=team_id)
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def list_observations(self, actor_id: str, batch_id: str) -> list[dict[str, Any]]:
        with transaction(self.connection):
            batch = self._resolve_visible("batches", "batch_id", batch_id, actor_id)
            rows = self.connection.execute(
                "SELECT observation_id,batch_id,source_batch,source_row,robot_id,stratum_key,observed_at,"
                "imported_by,imported_at FROM observations "
                "WHERE org_id=? AND team_id=? AND batch_id=? ORDER BY observation_id",
                (batch["org_id"], batch["team_id"], batch_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        with transaction(self.connection):
            batch_row = self._resolve_visible("batches", "batch_id", batch_id, actor_id)
            org_id, team_id = batch_row["org_id"], batch_row["team_id"]
            role = self._team_role(actor_id, org_id, team_id)
            if role is not None:
                if "report.read" not in ROLE_PERMISSIONS[role]:
                    # 成员但角色无权：可以暴露 Forbidden，因为其本身已能看到对象存在
                    raise Forbidden("当前角色不能读取完整报告")
            else:
                # 能解析到对象说明必是组织审计员
                role = "org_auditor"
            batch = dict(batch_row)
            protocol, protocol_digest = self._protocol_scoped(
                org_id, team_id, batch_row["protocol_id"], batch_row["protocol_version"]
            )
            analysis_row = self.connection.execute(
                "SELECT * FROM analyses WHERE org_id=? AND team_id=? AND batch_id=? "
                "ORDER BY analysis_id DESC LIMIT 1",
                (org_id, team_id, batch_id),
            ).fetchone()
            decision_row = None
            if analysis_row is not None:
                decision_row = self.connection.execute(
                    "SELECT * FROM decisions WHERE org_id=? AND team_id=? AND analysis_id=?",
                    (org_id, team_id, analysis_row["analysis_id"]),
                ).fetchone()
            exclusions = self.connection.execute(
                "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
                "FROM exclusion_requests e JOIN observations o "
                "ON o.observation_id=e.observation_id AND o.org_id=e.org_id "
                "WHERE o.org_id=? AND o.team_id=? AND o.batch_id=? ORDER BY e.exclusion_id",
                (org_id, team_id, batch_id),
            ).fetchall()
            events = self.connection.execute(
                "SELECT event_type,actor_id,actor_role,payload_json,created_at FROM audit_events "
                "WHERE entity_type='batch' AND org_id=? AND team_id=? AND entity_id=? ORDER BY event_id",
                (org_id, team_id, batch_id),
            ).fetchall()
        return {
            "batch": batch,
            "viewer_role": role,
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
            "events": [
                dict(row) | {"payload": json.loads(row["payload_json"])} for row in events
            ],
        }
