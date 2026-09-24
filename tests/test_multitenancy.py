"""多组织、多团队范围的隔离与职责分离测试。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.api import JsonApplication
from robot_trials.clock import FrozenClock
from robot_trials.errors import Forbidden, InvalidState, NotFound, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class MultiTenancyTests(unittest.TestCase):
    ORG_A = "org-a"
    ORG_B = "org-b"
    TEAM_A1 = "team-a1"
    TEAM_A2 = "team-a2"
    TEAM_B1 = "team-b1"

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        # 两个组织：org-a 有两个团队，org-b 有一个团队
        for org, name in ((self.ORG_A, "事业一部"), (self.ORG_B, "事业二部")):
            for uid, display in ((f"admin-{org}", f"{name}管理员"), (f"orgaud-{org}", f"{name}组织审计员")):
                self.service.create_user(uid, display)
            self.service.create_organization(org, name, f"admin-{org}")
            self.service.grant_membership(
                f"admin-{org}", f"orgaud-{org}", org, None, "org_auditor"
            )
        for team in (self.TEAM_A1, self.TEAM_A2):
            self.service.create_team(f"admin-{self.ORG_A}", self.ORG_A, team, team)
        self.service.create_team(f"admin-{self.ORG_B}", self.ORG_B, self.TEAM_B1, self.TEAM_B1)
        # 每个团队一套四种角色
        self.actors: dict[tuple[str, str], dict[str, str]] = {}
        for org, teams in ((self.ORG_A, (self.TEAM_A1, self.TEAM_A2)), (self.ORG_B, (self.TEAM_B1,))):
            for team in teams:
                self.actors[(org, team)] = {}
                for role in ("operator", "statistician", "approver", "auditor"):
                    uid = f"{role}-{team}"
                    self.service.create_user(uid, uid)
                    self.service.grant_membership(f"admin-{org}", uid, org, team, role)
                    self.actors[(org, team)][role] = uid

    def tearDown(self) -> None:
        self.connection.close()

    # ------------------------------------------------------------ 辅助

    def _rows(self, team: str):
        rewritten = [dict(row) for row in self.rows]
        for row in rewritten:
            row["robot_id"] = f"robot-{team}"
        return rewritten

    def _bootstrap_batch(self, org: str, team: str, *, running: bool = True) -> str:
        actor = self.actors[(org, team)]
        robot_id, build_id, batch_id = f"robot-{team}", f"build-{team}", f"batch-{team}"
        self.service.register_robot(actor["operator"], org, team, robot_id, "型号", "厂商")
        self.service.register_build(
            actor["operator"], org, team, build_id, robot_id, "1.0", "c" * 64
        )
        self.service.publish_protocol(actor["statistician"], org, team, self.protocol)
        self.service.create_batch(
            actor["operator"], org, team, batch_id, "demo-delivery-v1", 1, build_id
        )
        if running:
            self.service.start_batch(actor["operator"], batch_id, 1)
        return batch_id

    # ----------------------------------------------------- 同一用户跨团队角色

    def test_user_can_hold_different_roles_in_different_teams(self) -> None:
        self.service.create_user("dual", "跨团队用户")
        self.service.grant_membership(
            f"admin-{self.ORG_A}", "dual", self.ORG_A, self.TEAM_A1, "operator"
        )
        self.service.grant_membership(
            f"admin-{self.ORG_A}", "dual", self.ORG_A, self.TEAM_A2, "statistician"
        )
        batch_a1 = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        batch_a2 = self._bootstrap_batch(self.ORG_A, self.TEAM_A2)
        # 在 A1 是操作员：可启动/导入，不能封存
        self.service.import_observations("dual", batch_a1, "k1", self._rows(self.TEAM_A1)[:3])
        with self.assertRaises(Forbidden):
            self.service.seal_batch("dual", batch_a1, 2)
        # 在 A2 是统计负责人：可封存，不能导入
        self.service.import_observations(
            self.actors[(self.ORG_A, self.TEAM_A2)]["operator"], batch_a2, "k1", self._rows(self.TEAM_A2)
        )
        self.service.seal_batch("dual", batch_a2, 2)
        with self.assertRaises(Forbidden):
            self.service.import_observations("dual", batch_a2, "k2", self._rows(self.TEAM_A2)[:1])

    def test_one_role_per_user_per_team(self) -> None:
        self.service.create_user("single", "单角色用户")
        self.service.grant_membership(
            f"admin-{self.ORG_A}", "single", self.ORG_A, self.TEAM_A1, "operator"
        )
        with self.assertRaises(Exception):
            self.service.grant_membership(
                f"admin-{self.ORG_A}", "single", self.ORG_A, self.TEAM_A1, "approver"
            )

    # ---------------------------------------------------------- 跨团队/跨组织

    def test_statistician_cannot_seal_other_team_batch(self) -> None:
        batch_a1 = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        # 同组织另一团队的统计负责人：无 A1 成员关系，得到 NotFound 而非 Forbidden
        with self.assertRaises(NotFound):
            self.service.seal_batch(
                self.actors[(self.ORG_A, self.TEAM_A2)]["statistician"], batch_a1, 2
            )
        # 跨组织同样 NotFound
        with self.assertRaises(NotFound):
            self.service.seal_batch(
                self.actors[(self.ORG_B, self.TEAM_B1)]["statistician"], batch_a1, 2
            )

    def test_team_auditor_cannot_see_other_teams_or_orgs(self) -> None:
        batch_a1 = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self._bootstrap_batch(self.ORG_A, self.TEAM_A2)
        self._bootstrap_batch(self.ORG_B, self.TEAM_B1)
        auditor = self.actors[(self.ORG_A, self.TEAM_A1)]["auditor"]
        # 同组织兄弟团队、跨组织批次都与"不存在"不可区分
        with self.assertRaises(NotFound):
            self.service.get_batch(auditor, "batch-team-a2")
        with self.assertRaises(NotFound):
            self.service.get_batch(auditor, "batch-team-b1")
        with self.assertRaises(NotFound):
            self.service.report(auditor, "batch-team-a2")
        # 列表只见本团队
        listed = self.service.list_batches(auditor)
        self.assertEqual([row["batch_id"] for row in listed], [batch_a1])
        # 按其他组织过滤得到空集合而非报错
        self.assertEqual(self.service.list_batches(auditor, self.ORG_B, self.TEAM_B1), [])

    def test_org_auditor_is_read_only_across_teams_but_isolated_per_org(self) -> None:
        batch_a1 = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        batch_a2 = self._bootstrap_batch(self.ORG_A, self.TEAM_A2)
        self._bootstrap_batch(self.ORG_B, self.TEAM_B1)
        org_auditor = f"orgaud-{self.ORG_A}"
        # 可读两个团队的批次与报告
        self.assertEqual(
            {row["batch_id"] for row in self.service.list_batches(org_auditor)},
            {batch_a1, batch_a2},
        )
        report = self.service.report(org_auditor, batch_a2)
        self.assertEqual(report["viewer_role"], "org_auditor")
        # 看不到其他组织
        with self.assertRaises(NotFound):
            self.service.report(org_auditor, "batch-team-b1")
        self.assertEqual(
            [row["batch_id"] for row in self.service.list_batches(org_auditor, self.ORG_B)], []
        )
        # 只读：任何写权限都没有（无团队成员关系，按不存在处理）
        with self.assertRaises(NotFound):
            self.service.seal_batch(org_auditor, batch_a1, 2)
        with self.assertRaises(NotFound):
            self.service.start_batch(org_auditor, batch_a1, 1)

    # ----------------------------------------------------------- 跨组织引用

    def test_cross_org_robot_reference_is_rejected(self) -> None:
        self.service.register_robot(
            self.actors[(self.ORG_A, self.TEAM_A1)]["operator"],
            self.ORG_A, self.TEAM_A1, "robot-x", "型号", "厂商",
        )
        with self.assertRaises(ValidationFailed):
            self.service.register_build(
                self.actors[(self.ORG_B, self.TEAM_B1)]["operator"],
                self.ORG_B, self.TEAM_B1, "build-x", "robot-x", "1.0", "d" * 64,
            )

    def test_cross_team_build_reference_is_rejected(self) -> None:
        self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        actor = self.actors[(self.ORG_A, self.TEAM_A2)]
        self.service.publish_protocol(actor["statistician"], self.ORG_A, self.TEAM_A2, self.protocol)
        with self.assertRaises(ValidationFailed):
            self.service.create_batch(
                actor["operator"], self.ORG_A, self.TEAM_A2, "batch-cross",
                "demo-delivery-v1", 1, "build-team-a1",
            )

    def test_same_protocol_digest_can_exist_in_separate_orgs(self) -> None:
        # 组织间对象命名空间独立：相同协议内容可分别归属不同组织
        self.service.publish_protocol(
            self.actors[(self.ORG_A, self.TEAM_A1)]["statistician"],
            self.ORG_A, self.TEAM_A1, self.protocol,
        )
        self.service.publish_protocol(
            self.actors[(self.ORG_B, self.TEAM_B1)]["statistician"],
            self.ORG_B, self.TEAM_B1, self.protocol,
        )
        rows = self.connection.execute(
            "SELECT org_id FROM protocol_catalog WHERE protocol_id='demo-delivery-v1'"
        ).fetchall()
        self.assertEqual({row["org_id"] for row in rows}, {self.ORG_A, self.ORG_B})

    # --------------------------------------------------------- 管理员边界

    def test_org_admin_can_manage_members_but_cannot_approve_conclusions(self) -> None:
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        admin = f"admin-{self.ORG_A}"
        # 管理员无团队角色，无法封存或审批——调整成员关系不产生审批权
        with self.assertRaises(NotFound):
            self.service.seal_batch(admin, batch, 2)
        self.service.create_user("new-approver", "新审批人")
        granted = self.service.grant_membership(
            admin, "new-approver", self.ORG_A, self.TEAM_A1, "approver"
        )
        self.assertEqual(granted["role"], "approver")
        # 不能越权管理其他组织
        with self.assertRaises(NotFound):
            self.service.create_team(admin, self.ORG_B, "sneaky", "越权团队")
        with self.assertRaises(NotFound):
            self.service.grant_membership(
                admin, "new-approver", self.ORG_B, self.TEAM_B1, "approver"
            )

    def test_last_org_admin_cannot_be_removed(self) -> None:
        with self.assertRaises(InvalidState):
            self.service.revoke_membership(
                f"admin-{self.ORG_B}", f"admin-{self.ORG_B}", self.ORG_B, None, "org_admin"
            )
        # 任命第二名管理员后即可撤销
        self.service.create_user("admin2", "次任管理员")
        self.service.grant_membership(
            f"admin-{self.ORG_B}", "admin2", self.ORG_B, None, "org_admin"
        )
        self.service.revoke_membership(
            "admin2", f"admin-{self.ORG_B}", self.ORG_B, None, "org_admin"
        )

    def test_org_level_role_cannot_be_bound_to_team(self) -> None:
        self.service.create_user("oa", "oa")
        with self.assertRaises(ValidationFailed):
            self.service.grant_membership(
                f"admin-{self.ORG_A}", "oa", self.ORG_A, self.TEAM_A1, "org_auditor"
            )

    # ------------------------------------------------- 撤权即时生效与历史身份

    def test_revoked_member_loses_access_immediately_but_history_keeps_role(self) -> None:
        actor = self.actors[(self.ORG_A, self.TEAM_A1)]
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self.service.import_observations(actor["operator"], batch, "k", self._rows(self.TEAM_A1))
        self.service.seal_batch(actor["statistician"], batch, 2)
        # 撤销统计负责人
        self.service.revoke_membership(
            f"admin-{self.ORG_A}", actor["statistician"], self.ORG_A, self.TEAM_A1, "statistician"
        )
        # 新请求立即失权
        with self.assertRaises(NotFound):
            self.service.seal_batch(actor["statistician"], batch, 3)
        # 历史事件仍记录当时身份
        event = self.connection.execute(
            "SELECT actor_role FROM audit_events WHERE event_type='batch.sealed'"
        ).fetchone()
        self.assertEqual(event["actor_role"], "statistician")
        # 组织审计员仍可在报告中看到当时的身份链
        report = self.service.report(f"orgaud-{self.ORG_A}", batch)
        sealed = [event for event in report["events"] if event["event_type"] == "batch.sealed"][0]
        self.assertEqual(sealed["actor_id"], actor["statistician"])
        self.assertEqual(sealed["actor_role"], "statistician")

    def test_deactivated_user_loses_access_immediately(self) -> None:
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        operator = self.actors[(self.ORG_A, self.TEAM_A1)]["operator"]
        self.service.set_user_active(f"admin-{self.ORG_A}", self.ORG_A, operator, False)
        with self.assertRaises(NotFound):
            self.service.import_observations(operator, batch, "k", self._rows(self.TEAM_A1)[:1])

    # ------------------------------------------------- 并发撤权 vs 封存/审批

    def test_concurrent_revoke_during_seal_is_rejected_inside_transaction(self) -> None:
        actor = self.actors[(self.ORG_A, self.TEAM_A1)]
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self.service.import_observations(actor["operator"], batch, "k", self._rows(self.TEAM_A1))

        def revoke_mid_transaction() -> None:
            # 模拟并发撤权：在权限初检后、写入前成员关系消失
            self.connection.execute(
                "DELETE FROM memberships WHERE user_id=? AND team_id='team-a1' AND role='statistician'",
                (actor["statistician"],),
            )

        self.service.permission_barrier = revoke_mid_transaction
        try:
            with self.assertRaises(NotFound):
                self.service.seal_batch(actor["statistician"], batch, 2)
        finally:
            self.service.permission_barrier = None
        # 封存没有写入
        state = self.connection.execute(
            "SELECT state FROM batches WHERE batch_id=?", (batch,)
        ).fetchone()["state"]
        self.assertEqual(state, "running")
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM audit_events WHERE event_type='batch.sealed'"
            ).fetchone()[0],
            0,
        )

    def test_concurrent_revoke_during_decision_is_rejected(self) -> None:
        actor = self.actors[(self.ORG_A, self.TEAM_A1)]
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self.service.import_observations(actor["operator"], batch, "k", self._rows(self.TEAM_A1))
        self.service.seal_batch(actor["statistician"], batch, 2)
        job = self.service.claim_job("worker", 60)
        analysis = self.service.complete_job("worker", job["job_id"], actor["statistician"])

        def revoke_mid_transaction() -> None:
            self.connection.execute(
                "DELETE FROM memberships WHERE user_id=? AND team_id='team-a1' AND role='approver'",
                (actor["approver"],),
            )

        self.service.permission_barrier = revoke_mid_transaction
        try:
            with self.assertRaises(NotFound):
                self.service.decide(
                    actor["approver"], batch, analysis["analysis_id"], "approved", "结论"
                )
        finally:
            self.service.permission_barrier = None
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decisions").fetchone()[0], 0
        )

    # ----------------------------------------------------- HTTP 存在性侧信道

    def test_api_does_not_distinguish_missing_from_forbidden(self) -> None:
        app = JsonApplication(self.service)
        self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        outsider = self.actors[(self.ORG_B, self.TEAM_B1)]["statistician"]
        headers = {"X-Actor-Id": outsider}
        missing = app.handle("GET", "/batches/does-not-exist", headers)
        hidden = app.handle("GET", "/batches/batch-team-a1", headers)
        self.assertEqual(missing.status, 404)
        self.assertEqual(hidden.status, 404)
        self.assertEqual(missing.body["error"]["code"], hidden.body["error"]["code"])
        robot_hidden = app.handle("GET", "/robots/robot-team-a1", headers)
        self.assertEqual(robot_hidden.status, 404)
        report_hidden = app.handle("GET", "/batches/batch-team-a1/report", headers)
        self.assertEqual(report_hidden.status, 404)
        # 列表同样不泄露
        listing = app.handle("GET", f"/batches?org_id={self.ORG_A}&team_id={self.TEAM_A1}", headers)
        self.assertEqual(listing.status, 200)
        self.assertEqual(listing.body, [])

    def test_api_requires_scope_for_writes(self) -> None:
        app = JsonApplication(self.service)
        actor = self.actors[(self.ORG_A, self.TEAM_A1)]["operator"]
        response = app.handle(
            "POST", "/robots", {"X-Actor-Id": actor},
            b'{"robot_id":"r","model_name":"m","vendor":"v"}',
        )
        self.assertEqual(response.status, 422)

    # ------------------------------------------- 编号冲突不再泄露其他范围存在性

    def test_same_identifiers_can_exist_in_separate_teams_and_orgs(self) -> None:
        shared = {
            "robot_id": "shared-robot", "build_id": "shared-build", "batch_id": "shared-batch",
        }
        created_batches: list[str] = []
        for org, teams in ((self.ORG_A, (self.TEAM_A1, self.TEAM_A2)), (self.ORG_B, (self.TEAM_B1,))):
            for team in teams:
                actor = self.actors[(org, team)]
                # 相同编号在每个团队都能登记成功——创建结果不泄露其他团队是否已占用
                self.service.register_robot(
                    actor["operator"], org, team,
                    shared["robot_id"], "型号", "厂商",
                )
                self.service.register_build(
                    actor["operator"], org, team,
                    shared["build_id"], shared["robot_id"], "1.0",
                    # 内容摘要也可以相同（团队级唯一）
                    "e" * 64,
                )
                self.service.publish_protocol(
                    actor["statistician"], org, team, self.protocol
                )
                created = self.service.create_batch(
                    actor["operator"], org, team, shared["batch_id"],
                    "demo-delivery-v1", 1, shared["build_id"],
                )
                created_batches.append(created["batch_id"])
        count = self.connection.execute(
            "SELECT count(*) FROM robots WHERE robot_id='shared-robot'"
        ).fetchone()[0]
        self.assertEqual(count, 3)
        # 三方都能各自解析到"同名"批次，且互不可见
        a1_operator = self.actors[(self.ORG_A, self.TEAM_A1)]["operator"]
        b1_operator = self.actors[(self.ORG_B, self.TEAM_B1)]["operator"]
        self.assertEqual(
            self.service.get_batch(a1_operator, "shared-batch")["team_id"], self.TEAM_A1
        )
        self.assertEqual(
            self.service.get_batch(b1_operator, "shared-batch")["team_id"], self.TEAM_B1
        )
        # 列表只返回自己可见范围内的那一个
        self.assertEqual(
            len(self.service.list_batches(a1_operator, self.ORG_A, self.TEAM_A1)), 1
        )

    def test_cross_org_reference_is_rejected_at_storage_level(self) -> None:
        # 即使绕过服务层校验，外键约束也拒绝跨组织/跨团队关联
        actor = self.actors[(self.ORG_A, self.TEAM_A1)]
        self.service.register_robot(
            actor["operator"], self.ORG_A, self.TEAM_A1, "fk-robot", "型号", "厂商"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO builds(build_id,org_id,team_id,robot_id,version,content_sha256,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                ("evil", self.ORG_B, self.TEAM_B1, "fk-robot", "9.9", "f" * 64, "2026-09-24T00:00:00Z"),
            )

    def test_catalog_lists_are_scope_filtered(self) -> None:
        self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self._bootstrap_batch(self.ORG_B, self.TEAM_B1)
        a1_auditor = self.actors[(self.ORG_A, self.TEAM_A1)]["auditor"]
        robots = self.service.list_robots(a1_auditor)
        self.assertEqual([row["robot_id"] for row in robots], ["robot-team-a1"])
        builds = self.service.list_builds(a1_auditor)
        self.assertEqual([row["build_id"] for row in builds], ["build-team-a1"])

    def test_analysis_runner_must_belong_to_batch_team(self) -> None:
        batch = self._bootstrap_batch(self.ORG_A, self.TEAM_A1)
        self.service.import_observations(
            self.actors[(self.ORG_A, self.TEAM_A1)]["operator"],
            batch, "k", self._rows(self.TEAM_A1),
        )
        self.service.seal_batch(self.actors[(self.ORG_A, self.TEAM_A1)]["statistician"], batch, 2)
        job = self.service.claim_job("worker", 60)
        # 其他团队的统计负责人无法以该身份完成本团队任务
        foreign_stat = self.actors[(self.ORG_B, self.TEAM_B1)]["statistician"]
        with self.assertRaises(NotFound):
            self.service.complete_job("worker", job["job_id"], foreign_stat)


if __name__ == "__main__":
    unittest.main()
