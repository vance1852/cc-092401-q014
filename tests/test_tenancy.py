from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.clock import FrozenClock
from robot_trials.errors import Forbidden, InvalidState, NotFound, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService
from robot_trials.storage import connect


ROOT = Path(__file__).resolve().parents[1]
CLOCK = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)


class TenancyTests(unittest.TestCase):
    """两个事业部、三个团队的隔离与共享场景。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(CLOCK)
        self.service = TrialService(self.connection, self.clock)
        service = self.service
        for user_id, display_name in (
            ("admin-a", "管理员甲"), ("admin-b", "管理员乙"),
            ("op-a1", "操作甲一"), ("stat-a1", "统计甲一"), ("appr-a1", "审批甲一"), ("aud-a1", "审计甲一"),
            ("op-a2", "操作甲二"), ("stat-a2", "统计甲二"),
            ("op-b1", "操作乙一"), ("stat-b1", "统计乙一"), ("appr-b1", "审批乙一"),
            ("orgaud-a", "组织审计甲"), ("dual", "跨组织成员"), ("botha", "跨团队成员"), ("multi", "多角色成员"),
        ):
            service.create_user(user_id, display_name)
        service.create_org("admin-a", "org-a", "事业部A")
        service.create_team("admin-a", "org-a", "team-a1", "A一组")
        service.create_team("admin-a", "org-a", "team-a2", "A二组")
        service.create_org("admin-b", "org-b", "事业部B")
        service.create_team("admin-b", "org-b", "team-b1", "B一组")
        for user_id, role in (
            ("op-a1", "operator"), ("stat-a1", "statistician"),
            ("appr-a1", "approver"), ("aud-a1", "auditor"),
            ("dual", "operator"), ("botha", "operator"),
        ):
            service.grant_membership("admin-a", "org-a", "team-a1", user_id, role)
        for user_id, role in (
            ("op-a2", "operator"), ("stat-a2", "statistician"),
            ("multi", "operator"), ("botha", "operator"),
        ):
            service.grant_membership("admin-a", "org-a", "team-a2", user_id, role)
        for user_id, role in (
            ("op-b1", "operator"), ("stat-b1", "statistician"),
            ("appr-b1", "approver"), ("dual", "operator"), ("multi", "statistician"),
        ):
            service.grant_membership("admin-b", "org-b", "team-b1", user_id, role)
        service.grant_org_role("admin-a", "org-a", "orgaud-a", "org_auditor")
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.alt_protocol = dict(self.protocol, protocol_id="demo-delivery-alt", title="备选协议")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self._catalog("org-a", "team-a1", "op-a1", "stat-a1", "robot-a", "build-a1", "batch-a1")
        self._catalog("org-a", "team-a2", "op-a2", "stat-a2", "robot-a2", "build-a2", "batch-a2")
        self._catalog("org-b", "team-b1", "op-b1", "stat-b1", "robot-b1", "build-b1", "batch-b1")
        # 仅在 team-a1 发布的备选协议，用于跨范围引用测试。
        service.publish_protocol("stat-a1", "org-a", "team-a1", self.alt_protocol)

    def tearDown(self) -> None:
        self.connection.close()

    def _catalog(self, org, team, operator, statistician, robot, build, batch) -> None:
        service = self.service
        service.register_robot(operator, org, team, robot, "型号", "厂商")
        digest = hashlib.sha256(build.encode("utf-8")).hexdigest()
        service.register_build(operator, build, robot, "1.0", digest)
        service.publish_protocol(statistician, org, team, self.protocol)
        service.create_batch(operator, batch, "demo-delivery-v1", 1, build)
        service.start_batch(operator, batch, 1)

    # ------------------------------------------------------------------
    # 同一用户在不同团队拥有不同角色
    # ------------------------------------------------------------------

    def test_user_has_different_roles_in_different_teams(self) -> None:
        # multi 在 team-a2 是操作员，在 team-b1 是统计负责人。
        created = self.service.register_robot("multi", "org-a", "team-a2", "robot-x", "型号", "厂商")
        self.assertEqual(created["team_id"], "team-a2")
        with self.assertRaises(Forbidden):
            self.service.seal_batch("multi", "batch-a2", 2)
        with self.assertRaises(Forbidden):
            self.service.register_robot("multi", "org-b", "team-b1", "robot-y", "型号", "厂商")
        sealed = self.service.seal_batch("multi", "batch-b1", 2)
        self.assertEqual(sealed["state"], "sealed")

    # ------------------------------------------------------------------
    # 跨组织与跨团队隔离：无权对象一律按不存在处理
    # ------------------------------------------------------------------

    def test_other_org_batch_is_indistinguishable_from_missing(self) -> None:
        with self.assertRaises(NotFound) as other:
            self.service.seal_batch("stat-a1", "batch-b1", 2)
        with self.assertRaises(NotFound) as missing:
            self.service.seal_batch("stat-a1", "ghost-batch", 2)
        self.assertEqual(str(other.exception), str(missing.exception))
        with self.assertRaises(NotFound) as other_get:
            self.service.get_batch("stat-a1", "batch-b1")
        with self.assertRaises(NotFound) as missing_get:
            self.service.get_batch("stat-a1", "ghost-batch")
        self.assertEqual(str(other_get.exception), str(missing_get.exception))
        with self.assertRaises(NotFound):
            self.service.report("stat-b1", "batch-a1")
        with self.assertRaises(NotFound):
            self.service.import_observations("op-b1", "batch-a1", "key-x", self.rows)

    def test_other_team_same_org_batch_is_hidden_for_writes(self) -> None:
        with self.assertRaises(NotFound):
            self.service.seal_batch("stat-a1", "batch-a2", 2)

    def test_member_with_wrong_role_gets_forbidden(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.seal_batch("op-a1", "batch-a1", 2)
        with self.assertRaises(Forbidden):
            self.service.report("op-a1", "batch-a1")

    def test_list_batches_only_returns_authorized_scopes(self) -> None:
        batches_of = lambda actor: {row["batch_id"] for row in self.service.list_batches(actor)["batches"]}
        self.assertEqual(batches_of("op-a1"), {"batch-a1"})
        self.assertEqual(batches_of("orgaud-a"), {"batch-a1", "batch-a2"})
        self.assertEqual(batches_of("dual"), {"batch-a1", "batch-b1"})
        filtered = self.service.list_batches("orgaud-a", org_id="org-b")
        self.assertEqual(filtered["batches"], [])
        filtered = self.service.list_batches("orgaud-a", team_id="team-a2")
        self.assertEqual({row["batch_id"] for row in filtered["batches"]}, {"batch-a2"})

    # ------------------------------------------------------------------
    # 组织审计员与组织管理员
    # ------------------------------------------------------------------

    def test_org_auditor_reads_across_teams_but_cannot_write(self) -> None:
        report_a1 = self.service.report("orgaud-a", "batch-a1")
        self.assertEqual(report_a1["batch"]["state"], "running")
        report_a2 = self.service.report("orgaud-a", "batch-a2")
        self.assertEqual(report_a2["batch"]["team_id"], "team-a2")
        with self.assertRaises(NotFound):
            self.service.report("orgaud-a", "batch-b1")
        with self.assertRaises(NotFound):
            self.service.seal_batch("orgaud-a", "batch-a1", 2)
        with self.assertRaises(NotFound):
            self.service.import_observations("orgaud-a", "batch-a1", "key-x", self.rows)

    def test_org_admin_manages_members_but_cannot_approve_trials(self) -> None:
        with self.assertRaises(NotFound):
            self.service.decide("admin-a", "batch-a1", 1, "approved", "越权审批")
        with self.assertRaises(NotFound):
            self.service.report("admin-a", "batch-a1")
        # 不能给自己授予团队成员或组织角色，无法借此获得审批/读取权限。
        with self.assertRaises(Forbidden):
            self.service.grant_membership("admin-a", "org-a", "team-a1", "admin-a", "approver")
        with self.assertRaises(Forbidden):
            self.service.grant_org_role("admin-a", "org-a", "admin-a", "org_auditor")
        with self.assertRaises(Forbidden):
            self.service.revoke_membership("admin-a", "org-a", "team-a1", "admin-a")
        # 其他组织的管理员在 org-a 没有任何身份，组织按不存在处理。
        with self.assertRaises(NotFound):
            self.service.grant_membership("admin-b", "org-a", "team-a1", "op-b1", "operator")
        # 正常的成员管理可用。
        self.service.create_user("newbie", "新成员")
        granted = self.service.grant_membership("admin-a", "org-a", "team-a1", "newbie", "operator")
        self.assertEqual(granted["role"], "operator")
        listing = self.service.list_memberships("admin-a", "org-a")
        self.assertIn("newbie", {row["user_id"] for row in listing["memberships"]})
        audit_listing = self.service.list_memberships("orgaud-a", "org-a")
        self.assertIn("org_admin", {row["role"] for row in audit_listing["org_roles"]})
        with self.assertRaises(Forbidden):
            self.service.list_memberships("op-a1", "org-a")
        with self.assertRaises(NotFound):
            self.service.list_memberships("op-b1", "org-a")

    # ------------------------------------------------------------------
    # 跨组织/跨团队引用必须拒绝，且不可见的引用按不存在处理
    # ------------------------------------------------------------------

    def test_cross_scope_references_are_rejected(self) -> None:
        # dual 同时是两个组织的成员：可见的跨组织引用被明确拒绝。
        with self.assertRaises(ValidationFailed):
            self.service.create_batch("dual", "batch-x1", "demo-delivery-alt", 1, "build-b1")
        # botha 同时是 team-a1/team-a2 的成员：同组织跨团队引用同样拒绝。
        with self.assertRaises(ValidationFailed):
            self.service.create_batch("botha", "batch-x2", "demo-delivery-alt", 1, "build-a2")
        # 不可见的协议按不存在处理，不泄露其他团队的对象。
        with self.assertRaises(NotFound):
            self.service.create_batch("op-b1", "batch-x3", "demo-delivery-alt", 1, "build-b1")
        # 不可见的构建同样按不存在处理。
        with self.assertRaises(NotFound):
            self.service.create_batch("op-a1", "batch-x4", "demo-delivery-v1", 1, "build-b1")
        # 同团队引用正常创建。
        created = self.service.create_batch("dual", "batch-x5", "demo-delivery-v1", 1, "build-b1")
        self.assertEqual(created["team_id"], "team-b1")

    # ------------------------------------------------------------------
    # 成员移除：新请求立即失权，历史事件保留当时身份
    # ------------------------------------------------------------------

    def test_member_removal_takes_effect_immediately_and_keeps_history(self) -> None:
        self.service.import_observations("op-a1", "batch-a1", "key-1", self.rows)
        self.service.seal_batch("stat-a1", "batch-a1", 2)
        self.service.revoke_membership("admin-a", "org-a", "team-a1", "stat-a1")
        with self.assertRaises(NotFound):
            self.service.report("stat-a1", "batch-a1")
        with self.assertRaises(NotFound):
            self.service.seal_batch("stat-a1", "batch-a1", 3)
        with self.assertRaises(NotFound):
            self.service.get_batch("stat-a1", "batch-a1")
        report = self.service.report("aud-a1", "batch-a1")
        sealed_events = [e for e in report["events"] if e["event_type"] == "batch.sealed"]
        self.assertEqual(sealed_events[0]["actor_id"], "stat-a1")
        self.assertEqual(sealed_events[0]["actor_name"], "统计甲一")
        # 组织审计员资格被移除后同样立即失权。
        self.service.report("orgaud-a", "batch-a1")
        self.service.revoke_org_role("admin-a", "org-a", "orgaud-a", "org_auditor")
        with self.assertRaises(NotFound):
            self.service.report("orgaud-a", "batch-a1")

    # ------------------------------------------------------------------
    # 排除申请与审批同样按团队隔离
    # ------------------------------------------------------------------

    def test_exclusion_and_decision_are_team_scoped(self) -> None:
        self.service.import_observations("op-a1", "batch-a1", "key-1", self.rows)
        observation_id = self.connection.execute(
            "SELECT observation_id FROM observations ORDER BY observation_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("op-a1", observation_id, "现场记录失效")
        with self.assertRaises(NotFound):
            self.service.review_exclusion("stat-b1", requested["exclusion_id"], True, "跨组织复核")
        with self.assertRaises(NotFound):
            self.service.review_exclusion("stat-a2", requested["exclusion_id"], True, "跨团队复核")
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("appr-a1", requested["exclusion_id"], True, "角色不符")
        reviewed = self.service.review_exclusion("stat-a1", requested["exclusion_id"], True, "证据充分")
        self.assertEqual(reviewed["status"], "approved")
        with self.assertRaises(NotFound):
            self.service.decide("appr-b1", "batch-a1", 1, "approved", "跨组织审批")
        with self.assertRaises(NotFound):
            self.service.request_exclusion("op-b1", observation_id, "跨组织申请")


class ConcurrencyTests(unittest.TestCase):
    """成员变更与封存并发时，权限检查与写入在同一事务内串行化。"""

    def _world(self, path: Path) -> None:
        connection = connect(path)
        clock = FrozenClock(CLOCK)
        service = TrialService(connection, clock)
        service.create_user("admin-r", "管理员")
        service.create_user("stat-r", "统计")
        service.create_user("op-r", "操作")
        service.create_org("admin-r", "org-r", "组织")
        service.create_team("admin-r", "org-r", "team-r", "团队")
        service.grant_membership("admin-r", "org-r", "team-r", "stat-r", "statistician")
        service.grant_membership("admin-r", "org-r", "team-r", "op-r", "operator")
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        service.register_robot("op-r", "org-r", "team-r", "robot-r", "型号", "厂商")
        service.register_build("op-r", "build-r", "robot-r", "1.0", "d" * 64)
        service.publish_protocol("stat-r", "org-r", "team-r", protocol)
        service.create_batch("op-r", "batch-r", "demo-delivery-v1", 1, "build-r")
        service.start_batch("op-r", "batch-r", 1)
        connection.close()

    def test_concurrent_revoke_and_seal_never_writes_after_revocation(self) -> None:
        for _ in range(5):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "race.sqlite3"
                self._world(path)
                clock = FrozenClock(CLOCK)
                barrier = threading.Barrier(3)
                outcome: dict[str, str] = {}

                def seal() -> None:
                    connection = connect(path)
                    try:
                        service = TrialService(connection, clock)
                        barrier.wait()
                        service.seal_batch("stat-r", "batch-r", 2)
                        outcome["seal"] = "sealed"
                    except (NotFound, Forbidden):
                        outcome["seal"] = "denied"
                    finally:
                        connection.close()

                def revoke() -> None:
                    connection = connect(path)
                    try:
                        service = TrialService(connection, clock)
                        barrier.wait()
                        service.revoke_membership("admin-r", "org-r", "team-r", "stat-r")
                        outcome["revoke"] = "revoked"
                    finally:
                        connection.close()

                threads = [threading.Thread(target=seal), threading.Thread(target=revoke)]
                for thread in threads:
                    thread.start()
                barrier.wait()
                for thread in threads:
                    thread.join()
                self.assertEqual(outcome["revoke"], "revoked")
                self.assertIn(outcome["seal"], {"sealed", "denied"})
                check = connect(path)
                try:
                    remaining = check.execute(
                        "SELECT count(*) FROM memberships WHERE user_id='stat-r'"
                    ).fetchone()[0]
                    self.assertEqual(remaining, 0)
                    state = check.execute(
                        "SELECT state FROM batches WHERE batch_id='batch-r'"
                    ).fetchone()[0]
                    # 两种串行化结果都合法：封存先于撤权，或撤权后封存被拒绝。
                    self.assertEqual(state, "sealed" if outcome["seal"] == "sealed" else "running")
                finally:
                    check.close()

    def test_seal_after_committed_revocation_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sequential.sqlite3"
            self._world(path)
            connection = connect(path)
            try:
                service = TrialService(connection, FrozenClock(CLOCK))
                service.revoke_membership("admin-r", "org-r", "team-r", "stat-r")
                with self.assertRaises(NotFound):
                    service.seal_batch("stat-r", "batch-r", 2)
                state = connection.execute(
                    "SELECT state FROM batches WHERE batch_id='batch-r'"
                ).fetchone()[0]
                self.assertEqual(state, "running")
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
