from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from pathlib import Path

from robot_trials.api import JsonApplication
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(TrialService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, payload: dict, actor: str | None = None):
        headers = {"X-Actor-Id": actor} if actor else {}
        return self.app.handle("POST", path, headers, json.dumps(payload).encode())

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["user_id"], "u1")

    def test_org_team_membership_routes(self) -> None:
        self._post("/users", {"user_id": "admin", "display_name": "管理员"})
        self._post("/users", {"user_id": "op", "display_name": "操作员"})
        response = self._post("/orgs", {"org_id": "org-1", "name": "事业部"}, actor="admin")
        self.assertEqual(response.status, 201)
        response = self._post("/orgs/org-1/teams", {"team_id": "team-1", "name": "试验组"}, actor="admin")
        self.assertEqual(response.status, 201)
        response = self._post(
            "/orgs/org-1/memberships",
            {"team_id": "team-1", "user_id": "op", "role": "operator"},
            actor="admin",
        )
        self.assertEqual(response.status, 201)
        response = self.app.handle("GET", "/orgs/org-1/memberships", {"X-Actor-Id": "admin"})
        self.assertEqual(response.status, 200)
        self.assertEqual(len(response.body["memberships"]), 1)
        response = self._post(
            "/orgs/org-1/memberships/revoke", {"team_id": "team-1", "user_id": "op"}, actor="admin"
        )
        self.assertEqual(response.status, 200)
        self.assertTrue(response.body["revoked"])

    def test_unknown_org_objects_return_not_found(self) -> None:
        self._post("/users", {"user_id": "admin", "display_name": "管理员"})
        self._post("/users", {"user_id": "op", "display_name": "操作员"})
        self._post("/orgs", {"org_id": "org-1", "name": "事业部"}, actor="admin")
        self._post("/orgs/org-1/teams", {"team_id": "team-1", "name": "试验组"}, actor="admin")
        self._post(
            "/orgs/org-1/memberships",
            {"team_id": "team-1", "user_id": "op", "role": "operator"},
            actor="admin",
        )
        missing = self.app.handle("GET", "/batches/no-such-batch", {"X-Actor-Id": "op"})
        self.assertEqual(missing.status, 404)
        self.assertEqual(missing.body["error"]["code"], "not_found")

    def _full_org(self, org: str, team: str, batch: str) -> None:
        self._post("/users", {"user_id": f"admin-{org}", "display_name": "管理员"})
        self._post("/users", {"user_id": f"op-{org}", "display_name": "操作员"})
        self._post("/users", {"user_id": f"stat-{org}", "display_name": "统计"})
        self._post("/orgs", {"org_id": org, "name": "事业部"}, actor=f"admin-{org}")
        self._post(f"/orgs/{org}/teams", {"team_id": team, "name": "试验组"}, actor=f"admin-{org}")
        self._post(
            f"/orgs/{org}/memberships",
            {"team_id": team, "user_id": f"op-{org}", "role": "operator"},
            actor=f"admin-{org}",
        )
        self._post(
            f"/orgs/{org}/memberships",
            {"team_id": team, "user_id": f"stat-{org}", "role": "statistician"},
            actor=f"admin-{org}",
        )
        self._post(
            "/robots",
            {"org_id": org, "team_id": team, "robot_id": f"robot-{org}",
             "model_name": "型号", "vendor": "厂商"},
            actor=f"op-{org}",
        )
        self._post(
            "/builds",
            {"build_id": f"build-{org}", "robot_id": f"robot-{org}",
             "version": "1.0", "content_sha256": hashlib.sha256(org.encode("utf-8")).hexdigest()},
            actor=f"op-{org}",
        )
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self._post("/protocols", {"org_id": org, "team_id": team, "protocol": protocol}, actor=f"stat-{org}")
        self._post(
            "/batches",
            {"batch_id": batch, "protocol_id": "demo-delivery-v1",
             "protocol_version": 1, "build_id": f"build-{org}"},
            actor=f"op-{org}",
        )

    def test_cross_org_objects_are_indistinguishable_from_missing(self) -> None:
        self._full_org("org-a", "team-a", "batch-a")
        self._full_org("org-b", "team-b", "batch-b")
        headers = {"X-Actor-Id": "stat-org-a"}
        other = self.app.handle("GET", "/batches/batch-b", headers)
        missing = self.app.handle("GET", "/batches/ghost", headers)
        self.assertEqual(other.status, 404)
        self.assertEqual(other.body, missing.body)
        other_report = self.app.handle("GET", "/batches/batch-b/report", headers)
        missing_report = self.app.handle("GET", "/batches/ghost/report", headers)
        self.assertEqual(other_report.status, 404)
        self.assertEqual(other_report.body, missing_report.body)
        seal_other = self.app.handle(
            "POST", "/batches/batch-b/seal", headers, json.dumps({"expected_revision": 1}).encode()
        )
        seal_missing = self.app.handle(
            "POST", "/batches/ghost/seal", headers, json.dumps({"expected_revision": 1}).encode()
        )
        self.assertEqual(seal_other.status, 404)
        self.assertEqual(seal_other.body, seal_missing.body)
        listing = self.app.handle("GET", "/batches", headers)
        self.assertEqual({row["batch_id"] for row in listing.body["batches"]}, {"batch-a"})
        own = self.app.handle("GET", "/batches/batch-a", headers)
        self.assertEqual(own.status, 200)
        self.assertEqual(own.body["org_id"], "org-a")


if __name__ == "__main__":
    unittest.main()
