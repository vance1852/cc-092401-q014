from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from robot_trials.clock import FrozenClock
from robot_trials.service import TrialService
from robot_trials.storage import initialize, inspect_schema, transaction


# v2 版本（全局角色）的完整模式快照，迁移测试以此构造旧库。
V2_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_catalog (
    protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS robots (
    robot_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (robot_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (protocol_id, protocol_version) REFERENCES protocol_catalog(protocol_id, version)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    stratum_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
ON exclusion_requests(observation_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class MigrationTests(unittest.TestCase):
    def _v2_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(V2_SCHEMA_SQL)
        with transaction(connection, immediate=True):
            connection.execute("INSERT INTO schema_meta(key, value) VALUES('schema_version', '2')")
            connection.execute(
                "INSERT INTO users(user_id, display_name, role) VALUES('op1', '操作员甲', 'operator')"
            )
            connection.execute(
                "INSERT INTO users(user_id, display_name, role) VALUES('stat1', '统计甲', 'statistician')"
            )
            connection.execute(
                "INSERT INTO robots(robot_id, model_name, vendor, created_at) "
                "VALUES('r1', 'A 型', '厂商', '2026-01-01T00:00:00Z')"
            )
            connection.execute(
                "INSERT INTO builds(build_id, robot_id, version, content_sha256, created_at) "
                "VALUES('b1', 'r1', '1.0', ?, '2026-01-01T00:00:00Z')",
                ("e" * 64,),
            )
            connection.execute(
                "INSERT INTO protocol_catalog(protocol_id, version, title, task_family, canonical_json, "
                "content_sha256, created_at) VALUES('p1', 1, '协议', '递送', '{}', ?, '2026-01-01T00:00:00Z')",
                ("f" * 64,),
            )
            connection.execute(
                "INSERT INTO batches(batch_id, protocol_id, protocol_version, build_id, state, revision, "
                "created_by, created_at) VALUES('batch1', 'p1', 1, 'b1', 'running', 2, 'op1', "
                "'2026-01-01T00:00:00Z')"
            )
            connection.execute(
                "INSERT INTO audit_events(entity_type, entity_id, event_type, actor_id, payload_json, "
                "created_at) VALUES('batch', 'batch1', 'batch.started', 'stat1', '{}', '2026-01-02T00:00:00Z')"
            )
        return connection

    def test_migrate_v2_to_v3_preserves_data_and_authorization(self) -> None:
        connection = self._v2_database()
        try:
            initialize(connection)
            summary = inspect_schema(connection)
            self.assertEqual(summary["schema_version"], "3")
            self.assertEqual(summary["missing_tables"], [])
            memberships = connection.execute(
                "SELECT user_id, org_id, team_id, role FROM memberships ORDER BY user_id"
            ).fetchall()
            self.assertEqual(
                [(row["user_id"], row["org_id"], row["team_id"], row["role"]) for row in memberships],
                [("op1", "legacy", "legacy", "operator"), ("stat1", "legacy", "legacy", "statistician")],
            )
            robot = connection.execute("SELECT org_id, team_id FROM robots WHERE robot_id='r1'").fetchone()
            self.assertEqual((robot["org_id"], robot["team_id"]), ("legacy", "legacy"))
            batch = connection.execute("SELECT org_id, team_id FROM batches WHERE batch_id='batch1'").fetchone()
            self.assertEqual((batch["org_id"], batch["team_id"]), ("legacy", "legacy"))
            event = connection.execute("SELECT actor_id, actor_name FROM audit_events").fetchone()
            self.assertEqual((event["actor_id"], event["actor_name"]), ("stat1", "统计甲"))
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            self.assertNotIn("role", columns)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            # 迁移后的成员关系立即可用：旧统计负责人仍能封存自己的批次。
            service = TrialService(connection, FrozenClock(datetime(2026, 9, 24, tzinfo=timezone.utc)))
            sealed = service.seal_batch("stat1", "batch1", 2)
            self.assertEqual(sealed["state"], "sealed")
            self.assertEqual(sealed["org_id"], "legacy")
        finally:
            connection.close()

    def test_initialize_on_empty_database_lands_on_v3(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            initialize(connection)
            summary = inspect_schema(connection)
            self.assertEqual(summary["schema_version"], "3")
            self.assertEqual(summary["missing_tables"], [])
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
