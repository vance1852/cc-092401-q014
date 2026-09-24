"""统计准入服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_STATEMENTS = (
    "PRAGMA foreign_keys = ON",
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS organizations (
        org_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS teams (
        org_id TEXT NOT NULL REFERENCES organizations(org_id),
        team_id TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (org_id, team_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_roles (
        user_id TEXT NOT NULL REFERENCES users(user_id),
        org_id TEXT NOT NULL REFERENCES organizations(org_id),
        role TEXT NOT NULL CHECK (role IN ('org_admin', 'org_auditor')),
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, org_id, role)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS memberships (
        user_id TEXT NOT NULL REFERENCES users(user_id),
        org_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, org_id, team_id),
        FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS protocol_catalog (
        org_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        title TEXT NOT NULL,
        task_family TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
        created_at TEXT NOT NULL,
        PRIMARY KEY (org_id, team_id, protocol_id, version),
        UNIQUE (org_id, team_id, content_sha256),
        FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS robots (
        robot_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        model_name TEXT NOT NULL,
        vendor TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS builds (
        build_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        robot_id TEXT NOT NULL REFERENCES robots(robot_id),
        version TEXT NOT NULL,
        content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (robot_id, version),
        UNIQUE (content_sha256),
        FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS batches (
        batch_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        protocol_version INTEGER NOT NULL,
        build_id TEXT NOT NULL REFERENCES builds(build_id),
        state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
        revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
        created_by TEXT NOT NULL REFERENCES users(user_id),
        created_at TEXT NOT NULL,
        started_at TEXT,
        sealed_at TEXT,
        FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, team_id),
        FOREIGN KEY (org_id, team_id, protocol_id, protocol_version)
            REFERENCES protocol_catalog(org_id, team_id, protocol_id, version)
    )
    """,
    """
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency_keys (
        scope TEXT NOT NULL,
        key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (scope, key)
    )
    """,
    """
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
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
    ON exclusion_requests(observation_id)
    WHERE status IN ('pending', 'approved')
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS decisions (
        decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT NOT NULL REFERENCES batches(batch_id),
        analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
        decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
        reason TEXT NOT NULL,
        decided_by TEXT NOT NULL REFERENCES users(user_id),
        decided_at TEXT NOT NULL,
        UNIQUE (batch_id, analysis_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_name TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
)

SCHEMA_SQL = "\n".join(SCHEMA_STATEMENTS) + "\n"

REQUIRED_TABLES = frozenset({
    "schema_meta", "organizations", "teams", "users", "org_roles", "memberships",
    "protocol_catalog", "robots", "builds", "batches", "observations",
    "idempotency_keys", "exclusion_requests", "analysis_jobs", "analyses",
    "decisions", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _schema_version(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    return None if row is None else row["value"]


def initialize(connection: sqlite3.Connection) -> None:
    """初始化或迁移基础资料表，重复执行不改变已有数据。"""

    for statement in SCHEMA_STATEMENTS:
        connection.execute(statement)
    version = _schema_version(connection)
    if version == str(SCHEMA_VERSION):
        return
    if version == "2":
        from .migrations import migrate_v2_to_v3

        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA legacy_alter_table = ON")
        try:
            with transaction(connection, immediate=True):
                migrate_v2_to_v3(connection)
        finally:
            connection.execute("PRAGMA legacy_alter_table = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
    elif version is not None:
        raise RuntimeError(f"不支持的数据库模式版本: {version}")
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": _schema_version(connection),
        "foreign_keys": bool(foreign_keys),
    }
