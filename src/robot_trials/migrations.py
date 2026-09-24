"""SQLite 模式版本迁移。

v2 的全局角色库会整体迁入名为 ``legacy`` 的默认组织与团队：机器人、构建、
协议和批次补齐组织归属，用户原有的全局角色转换为该团队的成员关系，审计
事件补写操作人当时的显示名快照。迁移在关闭外键检查的单个事务中执行，
完成后立即做外键一致性校验。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .clock import isoformat
from .storage import SCHEMA_STATEMENTS


LEGACY_ORG_ID = "legacy"
LEGACY_TEAM_ID = "legacy"

# v2 中被 v3 改变结构的表；其余业务表两个版本完全一致，迁移时保持不动。
_RESHAPED_TABLES = ("users", "robots", "builds", "protocol_catalog", "batches", "audit_events")


def migrate_v2_to_v3(connection: sqlite3.Connection) -> None:
    """把 v2 数据库重建成 v3 结构并保留全部历史数据。必须在事务内调用。"""

    now = isoformat(datetime.now(timezone.utc))
    for table in _RESHAPED_TABLES:
        connection.execute(f"ALTER TABLE {table} RENAME TO {table}_v2")
    for statement in SCHEMA_STATEMENTS:
        connection.execute(statement)
    connection.execute(
        "INSERT INTO organizations(org_id, name, created_at) VALUES(?, ?, ?)",
        (LEGACY_ORG_ID, "迁移默认组织", now),
    )
    connection.execute(
        "INSERT INTO teams(org_id, team_id, name, created_at) VALUES(?, ?, ?, ?)",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID, "迁移默认团队", now),
    )
    connection.execute(
        "INSERT INTO users(user_id, display_name, active) "
        "SELECT user_id, display_name, active FROM users_v2"
    )
    connection.execute(
        "INSERT INTO memberships(user_id, org_id, team_id, role, created_at) "
        "SELECT user_id, ?, ?, role, ? FROM users_v2",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID, now),
    )
    connection.execute(
        "INSERT INTO robots(robot_id, org_id, team_id, model_name, vendor, created_at) "
        "SELECT robot_id, ?, ?, model_name, vendor, created_at FROM robots_v2",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID),
    )
    connection.execute(
        "INSERT INTO builds(build_id, org_id, team_id, robot_id, version, content_sha256, created_at) "
        "SELECT build_id, ?, ?, robot_id, version, content_sha256, created_at FROM builds_v2",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID),
    )
    connection.execute(
        "INSERT INTO protocol_catalog(org_id, team_id, protocol_id, version, title, task_family, "
        "canonical_json, content_sha256, created_at) "
        "SELECT ?, ?, protocol_id, version, title, task_family, canonical_json, content_sha256, created_at "
        "FROM protocol_catalog_v2",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID),
    )
    connection.execute(
        "INSERT INTO batches(batch_id, org_id, team_id, protocol_id, protocol_version, build_id, state, "
        "revision, created_by, created_at, started_at, sealed_at) "
        "SELECT batch_id, ?, ?, protocol_id, protocol_version, build_id, state, revision, created_by, "
        "created_at, started_at, sealed_at FROM batches_v2",
        (LEGACY_ORG_ID, LEGACY_TEAM_ID),
    )
    connection.execute(
        "INSERT INTO audit_events(event_id, entity_type, entity_id, event_type, actor_id, actor_name, "
        "payload_json, created_at) "
        "SELECT e.event_id, e.entity_type, e.entity_id, e.event_type, e.actor_id, "
        "COALESCE((SELECT u.display_name FROM users u WHERE u.user_id = e.actor_id), e.actor_id), "
        "e.payload_json, e.created_at FROM audit_events_v2 e"
    )
    for table in _RESHAPED_TABLES:
        connection.execute(f"DROP TABLE {table}_v2")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"v2 到 v3 迁移后外键不一致: {[tuple(row) for row in violations]!r}")
