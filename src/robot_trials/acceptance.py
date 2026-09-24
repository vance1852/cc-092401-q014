"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .service import TrialService
from .storage import connect, inspect_schema


ORG_ID = "demo-org"
TEAM_ID = "demo-team"


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="robot-trials-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = TrialService(connection)
            for user_id, display_name in (
                ("admin-1", "组织管理员"),
                ("operator-1", "测试操作员"),
                ("stat-1", "统计负责人"),
                ("approver-1", "准入审批人"),
                ("auditor-1", "团队审计人员"),
                ("org-auditor-1", "组织审计人员"),
            ):
                service.create_user(user_id, display_name)
            service.create_organization(ORG_ID, "示例事业部", "admin-1")
            service.create_team("admin-1", ORG_ID, TEAM_ID, "递送试验团队")
            for user_id, role in (
                ("operator-1", "operator"),
                ("stat-1", "statistician"),
                ("approver-1", "approver"),
                ("auditor-1", "auditor"),
            ):
                service.grant_membership("admin-1", user_id, ORG_ID, TEAM_ID, role)
            service.grant_membership("admin-1", "org-auditor-1", ORG_ID, None, "org_auditor")
            service.register_robot(
                "operator-1", ORG_ID, TEAM_ID, "robot-a", "A 型人形机器人", "示例厂商"
            )
            service.register_build(
                "operator-1", ORG_ID, TEAM_ID, "build-a1", "robot-a", "1.0.0", "a" * 64
            )
            service.publish_protocol("stat-1", ORG_ID, TEAM_ID, protocol)
            service.create_batch(
                "operator-1", ORG_ID, TEAM_ID, "batch-demo",
                protocol["protocol_id"], protocol["version"], "build-a1",
            )
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report("auditor-1", "batch-demo")
            org_report = service.report("org-auditor-1", "batch-demo")
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    if org_report["viewer_role"] != "org_auditor":
        raise RuntimeError("组织审计员应能跨团队只读报告")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "organization": ORG_ID,
        "team": TEAM_ID,
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行试验数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
