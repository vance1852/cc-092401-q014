"""无第三方依赖的 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import ServiceError, ValidationFailed
from .service import TrialService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any] | list[Any]


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。"""

    def __init__(self, service: TrialService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    @staticmethod
    def _scope(payload: dict[str, Any]) -> tuple[str, str]:
        org_id = str(payload.get("org_id", "")).strip()
        team_id = str(payload.get("team_id", "")).strip()
        if not org_id or not team_id:
            raise ValidationFailed("必须提供 org_id 与 team_id")
        return org_id, team_id

    @staticmethod
    def _filters(query: str) -> tuple[str | None, str | None]:
        params = parse_qs(query)
        org = params.get("org_id", [None])[0]
        team = params.get("team_id", [None])[0]
        if team and not org:
            raise ValidationFailed("按团队过滤时必须同时提供 org_id")
        return org, team

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        actor = lambda: self._actor(normalized_headers)  # noqa: E731
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            # -- 身份与组织治理 -------------------------------------------------
            if method == "POST" and path == "/users":
                result = self.service.create_user(
                    payload["user_id"], payload["display_name"]
                )
                return Response(201, result)
            if method == "POST" and path == "/organizations":
                result = self.service.create_organization(
                    payload["org_id"], payload["display_name"],
                    payload["admin_user_id"], payload.get("admin_display_name"),
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "organizations" and parts[2] == "teams":
                result = self.service.create_team(
                    actor(), parts[1], payload["team_id"], payload["display_name"]
                )
                return Response(201, result)
            if method == "POST" and path == "/memberships":
                result = self.service.grant_membership(
                    actor(), payload["user_id"], payload["org_id"],
                    payload.get("team_id"), payload["role"],
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 2 and parts[0] == "memberships" and parts[1] == "revoke":
                result = self.service.revoke_membership(
                    actor(), payload["user_id"], payload["org_id"],
                    payload.get("team_id"), payload["role"],
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "users" and parts[2] == "active":
                result = self.service.set_user_active(
                    actor(), payload["org_id"], parts[1], bool(payload["active"])
                )
                return Response(200, result)

            # -- 列表与单项读取（按可见范围过滤） -------------------------------
            if method == "GET" and path == "/robots":
                org, team = self._filters(parsed.query)
                return Response(200, self.service.list_robots(actor(), org, team))
            if method == "GET" and path == "/builds":
                org, team = self._filters(parsed.query)
                return Response(200, self.service.list_builds(actor(), org, team))
            if method == "GET" and path == "/protocols":
                org, team = self._filters(parsed.query)
                return Response(200, self.service.list_protocols(actor(), org, team))
            if method == "GET" and path == "/batches":
                org, team = self._filters(parsed.query)
                return Response(200, self.service.list_batches(actor(), org, team))
            if method == "GET" and len(parts) == 2 and parts[0] == "robots":
                return Response(200, self.service.get_robot(actor(), parts[1]))
            if method == "GET" and len(parts) == 2 and parts[0] == "builds":
                return Response(200, self.service.get_build(actor(), parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "protocols":
                query = parse_qs(parsed.query)
                org = query.get("org_id", [None])[0]
                team = query.get("team_id", [None])[0]
                if not org or not team:
                    raise ValidationFailed("读取协议必须提供 org_id 与 team_id")
                return Response(
                    200, self.service.get_protocol(actor(), org, team, parts[1], int(parts[2]))
                )

            # -- 业务写入 ------------------------------------------------------
            if method == "POST" and path == "/robots":
                org_id, team_id = self._scope(payload)
                result = self.service.register_robot(
                    actor(), org_id, team_id,
                    payload["robot_id"], payload["model_name"], payload["vendor"],
                )
                return Response(201, result)
            if method == "POST" and path == "/builds":
                org_id, team_id = self._scope(payload)
                result = self.service.register_build(
                    actor(), org_id, team_id, payload["build_id"], payload["robot_id"],
                    payload["version"], payload["content_sha256"],
                )
                return Response(201, result)
            if method == "POST" and path == "/protocols":
                org_id, team_id = self._scope(payload)
                return Response(
                    201,
                    self.service.publish_protocol(actor(), org_id, team_id, payload["protocol"]),
                )
            if method == "POST" and path == "/batches":
                org_id, team_id = self._scope(payload)
                result = self.service.create_batch(
                    actor(), org_id, team_id, payload["batch_id"], payload["protocol_id"],
                    int(payload["protocol_version"]), payload["build_id"],
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 2 and parts[0] == "batches":
                return Response(200, self.service.get_batch(actor(), parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "start":
                result = self.service.start_batch(actor(), parts[1], int(payload["expected_revision"]))
                return Response(200, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "observations":
                return Response(200, self.service.list_observations(actor(), parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "observations":
                key = normalized_headers.get("idempotency-key", "").strip()
                if not key:
                    raise ValidationFailed("缺少 Idempotency-Key")
                result = self.service.import_observations(
                    actor(), parts[1], key, payload.get("observations", [])
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "seal":
                result = self.service.seal_batch(actor(), parts[1], int(payload["expected_revision"]))
                return Response(200, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "report":
                return Response(200, self.service.report(actor(), parts[1]))
            if method == "POST" and path == "/exclusions":
                result = self.service.request_exclusion(
                    actor(), int(payload["observation_id"]), payload["reason"]
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "exclusions" and parts[2] == "review":
                result = self.service.review_exclusion(
                    actor(), int(parts[1]), bool(payload["approve"]), payload.get("note", "")
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "exclusions" and parts[2] == "revoke":
                result = self.service.revoke_exclusion(
                    actor(), int(parts[1]), payload["reason"]
                )
                return Response(200, result)
            if method == "POST" and path == "/jobs/claim":
                result = self.service.claim_job(payload["worker_id"], int(payload.get("lease_seconds", 60)))
                return Response(200, {"job": result})
            if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "complete":
                result = self.service.complete_job(
                    payload["worker_id"], int(parts[1]), actor()
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "fail":
                result = self.service.fail_job(
                    payload["worker_id"], int(parts[1]), payload["error"],
                    int(payload.get("retry_seconds", 0)),
                )
                return Response(200, result)
            if method == "POST" and path == "/decisions":
                result = self.service.decide(
                    actor(), payload["batch_id"], int(payload["analysis_id"]),
                    payload["decision"], payload["reason"],
                )
                return Response(201, result)
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RobotTrials/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动人形机器人试验统计准入 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("robot_trials.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(TrialService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
