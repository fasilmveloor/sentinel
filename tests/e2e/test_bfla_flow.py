import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


class BFLAMockHandler(BaseHTTPRequestHandler):
    USER_TOKEN = "user-token"

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path != "/api/admin/users":
            self._send_json({"error": "not found"}, status=404)
            return

        auth = self.headers.get("Authorization")
        if auth != f"Bearer {self.USER_TOKEN}":
            self._send_json({"error": "unauthorized"}, status=401)
            return

        if self.headers.get("X-Role") != "admin":
            self._send_json({"error": "forbidden"}, status=403)
            return

        self._send_json(
            {"user": {"id": "99", "email": "admin@example.com", "account": "admin"}},
            status=200,
        )


@pytest.fixture(scope="module")
def bfla_mock_server():
    server = HTTPServer(("127.0.0.1", 0), BFLAMockHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_bfla_flow_produces_proven_vulnerability(bfla_mock_server):
    endpoint = Endpoint(
        path="/api/admin/users",
        method=HttpMethod.GET,
        parameters=[],
        security=[{"bearerAuth": []}],
    )

    orchestrator = SentinelOrchestrator(
        bfla_mock_server,
        max_iterations=1,
        max_tasks=3,
        endpoints=[endpoint],
    )
    orchestrator.push_task(
        ScanTask(
            endpoint=endpoint,
            attack_type=AttackType.BFLA,
            artifacts={"auth_token": BFLAMockHandler.USER_TOKEN},
            reason="seed",
        )
    )

    results = orchestrator.run()

    assert orchestrator.vulnerabilities
    vulnerability = orchestrator.vulnerabilities[0]
    assert vulnerability.attack_type == AttackType.AUTH_BYPASS

    successful_results = [
        result for result in results
        if result.attack_type == AttackType.BFLA and result.success
    ]
    assert successful_results
    assert successful_results[0].payload == "endpoint_access: /api/admin/users"
    assert successful_results[0].evidence_excerpt is not None
    assert successful_results[0].request_url is not None
