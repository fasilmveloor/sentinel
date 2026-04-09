import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


class BrokenAuthMockHandler(BaseHTTPRequestHandler):
    VALID_TOKEN = "valid-token"

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path == "/api/protected-profile":
            auth = self.headers.get("Authorization")
            sensitive_payload = {
                "user": {
                    "id": "2",
                    "email": "victim@example.com",
                    "account": "premium",
                }
            }

            if auth == f"Bearer {self.VALID_TOKEN}":
                self._send_json(sensitive_payload, status=200)
                return

            self._send_json(
                sensitive_payload,
                status=200,
            )
            return

        self._send_json({"error": "not found"}, status=404)


@pytest.fixture(scope="module")
def broken_auth_mock_server():
    server = HTTPServer(("127.0.0.1", 0), BrokenAuthMockHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_broken_auth_flow_produces_proven_vulnerability(broken_auth_mock_server):
    protected_endpoint = Endpoint(
        path="/api/protected-profile",
        method=HttpMethod.GET,
        parameters=[],
        security=[{"bearerAuth": []}],
    )

    orchestrator = SentinelOrchestrator(
        broken_auth_mock_server,
        max_iterations=1,
        max_tasks=3,
        endpoints=[protected_endpoint],
    )
    orchestrator.push_task(
        ScanTask(
            endpoint=protected_endpoint,
            attack_type=AttackType.BROKEN_AUTH,
            artifacts={"auth_token": BrokenAuthMockHandler.VALID_TOKEN},
            reason="seed",
        )
    )

    results = orchestrator.run()

    assert orchestrator.vulnerabilities
    vulnerability = orchestrator.vulnerabilities[0]
    assert vulnerability.attack_type == AttackType.BROKEN_AUTH

    successful_results = [
        result for result in results
        if result.attack_type == AttackType.BROKEN_AUTH and result.success
    ]
    assert successful_results
    assert successful_results[0].payload in {"no_auth", "invalid_token", "reused_token"}
    assert successful_results[0].response_status in {200, 201}
    assert successful_results[0].evidence_excerpt is not None
    assert successful_results[0].request_url is not None
