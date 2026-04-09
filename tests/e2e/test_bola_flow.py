import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


class BOLAMockHandler(BaseHTTPRequestHandler):
    VALID_TOKEN = "user-token"

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        auth = self.headers.get("Authorization")
        if auth != f"Bearer {self.VALID_TOKEN}":
            self._send_json({"error": "unauthorized"}, status=401)
            return

        if self.path == "/api/users/2":
            self._send_json(
                {"user": {"id": "2", "email": "user2@example.com", "account": "basic"}},
                status=200,
            )
            return

        if self.path == "/api/users/1":
            self._send_json(
                {"user": {"id": "1", "email": "user1@example.com", "account": "pro"}},
                status=200,
            )
            return

        if self.path == "/api/users/3":
            self._send_json(
                {"user": {"id": "3", "email": "user3@example.com", "account": "team"}},
                status=200,
            )
            return

        self._send_json({"error": "not found"}, status=404)


@pytest.fixture(scope="module")
def bola_mock_server():
    server = HTTPServer(("127.0.0.1", 0), BOLAMockHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_bola_flow_produces_proven_vulnerability(bola_mock_server):
    endpoint = Endpoint(
        path="/api/users/2",
        method=HttpMethod.GET,
        parameters=[],
        security=[{"bearerAuth": []}],
    )

    orchestrator = SentinelOrchestrator(
        bola_mock_server,
        max_iterations=1,
        max_tasks=3,
        endpoints=[endpoint],
    )
    orchestrator.push_task(
        ScanTask(
            endpoint=endpoint,
            attack_type=AttackType.BOLA,
            artifacts={"auth_token": BOLAMockHandler.VALID_TOKEN},
            reason="seed",
        )
    )

    results = orchestrator.run()

    assert orchestrator.vulnerabilities
    vulnerability = orchestrator.vulnerabilities[0]
    assert vulnerability.attack_type == AttackType.BOLA

    successful_results = [
        result for result in results
        if result.attack_type == AttackType.BOLA and result.success
    ]
    assert successful_results
    assert successful_results[0].evidence_excerpt is not None
    assert successful_results[0].request_url is not None
