import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


class InjectionMockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/search":
            self._send_json({"error": "not found"}, status=404)
            return

        query = parse_qs(parsed.query).get("q", [""])[0]
        if any(payload in query for payload in ("' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1 --")):
            self._send_json(
                {
                    "error": "SQL syntax error near users",
                    "user": {"id": "2", "email": "victim@example.com"},
                },
                status=500,
            )
            return

        self._send_json({"results": []}, status=200)


@pytest.fixture(scope="module")
def injection_mock_server():
    server = HTTPServer(("127.0.0.1", 0), InjectionMockHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_injection_flow_produces_proven_vulnerability(injection_mock_server):
    endpoint = Endpoint(
        path="/api/search",
        method=HttpMethod.GET,
        parameters=[Parameter(name="q", location="query", required=True)],
    )

    orchestrator = SentinelOrchestrator(
        injection_mock_server,
        max_iterations=1,
        max_tasks=3,
        endpoints=[endpoint],
    )
    orchestrator.push_task(
        ScanTask(
            endpoint=endpoint,
            attack_type=AttackType.SQL_INJECTION,
            reason="seed",
        )
    )

    results = orchestrator.run()

    assert orchestrator.vulnerabilities
    vulnerability = orchestrator.vulnerabilities[0]
    assert vulnerability.attack_type == AttackType.SQL_INJECTION

    successful_results = [
        result for result in results
        if result.attack_type == AttackType.SQL_INJECTION and result.success
    ]
    assert successful_results
    assert successful_results[0].evidence_excerpt is not None
    assert successful_results[0].request_url is not None
