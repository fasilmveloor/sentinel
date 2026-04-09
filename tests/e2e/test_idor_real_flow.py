import threading
import time
from http.server import HTTPServer

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator
from tests.integration.test_mock_server import MockAPIHandler


@pytest.fixture(scope="module")
def idor_mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockAPIHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_real_idor_flow_produces_proven_vulnerability(idor_mock_server):
    login_endpoint = Endpoint(
        path="/api/login",
        method=HttpMethod.POST,
        parameters=[
            Parameter(name="username", location="body", required=True),
            Parameter(name="password", location="body", required=True),
        ],
    )
    idor_endpoint = Endpoint(
        path="/api/orders/{orderId}",
        method=HttpMethod.GET,
        parameters=[Parameter(name="orderId", location="path", required=True, param_type="integer")],
        security=[{"bearerAuth": []}],
    )

    orchestrator = SentinelOrchestrator(
        idor_mock_server,
        max_iterations=2,
        max_tasks=5,
        endpoints=[idor_endpoint],
    )
    orchestrator.push_task(
        ScanTask(
            endpoint=login_endpoint,
            attack_type=AttackType.BROKEN_AUTH,
            reason="seed",
        )
    )

    results = orchestrator.run()

    assert orchestrator.vulnerabilities
    vulnerability = orchestrator.vulnerabilities[0]
    assert vulnerability.attack_type == AttackType.IDOR

    idor_results = [result for result in results if result.attack_type == AttackType.IDOR and result.success]
    assert idor_results
    assert idor_results[0].evidence_excerpt is not None
    assert idor_results[0].request_url is not None
