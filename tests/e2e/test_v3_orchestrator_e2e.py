import threading
import time
from http.server import HTTPServer

import pytest

from sentinel.models import AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator
from tests.integration.test_mock_server import MockAPIHandler


@pytest.fixture(scope="module")
def v3_mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockAPIHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()


def test_endpoint_returning_id_enqueues_and_executes_idor(v3_mock_server):
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
        v3_mock_server,
        max_iterations=2,
        max_tasks=5,
        endpoints=[idor_endpoint],
    )
    orchestrator.push_task(ScanTask(endpoint=login_endpoint, attack_type=AttackType.BROKEN_AUTH, reason="seed"))

    results = orchestrator.run()

    assert len(orchestrator.context.discovered_ids) > 0
    assert any(result.attack_type == AttackType.BROKEN_AUTH for result in results)
    assert any(result.attack_type == AttackType.IDOR for result in results)
    assert orchestrator.tasks_executed == 2


def test_no_id_case_generates_no_followup_tasks(v3_mock_server):
    public_endpoint = Endpoint(
        path="/api/health",
        method=HttpMethod.GET,
        parameters=[],
    )
    idor_endpoint = Endpoint(
        path="/api/orders/{orderId}",
        method=HttpMethod.GET,
        parameters=[Parameter(name="orderId", location="path", required=True, param_type="integer")],
    )

    orchestrator = SentinelOrchestrator(
        v3_mock_server,
        max_iterations=2,
        max_tasks=5,
        endpoints=[idor_endpoint],
    )
    orchestrator.push_task(ScanTask(endpoint=public_endpoint, attack_type=AttackType.RATE_LIMIT, reason="seed"))

    results = orchestrator.run()

    assert orchestrator.context.discovered_ids == set()
    assert all(result.attack_type != AttackType.IDOR for result in results)
    assert orchestrator.tasks_executed == 1


def test_loop_limit_stops_before_followup_execution(v3_mock_server):
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
        v3_mock_server,
        max_iterations=1,
        max_tasks=5,
        endpoints=[idor_endpoint],
    )
    orchestrator.push_task(ScanTask(endpoint=login_endpoint, attack_type=AttackType.BROKEN_AUTH, reason="seed"))

    results = orchestrator.run()

    assert any(result.attack_type == AttackType.BROKEN_AUTH for result in results)
    assert all(result.attack_type != AttackType.IDOR for result in results)
    assert len(orchestrator.context.discovered_ids) > 0
    assert orchestrator.tasks_executed == 1
