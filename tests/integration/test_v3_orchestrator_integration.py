from unittest.mock import Mock

import pytest

from sentinel.models import AttackResult, AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


class FakeAttacker:
    def __init__(self, results):
        self.results = results

    def attack(self, endpoint, *args, **kwargs):
        return list(self.results)


@pytest.fixture
def list_endpoint():
    return Endpoint(
        path="/api/list-users",
        method=HttpMethod.GET,
        parameters=[Parameter(name="q", location="query", required=False)],
    )


@pytest.fixture
def id_endpoint():
    return Endpoint(
        path="/api/users/{id}",
        method=HttpMethod.GET,
        parameters=[Parameter(name="id", location="path", required=True, param_type="integer")],
    )


def test_loop_updates_context_and_enqueues_followup_tasks(list_endpoint, id_endpoint, monkeypatch):
    orchestrator = SentinelOrchestrator("http://example.com", max_iterations=2, endpoints=[list_endpoint, id_endpoint])
    orchestrator.push_task(ScanTask(endpoint=list_endpoint, attack_type=AttackType.SQL_INJECTION, reason="seed"))

    sql_result = AttackResult(
        endpoint=list_endpoint,
        attack_type=AttackType.SQL_INJECTION,
        success=True,
        response_body='{"userId": "42"}',
    )
    idor_result = AttackResult(
        endpoint=id_endpoint,
        attack_type=AttackType.IDOR,
        success=False,
        payload="id=42",
    )

    class FakeIDORAttacker:
        def __init__(self, target_url, timeout):
            self.results = [idor_result]
            self.session = Mock()
            self.session.headers = {}
            self.ID_PATTERNS = []

        def attack(self, endpoint, *args, **kwargs):
            return list(self.results)

    def fake_get_attacker(attack_type):
        if attack_type == AttackType.SQL_INJECTION:
            return FakeAttacker([sql_result])
        if attack_type == AttackType.IDOR:
            return FakeAttacker([idor_result])
        raise AssertionError(f"Unexpected attack type: {attack_type}")

    monkeypatch.setattr(orchestrator, "_get_attacker", fake_get_attacker)
    monkeypatch.setattr("sentinel.orchestrator.IDORAttacker", FakeIDORAttacker)

    results = orchestrator.run()

    assert "42" in orchestrator.context.discovered_ids
    assert len(results) == 2
    assert any(result.attack_type == AttackType.IDOR for result in results)
    assert orchestrator.tasks_executed == 2


def test_chaining_generates_idor_tasks_from_discovered_ids(id_endpoint):
    orchestrator = SentinelOrchestrator("http://example.com", endpoints=[id_endpoint])
    orchestrator.context.discovered_ids.add("77")

    orchestrator._enqueue_idor_followups()

    followup = orchestrator.queue.pop()
    assert followup is not None
    assert followup.attack_type == AttackType.IDOR
    assert followup.artifacts == {"candidate_id": "77"}
    assert followup.parameters == ["id"]
