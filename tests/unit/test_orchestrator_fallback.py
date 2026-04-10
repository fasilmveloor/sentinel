from sentinel.models import AttackResult, AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator


def test_orchestrator_creates_generic_vulnerability_when_attacker_missing(monkeypatch):
    endpoint = Endpoint(
        path="/api/protected",
        method=HttpMethod.GET,
        parameters=[Parameter(name="id", location="query", required=False)],
    )
    orchestrator = SentinelOrchestrator("http://example.com", endpoints=[endpoint])
    orchestrator.push_task(ScanTask(endpoint=endpoint, attack_type=AttackType.BROKEN_AUTH, reason="seed"))

    successful_result = AttackResult(
        endpoint=endpoint,
        attack_type=AttackType.BROKEN_AUTH,
        success=True,
        payload="no_auth",
        request_url="http://example.com/api/protected",
        request_method="GET",
        response_status=200,
        response_body='{"user":{"email":"victim@example.com"}}',
        evidence_excerpt='{"user":{"email":"victim@example.com"}}',
    )

    monkeypatch.setattr(orchestrator, "_execute_task", lambda task: [successful_result])
    monkeypatch.setattr(orchestrator, "_enqueue_idor_followups", lambda: None)

    results = orchestrator.run()

    assert results == [successful_result]
    assert len(orchestrator.vulnerabilities) == 1
    assert orchestrator.vulnerabilities[0].attack_type == AttackType.BROKEN_AUTH
