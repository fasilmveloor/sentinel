from sentinel.deduplication import Evidence, VulnerabilityDeduplicator
from sentinel.models import AttackResult, AttackType, Endpoint, HttpMethod, Severity


def make_endpoint(path="/api/users"):
    return Endpoint(path=path, method=HttpMethod.GET, parameters=[])


def make_result(attack_type=AttackType.SQL_INJECTION, **overrides):
    values = {
        "endpoint": make_endpoint(),
        "attack_type": attack_type,
        "success": True,
        "payload": "' OR 1=1 --",
        "response_status": 500,
        "response_body": '{"error":"SQL syntax error"}',
        "duration_ms": 123.0,
        "extra_data": {"technique": "error_based"},
    }
    values.update(overrides)
    return AttackResult(**values)


def test_determine_root_cause_for_sql_and_auth():
    deduplicator = VulnerabilityDeduplicator()

    sql_root = deduplicator._determine_root_cause(
        AttackType.SQL_INJECTION,
        make_result(),
    )
    auth_root = deduplicator._determine_root_cause(
        AttackType.AUTH_BYPASS,
        make_result(
            attack_type=AttackType.AUTH_BYPASS,
            payload="none",
            response_status=200,
            extra_data=None,
        ),
    )

    assert sql_root == "sql_injection_error_based"
    assert auth_root == "auth_missing_token_accepted"


def test_add_finding_deduplicates_and_aggregates_evidence():
    deduplicator = VulnerabilityDeduplicator()
    endpoint = make_endpoint()
    result = make_result(endpoint=endpoint)

    first_added = deduplicator.add_finding(result, endpoint, technique="error_based")
    second_added = deduplicator.add_finding(result, endpoint, technique="error_based")

    assert first_added is True
    assert second_added is False
    grouped = deduplicator.get_unique_vulnerabilities()[0]
    assert grouped.evidence_count == 2
    assert grouped.confidence > 0.5


def test_statistics_and_vulnerability_models_are_generated():
    deduplicator = VulnerabilityDeduplicator()
    sql_endpoint = make_endpoint("/api/users")
    idor_endpoint = make_endpoint("/api/orders/{id}")

    deduplicator.add_finding(make_result(endpoint=sql_endpoint), sql_endpoint, technique="error_based")
    deduplicator.add_finding(
        make_result(
            attack_type=AttackType.IDOR,
            endpoint=idor_endpoint,
            response_status=200,
            response_body='{"user":{"email":"victim@example.com"}}',
            extra_data=None,
        ),
        idor_endpoint,
        technique="idor",
    )

    stats = deduplicator.get_statistics()
    models = deduplicator.to_vulnerability_models()

    assert stats["total_unique"] == 2
    assert stats["severity_distribution"][Severity.HIGH] >= 1
    assert stats["by_attack_type"]["sql_injection"] == 1
    assert len(models) == 2
    assert all(model.proof_of_concept for model in models)


def test_severity_to_cvss_and_evidence_defaults():
    evidence = Evidence(
        payload="test",
        response_status=200,
        response_preview="{}",
        technique="basic",
        duration_ms=1.0,
    )
    deduplicator = VulnerabilityDeduplicator()

    assert evidence.timestamp
    assert deduplicator._severity_to_cvss(Severity.CRITICAL) == 9.5
    assert deduplicator._severity_to_cvss(Severity.INFO) == 0.0
