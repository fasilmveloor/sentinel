from sentinel.deduplication import Evidence, GroupedVulnerability, VulnerabilityDeduplicator
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


def test_root_cause_for_multiple_attack_types():
    deduplicator = VulnerabilityDeduplicator()

    # SSRF variations
    assert deduplicator._determine_root_cause(
        AttackType.SSRF,
        make_result(attack_type=AttackType.SSRF, extra_data={"ssrf_type": "cloud_metadata"})
    ) == "ssrf_cloud_metadata_access"

    assert deduplicator._determine_root_cause(
        AttackType.SSRF,
        make_result(attack_type=AttackType.SSRF, extra_data={"ssrf_type": "blind"})
    ) == "ssrf_blind"

    # JWT variations
    assert deduplicator._determine_root_cause(
        AttackType.JWT,
        make_result(attack_type=AttackType.JWT, extra_data={"vulnerability_type": "none_algorithm"})
    ) == "jwt_none_algorithm_accepted"

    assert deduplicator._determine_root_cause(
        AttackType.JWT,
        make_result(attack_type=AttackType.JWT, extra_data={"vulnerability_type": "weak_secret"})
    ) == "jwt_weak_secret"

    # XSS
    assert deduplicator._determine_root_cause(
        AttackType.XSS,
        make_result(attack_type=AttackType.XSS, extra_data={"xss_context": "attribute"})
    ) == "xss_attribute_context"

    # Rate limit
    assert deduplicator._determine_root_cause(
        AttackType.RATE_LIMIT,
        make_result(attack_type=AttackType.RATE_LIMIT)
    ) == "rate_limit_missing"

    # BOLA
    assert deduplicator._determine_root_cause(
        AttackType.BOLA,
        make_result(attack_type=AttackType.BOLA)
    ) == "bola_missing_object_authorization"

    # BFLA
    assert deduplicator._determine_root_cause(
        AttackType.BFLA,
        make_result(attack_type=AttackType.BFLA)
    ) == "bfla_missing_function_authorization"

    # Mass assignment
    assert deduplicator._determine_root_cause(
        AttackType.MASS_ASSIGNMENT,
        make_result(attack_type=AttackType.MASS_ASSIGNMENT)
    ) == "mass_assignment_unfiltered_properties"

    # Excessive data
    assert deduplicator._determine_root_cause(
        AttackType.EXCESSIVE_DATA,
        make_result(attack_type=AttackType.EXCESSIVE_DATA)
    ) == "excessive_data_exposure"

    # NoSQL injection
    assert deduplicator._determine_root_cause(
        AttackType.NOSQL_INJECTION,
        make_result(attack_type=AttackType.NOSQL_INJECTION, extra_data={"technique": "operator"})
    ) == "nosql_injection_operator"

    # Command injection
    assert deduplicator._determine_root_cause(
        AttackType.CMD_INJECTION,
        make_result(attack_type=AttackType.CMD_INJECTION)
    ) == "command_injection"


def test_grouped_vulnerability_properties():
    endpoint = make_endpoint()
    vuln = GroupedVulnerability(
        endpoint=endpoint,
        attack_type=AttackType.SQL_INJECTION,
        root_cause="sql_injection_error_based",
        severity=Severity.HIGH,
        confidence=0.8,
    )

    assert vuln.evidence_count == 0

    result = make_result()
    vuln.add_evidence(result, "error_based")

    assert vuln.evidence_count == 1
    assert vuln.confidence == 0.6  # 0.5 + 0.1


def test_generate_finding_key():
    deduplicator = VulnerabilityDeduplicator()
    endpoint = make_endpoint("/api/admin")

    key1 = deduplicator._generate_finding_key(endpoint, AttackType.BFLA, "test")
    key2 = deduplicator._generate_finding_key(endpoint, AttackType.BFLA, "test")
    key3 = deduplicator._generate_finding_key(endpoint, AttackType.BOLA, "test")

    assert key1 == key2  # Same inputs = same key
    assert key1 != key3  # Different attack type = different key
    assert len(key1) == 16  # SHA256 truncated to 16 chars


def test_get_unique_vulnerabilities_ordering():
    deduplicator = VulnerabilityDeduplicator()

    # Add findings in different order
    deduplicator.add_finding(
        make_result(attack_type=AttackType.IDOR, response_status=200),
        make_endpoint("/api/orders"),
        technique="idor"
    )
    deduplicator.add_finding(
        make_result(attack_type=AttackType.SQL_INJECTION, response_status=500),
        make_endpoint("/api/users"),
        technique="error_based"
    )

    vulns = deduplicator.get_unique_vulnerabilities()
    assert len(vulns) == 2
