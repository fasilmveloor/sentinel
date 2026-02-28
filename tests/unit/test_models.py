"""
Unit tests for Sentinel data models.

Tests cover:
- Enum values and behavior
- Pydantic model validation
- Computed properties
- Default values
- Edge cases
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from sentinel.models import (
    HttpMethod, AttackType, Severity, LLMProvider, ReportFormat,
    Parameter, Endpoint, AttackResult, Vulnerability, ScanConfig,
    ScanResult, AIAttackDecision,
    SQLInjectionResult, XSSResult, SSRFResult, JWTResult, RateLimitResult
)


# ============================================================================
# ENUM TESTS
# ============================================================================

class TestHttpMethod:
    """Tests for HttpMethod enum."""

    def test_all_methods_exist(self):
        """Test all expected HTTP methods exist."""
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"
        assert HttpMethod.PUT.value == "PUT"
        assert HttpMethod.PATCH.value == "PATCH"
        assert HttpMethod.DELETE.value == "DELETE"

    def test_method_count(self):
        """Test we have exactly 5 HTTP methods."""
        assert len(HttpMethod) == 5

    def test_method_is_string_enum(self):
        """Test HttpMethod is a string enum."""
        assert isinstance(HttpMethod.GET, str)
        assert HttpMethod.GET == "GET"


class TestAttackType:
    """Tests for AttackType enum."""

    def test_v1_attack_types(self):
        """Test v1.0 attack types exist."""
        assert AttackType.SQL_INJECTION.value == "sql_injection"
        assert AttackType.AUTH_BYPASS.value == "auth_bypass"
        assert AttackType.IDOR.value == "idor"

    def test_v2_attack_types(self):
        """Test v2.0 attack types exist."""
        assert AttackType.XSS.value == "xss"
        assert AttackType.SSRF.value == "ssrf"
        assert AttackType.JWT.value == "jwt"
        assert AttackType.CMD_INJECTION.value == "cmd_injection"
        assert AttackType.RATE_LIMIT.value == "rate_limit"

    def test_future_attack_types(self):
        """Test future attack types exist."""
        assert AttackType.XXE.value == "xxe"
        assert AttackType.PATH_TRAVERSAL.value == "path_traversal"

    def test_attack_type_count(self):
        """Test total attack type count."""
        assert len(AttackType) == 10


class TestSeverity:
    """Tests for Severity enum."""

    def test_all_severities_exist(self):
        """Test all severity levels exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_order(self):
        """Test severity values are strings."""
        severities = [s.value for s in Severity]
        assert severities == ["critical", "high", "medium", "low", "info"]


class TestLLMProvider:
    """Tests for LLMProvider enum."""

    def test_all_providers_exist(self):
        """Test all LLM providers exist."""
        assert LLMProvider.GEMINI.value == "gemini"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.CLAUDE.value == "claude"
        assert LLMProvider.LOCAL.value == "local"

    def test_provider_count(self):
        """Test we have 4 LLM providers."""
        assert len(LLMProvider) == 4


class TestReportFormat:
    """Tests for ReportFormat enum."""

    def test_all_formats_exist(self):
        """Test all report formats exist."""
        assert ReportFormat.MARKDOWN.value == "markdown"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.SARIF.value == "sarif"
        assert ReportFormat.JUNIT.value == "junit"

    def test_format_count(self):
        """Test we have 5 report formats."""
        assert len(ReportFormat) == 5


# ============================================================================
# PARAMETER TESTS
# ============================================================================

class TestParameter:
    """Tests for Parameter model."""

    def test_minimal_parameter(self):
        """Test creating parameter with minimal fields."""
        param = Parameter(name="id", location="query")
        assert param.name == "id"
        assert param.location == "query"
        assert param.required is False
        assert param.param_type == "string"
        assert param.description is None
        assert param.example is None

    def test_full_parameter(self):
        """Test creating parameter with all fields."""
        param = Parameter(
            name="user_id",
            location="path",
            required=True,
            param_type="integer",
            description="User identifier",
            example=12345
        )
        assert param.name == "user_id"
        assert param.location == "path"
        assert param.required is True
        assert param.param_type == "integer"
        assert param.description == "User identifier"
        assert param.example == 12345

    def test_parameter_locations(self):
        """Test all parameter locations."""
        locations = ["query", "path", "header", "body", "cookie"]
        for loc in locations:
            param = Parameter(name="test", location=loc)
            assert param.location == loc

    def test_parameter_required_field(self):
        """Test required field name is mandatory."""
        with pytest.raises(ValidationError):
            Parameter(location="query")  # Missing name

    def test_parameter_location_required(self):
        """Test location field is mandatory."""
        with pytest.raises(ValidationError):
            Parameter(name="test")  # Missing location


# ============================================================================
# ENDPOINT TESTS
# ============================================================================

class TestEndpoint:
    """Tests for Endpoint model."""

    def test_minimal_endpoint(self):
        """Test creating endpoint with minimal fields."""
        endpoint = Endpoint(path="/users", method=HttpMethod.GET)
        assert endpoint.path == "/users"
        assert endpoint.method == HttpMethod.GET
        assert endpoint.parameters == []
        assert endpoint.tags == []
        assert endpoint.responses == {}

    def test_full_endpoint(self):
        """Test creating endpoint with all fields."""
        endpoint = Endpoint(
            path="/api/users/{id}",
            method=HttpMethod.GET,
            operation_id="getUserById",
            summary="Get user by ID",
            description="Retrieves a user by their unique identifier",
            parameters=[
                Parameter(name="id", location="path", required=True)
            ],
            request_body={"type": "object"},
            responses={"200": {"description": "Success"}},
            security=[{"bearerAuth": []}],
            tags=["users"]
        )
        assert endpoint.path == "/api/users/{id}"
        assert endpoint.method == HttpMethod.GET
        assert endpoint.operation_id == "getUserById"
        assert len(endpoint.parameters) == 1
        assert endpoint.requires_auth is True
        assert "users" in endpoint.tags

    def test_requires_auth_with_security(self):
        """Test requires_auth property with security."""
        endpoint = Endpoint(
            path="/protected",
            method=HttpMethod.GET,
            security=[{"bearerAuth": []}]
        )
        assert endpoint.requires_auth is True

    def test_requires_auth_without_security(self):
        """Test requires_auth property without security."""
        endpoint = Endpoint(path="/public", method=HttpMethod.GET)
        assert endpoint.requires_auth is False

    def test_requires_auth_empty_security(self):
        """Test requires_auth property with empty security."""
        endpoint = Endpoint(
            path="/public",
            method=HttpMethod.GET,
            security=[]
        )
        assert endpoint.requires_auth is False

    def test_full_path_property(self):
        """Test full_path computed property."""
        endpoint = Endpoint(path="/users", method=HttpMethod.GET)
        assert endpoint.full_path == "GET /users"

        endpoint2 = Endpoint(path="/posts/{id}", method=HttpMethod.DELETE)
        assert endpoint2.full_path == "DELETE /posts/{id}"

    def test_endpoint_with_all_http_methods(self):
        """Test endpoint with each HTTP method."""
        for method in HttpMethod:
            endpoint = Endpoint(path="/test", method=method)
            assert endpoint.method == method


# ============================================================================
# ATTACK RESULT TESTS
# ============================================================================

class TestAttackResult:
    """Tests for AttackResult model."""

    def test_minimal_attack_result(self, sample_endpoint):
        """Test creating attack result with minimal fields."""
        result = AttackResult(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            success=True
        )
        assert result.endpoint == sample_endpoint
        assert result.attack_type == AttackType.SQL_INJECTION
        assert result.success is True
        assert result.payload is None
        assert result.response_status is None

    def test_full_attack_result(self, sample_endpoint):
        """Test creating attack result with all fields."""
        result = AttackResult(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            success=True,
            payload="' OR '1'='1",
            response_status=500,
            response_body='{"error": "SQL syntax error"}',
            error_message=None,
            timestamp="2024-01-15T10:30:00Z",
            duration_ms=150.5,
            extra_data={"injection_type": "error-based"}
        )
        assert result.payload == "' OR '1'='1"
        assert result.response_status == 500
        assert result.duration_ms == 150.5
        assert result.extra_data["injection_type"] == "error-based"

    def test_failed_attack_result(self, sample_endpoint):
        """Test creating failed attack result."""
        result = AttackResult(
            endpoint=sample_endpoint,
            attack_type=AttackType.XSS,
            success=False,
            error_message="Connection timeout"
        )
        assert result.success is False
        assert result.error_message == "Connection timeout"

    def test_attack_result_with_each_attack_type(self, sample_endpoint):
        """Test attack result with each attack type."""
        for attack_type in AttackType:
            result = AttackResult(
                endpoint=sample_endpoint,
                attack_type=attack_type,
                success=True
            )
            assert result.attack_type == attack_type


# ============================================================================
# VULNERABILITY TESTS
# ============================================================================

class TestVulnerability:
    """Tests for Vulnerability model."""

    def test_minimal_vulnerability(self, sample_endpoint):
        """Test creating vulnerability with required fields."""
        vuln = Vulnerability(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Vulnerable to SQL injection",
            payload="' OR '1'='1",
            proof_of_concept="curl -X GET '...'",
            recommendation="Use parameterized queries"
        )
        assert vuln.endpoint == sample_endpoint
        assert vuln.severity == Severity.HIGH
        assert vuln.title == "SQL Injection"

    def test_full_vulnerability(self, sample_endpoint):
        """Test creating vulnerability with all fields."""
        vuln = Vulnerability(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="SQL Injection in Login",
            description="Authentication bypass via SQL injection",
            payload="' OR '1'='1' --",
            proof_of_concept="POST /login with payload",
            recommendation="Use parameterized queries and input validation",
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            response_evidence="SQL error: syntax error",
            cvss_score=9.8,
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        )
        assert vuln.cwe_id == "CWE-89"
        assert vuln.cvss_score == 9.8
        assert len(vuln.references) == 1

    def test_vulnerability_all_severities(self, sample_endpoint):
        """Test vulnerability with each severity level."""
        for severity in Severity:
            vuln = Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=severity,
                title="Test",
                description="Test",
                payload="test",
                proof_of_concept="test",
                recommendation="test"
            )
            assert vuln.severity == severity


# ============================================================================
# SCAN CONFIG TESTS
# ============================================================================

class TestScanConfig:
    """Tests for ScanConfig model."""

    def test_minimal_scan_config(self):
        """Test creating scan config with minimal fields."""
        config = ScanConfig(
            target_url="https://api.example.com",
            swagger_path="/openapi.json"
        )
        assert config.target_url == "https://api.example.com"
        assert config.swagger_path == "/openapi.json"
        assert config.output_path == "sentinel_report.md"
        assert config.timeout == 5
        assert config.verbose is False

    def test_full_scan_config(self):
        """Test creating scan config with all fields."""
        config = ScanConfig(
            target_url="https://api.example.com",
            swagger_path="/openapi.json",
            output_path="/reports/scan.md",
            output_format=ReportFormat.HTML,
            attack_types=[AttackType.SQL_INJECTION, AttackType.XSS],
            timeout=10,
            verbose=True,
            max_endpoints=100,
            rate_limit_delay=1.0,
            llm_provider=LLMProvider.OPENAI,
            llm_api_key="test-key",
            follow_redirects=False,
            verify_ssl=False,
            custom_headers={"X-Custom": "value"},
            auth_token="Bearer token123"
        )
        assert config.output_format == ReportFormat.HTML
        assert len(config.attack_types) == 2
        assert config.llm_provider == LLMProvider.OPENAI
        assert config.auth_token == "Bearer token123"

    def test_default_attack_types(self):
        """Test default attack types includes all."""
        config = ScanConfig(
            target_url="https://api.example.com",
            swagger_path="/openapi.json"
        )
        # Default should be all attack types
        assert len(config.attack_types) == len(AttackType)


# ============================================================================
# SCAN RESULT TESTS
# ============================================================================

class TestScanResult:
    """Tests for ScanResult model."""

    def test_minimal_scan_result(self, sample_scan_config):
        """Test creating scan result with minimal fields."""
        result = ScanResult(config=sample_scan_config)
        assert result.config == sample_scan_config
        assert result.endpoints_tested == []
        assert result.vulnerabilities == []
        assert result.vulnerability_count == 0

    def test_vulnerability_count_property(self, sample_scan_config, sample_endpoint):
        """Test vulnerability_count computed property."""
        vuln = Vulnerability(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            payload="test",
            proof_of_concept="test",
            recommendation="test"
        )
        result = ScanResult(
            config=sample_scan_config,
            vulnerabilities=[vuln, vuln]
        )
        assert result.vulnerability_count == 2

    def test_severity_count_properties(self, sample_scan_config, sample_endpoint):
        """Test severity count computed properties."""
        vulns = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                title="Critical", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="High", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XSS,
                severity=Severity.HIGH,
                title="High2", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XSS,
                severity=Severity.MEDIUM,
                title="Medium", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SSRF,
                severity=Severity.LOW,
                title="Low", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XXE,
                severity=Severity.INFO,
                title="Info", description="d", payload="p",
                proof_of_concept="poc", recommendation="r"
            ),
        ]
        result = ScanResult(config=sample_scan_config, vulnerabilities=vulns)
        
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1
        assert result.vulnerability_count == 6

    def test_scan_result_with_attack_results(self, sample_scan_config, sample_attack_results):
        """Test scan result with attack results."""
        result = ScanResult(
            config=sample_scan_config,
            attack_results=sample_attack_results,
            total_requests=10,
            duration_seconds=5.5
        )
        assert len(result.attack_results) == 3
        assert result.total_requests == 10
        assert result.duration_seconds == 5.5


# ============================================================================
# AI ATTACK DECISION TESTS
# ============================================================================

class TestAIAttackDecision:
    """Tests for AIAttackDecision model."""

    def test_minimal_decision(self, sample_endpoint):
        """Test creating AI decision with minimal fields."""
        decision = AIAttackDecision(
            endpoint=sample_endpoint,
            recommended_attacks=[AttackType.SQL_INJECTION],
            reasoning="Test reasoning"
        )
        assert decision.endpoint == sample_endpoint
        assert decision.recommended_attacks == [AttackType.SQL_INJECTION]
        assert decision.priority == 1
        assert decision.confidence == 1.0

    def test_full_decision(self, sample_endpoint):
        """Test creating AI decision with all fields."""
        decision = AIAttackDecision(
            endpoint=sample_endpoint,
            recommended_attacks=[AttackType.SQL_INJECTION, AttackType.IDOR],
            reasoning="Endpoint has ID parameter in path",
            priority=2,
            parameters_to_test=["id", "user_id"],
            confidence=0.85
        )
        assert len(decision.recommended_attacks) == 2
        assert decision.priority == 2
        assert decision.parameters_to_test == ["id", "user_id"]
        assert decision.confidence == 0.85


# ============================================================================
# ATTACK-SPECIFIC RESULT TESTS
# ============================================================================

class TestSQLInjectionResult:
    """Tests for SQLInjectionResult model."""

    def test_minimal_sqli_result(self):
        """Test minimal SQL injection result."""
        result = SQLInjectionResult(injection_type="error-based")
        assert result.injection_type == "error-based"
        assert result.database_type is None
        assert result.extractable_data is None

    def test_full_sqli_result(self):
        """Test full SQL injection result."""
        result = SQLInjectionResult(
            injection_type="union-based",
            database_type="postgresql",
            extractable_data="users table: id, username, password"
        )
        assert result.injection_type == "union-based"
        assert result.database_type == "postgresql"


class TestXSSResult:
    """Tests for XSSResult model."""

    def test_minimal_xss_result(self):
        """Test minimal XSS result."""
        result = XSSResult(xss_type="reflected", context="html")
        assert result.xss_type == "reflected"
        assert result.context == "html"
        assert result.bypass_technique is None

    def test_full_xss_result(self):
        """Test full XSS result."""
        result = XSSResult(
            xss_type="stored",
            context="script",
            bypass_technique="HTML entity encoding bypass"
        )
        assert result.xss_type == "stored"
        assert result.bypass_technique is not None


class TestSSRFResult:
    """Tests for SSRFResult model."""

    def test_minimal_ssrf_result(self):
        """Test minimal SSRF result."""
        result = SSRFResult(ssrf_type="basic")
        assert result.ssrf_type == "basic"
        assert result.reachable_host is None
        assert result.protocol is None

    def test_full_ssrf_result(self):
        """Test full SSRF result."""
        result = SSRFResult(
            ssrf_type="blind",
            reachable_host="169.254.169.254",
            protocol="http"
        )
        assert result.ssrf_type == "blind"
        assert result.reachable_host == "169.254.169.254"


class TestJWTResult:
    """Tests for JWTResult model."""

    def test_minimal_jwt_result(self):
        """Test minimal JWT result."""
        result = JWTResult(vulnerability_type="none-alg")
        assert result.vulnerability_type == "none-alg"
        assert result.token_header is None
        assert result.token_payload is None

    def test_full_jwt_result(self):
        """Test full JWT result."""
        result = JWTResult(
            vulnerability_type="weak-secret",
            token_header={"alg": "HS256", "typ": "JWT"},
            token_payload={"sub": "admin", "role": "administrator"}
        )
        assert result.vulnerability_type == "weak-secret"
        assert result.token_header["alg"] == "HS256"


class TestRateLimitResult:
    """Tests for RateLimitResult model."""

    def test_minimal_rate_limit_result(self):
        """Test minimal rate limit result."""
        result = RateLimitResult()
        assert result.requests_made == 0
        assert result.time_window_seconds == 0.0
        assert result.blocked_after is None
        assert result.bypass_found is False

    def test_full_rate_limit_result(self):
        """Test full rate limit result."""
        result = RateLimitResult(
            requests_made=100,
            time_window_seconds=60.0,
            blocked_after=50,
            bypass_found=True
        )
        assert result.requests_made == 100
        assert result.blocked_after == 50
        assert result.bypass_found is True


# ============================================================================
# MODEL SERIALIZATION TESTS
# ============================================================================

class TestModelSerialization:
    """Tests for model serialization and deserialization."""

    def test_endpoint_json_serialization(self, sample_endpoint):
        """Test endpoint can be serialized to JSON."""
        json_str = sample_endpoint.model_dump_json()
        assert isinstance(json_str, str)
        assert "/api/users" in json_str

    def test_endpoint_json_deserialization(self, sample_endpoint):
        """Test endpoint can be deserialized from JSON."""
        json_str = sample_endpoint.model_dump_json()
        endpoint = Endpoint.model_validate_json(json_str)
        assert endpoint.path == sample_endpoint.path
        assert endpoint.method == sample_endpoint.method

    def test_attack_result_serialization(self, sample_attack_result):
        """Test attack result serialization."""
        data = sample_attack_result.model_dump()
        assert "endpoint" in data
        assert "attack_type" in data
        assert data["success"] is True

    def test_vulnerability_serialization(self, sample_vulnerability):
        """Test vulnerability serialization."""
        data = sample_vulnerability.model_dump()
        assert "title" in data
        assert "severity" in data
        assert data["severity"] == Severity.HIGH


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_parameter_list(self):
        """Test endpoint with empty parameter list."""
        endpoint = Endpoint(
            path="/health",
            method=HttpMethod.GET,
            parameters=[]
        )
        assert endpoint.parameters == []

    def test_very_long_path(self):
        """Test endpoint with very long path."""
        long_path = "/api/v1/users/" + "/".join(["sub"] * 100)
        endpoint = Endpoint(path=long_path, method=HttpMethod.GET)
        assert endpoint.path == long_path

    def test_special_characters_in_path(self):
        """Test endpoint with special characters in path."""
        endpoint = Endpoint(
            path="/api/users/{id}/files/{filename}",
            method=HttpMethod.GET
        )
        assert "{" in endpoint.path and "}" in endpoint.path

    def test_confidence_range(self, sample_endpoint):
        """Test confidence can be decimal between 0 and 1."""
        decision = AIAttackDecision(
            endpoint=sample_endpoint,
            recommended_attacks=[AttackType.SQL_INJECTION],
            reasoning="Test",
            confidence=0.75
        )
        assert 0 <= decision.confidence <= 1

    def test_cvss_score_range(self, sample_endpoint):
        """Test CVSS score can be decimal."""
        vuln = Vulnerability(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="Test",
            description="Test",
            payload="test",
            proof_of_concept="test",
            recommendation="test",
            cvss_score=9.8
        )
        assert 0 <= vuln.cvss_score <= 10
