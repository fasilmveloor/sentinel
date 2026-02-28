"""
Unit tests for Passive Scanner module.

Tests cover:
- Security header detection
- Sensitive data pattern matching
- Version disclosure detection
- CORS misconfiguration detection
- Cookie security checks
- Error message detection
- False positive filtering
"""

import pytest
from unittest.mock import patch

from sentinel.passive import (
    PassiveScanner, PassiveFinding, PassiveFindingType, create_passive_scanner
)
from sentinel.models import Severity


# ============================================================================
# PASSIVE SCANNER INITIALIZATION TESTS
# ============================================================================

class TestPassiveScannerInit:
    """Tests for PassiveScanner initialization."""

    def test_init(self):
        """Test scanner initialization."""
        scanner = PassiveScanner()
        assert scanner.findings == []

    def test_create_passive_scanner(self):
        """Test create_passive_scanner factory function."""
        scanner = create_passive_scanner()
        assert isinstance(scanner, PassiveScanner)


# ============================================================================
# SECURITY HEADER CHECKS TESTS
# ============================================================================

class TestSecurityHeaderChecks:
    """Tests for security header detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_missing_x_content_type_options(self, scanner):
        """Test detection of missing X-Content-Type-Options header."""
        findings = scanner.analyze_response(
            url="https://example.com/api",
            method="GET",
            request_headers={},
            response_headers={},
            response_body="{}",
            status_code=200
        )
        
        finding = next(
            (f for f in findings if "X-Content-Type-Options" in f.title),
            None
        )
        assert finding is not None
        assert finding.finding_type == PassiveFindingType.MISSING_SECURITY_HEADER

    def test_detect_missing_hsts(self, scanner):
        """Test detection of missing HSTS header."""
        findings = scanner.analyze_response(
            url="https://example.com",
            method="GET",
            request_headers={},
            response_headers={"Content-Type": "application/json"},
            response_body="{}",
            status_code=200
        )
        
        finding = next(
            (f for f in findings if "Strict-Transport-Security" in f.title),
            None
        )
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_detect_missing_csp(self, scanner):
        """Test detection of missing Content-Security-Policy header."""
        findings = scanner.analyze_response(
            url="https://example.com",
            method="GET",
            request_headers={},
            response_headers={},
            response_body="{}",
            status_code=200
        )
        
        finding = next(
            (f for f in findings if "Content-Security-Policy" in f.title),
            None
        )
        assert finding is not None

    def test_all_headers_present_no_findings(self, scanner):
        """Test no findings when all security headers present."""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()"
        }
        
        findings = scanner._check_security_headers(headers, "https://example.com")
        
        # Should not find any missing security headers
        assert len(findings) == 0

    def test_header_case_insensitive(self, scanner):
        """Test header detection is case insensitive."""
        headers = {
            "x-content-type-options": "nosniff",  # lowercase
            "X-FRAME-OPTIONS": "DENY",  # mixed case
        }
        
        findings = scanner._check_security_headers(headers, "https://example.com")
        
        # Should not find these as missing
        xcto_finding = next(
            (f for f in findings if "X-Content-Type-Options" in f.title),
            None
        )
        xfo_finding = next(
            (f for f in findings if "X-Frame-Options" in f.title),
            None
        )
        
        assert xcto_finding is None
        assert xfo_finding is None


# ============================================================================
# SENSITIVE DATA DETECTION TESTS
# ============================================================================

class TestSensitiveDataDetection:
    """Tests for sensitive data pattern matching."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_api_key(self, scanner):
        """Test detection of API key in response."""
        body = '{"config": {"api_key": "sk-1234567890abcdefghijklmnop"}}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        api_key_finding = next(
            (f for f in findings if "API Key" in f.title),
            None
        )
        assert api_key_finding is not None
        assert api_key_finding.severity == Severity.HIGH

    def test_detect_password(self, scanner):
        """Test detection of password in response."""
        body = '{"user": {"password": "supersecret123"}}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        pwd_finding = next(
            (f for f in findings if "Password" in f.title),
            None
        )
        assert pwd_finding is not None
        assert pwd_finding.severity == Severity.CRITICAL

    def test_detect_aws_key(self, scanner):
        """Test detection of AWS access key."""
        # Use a realistic AWS key that doesn't contain 'example' (filtered as false positive)
        body = '{"aws_key": "AKIAIOSFODNN7REALKEY"}'  # Contains no 'example' substring
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        aws_finding = next(
            (f for f in findings if "AWS" in f.title),
            None
        )
        assert aws_finding is not None
        assert aws_finding.severity == Severity.CRITICAL

    def test_detect_jwt_token(self, scanner):
        """Test detection of JWT token."""
        body = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        jwt_finding = next(
            (f for f in findings if "JWT" in f.title),
            None
        )
        assert jwt_finding is not None

    def test_detect_private_key(self, scanner):
        """Test detection of private key."""
        body = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        key_finding = next(
            (f for f in findings if "Private Key" in f.title),
            None
        )
        assert key_finding is not None
        assert key_finding.severity == Severity.CRITICAL

    def test_detect_credit_card(self, scanner):
        """Test detection of credit card number."""
        body = '{"card_number": "4532015112830366"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        cc_finding = next(
            (f for f in findings if "Credit Card" in f.title),
            None
        )
        assert cc_finding is not None
        assert cc_finding.severity == Severity.CRITICAL

    def test_detect_internal_ip(self, scanner):
        """Test detection of internal IP address."""
        body = '{"server": "192.168.1.100", "internal": "10.0.0.1"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        ip_finding = next(
            (f for f in findings if "Internal IP" in f.title),
            None
        )
        assert ip_finding is not None

    def test_detect_email(self, scanner):
        """Test detection of email address (PII)."""
        # Use an email that doesn't contain 'example', 'test', 'sample', etc.
        body = '{"contact": "admin@mycompany.org"}'
        
        findings = scanner._check_sensitive_data(body, "https://api.mysite.com")
        
        email_finding = next(
            (f for f in findings if "Email" in f.title),
            None
        )
        assert email_finding is not None
        assert email_finding.severity == Severity.LOW


# ============================================================================
# FALSE POSITIVE FILTERING TESTS
# ============================================================================

class TestFalsePositiveFiltering:
    """Tests for false positive filtering."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_filter_placeholder_api_key(self, scanner):
        """Test placeholder API keys are filtered."""
        body = '{"api_key": "your_key_here"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        api_key_finding = next(
            (f for f in findings if "API Key" in f.title),
            None
        )
        # Should be filtered as false positive
        assert api_key_finding is None

    def test_filter_placeholder_password(self, scanner):
        """Test placeholder passwords are filtered."""
        body = '{"password": "changeme"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        pwd_finding = next(
            (f for f in findings if "Password" in f.title),
            None
        )
        # Should be filtered
        assert pwd_finding is None

    def test_filter_test_values(self, scanner):
        """Test test/dummy values are filtered."""
        body = '{"api_key": "test_key_for_demo"}'
        
        matches = [("api_key", "test_key_for_demo")]
        filtered = scanner._filter_false_positives(matches, "API Key")
        
        assert len(filtered) == 0

    def test_real_value_not_filtered(self, scanner):
        """Test real values are not filtered."""
        body = '{"api_key": "sk-abc123def456ghi789jkl"}'
        
        findings = scanner._check_sensitive_data(body, "https://example.com")
        
        api_key_finding = next(
            (f for f in findings if "API Key" in f.title),
            None
        )
        # Should NOT be filtered
        assert api_key_finding is not None


# ============================================================================
# VERSION DISCLOSURE TESTS
# ============================================================================

class TestVersionDisclosure:
    """Tests for version disclosure detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_server_version(self, scanner):
        """Test detection of server version disclosure."""
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        
        findings = scanner._check_version_disclosure(headers, "https://example.com")
        
        assert len(findings) > 0
        assert findings[0].finding_type == PassiveFindingType.VERSION_DISCLOSURE
        # Title is 'Server Version Disclosure', evidence contains the server info
        assert "Version Disclosure" in findings[0].title
        assert "Apache" in findings[0].evidence

    def test_detect_x_powered_by(self, scanner):
        """Test detection of X-Powered-By header."""
        headers = {
            "X-Powered-By": "PHP/7.4.3"
        }
        
        findings = scanner._check_version_disclosure(headers, "https://example.com")
        
        assert len(findings) > 0
        assert "Version Disclosure" in findings[0].title

    def test_no_version_disclosure(self, scanner):
        """Test no findings when version not disclosed."""
        headers = {
            "Server": "nginx",  # No version
            "Content-Type": "application/json"
        }
        
        findings = scanner._check_version_disclosure(headers, "https://example.com")
        
        # Should not detect version disclosure
        version_findings = [f for f in findings if f.finding_type == PassiveFindingType.VERSION_DISCLOSURE]
        assert len(version_findings) == 0


# ============================================================================
# FRAMEWORK DETECTION TESTS
# ============================================================================

class TestFrameworkDetection:
    """Tests for framework fingerprinting."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_laravel(self, scanner):
        """Test detection of Laravel framework."""
        headers = {"Set-Cookie": "laravel_session=abc123"}
        body = ""
        
        findings = scanner._check_framework_disclosure(headers, body, "https://example.com")
        
        laravel_finding = next(
            (f for f in findings if "Laravel" in f.title),
            None
        )
        assert laravel_finding is not None

    def test_detect_php(self, scanner):
        """Test detection of PHP framework."""
        headers = {"Set-Cookie": "PHPSESSID=xyz789"}
        body = ""
        
        findings = scanner._check_framework_disclosure(headers, body, "https://example.com")
        
        php_finding = next(
            (f for f in findings if "PHP" in f.title),
            None
        )
        assert php_finding is not None

    def test_detect_django(self, scanner):
        """Test detection of Django framework."""
        headers = {"Set-Cookie": "csrftoken=abc123"}
        body = ""
        
        findings = scanner._check_framework_disclosure(headers, body, "https://example.com")
        
        django_finding = next(
            (f for f in findings if "Django" in f.title),
            None
        )
        assert django_finding is not None

    def test_detect_express(self, scanner):
        """Test detection of Express.js framework."""
        headers = {}
        body = "connect.sid=s%3A123"
        
        findings = scanner._check_framework_disclosure(headers, body, "https://example.com")
        
        express_finding = next(
            (f for f in findings if "Express" in f.title),
            None
        )
        assert express_finding is not None


# ============================================================================
# ERROR MESSAGE DETECTION TESTS
# ============================================================================

class TestErrorDetection:
    """Tests for error message detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_mysql_error(self, scanner):
        """Test detection of MySQL error message."""
        # Pattern requires 'SQL syntax.*?MySQL'
        body = '{"error": "SQL syntax error MySQL server"}'
        
        findings = scanner._check_error_messages(body, "https://example.com")
        
        mysql_finding = next(
            (f for f in findings if "MySQL" in f.title),
            None
        )
        assert mysql_finding is not None
        assert mysql_finding.severity == Severity.MEDIUM

    def test_detect_stack_trace(self, scanner):
        """Test detection of stack trace."""
        # Pattern matches 'StackTrace|Stack trace|at [a-zA-Z0-9.]+\([a-zA-Z0-9.]+:\d+\)'
        body = '''
        Error: Cannot read property 'id' of undefined
            StackTrace:
            at UserController.getUser(app.js:45)
        '''
        
        findings = scanner._check_error_messages(body, "https://example.com")
        
        stack_finding = next(
            (f for f in findings if "Stack Trace" in f.title),
            None
        )
        assert stack_finding is not None

    def test_detect_debug_mode(self, scanner):
        """Test detection of debug mode enabled."""
        body = '{"debug": true, "debug_mode": "enabled"}'
        
        findings = scanner._check_error_messages(body, "https://example.com")
        
        debug_finding = next(
            (f for f in findings if "Debug" in f.title),
            None
        )
        assert debug_finding is not None

    def test_no_error_in_normal_response(self, scanner):
        """Test no findings for normal response."""
        body = '{"status": "success", "data": {"id": 1, "name": "Test"}}'
        
        findings = scanner._check_error_messages(body, "https://example.com")
        
        assert len(findings) == 0


# ============================================================================
# CORS MISCONFIGURATION TESTS
# ============================================================================

class TestCORSDetection:
    """Tests for CORS misconfiguration detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_wildcard_cors(self, scanner):
        """Test detection of wildcard CORS origin."""
        headers = {
            "Access-Control-Allow-Origin": "*"
        }
        
        findings = scanner._check_cors(headers, "https://example.com")
        
        cors_finding = next(
            (f for f in findings if "CORS" in f.title),
            None
        )
        assert cors_finding is not None
        assert cors_finding.severity == Severity.MEDIUM

    def test_detect_dangerous_cors_with_credentials(self, scanner):
        """Test detection of CORS wildcard with credentials."""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        
        findings = scanner._check_cors(headers, "https://example.com")
        
        dangerous_finding = next(
            (f for f in findings if "Dangerous" in f.title),
            None
        )
        assert dangerous_finding is not None
        assert dangerous_finding.severity == Severity.HIGH

    def test_no_cors_findings_with_proper_config(self, scanner):
        """Test no findings with proper CORS configuration."""
        headers = {
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Credentials": "true"
        }
        
        findings = scanner._check_cors(headers, "https://example.com")
        
        # Should not find wildcard CORS
        wildcard_finding = next(
            (f for f in findings if "*" in f.evidence),
            None
        )
        assert wildcard_finding is None


# ============================================================================
# COOKIE SECURITY TESTS
# ============================================================================

class TestCookieSecurity:
    """Tests for cookie security detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_missing_secure_flag(self, scanner):
        """Test detection of missing Secure flag."""
        headers = {
            "Set-Cookie": "session=abc123; Path=/"
        }
        
        findings = scanner._check_cookies(headers, "https://example.com")
        
        secure_finding = next(
            (f for f in findings if "Secure" in f.title),
            None
        )
        assert secure_finding is not None
        assert secure_finding.severity == Severity.MEDIUM

    def test_detect_missing_httponly_flag(self, scanner):
        """Test detection of missing HttpOnly flag."""
        headers = {
            "Set-Cookie": "session=abc123; Secure"
        }
        
        findings = scanner._check_cookies(headers, "https://example.com")
        
        httponly_finding = next(
            (f for f in findings if "HttpOnly" in f.title),
            None
        )
        assert httponly_finding is not None

    def test_detect_missing_samesite(self, scanner):
        """Test detection of missing SameSite attribute."""
        headers = {
            "Set-Cookie": "session=abc123; Secure; HttpOnly"
        }
        
        findings = scanner._check_cookies(headers, "https://example.com")
        
        samesite_finding = next(
            (f for f in findings if "SameSite" in f.title),
            None
        )
        assert samesite_finding is not None

    def test_secure_cookie_no_findings(self, scanner):
        """Test no findings for properly secured cookie."""
        headers = {
            "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"
        }
        
        findings = scanner._check_cookies(headers, "https://example.com")
        
        # Should not find any cookie security issues
        assert len(findings) == 0


# ============================================================================
# CACHE CONTROL TESTS
# ============================================================================

class TestCacheControl:
    """Tests for cache control detection."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_detect_missing_cache_control(self, scanner):
        """Test detection of missing Cache-Control header."""
        headers = {}
        
        findings = scanner._check_cache_control(headers, "https://example.com")
        
        assert len(findings) > 0
        assert findings[0].finding_type == PassiveFindingType.CACHE_CONTROL

    def test_proper_cache_control_no_findings(self, scanner):
        """Test no findings with proper cache control."""
        headers = {
            "Cache-Control": "no-store, no-cache, private"
        }
        
        findings = scanner._check_cache_control(headers, "https://example.com")
        
        assert len(findings) == 0


# ============================================================================
# REQUEST ANALYSIS TESTS
# ============================================================================

class TestRequestAnalysis:
    """Tests for request analysis."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_analyze_request_detects_url_params(self, scanner):
        """Test request analysis detects sensitive data in URL."""
        url = "https://example.com/api?api_key=sk-secret123456789012"
        
        findings = scanner.analyze_request(
            url=url,
            method="GET",
            headers={},
            body=None
        )
        
        # Should find API key in URL
        key_finding = next(
            (f for f in findings if "API Key" in f.title),
            None
        )
        assert key_finding is not None
        assert key_finding.location == "url"

    def test_analyze_request_detects_insecure_cookies(self, scanner):
        """Test request analysis detects cookies over HTTP."""
        findings = scanner.analyze_request(
            url="http://example.com/api",  # HTTP not HTTPS
            method="GET",
            headers={"Cookie": "session=abc123"},
            body=None
        )
        
        insecure_finding = next(
            (f for f in findings if "HTTP" in f.title),
            None
        )
        assert insecure_finding is not None
        assert insecure_finding.severity == Severity.MEDIUM


# ============================================================================
# FULL RESPONSE ANALYSIS TESTS
# ============================================================================

class TestFullResponseAnalysis:
    """Tests for complete response analysis."""

    @pytest.fixture
    def scanner(self):
        return PassiveScanner()

    def test_full_analysis_returns_findings(self, scanner):
        """Test full analysis returns multiple findings."""
        findings = scanner.analyze_response(
            url="https://example.com/api",
            method="GET",
            request_headers={},
            response_headers={
                "Server": "Apache/2.4.41",
                "Access-Control-Allow-Origin": "*"
            },
            response_body='{"api_key": "sk-test123456789"}',
            status_code=200
        )
        
        # Should have findings from multiple checks
        assert len(findings) > 0
        
        # Check we have different types of findings
        finding_types = {f.finding_type for f in findings}
        assert len(finding_types) > 1

    def test_full_analysis_clean_response(self, scanner):
        """Test analysis of clean response has minimal findings."""
        findings = scanner.analyze_response(
            url="https://example.com/api",
            method="GET",
            request_headers={},
            response_headers={
                "Content-Type": "application/json",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Cache-Control": "no-store, private"
            },
            response_body='{"status": "ok"}',
            status_code=200
        )
        
        # Should have minimal findings (mostly INFO level framework detection)
        critical_high = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_high) == 0


# ============================================================================
# PASSIVE FINDING TYPE TESTS
# ============================================================================

class TestPassiveFindingType:
    """Tests for PassiveFindingType enum."""

    def test_all_finding_types_exist(self):
        """Test all expected finding types exist."""
        expected_types = [
            'VERSION_DISCLOSURE', 'FRAMEWORK_DISCLOSURE', 'SERVER_HEADER',
            'DEBUG_INFO', 'STACK_TRACE', 'MISSING_SECURITY_HEADER',
            'INSECURE_HEADER', 'CORS_MISCONFIG', 'SENSITIVE_DATA_EXPOSURE',
            'CREDENTIAL_LEAK', 'TOKEN_EXPOSURE', 'PII_EXPOSURE',
            'WEAK_AUTH', 'SESSION_ISSUE', 'COOKIE_SECURITY',
            'EXCESSIVE_DATA', 'RATE_LIMIT_MISSING', 'CACHE_CONTROL',
            'ERROR_MESSAGE', 'INSECURE_LINK', 'MIXED_CONTENT'
        ]
        
        for type_name in expected_types:
            assert hasattr(PassiveFindingType, type_name), f"Missing {type_name}"


# ============================================================================
# PASSIVE FINDING DATA CLASS TESTS
# ============================================================================

class TestPassiveFinding:
    """Tests for PassiveFinding dataclass."""

    def test_create_passive_finding(self):
        """Test creating a passive finding."""
        finding = PassiveFinding(
            finding_type=PassiveFindingType.VERSION_DISCLOSURE,
            severity=Severity.LOW,
            title="Test Finding",
            description="Test description",
            evidence="Test evidence",
            location="header",
            remediation="Test remediation"
        )
        
        assert finding.finding_type == PassiveFindingType.VERSION_DISCLOSURE
        assert finding.severity == Severity.LOW
        assert finding.confidence == 0.8  # Default value

    def test_passive_finding_with_all_fields(self):
        """Test creating finding with all fields."""
        finding = PassiveFinding(
            finding_type=PassiveFindingType.CREDENTIAL_LEAK,
            severity=Severity.CRITICAL,
            title="Credential Leak",
            description="Credentials exposed in response",
            evidence="password=admin123",
            location="body",
            remediation="Remove credentials from response",
            confidence=0.95,
            cwe_id=798,
            owasp_category="A01:2021 - Broken Access Control"
        )
        
        assert finding.cwe_id == 798
        assert finding.owasp_category == "A01:2021 - Broken Access Control"
        assert finding.confidence == 0.95
