"""
Comprehensive tests for JSON Reporter module.

Tests cover:
- JSON report generation
- SARIF report generation
- JUnit report generation
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    ScanConfig, ScanResult, AttackResult, Vulnerability
)
from sentinel.json_reporter import (
    JSONReporter, SARIFReporter, JUnitReporter,
    generate_json_report, generate_sarif_report, generate_junit_report
)


# ============================================================================
# JSON REPORTER TESTS
# ============================================================================

class TestJSONReporter:
    """Tests for JSONReporter."""

    @pytest.fixture
    def reporter(self, temp_dir):
        """Create a reporter instance."""
        output_path = temp_dir / "report.json"
        return JSONReporter(str(output_path))

    @pytest.fixture
    def sample_scan_result(self, sample_scan_config, sample_endpoints, sample_attack_results, sample_endpoint):
        """Create a sample scan result with vulnerabilities."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                title="SQL Injection",
                description="SQL injection vulnerability",
                payload="' OR '1'='1",
                proof_of_concept="curl -X POST ...",
                recommendation="Use parameterized queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                cvss_score=9.8
            ),
        ]
        
        return ScanResult(
            config=sample_scan_config,
            endpoints_tested=sample_endpoints,
            attack_results=sample_attack_results,
            vulnerabilities=vulnerabilities,
            total_requests=100,
            duration_seconds=15.5,
            ai_decisions=[{"endpoint": "/users", "attacks": ["sql_injection"]}]
        )

    def test_generate_returns_dict(self, reporter, sample_scan_result):
        """Test generate returns a dictionary."""
        report = reporter.generate(sample_scan_result)
        
        assert isinstance(report, dict)
        assert "version" in report
        assert "scan_info" in report
        assert "summary" in report

    def test_generate_includes_target(self, reporter, sample_scan_result):
        """Test report includes target URL."""
        report = reporter.generate(sample_scan_result)
        
        assert report["scan_info"]["target"] == "https://api.example.com"

    def test_generate_includes_summary(self, reporter, sample_scan_result):
        """Test report includes summary."""
        report = reporter.generate(sample_scan_result)
        
        assert "summary" in report
        assert "vulnerabilities_found" in report["summary"]
        assert "by_severity" in report["summary"]

    def test_generate_includes_endpoints(self, reporter, sample_scan_result):
        """Test report includes endpoints."""
        report = reporter.generate(sample_scan_result)
        
        assert "endpoints" in report
        assert len(report["endpoints"]) > 0

    def test_generate_includes_vulnerabilities(self, reporter, sample_scan_result):
        """Test report includes vulnerabilities."""
        report = reporter.generate(sample_scan_result)
        
        assert "vulnerabilities" in report
        assert len(report["vulnerabilities"]) > 0

    def test_generate_includes_ai_decisions(self, reporter, sample_scan_result):
        """Test report includes AI decisions."""
        report = reporter.generate(sample_scan_result)
        
        assert "ai_decisions" in report

    def test_generate_empty_result(self, reporter, sample_scan_config):
        """Test generating report with empty result."""
        empty_result = ScanResult(config=sample_scan_config)
        
        report = reporter.generate(empty_result)
        
        assert report["summary"]["vulnerabilities_found"] == 0

    def test_save_creates_file(self, reporter, sample_scan_result, temp_dir):
        """Test save creates output file."""
        output_path = temp_dir / "saved_report.json"
        reporter.output_path = output_path
        
        saved_path = reporter.save(sample_scan_result)
        
        assert Path(saved_path).exists()
        
        # Verify JSON is valid
        with open(saved_path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_count_by_attack_type(self, reporter, sample_endpoint):
        """Test counting by attack type."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQLi 1",
                description="desc",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQLi 2",
                description="desc",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XSS,
                severity=Severity.HIGH,
                title="XSS",
                description="desc",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            )
        ]
        
        counts = reporter._count_by_attack_type(vulnerabilities)
        
        assert counts["sql_injection"] == 2
        assert counts["xss"] == 1

    def test_vulnerability_to_dict(self, reporter, sample_endpoint):
        """Test converting vulnerability to dict."""
        vuln = Vulnerability(
            endpoint=sample_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Test description",
            payload="' OR '1'='1",
            proof_of_concept="poc",
            recommendation="fix it",
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            cvss_score=9.8,
            references=["https://owasp.org"]
        )
        
        result = reporter._vulnerability_to_dict(vuln, 1)
        
        assert result["id"] == "SEN-001"
        assert result["title"] == "SQL Injection"
        assert result["severity"] == "high"


# ============================================================================
# SARIF REPORTER TESTS
# ============================================================================

class TestSARIFReporter:
    """Tests for SARIFReporter."""

    @pytest.fixture
    def reporter(self, temp_dir):
        """Create a reporter instance."""
        output_path = temp_dir / "report.sarif"
        return SARIFReporter(str(output_path))

    @pytest.fixture
    def sample_scan_result(self, sample_scan_config, sample_endpoint):
        """Create a sample scan result."""
        return ScanResult(
            config=sample_scan_config,
            endpoints_tested=[sample_endpoint],
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="SQL Injection",
                    description="SQL injection vulnerability",
                    payload="' OR '1'='1",
                    proof_of_concept="curl -X POST ...",
                    recommendation="Use parameterized queries",
                    cwe_id="CWE-89"
                )
            ],
            total_requests=50,
            duration_seconds=10.0
        )

    def test_generate_returns_dict(self, reporter, sample_scan_result):
        """Test generate returns a dictionary."""
        report = reporter.generate(sample_scan_result)
        
        assert isinstance(report, dict)
        assert "$schema" in report
        assert "version" in report
        assert "runs" in report

    def test_generate_includes_tool_info(self, reporter, sample_scan_result):
        """Test report includes tool info."""
        report = reporter.generate(sample_scan_result)
        
        assert report["runs"][0]["tool"]["driver"]["name"] == "Sentinel"

    def test_generate_includes_results(self, reporter, sample_scan_result):
        """Test report includes results."""
        report = reporter.generate(sample_scan_result)
        
        assert "results" in report["runs"][0]

    def test_save_creates_file(self, reporter, sample_scan_result, temp_dir):
        """Test save creates output file."""
        output_path = temp_dir / "saved.sarif"
        reporter.output_path = output_path
        
        saved_path = reporter.save(sample_scan_result)
        
        assert Path(saved_path).exists()

    def test_get_rule_id(self, reporter):
        """Test getting rule ID."""
        rule_id = reporter._get_rule_id(AttackType.SQL_INJECTION)
        
        assert "SQL_INJECTION" in rule_id

    def test_get_rule_name(self, reporter):
        """Test getting rule name."""
        name = reporter._get_rule_name(AttackType.SQL_INJECTION)
        
        assert "SQL Injection" in name

    def test_severity_to_sarif_level(self, reporter):
        """Test severity to SARIF level mapping."""
        assert reporter._severity_to_sarif_level(Severity.CRITICAL) == "error"
        assert reporter._severity_to_sarif_level(Severity.HIGH) == "error"
        assert reporter._severity_to_sarif_level(Severity.MEDIUM) == "warning"
        assert reporter._severity_to_sarif_level(Severity.LOW) == "note"

    def test_generate_rules(self, reporter, sample_endpoint):
        """Test generating rules."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQLi",
                description="desc",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            )
        ]
        
        rules = reporter._generate_rules(vulnerabilities)
        
        assert len(rules) > 0

    def test_generate_results(self, reporter, sample_endpoint):
        """Test generating results."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQLi",
                description="desc",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            )
        ]
        
        results = reporter._generate_results(vulnerabilities)
        
        assert len(results) > 0


# ============================================================================
# JUNIT REPORTER TESTS
# ============================================================================

class TestJUnitReporter:
    """Tests for JUnitReporter."""

    @pytest.fixture
    def reporter(self, temp_dir):
        """Create a reporter instance."""
        output_path = temp_dir / "report.xml"
        return JUnitReporter(str(output_path))

    @pytest.fixture
    def sample_scan_result(self, sample_scan_config, sample_endpoint):
        """Create a sample scan result."""
        return ScanResult(
            config=sample_scan_config,
            endpoints_tested=[sample_endpoint],
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="SQL Injection",
                    description="SQL injection vulnerability",
                    payload="' OR '1'='1",
                    proof_of_concept="curl -X POST ...",
                    recommendation="Use parameterized queries"
                )
            ],
            total_requests=50,
            duration_seconds=10.0
        )

    def test_generate_returns_string(self, reporter, sample_scan_result):
        """Test generate returns a string."""
        report = reporter.generate(sample_scan_result)
        
        assert isinstance(report, str)
        assert "<?xml" in report

    def test_generate_includes_testsuite(self, reporter, sample_scan_result):
        """Test report includes testsuite."""
        report = reporter.generate(sample_scan_result)
        
        assert "<testsuite" in report
        assert "</testsuite>" in report

    def test_generate_includes_testcases(self, reporter, sample_scan_result):
        """Test report includes testcases."""
        report = reporter.generate(sample_scan_result)
        
        assert "<testcase" in report

    def test_save_creates_file(self, reporter, sample_scan_result, temp_dir):
        """Test save creates output file."""
        output_path = temp_dir / "saved.xml"
        reporter.output_path = output_path
        
        saved_path = reporter.save(sample_scan_result)
        
        assert Path(saved_path).exists()

    def test_escape_xml(self, reporter):
        """Test XML escaping."""
        text = '<script>alert("XSS")</script>'
        
        escaped = reporter._escape_xml(text)
        
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped

    def test_empty_vulnerabilities(self, reporter, sample_scan_config):
        """Test with no vulnerabilities."""
        result = ScanResult(
            config=sample_scan_config,
            endpoints_tested=[
                Endpoint(path="/users", method=HttpMethod.GET)
            ]
        )
        
        report = reporter.generate(result)
        
        assert "tests=" in report
        assert "failures=\"0\"" in report


# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_generate_json_report(self, sample_scan_config, temp_dir):
        """Test generate_json_report function."""
        result = ScanResult(config=sample_scan_config)
        output_path = temp_dir / "convenience.json"
        
        report = generate_json_report(result, str(output_path))
        
        assert isinstance(report, str)
        assert Path(report).exists()

    def test_generate_sarif_report(self, sample_scan_config, temp_dir):
        """Test generate_sarif_report function."""
        result = ScanResult(config=sample_scan_config)
        output_path = temp_dir / "convenience.sarif"
        
        report = generate_sarif_report(result, str(output_path))
        
        assert isinstance(report, str)
        assert Path(report).exists()

    def test_generate_junit_report(self, sample_scan_config, temp_dir):
        """Test generate_junit_report function."""
        result = ScanResult(
            config=sample_scan_config,
            endpoints_tested=[Endpoint(path="/test", method=HttpMethod.GET)]
        )
        output_path = temp_dir / "convenience.xml"
        
        report = generate_junit_report(result, str(output_path))
        
        assert isinstance(report, str)
        assert Path(report).exists()
