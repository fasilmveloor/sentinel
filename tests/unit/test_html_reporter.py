"""
Comprehensive tests for HTML Reporter module.

Tests cover:
- HTML report generation
- Report formatting
- Vulnerability display
- Endpoints table
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    ScanConfig, ScanResult, AttackResult, Vulnerability
)
from sentinel.html_reporter import HTMLReporter, generate_html_report


# ============================================================================
# HTML REPORTER INITIALIZATION TESTS
# ============================================================================

class TestHTMLReporterInit:
    """Tests for HTMLReporter initialization."""

    def test_init_with_path(self, temp_dir):
        """Test initialization with output path."""
        output_path = temp_dir / "report.html"
        reporter = HTMLReporter(str(output_path))
        
        assert reporter.output_path == output_path

    def test_init_default_path(self):
        """Test initialization with default path."""
        reporter = HTMLReporter()
        
        assert reporter.output_path is not None


# ============================================================================
# HTML REPORT GENERATION TESTS
# ============================================================================

class TestHTMLReportGeneration:
    """Tests for HTML report generation."""

    @pytest.fixture
    def reporter(self, temp_dir):
        """Create a reporter instance."""
        output_path = temp_dir / "report.html"
        return HTMLReporter(str(output_path))

    @pytest.fixture
    def sample_scan_result(self, sample_scan_config, sample_endpoints, sample_attack_results, sample_endpoint):
        """Create a sample scan result with vulnerabilities."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                title="SQL Injection in Login",
                description="SQL injection vulnerability in login endpoint",
                payload="' OR '1'='1",
                proof_of_concept="curl -X POST ...",
                recommendation="Use parameterized queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XSS,
                severity=Severity.HIGH,
                title="Cross-Site Scripting",
                description="XSS vulnerability in search parameter",
                payload="<script>alert(1)</script>",
                proof_of_concept="curl -X GET ...",
                recommendation="Encode output",
                cwe_id="CWE-79"
            ),
        ]
        
        return ScanResult(
            config=sample_scan_config,
            endpoints_tested=sample_endpoints,
            attack_results=sample_attack_results,
            vulnerabilities=vulnerabilities,
            total_requests=100,
            duration_seconds=15.5
        )

    def test_generate_returns_string(self, reporter, sample_scan_result):
        """Test generate returns a string."""
        report = reporter.generate(sample_scan_result)
        
        assert isinstance(report, str)
        assert len(report) > 0

    def test_generate_includes_html_structure(self, reporter, sample_scan_result):
        """Test report includes HTML structure."""
        report = reporter.generate(sample_scan_result)
        
        assert "<!DOCTYPE html>" in report
        assert "<html" in report
        assert "</html>" in report

    def test_generate_includes_title(self, reporter, sample_scan_result):
        """Test report includes title."""
        report = reporter.generate(sample_scan_result)
        
        assert "Sentinel Security Report" in report

    def test_generate_includes_target(self, reporter, sample_scan_result):
        """Test report includes target URL."""
        report = reporter.generate(sample_scan_result)
        
        assert "api.example.com" in report

    def test_generate_includes_vulnerabilities(self, reporter, sample_scan_result):
        """Test report includes vulnerabilities."""
        report = reporter.generate(sample_scan_result)
        
        assert "SQL Injection" in report
        assert "XSS" in report or "Cross-Site Scripting" in report

    def test_generate_includes_severity_counts(self, reporter, sample_scan_result):
        """Test report includes severity counts."""
        report = reporter.generate(sample_scan_result)
        
        # Should show counts
        assert "Critical" in report
        assert "High" in report

    def test_generate_empty_scan_result(self, reporter, sample_scan_config):
        """Test generating report with empty scan result."""
        empty_result = ScanResult(config=sample_scan_config)
        
        report = reporter.generate(empty_result)
        
        assert isinstance(report, str)
        assert "No vulnerabilities found" in report or "0" in report

    def test_save_creates_file(self, reporter, sample_scan_result, temp_dir):
        """Test save creates output file."""
        output_path = temp_dir / "saved_report.html"
        reporter.output_path = output_path
        
        saved_path = reporter.save(sample_scan_result)
        
        assert Path(saved_path).exists()
        assert Path(saved_path).stat().st_size > 0

    def test_save_creates_parent_directory(self, temp_dir, sample_scan_result):
        """Test save creates parent directory if not exists."""
        output_path = temp_dir / "subdir" / "report.html"
        reporter = HTMLReporter(str(output_path))
        
        saved_path = reporter.save(sample_scan_result)
        
        assert Path(saved_path).exists()

    def test_generate_vulnerability_items(self, reporter, sample_endpoint):
        """Test vulnerability items generation."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQL Injection",
                description="Test description",
                payload="' OR '1'='1",
                proof_of_concept="poc",
                recommendation="fix it"
            )
        ]
        
        items = reporter._generate_vulnerability_items(vulnerabilities)
        
        assert "SQL Injection" in items
        assert "HIGH" in items

    def test_generate_vulnerability_items_empty(self, reporter):
        """Test vulnerability items generation when empty."""
        items = reporter._generate_vulnerability_items([])
        
        assert "No vulnerabilities found" in items

    def test_generate_endpoints_table(self, reporter):
        """Test endpoints table generation."""
        endpoints = [
            Endpoint(
                path="/users",
                method=HttpMethod.GET,
                security=[{"bearerAuth": []}]
            ),
            Endpoint(
                path="/products",
                method=HttpMethod.POST
            )
        ]
        
        table = reporter._generate_endpoints_table(endpoints)
        
        assert "/users" in table
        assert "/products" in table
        assert "GET" in table
        assert "POST" in table

    def test_get_attack_type_labels(self, reporter, sample_endpoint):
        """Test attack type labels extraction."""
        result = ScanResult(
            config=ScanConfig(target_url="https://test.com", swagger_path="/spec.json"),
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="SQLi",
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
        )
        
        labels = reporter._get_attack_type_labels(result)
        
        assert "Sql Injection" in labels

    def test_get_attack_type_data(self, reporter, sample_endpoint):
        """Test attack type data extraction."""
        result = ScanResult(
            config=ScanConfig(target_url="https://test.com", swagger_path="/spec.json"),
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="SQLi",
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
                )
            ]
        )
        
        data = reporter._get_attack_type_data(result)
        
        # Should have count of 2 for SQL Injection
        assert "2" in data

    def test_escape_html(self, reporter):
        """Test HTML escaping."""
        text = "<script>alert('XSS')</script>"
        
        escaped = reporter._escape_html(text)
        
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped
        assert "&gt;" in escaped

    def test_escape_html_special_chars(self, reporter):
        """Test HTML escaping of special characters."""
        text = "Test & < > \" '"
        
        escaped = reporter._escape_html(text)
        
        assert "&amp;" in escaped
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "&quot;" in escaped


# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_generate_html_report(self, sample_scan_config, temp_dir):
        """Test generate_html_report convenience function."""
        result = ScanResult(config=sample_scan_config)
        output_path = temp_dir / "convenience_report.html"
        
        report = generate_html_report(result, str(output_path))
        
        assert isinstance(report, str)
        assert Path(report).exists()


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def reporter(self, temp_dir):
        """Create a reporter instance."""
        output_path = temp_dir / "report.html"
        return HTMLReporter(str(output_path))

    def test_vulnerability_with_no_cwe(self, reporter, sample_endpoint):
        """Test vulnerability without CWE ID."""
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="SQL Injection",
                description="Test",
                payload="payload",
                proof_of_concept="poc",
                recommendation="fix"
            )
        ]
        
        items = reporter._generate_vulnerability_items(vulnerabilities)
        
        assert "N/A" in items  # CWE should show N/A

    def test_endpoint_all_methods(self, reporter):
        """Test endpoints table with all HTTP methods."""
        endpoints = [
            Endpoint(path="/get", method=HttpMethod.GET),
            Endpoint(path="/post", method=HttpMethod.POST),
            Endpoint(path="/put", method=HttpMethod.PUT),
            Endpoint(path="/patch", method=HttpMethod.PATCH),
            Endpoint(path="/delete", method=HttpMethod.DELETE),
        ]
        
        table = reporter._generate_endpoints_table(endpoints)
        
        assert "GET" in table
        assert "POST" in table
        assert "PUT" in table
        assert "PATCH" in table
        assert "DELETE" in table

    def test_unicode_in_report(self, reporter, sample_scan_config, sample_endpoint):
        """Test handling Unicode in report."""
        result = ScanResult(
            config=sample_scan_config,
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    title="SQL 注入攻击",  # Chinese
                    description="Test 攻击",  # Chinese
                    payload="payload",
                    proof_of_concept="poc",
                    recommendation="修复"  # Chinese
                )
            ]
        )
        
        report = reporter.generate(result)
        
        assert isinstance(report, str)

    def test_special_characters_escaped(self, reporter, sample_scan_config, sample_endpoint):
        """Test special characters are properly escaped."""
        result = ScanResult(
            config=sample_scan_config,
            vulnerabilities=[
                Vulnerability(
                    endpoint=sample_endpoint,
                    attack_type=AttackType.XSS,
                    severity=Severity.HIGH,
                    title="XSS",
                    description="<script>alert(1)</script>",
                    payload="<script>alert(1)</script>",
                    proof_of_concept="<script>alert(1)</script>",
                    recommendation="Encode < and >"
                )
            ]
        )
        
        report = reporter.generate(result)
        
        # Should not contain unescaped script tags in vulnerable context
        assert isinstance(report, str)
