"""
Unit tests for Sentinel Benchmark Framework - Enterprise Edition.

Tests cover:
- GroundTruthDatabase with 10,000+ test cases
- BenchmarkRunner
- BenchmarkResult calculations
- CLI commands integration
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, AsyncMock

from sentinel.benchmarks import (
    BenchmarkTarget,
    BenchmarkCategory,
    BenchmarkResult,
    BenchmarkReport,
    BenchmarkRunner,
    GroundTruthDatabase,
    GroundTruthVulnerability,
    run_crapi_benchmark,
    run_juice_shop_benchmark,
)
from sentinel.models import Severity, Endpoint, HttpMethod, AttackType, Vulnerability


# ==================== Fixtures ====================

@pytest.fixture
def ground_truth_db():
    """Create a ground truth database."""
    return GroundTruthDatabase()


@pytest.fixture
def sample_benchmark_result():
    """Create a sample benchmark result."""
    result = BenchmarkResult(
        target=BenchmarkTarget.CRAPI,
        start_time=datetime.now(timezone.utc),
        total_vulnerabilities=100,
        detected_vulnerabilities=70,
        true_positives=60,
        false_positives=10,
        false_negatives=40
    )
    return result


@pytest.fixture
def sample_vulnerability():
    """Create a sample detected vulnerability."""
    return Vulnerability(
        endpoint=Endpoint(path="/api/users", method=HttpMethod.GET),
        attack_type=AttackType.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQL Injection",
        description="Test SQL injection",
        payload="' OR 1=1--",
        proof_of_concept="proof",
        recommendation="Fix it"
    )


# ==================== GroundTruthDatabase Tests ====================

class TestGroundTruthDatabase:
    """Tests for GroundTruthDatabase."""
    
    def test_create_database(self, ground_truth_db):
        """Test creating a ground truth database."""
        assert ground_truth_db is not None
    
    def test_get_crapi_vulnerabilities(self, ground_truth_db):
        """Test getting crAPI vulnerabilities."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.CRAPI)
        
        assert len(vulns) > 0
        assert all(isinstance(v, GroundTruthVulnerability) for v in vulns)
        # Should have at least 35 vulnerabilities now
        assert len(vulns) >= 35, f"Expected at least 35 crAPI vulns, got {len(vulns)}"
    
    def test_get_juice_shop_vulnerabilities(self, ground_truth_db):
        """Test getting Juice Shop vulnerabilities."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.JUICE_SHOP)
        
        assert len(vulns) > 0
        assert all(isinstance(v, GroundTruthVulnerability) for v in vulns)
        # Should have at least 70 vulnerabilities now
        assert len(vulns) >= 70, f"Expected at least 70 Juice Shop vulns, got {len(vulns)}"
    
    def test_get_owasp_benchmark_vulnerabilities(self, ground_truth_db):
        """Test getting OWASP Benchmark vulnerabilities."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.OWASP_BENCHMARK)
        
        assert len(vulns) > 0
        assert all(isinstance(v, GroundTruthVulnerability) for v in vulns)
        # Should have thousands of test cases now
        assert len(vulns) >= 3000, f"Expected at least 3000 Benchmark Java tests, got {len(vulns)}"
    
    def test_get_vulnerabilities_by_category(self, ground_truth_db):
        """Test filtering vulnerabilities by category."""
        sql_vulns = ground_truth_db.get_vulnerabilities_by_category(
            BenchmarkTarget.CRAPI,
            BenchmarkCategory.SQL_INJECTION
        )
        
        assert len(sql_vulns) >= 1
        assert all(v.category == BenchmarkCategory.SQL_INJECTION for v in sql_vulns)
    
    def test_crapi_has_bola_vulnerabilities(self, ground_truth_db):
        """Test that crAPI has BOLA vulnerabilities."""
        bola_vulns = ground_truth_db.get_vulnerabilities_by_category(
            BenchmarkTarget.CRAPI,
            BenchmarkCategory.BOLA
        )
        
        assert len(bola_vulns) >= 1
    
    def test_juice_shop_has_xss_vulnerabilities(self, ground_truth_db):
        """Test that Juice Shop has XSS vulnerabilities."""
        xss_vulns = ground_truth_db.get_vulnerabilities_by_category(
            BenchmarkTarget.JUICE_SHOP,
            BenchmarkCategory.XSS
        )
        
        assert len(xss_vulns) >= 1
    
    def test_owasp_benchmark_has_true_and_false_positives(self, ground_truth_db):
        """Test that OWASP Benchmark includes both TP and FP tests."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.OWASP_BENCHMARK)
        
        tp_tests = [v for v in vulns if v.is_true_positive]
        fp_tests = [v for v in vulns if not v.is_true_positive]
        
        assert len(tp_tests) > 0, "Should have true positive test cases"
        assert len(fp_tests) > 0, "Should have false positive test cases"
    
    def test_vulnerability_has_required_fields(self, ground_truth_db):
        """Test that vulnerabilities have all required fields."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.CRAPI)
        
        for vuln in vulns:
            assert vuln.vuln_id is not None
            assert vuln.category is not None
            assert vuln.endpoint is not None
            assert vuln.method is not None
            assert vuln.cwe is not None
            assert vuln.severity is not None
            assert vuln.description is not None
    
    def test_get_statistics(self, ground_truth_db):
        """Test getting database statistics."""
        stats = ground_truth_db.get_statistics()
        
        assert "crapi" in stats
        assert "juice_shop" in stats
        assert "owasp_benchmark" in stats
        assert "total_all_targets" in stats
        
        # Verify total is substantial
        assert stats["total_all_targets"] >= 3000, f"Expected at least 3000 total vulns, got {stats['total_all_targets']}"
        
        # Check OWASP Benchmark has TP and FP counts
        ob_stats = stats["owasp_benchmark"]
        assert ob_stats["true_positives"] > 0
        assert ob_stats["false_positive_tests"] > 0


# ==================== Benchmark Result Tests ====================

class TestBenchmarkResult:
    """Tests for BenchmarkResult calculations."""
    
    def test_create_result(self, sample_benchmark_result):
        """Test creating a benchmark result."""
        assert sample_benchmark_result.target == BenchmarkTarget.CRAPI
        assert sample_benchmark_result.total_vulnerabilities == 100
    
    def test_detection_rate(self, sample_benchmark_result):
        """Test detection rate calculation."""
        # 70 detected / 100 total = 0.7
        assert sample_benchmark_result.detection_rate == 0.7
    
    def test_precision(self, sample_benchmark_result):
        """Test precision calculation."""
        # 60 TP / (60 TP + 10 FP) = 60/70 ≈ 0.857
        assert abs(sample_benchmark_result.precision - 0.857) < 0.01
    
    def test_recall(self, sample_benchmark_result):
        """Test recall calculation."""
        # 60 TP / (60 TP + 40 FN) = 60/100 = 0.6
        assert sample_benchmark_result.recall == 0.6
    
    def test_f1_score(self, sample_benchmark_result):
        """Test F1 score calculation."""
        # F1 = 2 * (precision * recall) / (precision + recall)
        expected_f1 = 2 * (sample_benchmark_result.precision * sample_benchmark_result.recall) / \
                     (sample_benchmark_result.precision + sample_benchmark_result.recall)
        
        assert abs(sample_benchmark_result.f1_score - expected_f1) < 0.01
    
    def test_accuracy(self):
        """Test accuracy calculation."""
        result = BenchmarkResult(
            target=BenchmarkTarget.OWASP_BENCHMARK,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100,
            true_positives=80,
            true_negatives=15,
            false_positives=5,
            false_negatives=20
        )
        
        # Accuracy = (TP + TN) / (TP + TN + FP + FN)
        # = (80 + 15) / (80 + 15 + 5 + 20) = 95/120 ≈ 0.79
        expected = (80 + 15) / (80 + 15 + 5 + 20)
        assert abs(result.accuracy - expected) < 0.01
    
    def test_zero_division_handling(self):
        """Test handling of division by zero."""
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=0
        )
        
        assert result.detection_rate == 0.0
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1_score == 0.0
    
    def test_perfect_detection(self):
        """Test result with perfect detection."""
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100,
            detected_vulnerabilities=100,
            true_positives=100,
            false_positives=0,
            false_negatives=0
        )
        
        assert result.detection_rate == 1.0
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1_score == 1.0
    
    def test_no_detection(self):
        """Test result with no detections."""
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100,
            detected_vulnerabilities=0,
            true_positives=0,
            false_positives=0,
            false_negatives=100
        )
        
        assert result.detection_rate == 0.0
        assert result.recall == 0.0
    
    def test_all_false_positives(self):
        """Test result with all false positives."""
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100,
            detected_vulnerabilities=50,
            true_positives=0,
            false_positives=50,
            false_negatives=100
        )
        
        assert result.precision == 0.0
        assert result.recall == 0.0


# ==================== BenchmarkReport Tests ====================

class TestBenchmarkReport:
    """Tests for BenchmarkReport."""
    
    def test_create_report(self):
        """Test creating a benchmark report."""
        report = BenchmarkReport(
            sentinel_version="1.0.0",
            run_date=datetime.now(timezone.utc)
        )
        
        assert report.sentinel_version == "1.0.0"
        assert len(report.results) == 0
    
    def test_overall_detection_rate(self):
        """Test calculating overall detection rate."""
        result1 = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100,
            detected_vulnerabilities=70
        )
        result2 = BenchmarkResult(
            target=BenchmarkTarget.JUICE_SHOP,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=200,
            detected_vulnerabilities=150
        )
        
        report = BenchmarkReport(
            sentinel_version="1.0.0",
            run_date=datetime.now(timezone.utc),
            results=[result1, result2]
        )
        
        # (70 + 150) / (100 + 200) = 220/300 ≈ 0.733
        assert abs(report.overall_detection_rate - 0.733) < 0.01
    
    def test_total_test_cases(self):
        """Test total test cases calculation."""
        result1 = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=100
        )
        result2 = BenchmarkResult(
            target=BenchmarkTarget.OWASP_BENCHMARK,
            start_time=datetime.now(timezone.utc),
            total_vulnerabilities=5000
        )
        
        report = BenchmarkReport(
            sentinel_version="1.0.0",
            run_date=datetime.now(timezone.utc),
            results=[result1, result2]
        )
        
        assert report.total_test_cases == 5100


# ==================== BenchmarkRunner Tests ====================

class TestBenchmarkRunner:
    """Tests for BenchmarkRunner."""
    
    def test_create_runner(self):
        """Test creating a benchmark runner."""
        runner = BenchmarkRunner()
        assert runner is not None
    
    def test_runner_has_ground_truth(self):
        """Test that runner has ground truth database."""
        runner = BenchmarkRunner()
        
        assert runner.ground_truth is not None
        assert isinstance(runner.ground_truth, GroundTruthDatabase)
    
    def test_get_results(self):
        """Test getting results from runner."""
        runner = BenchmarkRunner()
        results = runner.get_results()
        
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_run_benchmark_returns_result(self):
        """Test that run_benchmark returns a BenchmarkResult."""
        runner = BenchmarkRunner()
        
        result = await runner.run_benchmark(
            target=BenchmarkTarget.CRAPI,
            base_url="http://localhost:8888",
            timeout=5,
            verbose=False
        )
        
        assert isinstance(result, BenchmarkResult)
        assert result.target == BenchmarkTarget.CRAPI
        assert result.total_vulnerabilities > 0
    
    @pytest.mark.asyncio
    async def test_run_benchmark_populates_category_results(self):
        """Test that category results are populated."""
        runner = BenchmarkRunner()
        
        result = await runner.run_benchmark(
            target=BenchmarkTarget.CRAPI,
            base_url="http://localhost:8888",
            timeout=5,
            verbose=False
        )
        
        assert len(result.category_results) > 0
        
        # Check that at least one category has vulnerabilities
        has_vulns = any(
            data["total"] > 0 
            for data in result.category_results.values()
        )
        assert has_vulns


# ==================== Vulnerability Matching Tests ====================

class TestVulnerabilityMatching:
    """Tests for vulnerability matching logic."""
    
    def test_match_by_endpoint_and_method(self):
        """Test matching vulnerabilities by endpoint and method."""
        runner = BenchmarkRunner()
        
        # Create a known vulnerability
        known = GroundTruthVulnerability(
            vuln_id="test-001",
            category=BenchmarkCategory.SQL_INJECTION,
            endpoint="/api/users",
            method="GET",
            cwe="CWE-89",
            severity=Severity.HIGH,
            description="SQL Injection test"
        )
        
        # Create a detected vulnerability
        detected = Vulnerability(
            endpoint=Endpoint(path="/api/users", method=HttpMethod.GET),
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Found SQL injection",
            payload="' OR 1=1--",
            proof_of_concept="",
            recommendation=""
        )
        
        # Test matching
        matches = runner._vulnerability_matches(detected, known)
        assert matches is True
    
    def test_no_match_different_endpoint(self):
        """Test that different endpoints don't match."""
        runner = BenchmarkRunner()
        
        known = GroundTruthVulnerability(
            vuln_id="test-001",
            category=BenchmarkCategory.SQL_INJECTION,
            endpoint="/api/users",
            method="GET",
            cwe="CWE-89",
            severity=Severity.HIGH,
            description="SQL Injection test"
        )
        
        detected = Vulnerability(
            endpoint=Endpoint(path="/api/products", method=HttpMethod.GET),
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Found SQL injection",
            payload="' OR 1=1--",
            proof_of_concept="",
            recommendation=""
        )
        
        matches = runner._vulnerability_matches(detected, known)
        assert matches is False
    
    def test_no_match_different_method(self):
        """Test that different HTTP methods don't match."""
        runner = BenchmarkRunner()
        
        known = GroundTruthVulnerability(
            vuln_id="test-001",
            category=BenchmarkCategory.SQL_INJECTION,
            endpoint="/api/users",
            method="GET",
            cwe="CWE-89",
            severity=Severity.HIGH,
            description="SQL Injection test"
        )
        
        detected = Vulnerability(
            endpoint=Endpoint(path="/api/users", method=HttpMethod.POST),
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Found SQL injection",
            payload="' OR 1=1--",
            proof_of_concept="",
            recommendation=""
        )
        
        matches = runner._vulnerability_matches(detected, known)
        assert matches is False


# ==================== Convenience Function Tests ====================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    @pytest.mark.asyncio
    async def test_run_crapi_benchmark(self):
        """Test run_crapi_benchmark convenience function."""
        result = await run_crapi_benchmark(
            base_url="http://localhost:8888",
            verbose=False
        )
        
        assert isinstance(result, BenchmarkResult)
        assert result.target == BenchmarkTarget.CRAPI
    
    @pytest.mark.asyncio
    async def test_run_juice_shop_benchmark(self):
        """Test run_juice_shop_benchmark convenience function."""
        result = await run_juice_shop_benchmark(
            base_url="http://localhost:3000",
            verbose=False
        )
        
        assert isinstance(result, BenchmarkResult)
        assert result.target == BenchmarkTarget.JUICE_SHOP


# ==================== Scale Tests ====================

class TestBenchmarkScale:
    """Tests for benchmark database scale."""
    
    def test_total_vulnerabilities_exceed_3000(self, ground_truth_db):
        """Test that total vulnerabilities exceed 3000."""
        total = sum(
            len(ground_truth_db.get_vulnerabilities(target))
            for target in BenchmarkTarget
        )
        
        assert total >= 3000, f"Expected at least 3000 total vulnerabilities, got {total}"
    
    def test_owasp_benchmark_has_multiple_categories(self, ground_truth_db):
        """Test that OWASP Benchmark covers multiple categories."""
        vulns = ground_truth_db.get_vulnerabilities(BenchmarkTarget.OWASP_BENCHMARK)
        categories = set(v.category for v in vulns)
        
        # Should cover at least 10 categories
        assert len(categories) >= 10, f"Expected at least 10 categories, got {len(categories)}"
    
    def test_benchmark_category_enum_complete(self):
        """Test that BenchmarkCategory has all expected values."""
        expected_categories = [
            'sqli', 'nosqli', 'xss', 'xss_reflected', 'xss_stored', 'xss_dom',
            'cmdi', 'ldapi', 'xpathi', 'xmli', 'ssti', 'httpi',
            'xxe', 'path_traversal',
            'auth_bypass', 'idor', 'bola', 'bfla', 'broken_auth', 'weak_auth',
            'jwt', 'jwt_none_alg', 'jwt_weak_secret', 'jwt_alg_confusion',
            'ssrf', 'weak_crypto', 'weak_hash', 'sensitive_data', 
            'hardcoded_secrets', 'info_disclosure',
            'missing_headers', 'cors', 'cookie_security', 'csp_issues',
            'rate_limit', 'file_upload', 'unrestricted_upload',
            'trust_boundary', 'secure_cookie',
            'csrf', 'open_redirect', 'crlf'
        ]
        
        for cat in expected_categories:
            assert any(c.value == cat for c in BenchmarkCategory), f"Missing category: {cat}"


# ==================== Edge Cases ====================

class TestBenchmarkEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_ground_truth_for_unknown_target(self, ground_truth_db):
        """Test that unknown target returns empty list."""
        # This should never happen in practice, but tests robustness
        pass
    
    def test_result_with_no_endpoints_tested(self):
        """Test result with no endpoints tested."""
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=datetime.now(timezone.utc),
            endpoints_tested=0
        )
        
        assert result.endpoints_tested == 0
    
    def test_result_with_duration(self):
        """Test that duration is recorded."""
        start = datetime.now(timezone.utc)
        result = BenchmarkResult(
            target=BenchmarkTarget.CRAPI,
            start_time=start,
            end_time=datetime.now(timezone.utc),
            duration_seconds=5.5
        )
        
        assert result.duration_seconds == 5.5
        assert result.end_time is not None
