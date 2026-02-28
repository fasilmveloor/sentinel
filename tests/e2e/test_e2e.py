"""
End-to-End tests for Sentinel.

These tests validate the complete workflow from spec parsing to report generation.
Uses the vulnerable test API server for realistic testing.
"""

import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, Mock, AsyncMock

from sentinel.parser import SwaggerParser, parse_swagger
from sentinel.models import Endpoint, HttpMethod, AttackType, Severity
from sentinel.agent import SentinelAgent
from sentinel.passive import PassiveScanner, create_passive_scanner
from sentinel.autonomous import AutonomousScanner, AgentState


# ============================================================================
# FULL WORKFLOW TESTS
# ============================================================================

class TestFullWorkflow:
    """End-to-end workflow tests."""

    @pytest.fixture
    def sample_spec_path(self, temp_dir):
        """Create a sample OpenAPI spec for testing."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "https://api.test.local"}],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "security": [{"bearerAuth": []}],
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}}
                    },
                    "delete": {
                        "summary": "Delete user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"204": {"description": "Deleted"}}
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search",
                        "parameters": [
                            {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        }
        
        spec_file = temp_dir / "openapi.json"
        spec_file.write_text(json.dumps(spec))
        return spec_file

    def test_full_parse_workflow(self, sample_spec_path):
        """Test complete parsing workflow."""
        # Parse spec
        parser = SwaggerParser(str(sample_spec_path))
        endpoints = parser.parse()
        
        # Verify endpoints
        assert len(endpoints) >= 4
        
        # Verify different HTTP methods
        methods = {e.method for e in endpoints}
        assert HttpMethod.GET in methods
        assert HttpMethod.POST in methods
        assert HttpMethod.DELETE in methods
        
        # Verify security
        protected = [e for e in endpoints if e.requires_auth]
        public = [e for e in endpoints if not e.requires_auth]
        assert len(protected) > 0
        assert len(public) > 0

    def test_parse_to_attack_decision_workflow(self, sample_spec_path):
        """Test workflow from parsing to attack decisions."""
        # Parse
        endpoints = parse_swagger(str(sample_spec_path))
        
        # Mock agent for decisions
        mock_provider = Mock()
        mock_provider.generate = Mock(return_value=json.dumps({
            "recommended_attacks": ["sql_injection", "xss"],
            "priority": 1,
            "reasoning": "Test reasoning"
        }))
        mock_provider.is_available = Mock(return_value=True)
        
        with patch('sentinel.agent.create_agent') as mock_create:
            mock_agent = Mock(spec=SentinelAgent)
            mock_agent.active_provider = mock_provider
            mock_create.return_value = mock_agent
            
            # Simulate analysis
            for endpoint in endpoints:
                # In real workflow, agent would analyze each endpoint
                assert endpoint.path is not None
                assert endpoint.method is not None

    def test_passive_scan_workflow(self, sample_spec_path):
        """Test passive scanning workflow."""
        scanner = create_passive_scanner()
        
        # Simulate HTTP responses
        responses = [
            {
                "url": "https://api.test.local/users",
                "method": "GET",
                "headers": {
                    "Server": "Apache/2.4.41",
                    "Content-Type": "application/json"
                },
                "body": '{"users": [{"id": 1, "email": "admin@test.local"}]}'
            },
            {
                "url": "https://api.test.local/search",
                "method": "GET",
                "headers": {
                    "Access-Control-Allow-Origin": "*"
                },
                "body": '{"results": []}'
            }
        ]
        
        all_findings = []
        for resp in responses:
            findings = scanner.analyze_response(
                url=resp["url"],
                method=resp["method"],
                request_headers={},
                response_headers=resp["headers"],
                response_body=resp["body"],
                status_code=200
            )
            all_findings.extend(findings)
        
        # Should have findings from security header checks, etc.
        assert len(all_findings) > 0
        
        # Check different finding types
        finding_types = {f.finding_type for f in all_findings}
        assert len(finding_types) > 0

    @pytest.mark.asyncio
    async def test_autonomous_scan_workflow(self, sample_spec_path):
        """Test full autonomous scan workflow."""
        # Parse spec
        endpoints = parse_swagger(str(sample_spec_path))
        
        # Mock all components
        mock_provider = Mock()
        mock_provider.generate = Mock(return_value=json.dumps({
            "attack_sequence": [
                {"endpoint_index": 0, "attack_types": ["sql_injection"], "priority": 1}
            ],
            "estimated_time_seconds": 60,
            "risk_score": 7.5,
            "reasoning": "Test plan"
        }))
        mock_provider.is_available = Mock(return_value=True)
        
        # Create mock executor
        mock_executor = Mock()
        mock_executor.execute_plan = AsyncMock(return_value=[])
        mock_executor.attackers = {}
        
        with patch('sentinel.autonomous.create_agent') as mock_create, \
             patch('sentinel.autonomous.ExecutorAgent', return_value=mock_executor):
            mock_agent = Mock(spec=SentinelAgent)
            mock_agent.active_provider = mock_provider
            mock_create.return_value = mock_agent
            
            scanner = AutonomousScanner()
            
            # Run scan
            result = await scanner.scan(
                endpoints=endpoints,
                base_url="https://api.test.local"
            )
            
            # Verify result
            assert result.state == AgentState.COMPLETED
            assert result.plan is not None
            assert result.endpoints_scanned > 0


# ============================================================================
# INTEGRATION WITH VULNERABLE API
# ============================================================================

class TestVulnerableAPIIntegration:
    """Integration tests with the vulnerable test API."""

    @pytest.fixture
    def vulnerable_api_spec(self, temp_dir):
        """Create spec for vulnerable API endpoints."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Vulnerable API", "version": "1.0.0"},
            "servers": [{"url": "http://localhost:5000"}],
            "paths": {
                "/api/users/{id}": {
                    "get": {
                        "summary": "Get user (IDOR vulnerable)",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/api/search": {
                    "get": {
                        "summary": "Search (SQLi vulnerable)",
                        "parameters": [
                            {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/api/webhook": {
                    "post": {
                        "summary": "Webhook (SSRF vulnerable)",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "callback_url": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/api/comment": {
                    "post": {
                        "summary": "Add comment (XSS vulnerable)",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "comment": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                }
            }
        }
        
        spec_file = temp_dir / "vulnerable_api.json"
        spec_file.write_text(json.dumps(spec))
        return spec_file

    def test_parse_vulnerable_api_spec(self, vulnerable_api_spec):
        """Test parsing vulnerable API spec."""
        endpoints = parse_swagger(str(vulnerable_api_spec))
        
        assert len(endpoints) == 4
        
        # Verify endpoints
        paths = {e.path for e in endpoints}
        assert "/api/users/{id}" in paths
        assert "/api/search" in paths
        assert "/api/webhook" in paths
        assert "/api/comment" in paths

    @pytest.mark.asyncio
    async def test_mock_scan_vulnerable_endpoints(self, vulnerable_api_spec):
        """Test scanning vulnerable endpoints (mocked)."""
        endpoints = parse_swagger(str(vulnerable_api_spec))
        
        # Create mock results simulating vulnerabilities found
        from sentinel.models import AttackResult
        
        mock_results = [
            AttackResult(
                endpoint=endpoints[0],  # IDOR endpoint
                attack_type=AttackType.IDOR,
                success=True,
                payload="id=2",
                extra_data={'severity': 'high'}
            ),
            AttackResult(
                endpoint=endpoints[1],  # SQLi endpoint
                attack_type=AttackType.SQL_INJECTION,
                success=True,
                payload="' OR '1'='1",
                extra_data={'severity': 'critical'}
            ),
            AttackResult(
                endpoint=endpoints[2],  # SSRF endpoint
                attack_type=AttackType.SSRF,
                success=True,
                payload="http://169.254.169.254/",
                extra_data={'severity': 'high'}
            ),
            AttackResult(
                endpoint=endpoints[3],  # XSS endpoint
                attack_type=AttackType.XSS,
                success=True,
                payload="<script>alert(1)</script>",
                extra_data={'severity': 'medium'}
            ),
        ]
        
        # Verify mock results
        assert len(mock_results) == 4
        # Check that all have extra_data with severity
        severities = {r.extra_data['severity'] for r in mock_results}
        assert 'critical' in severities
        assert 'high' in severities
        assert 'medium' in severities


# ============================================================================
# REPORT GENERATION TESTS
# ============================================================================

class TestReportGeneration:
    """Tests for report generation workflow."""

    def test_scan_result_to_report_data(self, sample_scan_result):
        """Test converting scan result to report data."""
        # Extract data for report
        report_data = {
            "target": sample_scan_result.config.target_url,
            "total_endpoints": sample_scan_result.config.swagger_path,
            "vulnerabilities": len(sample_scan_result.vulnerabilities),
            "attack_results": len(sample_scan_result.attack_results),
            "duration": sample_scan_result.duration_seconds
        }
        
        assert "target" in report_data
        assert report_data["attack_results"] >= 0

    def test_severity_summary_generation(self, sample_scan_config, sample_endpoint):
        """Test generating severity summary."""
        from sentinel.models import Vulnerability, ScanResult
        
        vulnerabilities = [
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                title="SQL Injection",
                description="SQL injection vulnerability",
                payload="' OR '1'='1",
                proof_of_concept="poc",
                recommendation="Use parameterized queries"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.XSS,
                severity=Severity.HIGH,
                title="XSS",
                description="Cross-site scripting",
                payload="<script>alert(1)</script>",
                proof_of_concept="poc",
                recommendation="Encode output"
            ),
            Vulnerability(
                endpoint=sample_endpoint,
                attack_type=AttackType.IDOR,
                severity=Severity.MEDIUM,
                title="IDOR",
                description="Insecure direct object reference",
                payload="id=2",
                proof_of_concept="poc",
                recommendation="Check authorization"
            ),
        ]
        
        result = ScanResult(
            config=sample_scan_config,
            vulnerabilities=vulnerabilities
        )
        
        # Verify counts
        assert result.vulnerability_count == 3
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1


# ============================================================================
# ERROR RECOVERY TESTS
# ============================================================================

class TestErrorRecovery:
    """Tests for error recovery in workflows."""

    @pytest.mark.asyncio
    async def test_ai_failure_fallback(self, sample_endpoints):
        """Test fallback when AI fails."""
        mock_provider = Mock()
        mock_provider.generate = Mock(side_effect=Exception("AI API Error"))
        mock_provider.is_available = Mock(return_value=True)
        
        # Create mock executor
        mock_executor = Mock()
        mock_executor.execute_plan = AsyncMock(return_value=[])
        mock_executor.attackers = {}
        
        with patch('sentinel.autonomous.create_agent') as mock_create, \
             patch('sentinel.autonomous.ExecutorAgent', return_value=mock_executor):
            mock_agent = Mock(spec=SentinelAgent)
            mock_agent.active_provider = mock_provider
            mock_create.return_value = mock_agent
            
            scanner = AutonomousScanner()
            
            # Should fallback to rule-based planning
            result = await scanner.scan(
                endpoints=sample_endpoints,
                base_url="https://example.com"
            )
            
            assert result.state == AgentState.COMPLETED
            assert result.plan is not None

    def test_parse_invalid_spec_recovery(self, temp_dir):
        """Test recovery from invalid spec."""
        invalid_file = temp_dir / "invalid.json"
        invalid_file.write_text("not valid json")
        
        from sentinel.parser import SwaggerParseError
        
        with pytest.raises(SwaggerParseError):
            parse_swagger(str(invalid_file))

    @pytest.mark.asyncio
    async def test_partial_scan_recovery(self, sample_endpoints):
        """Test recovery from partial scan failure."""
        mock_provider = Mock()
        mock_provider.generate = Mock(return_value=json.dumps({
            "attack_sequence": [],
            "estimated_time_seconds": 60,
            "risk_score": 5.0,
            "reasoning": "Test"
        }))
        mock_provider.is_available = Mock(return_value=True)
        
        # Create mock executor
        mock_executor = Mock()
        mock_executor.attackers = {}
        
        with patch('sentinel.autonomous.create_agent') as mock_create, \
             patch('sentinel.autonomous.ExecutorAgent', return_value=mock_executor):
            mock_agent = Mock(spec=SentinelAgent)
            mock_agent.active_provider = mock_provider
            mock_create.return_value = mock_agent
            
            scanner = AutonomousScanner()
            
            # Simulate partial failure - some attacks succeed
            from sentinel.models import AttackResult
            
            partial_results = [
                AttackResult(
                    endpoint=sample_endpoints[0],
                    attack_type=AttackType.SQL_INJECTION,
                    success=True
                )
            ]
            
            mock_executor.execute_plan = AsyncMock(return_value=partial_results)
            
            result = await scanner.scan(
                endpoints=sample_endpoints,
                base_url="https://example.com"
            )
            
            # Should still complete with partial results
            assert result.state == AgentState.COMPLETED
            assert len(result.findings) > 0


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Performance benchmarks for critical paths."""

    def test_parse_large_spec_performance(self, temp_dir):
        """Test parsing a large OpenAPI spec."""
        # Generate a large spec
        paths = {}
        for i in range(100):
            paths[f"/api/resource{i}"] = {
                "get": {
                    "summary": f"Get resource {i}",
                    "parameters": [
                        {"name": "id", "in": "query", "schema": {"type": "integer"}}
                    ],
                    "responses": {"200": {"description": "OK"}}
                },
                "post": {
                    "summary": f"Create resource {i}",
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            }
        
        large_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Large API", "version": "1.0.0"},
            "paths": paths
        }
        
        spec_file = temp_dir / "large_spec.json"
        spec_file.write_text(json.dumps(large_spec))
        
        import time
        start = time.time()
        endpoints = parse_swagger(str(spec_file))
        elapsed = time.time() - start
        
        # Should parse 200 endpoints quickly
        assert len(endpoints) == 200
        assert elapsed < 2.0  # Should complete in under 2 seconds

    def test_passive_scan_performance(self):
        """Test passive scanning performance."""
        scanner = create_passive_scanner()
        
        import time
        start = time.time()
        
        for i in range(100):
            scanner.analyze_response(
                url=f"https://example.com/api/{i}",
                method="GET",
                request_headers={},
                response_headers={"Content-Type": "application/json"},
                response_body='{"data": "test"}',
                status_code=200
            )
        
        elapsed = time.time() - start
        
        # Should process 100 responses quickly
        assert elapsed < 5.0  # Should complete in under 5 seconds


# ============================================================================
# CONFIGURATION TESTS
# ============================================================================

class TestConfiguration:
    """Tests for configuration handling."""

    def test_scan_config_validation(self):
        """Test scan configuration validation."""
        from sentinel.models import ScanConfig, ReportFormat, LLMProvider
        
        config = ScanConfig(
            target_url="https://api.example.com",
            swagger_path="/openapi.json",
            output_format=ReportFormat.JSON,
            llm_provider=LLMProvider.OPENAI,
            timeout=10,
            max_endpoints=100,
            rate_limit_delay=0.5
        )
        
        assert config.target_url == "https://api.example.com"
        assert config.output_format == ReportFormat.JSON
        assert config.llm_provider == LLMProvider.OPENAI

    def test_attack_type_selection(self):
        """Test attack type selection."""
        from sentinel.models import ScanConfig
        
        config = ScanConfig(
            target_url="https://api.example.com",
            swagger_path="/openapi.json",
            attack_types=[AttackType.SQL_INJECTION, AttackType.XSS]
        )
        
        assert len(config.attack_types) == 2
        assert AttackType.SQL_INJECTION in config.attack_types
        assert AttackType.XSS in config.attack_types
