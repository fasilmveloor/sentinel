"""
Pytest Configuration and Fixtures for Sentinel Tests.

This module provides shared fixtures and utilities for unit, integration,
and end-to-end tests.
"""

import os
import sys
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

# Add sentinel to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    LLMProvider, ScanConfig, ScanResult, AttackResult, Vulnerability,
    AIAttackDecision
)


# ============================================================================
# MOCK RESPONSES
# ============================================================================

@dataclass
class MockResponse:
    """Mock HTTP response for testing."""
    status_code: int = 200
    text: str = '{"data": "test"}'
    headers: Dict[str, str] = None
    content: bytes = b'{"data": "test"}'
    json_data: Dict[str, Any] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}
        if self.json_data is None:
            try:
                self.json_data = json.loads(self.text)
            except:
                self.json_data = {}

    def json(self):
        return self.json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


# ============================================================================
# SAMPLE DATA FIXTURES
# ============================================================================

@pytest.fixture
def sample_parameter():
    """Create a sample Parameter for testing."""
    return Parameter(
        name="user_id",
        location="query",
        required=True,
        type="string",
        description="User identifier"
    )


@pytest.fixture
def sample_parameters():
    """Create a list of sample Parameters for testing."""
    return [
        Parameter(name="id", location="query", required=True, type="integer"),
        Parameter(name="name", location="query", required=False, type="string"),
        Parameter(name="callback", location="body", required=True, type="string"),
        Parameter(name="token", location="header", required=True, type="string"),
    ]


@pytest.fixture
def sample_endpoint():
    """Create a sample Endpoint for testing."""
    return Endpoint(
        path="/api/users/{id}",
        method=HttpMethod.GET,
        parameters=[
            Parameter(name="id", location="path", required=True, type="integer"),
            Parameter(name="fields", location="query", required=False, type="string"),
        ],
        requires_auth=True,
        summary="Get user by ID",
        description="Retrieves a user by their unique identifier"
    )


@pytest.fixture
def sample_endpoints():
    """Create a list of sample Endpoints for testing."""
    return [
        Endpoint(
            path="/api/users",
            method=HttpMethod.GET,
            parameters=[Parameter(name="limit", location="query", required=False)],
            requires_auth=False,
            summary="List users"
        ),
        Endpoint(
            path="/api/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="id", location="path", required=True)],
            requires_auth=True,
            summary="Get user"
        ),
        Endpoint(
            path="/api/users",
            method=HttpMethod.POST,
            parameters=[Parameter(name="body", location="body", required=True)],
            requires_auth=True,
            summary="Create user"
        ),
        Endpoint(
            path="/api/admin/delete",
            method=HttpMethod.DELETE,
            parameters=[Parameter(name="user_id", location="query", required=True)],
            requires_auth=True,
            summary="Delete user"
        ),
        Endpoint(
            path="/api/webhook",
            method=HttpMethod.POST,
            parameters=[Parameter(name="callback_url", location="body", required=True)],
            requires_auth=False,
            summary="Webhook callback"
        ),
        Endpoint(
            path="/api/search",
            method=HttpMethod.GET,
            parameters=[Parameter(name="q", location="query", required=True)],
            requires_auth=False,
            summary="Search endpoint"
        ),
    ]


@pytest.fixture
def sample_scan_config():
    """Create a sample ScanConfig for testing."""
    return ScanConfig(
        target_url="https://api.example.com",
        swagger_path="/openapi.json",
        attack_types=[AttackType.SQL_INJECTION, AttackType.XSS],
        timeout=10,
        verify_ssl=True
    )


@pytest.fixture
def sample_attack_result(sample_endpoint):
    """Create a sample AttackResult for testing."""
    return AttackResult(
        endpoint=sample_endpoint,
        attack_type=AttackType.SQL_INJECTION,
        success=True,
        payload="' OR '1'='1",
        response_status=500,
        duration_ms=500
    )


@pytest.fixture
def sample_attack_results(sample_endpoints):
    """Create a list of sample AttackResults for testing."""
    return [
        AttackResult(
            endpoint=sample_endpoints[0],
            attack_type=AttackType.SQL_INJECTION,
            success=True,
            payload="' OR '1'='1",
            response_status=500,
            duration_ms=300
        ),
        AttackResult(
            endpoint=sample_endpoints[1],
            attack_type=AttackType.XSS,
            success=True,
            payload="<script>alert(1)</script>",
            response_status=200,
            duration_ms=200
        ),
        AttackResult(
            endpoint=sample_endpoints[2],
            attack_type=AttackType.IDOR,
            success=False,
            payload="id=2",
            response_status=403,
            duration_ms=100
        ),
    ]


@pytest.fixture
def sample_vulnerability(sample_endpoint):
    """Create a sample Vulnerability for testing."""
    return Vulnerability(
        endpoint=sample_endpoint,
        attack_type=AttackType.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQL Injection in user_id parameter",
        description="The user_id parameter is vulnerable to SQL injection",
        payload="' OR '1'='1",
        proof_of_concept="curl -X GET '...'",
        recommendation="Use parameterized queries",
        cvss_score=9.8,
        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
    )


@pytest.fixture
def sample_scan_result(sample_scan_config, sample_endpoints, sample_attack_results):
    """Create a sample ScanResult for testing."""
    return ScanResult(
        config=sample_scan_config,
        endpoints_tested=sample_endpoints,
        attack_results=sample_attack_results,
        vulnerabilities=[],
        duration_seconds=5.5
    )


@pytest.fixture
def sample_ai_decision():
    """Create a sample AIAttackDecision for testing."""
    return AIAttackDecision(
        recommended_attacks=[AttackType.SQL_INJECTION, AttackType.IDOR],
        priority=1,
        reasoning="Endpoint has database query parameters",
        risk_score=8.5,
        confidence=0.9
    )


# ============================================================================
# OPENAPI SPEC FIXTURES
# ============================================================================

@pytest.fixture
def sample_openapi_spec():
    """Create a sample OpenAPI 3.0 specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "A test API for security testing"
        },
        "servers": [
            {"url": "https://api.example.com", "description": "Production"}
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "operationId": "listUsers",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {"application/json": {}}
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "createUser",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
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
                    "operationId": "getUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "email": {"type": "string"}
                    }
                }
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    }


@pytest.fixture
def sample_swagger_2_spec():
    """Create a sample Swagger 2.0 specification for testing."""
    return {
        "swagger": "2.0",
        "info": {
            "title": "Test API v2",
            "version": "2.0.0"
        },
        "host": "api.example.com",
        "basePath": "/v2",
        "schemes": ["https"],
        "paths": {
            "/products": {
                "get": {
                    "summary": "List products",
                    "parameters": [
                        {
                            "name": "category",
                            "in": "query",
                            "type": "string"
                        }
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        },
        "definitions": {
            "Product": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                }
            }
        }
    }


# ============================================================================
# HTTP MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_requests_get():
    """Mock requests.get for testing."""
    with patch('requests.get') as mock_get:
        mock_get.return_value = MockResponse(status_code=200, text='{"data": "test"}')
        yield mock_get


@pytest.fixture
def mock_requests_post():
    """Mock requests.post for testing."""
    with patch('requests.post') as mock_post:
        mock_post.return_value = MockResponse(status_code=200, text='{"success": true}')
        yield mock_post


@pytest.fixture
def mock_requests_session():
    """Mock requests.Session for testing."""
    mock_session = MagicMock()
    mock_session.get.return_value = MockResponse(status_code=200)
    mock_session.post.return_value = MockResponse(status_code=201)
    mock_session.request.return_value = MockResponse(status_code=200)

    with patch('requests.Session', return_value=mock_session):
        yield mock_session


@pytest.fixture
def mock_vulnerable_response():
    """Mock HTTP response with SQL error."""
    return MockResponse(
        status_code=500,
        text='{"error": "SQL syntax error"}',
        headers={"Content-Type": "application/json"}
    )


@pytest.fixture
def mock_xss_response():
    """Mock HTTP response with XSS reflection."""
    return MockResponse(
        status_code=200,
        text='<html><body>Hello <script>alert(1)</script></body></html>',
        headers={"Content-Type": "text/html"}
    )


# ============================================================================
# LLM MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_llm_response():
    """Mock LLM API response."""
    return {
        "recommended_attacks": ["sql_injection", "idor"],
        "priority": 1,
        "reasoning": "Endpoint has database query parameters",
        "risk_score": 8.5,
        "confidence": 0.9
    }


@pytest.fixture
def mock_gemini_provider():
    """Mock Gemini provider for testing."""
    mock = MagicMock()
    mock.generate.return_value = json.dumps({
        "recommended_attacks": ["sql_injection"],
        "priority": 1,
        "reasoning": "Test reasoning",
        "risk_score": 7.5,
        "confidence": 0.8
    })
    mock.is_available.return_value = True
    return mock


@pytest.fixture
def mock_openai_provider():
    """Mock OpenAI provider for testing."""
    mock = MagicMock()
    mock.generate.return_value = json.dumps({
        "recommended_attacks": ["xss"],
        "priority": 2,
        "reasoning": "Input reflection detected",
        "risk_score": 6.0,
        "confidence": 0.7
    })
    mock.is_available.return_value = True
    return mock


@pytest.fixture
def mock_claude_provider():
    """Mock Claude provider for testing."""
    mock = MagicMock()
    mock.generate.return_value = json.dumps({
        "recommended_attacks": ["ssrf"],
        "priority": 1,
        "reasoning": "URL parameter detected",
        "risk_score": 8.0,
        "confidence": 0.85
    })
    mock.is_available.return_value = True
    return mock


# ============================================================================
# FILE SYSTEM FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for file operations."""
    return tmp_path


@pytest.fixture
def temp_openapi_file(temp_dir, sample_openapi_spec):
    """Create a temporary OpenAPI spec file."""
    spec_file = temp_dir / "openapi.json"
    spec_file.write_text(json.dumps(sample_openapi_spec))
    return spec_file


@pytest.fixture
def temp_swagger_file(temp_dir, sample_swagger_2_spec):
    """Create a temporary Swagger 2.0 spec file."""
    spec_file = temp_dir / "swagger.json"
    spec_file.write_text(json.dumps(sample_swagger_2_spec))
    return spec_file


@pytest.fixture
def temp_yaml_spec_file(temp_dir):
    """Create a temporary YAML spec file."""
    yaml_content = """
openapi: '3.0.0'
info:
  title: YAML Test API
  version: '1.0.0'
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        '200':
          description: Success
"""
    spec_file = temp_dir / "spec.yaml"
    spec_file.write_text(yaml_content)
    return spec_file


# ============================================================================
# ENVIRONMENT FIXTURES
# ============================================================================

@pytest.fixture
def mock_env_api_keys(monkeypatch):
    """Mock API key environment variables."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment variables for testing."""
    for key in ["GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        monkeypatch.delenv(key, raising=False)


# ============================================================================
# ASSERTION HELPERS
# ============================================================================

def assert_valid_endpoint(endpoint: Endpoint):
    """Assert that an endpoint has valid required fields."""
    assert endpoint.path, "Endpoint path is required"
    assert endpoint.method, "Endpoint method is required"
    assert isinstance(endpoint.parameters, list), "Parameters must be a list"


def assert_valid_attack_result(result: AttackResult):
    """Assert that an attack result has valid fields."""
    assert result.endpoint, "AttackResult endpoint is required"
    assert result.attack_type, "AttackResult attack_type is required"
    assert isinstance(result.success, bool), "AttackResult success must be boolean"
    assert result.severity, "AttackResult severity is required"


def assert_valid_vulnerability(vuln: Vulnerability):
    """Assert that a vulnerability has valid required fields."""
    assert vuln.id, "Vulnerability ID is required"
    assert vuln.endpoint, "Vulnerability endpoint is required"
    assert vuln.attack_type, "Vulnerability attack_type is required"
    assert vuln.severity, "Vulnerability severity is required"
    assert vuln.title, "Vulnerability title is required"


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "requires_api: Tests requiring external APIs")
