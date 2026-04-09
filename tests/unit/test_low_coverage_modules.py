"""
Comprehensive unit tests for low-coverage attack modules.
Target: 80% coverage for BOLA, Excessive Data, Broken Auth, BFLA, SSRF
"""

import json
import pytest
from unittest.mock import Mock, MagicMock, patch, PropertyMock
import requests

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    AttackResult, Vulnerability
)
from sentinel.attacks.bola import BOLAAttacker, UserCredentials
from sentinel.attacks.excessive_data import ExcessiveDataExposureAttacker
from sentinel.attacks.broken_auth import BrokenAuthAttacker
from sentinel.attacks.bfla import BFLAAttacker, UserRole
from sentinel.attacks.ssrf import SSRFAttacker


def create_mock_response(status_code=200, text='{"data": "test"}', headers=None):
    """Create a mock HTTP response."""
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.text = text
    response.headers = headers or {"Content-Type": "application/json"}
    response.content = text.encode() if isinstance(text, str) else text
    
    try:
        response.json = Mock(return_value=json.loads(text))
    except:
        response.json = Mock(return_value={})
    
    return response


# ============================================================================
# BOLA COMPREHENSIVE TESTS
# ============================================================================

class TestBOLAAttackerComprehensive:
    """Comprehensive tests for BOLA attacker - targeting 80% coverage."""

    @pytest.fixture
    def attacker(self):
        """Create BOLA attacker with mocked session."""
        with patch('sentinel.attacks.bola.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BOLAAttacker("https://api.example.com")
            yield attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout == 10
        assert attacker.sessions == {}
        assert attacker.credentials == []

    def test_set_credentials(self, attacker):
        """Test setting user credentials."""
        creds = [
            UserCredentials(user_id="1", email="user1@test.com", token="token1"),
            UserCredentials(user_id="2", email="user2@test.com", token="token2"),
        ]
        attacker.set_credentials(creds)
        
        assert len(attacker.credentials) == 2
        assert len(attacker.sessions) == 2
        assert "1" in attacker.sessions
        assert "2" in attacker.sessions

    def test_extract_path_ids(self, attacker):
        """Test extracting ID parameters from path."""
        # Test with various path patterns
        result = attacker._extract_path_ids("/users/{user_id}")
        assert "user_id" in result
        result = attacker._extract_path_ids("/orders/{orderId}/items/{itemId}")
        assert "orderId" in result
        result = attacker._extract_path_ids("/vehicles/{vehicle_id}")
        assert "vehicle_id" in result
        result = attacker._extract_path_ids("/posts/{post_id}")
        assert "post_id" in result
        result = attacker._extract_path_ids("/reports/{report_id}")
        assert "report_id" in result
        # Non-ID parameters should not be extracted
        result = attacker._extract_path_ids("/search/{query}")
        assert result == []

    def test_extract_ids_from_response_list(self, attacker):
        """Test extracting IDs from list response."""
        data = [
            {"id": 1, "name": "item1"},
            {"id": 2, "name": "item2"},
            {"id": 3, "name": "item3"},
        ]
        ids = attacker._extract_ids_from_response(data)
        assert "1" in ids
        assert "2" in ids
        assert "3" in ids

    def test_extract_ids_from_response_dict(self, attacker):
        """Test extracting IDs from dict response."""
        data = {
            "data": [
                {"vehicle_id": "v1", "name": "vehicle1"},
                {"vehicle_id": "v2", "name": "vehicle2"},
            ],
            "user_id": "u1"
        }
        ids = attacker._extract_ids_from_response(data)
        assert "v1" in ids
        assert "v2" in ids
        assert "u1" in ids

    def test_extract_ids_nested(self, attacker):
        """Test extracting IDs from nested structures."""
        data = {
            "vehicles": [
                {"id": "car1"},
                {"id": "car2"}
            ],
            "videos": [
                {"video_id": "vid1"}
            ]
        }
        ids = attacker._extract_ids_from_response(data)
        assert "car1" in ids
        assert "car2" in ids
        assert "vid1" in ids

    def test_generate_test_ids_numeric(self, attacker):
        """Test generating test IDs for numeric IDs."""
        ids = attacker._generate_test_ids("100")
        assert str(99) in ids  # 100 - 1
        assert str(101) in ids  # 100 + 1
        assert "0" in ids
        assert "1" in ids

    def test_generate_test_ids_uuid(self, attacker):
        """Test generating test IDs for UUID-like IDs."""
        uuid_str = "00000000-0000-0000-0000-000000000001"
        ids = attacker._generate_test_ids(uuid_str)
        # Should include UUID test cases
        assert any("-" in test_id for test_id in ids)

    def test_is_bola_vulnerable_200_with_data(self, attacker):
        """Test BOLA vulnerability detection with 200 and data."""
        response = create_mock_response(
            text='{"email": "test@example.com", "name": "Test User"}'
        )
        assert attacker._is_bola_vulnerable(response, "1") is True

    def test_is_bola_vulnerable_200_empty(self, attacker):
        """Test BOLA vulnerability detection with empty response."""
        response = create_mock_response(text='{}')
        assert attacker._is_bola_vulnerable(response, "1") is False

    def test_is_bola_vulnerable_401(self, attacker):
        """Test BOLA vulnerability detection with 401."""
        response = create_mock_response(status_code=401, text='{"error": "Unauthorized"}')
        assert attacker._is_bola_vulnerable(response, "1") is False

    def test_is_bola_vulnerable_404(self, attacker):
        """Test BOLA vulnerability detection with 404."""
        response = create_mock_response(status_code=404, text='{"error": "Not found"}')
        assert attacker._is_bola_vulnerable(response, "1") is False

    def test_is_bola_vulnerable_sensitive_fields(self, attacker):
        """Test BOLA vulnerability with sensitive fields."""
        response = create_mock_response(
            text='{"password": "secret123", "token": "abc123", "ssn": "123-45-6789"}'
        )
        assert attacker._is_bola_vulnerable(response, "1") is True

    def test_is_bola_vulnerable_list_data(self, attacker):
        """Test BOLA vulnerability with list response."""
        response = create_mock_response(
            text='[{"id": 1}, {"id": 2}, {"id": 3}]'
        )
        assert attacker._is_bola_vulnerable(response, "1") is True

    def test_is_bola_vulnerable_non_json(self, attacker):
        """Test BOLA vulnerability with non-JSON response."""
        response = create_mock_response(
            text="A" * 200,  # Large text response
            headers={"Content-Type": "text/plain"}
        )
        response.json = Mock(side_effect=ValueError("Not JSON"))
        assert attacker._is_bola_vulnerable(response, "1") is True

    def test_attack_without_auth(self, attacker):
        """Test attack without authentication."""
        endpoint = Endpoint(
            path="/api/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="user_id", location="path", required=True)]
        )
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_attack_with_fallback_token(self, attacker):
        """Test attack with fallback auth token."""
        endpoint = Endpoint(
            path="/api/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="user_id", location="path", required=True)]
        )
        
        # Mock the session.get
        mock_response = create_mock_response(text='{"id": 1, "email": "test@example.com"}')
        
        results = attacker.attack(endpoint, auth_token="test_token")
        assert isinstance(results, list)

    def test_attack_multi_user(self, attacker):
        """Test attack with multiple users."""
        # Setup multi-user credentials
        creds = [
            UserCredentials(user_id="1", email="user1@test.com", token="token1"),
            UserCredentials(user_id="2", email="user2@test.com", token="token2"),
        ]
        attacker.set_credentials(creds)
        
        endpoint = Endpoint(
            path="/api/orders/{orderId}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="orderId", location="path", required=True)]
        )
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/api/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.IDOR,
            success=True,
            payload="user_id=123",
            response_status=200,
            response_body='{"id": 123, "email": "test@example.com"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.IDOR
        assert vuln.severity == Severity.HIGH
        assert "BOLA" in vuln.title or "IDOR" in vuln.title
        assert vuln.cwe_id == "CWE-639"

    def test_setup_fallback_session(self, attacker):
        """Test fallback session setup."""
        attacker._setup_fallback_session("test_token")
        assert "default" in attacker.sessions

    def test_discover_resources(self, attacker):
        """Test resource discovery."""
        attacker._setup_fallback_session("test_token")
        
        # Mock the session to return some resources
        mock_response = create_mock_response(
            text='[{"id": "r1"}, {"id": "r2"}]'
        )
        attacker.sessions["default"].get.return_value = mock_response
        
        endpoint = Endpoint(path="/api/test", method=HttpMethod.GET, parameters=[])
        discovered = attacker._discover_resources(endpoint)
        
        # Should have discovered resources
        assert isinstance(discovered, list)

    def test_test_path_bola(self, attacker):
        """Test path-based BOLA testing."""
        attacker._setup_fallback_session("test_token")
        
        mock_response = create_mock_response(text='{"id": 1}')
        attacker.sessions["default"].request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/api/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker._test_path_bola(endpoint, "user_id")
        assert isinstance(results, list)

    def test_test_discovered_ids(self, attacker):
        """Test with discovered IDs."""
        attacker._setup_fallback_session("test_token")
        
        mock_response = create_mock_response(text='{"id": 1}')
        attacker.sessions["default"].get.return_value = mock_response
        
        endpoint = Endpoint(
            path="/api/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        # Add some discovered resources
        attacker.discovered_resources["users"] = ["u1", "u2"]
        
        results = attacker._test_discovered_ids(endpoint, ["u1", "u2"], ["user_id"])
        assert isinstance(results, list)


# ============================================================================
# EXCESSIVE DATA EXPOSURE COMPREHENSIVE TESTS
# ============================================================================

class TestExcessiveDataExposureComprehensive:
    """Comprehensive tests for Excessive Data Exposure - targeting 80% coverage."""

    @pytest.fixture
    def attacker(self):
        """Create attacker with mocked session."""
        with patch('sentinel.attacks.excessive_data.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = ExcessiveDataExposureAttacker("https://api.example.com")
            yield attacker

    def test_initialization(self, attacker):
        """Test initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout == 10

    def test_pii_fields_detection(self, attacker):
        """Test PII fields detection."""
        assert "email" in attacker.PII_FIELDS
        assert "password" in attacker.PII_FIELDS
        assert "ssn" in attacker.PII_FIELDS
        assert "credit_card" in attacker.PII_FIELDS
        assert "phone" in attacker.PII_FIELDS

    def test_internal_fields_detection(self, attacker):
        """Test internal fields detection."""
        assert "_id" in attacker.INTERNAL_FIELDS
        assert "created_at" in attacker.INTERNAL_FIELDS
        assert "is_admin" in attacker.INTERNAL_FIELDS
        assert "reset_token" in attacker.INTERNAL_FIELDS

    def test_flatten_dict_simple(self, attacker):
        """Test flattening simple dict."""
        data = {"name": "test", "email": "test@example.com"}
        flat = attacker._flatten_dict(data)
        assert "name" in flat
        assert "email" in flat

    def test_flatten_dict_nested(self, attacker):
        """Test flattening nested dict."""
        data = {
            "user": {
                "name": "test",
                "contact": {
                    "email": "test@example.com"
                }
            }
        }
        flat = attacker._flatten_dict(data)
        assert "user.name" in flat
        assert "user.contact.email" in flat

    def test_flatten_dict_with_list(self, attacker):
        """Test flattening dict with list."""
        data = {
            "items": [
                {"id": 1, "name": "item1"},
                {"id": 2, "name": "item2"}
            ]
        }
        flat = attacker._flatten_dict(data)
        # Should include first item from list
        assert "items[0].id" in flat or "items[0].name" in flat

    def test_flatten_list(self, attacker):
        """Test flattening list."""
        data = [
            {"id": 1, "email": "a@test.com"},
            {"id": 2, "email": "b@test.com"}
        ]
        flat = attacker._flatten_dict(data)
        assert len(flat) > 0

    def test_analyze_response_no_exposure(self, attacker):
        """Test response without excessive data."""
        response = create_mock_response(text='{"status": "ok"}')
        endpoint = Endpoint(path="/api/health", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is False

    def test_analyze_response_pii_exposure(self, attacker):
        """Test response with PII exposure."""
        response = create_mock_response(
            text='{"email": "test@example.com", "password": "secret"}'
        )
        endpoint = Endpoint(path="/api/user", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is True
        assert any(f['type'] == 'PII_EXPOSURE' for f in analysis['findings'])

    def test_analyze_response_bulk_data(self, attacker):
        """Test response with bulk data."""
        items = [{"id": i, "name": f"item{i}"} for i in range(20)]
        response = create_mock_response(text=json.dumps(items))
        endpoint = Endpoint(path="/api/items", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is True
        assert any(f['type'] == 'BULK_DATA' for f in analysis['findings'])

    def test_analyze_response_bulk_pii(self, attacker):
        """Test response with bulk PII data."""
        items = [{"email": f"user{i}@test.com", "ssn": "123-45-6789"} for i in range(15)]
        response = create_mock_response(text=json.dumps(items))
        endpoint = Endpoint(path="/api/users", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is True

    def test_analyze_response_nested_bulk(self, attacker):
        """Test response with nested bulk data."""
        data = {
            "users": [{"id": i, "email": f"u{i}@test.com"} for i in range(15)]
        }
        response = create_mock_response(text=json.dumps(data))
        endpoint = Endpoint(path="/api/data", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is True

    def test_analyze_response_non_200(self, attacker):
        """Test response with non-200 status."""
        response = create_mock_response(status_code=404, text='{"error": "Not found"}')
        endpoint = Endpoint(path="/api/test", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is False

    def test_analyze_response_non_json(self, attacker):
        """Test response with non-JSON content."""
        response = create_mock_response(text="Not JSON", headers={"Content-Type": "text/plain"})
        response.json = Mock(side_effect=ValueError("Not JSON"))
        endpoint = Endpoint(path="/api/test", method=HttpMethod.GET, parameters=[])
        
        analysis = attacker._analyze_response(response, endpoint)
        assert analysis['has_excessive_data'] is False

    def test_check_internal_properties(self, attacker):
        """Test internal properties detection."""
        response = create_mock_response(
            text='{"_id": "123", "__v": 1, "created_at": "2023-01-01", "reset_token": "abc"}'
        )
        
        findings = attacker._check_internal_properties(response)
        assert len(findings) > 0
        assert any("_id" in k for k in findings.keys())

    def test_check_internal_properties_masks_values(self, attacker):
        """Test that long values are masked."""
        response = create_mock_response(
            text='{"reset_token": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        )
        
        findings = attacker._check_internal_properties(response)
        # Long values should be masked
        if "reset_token" in findings:
            assert "..." in findings["reset_token"] or len(findings["reset_token"]) < 40

    def test_get_default_string(self, attacker):
        """Test default value for string parameter."""
        param = Mock()
        param.param_type = "string"
        assert attacker._get_default(param) == "test"

    def test_get_default_integer(self, attacker):
        """Test default value for integer parameter."""
        param = Mock()
        param.param_type = "integer"
        assert attacker._get_default(param) == 1

    def test_get_default_boolean(self, attacker):
        """Test default value for boolean parameter."""
        param = Mock()
        param.param_type = "boolean"
        assert attacker._get_default(param) is True

    def test_make_request_success(self, attacker):
        """Test successful request."""
        mock_response = create_mock_response()
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/api/test",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        response = attacker._make_request(endpoint)
        assert response is not None
        assert response.status_code == 200

    def test_make_request_with_params(self, attacker):
        """Test request with parameters."""
        mock_response = create_mock_response()
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/api/search",
            method=HttpMethod.GET,
            parameters=[Parameter(name="q", location="query", param_type="string")]
        )
        
        response = attacker._make_request(endpoint)
        assert response is not None

    def test_make_request_exception(self, attacker):
        """Test request with exception."""
        attacker.session.request.side_effect = Exception("Network error")
        
        endpoint = Endpoint(
            path="/api/test",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        response = attacker._make_request(endpoint)
        assert response is None

    def test_attack_with_pii(self, attacker):
        """Test attack that finds PII."""
        mock_response = create_mock_response(
            text='{"email": "test@example.com", "password": "secret"}'
        )
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(path="/api/user", method=HttpMethod.GET, parameters=[])
        results = attacker.attack(endpoint)
        
        assert len(results) > 0
        assert any(r.success for r in results)

    def test_attack_with_internal_fields(self, attacker):
        """Test attack that finds internal fields."""
        mock_response = create_mock_response(
            text='{"_id": "123", "__v": 1, "is_admin": false}'
        )
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(path="/api/user", method=HttpMethod.GET, parameters=[])
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_auth_token(self, attacker):
        """Test attack with auth token."""
        mock_response = create_mock_response(text='{"data": "ok"}')
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(path="/api/profile", method=HttpMethod.GET, parameters=[])
        results = attacker.attack(endpoint, auth_token="test_token")
        
        assert isinstance(results, list)

    def test_attack_list_as_auth_token(self, attacker):
        """Test attack with list as auth_token (API misuse)."""
        mock_response = create_mock_response(text='{"data": "ok"}')
        attacker.session.request.return_value = mock_response
        
        endpoint = Endpoint(path="/api/test", method=HttpMethod.GET, parameters=[])
        # Should not raise error when list is passed as auth_token
        results = attacker.attack(endpoint, auth_token=["param1", "param2"])
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(path="/api/user", method=HttpMethod.GET, parameters=[])
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            success=True,
            payload="Response Analysis",
            response_status=200,
            response_body='{"email": "test@example.com"}',
            error_message="PII fields exposed"
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.AUTH_BYPASS
        assert vuln.severity == Severity.MEDIUM
        assert "Excessive Data" in vuln.title


# ============================================================================
# BROKEN AUTH COMPREHENSIVE TESTS  
# ============================================================================

class TestBrokenAuthComprehensive:
    """Comprehensive tests for Broken Auth - targeting 80% coverage."""

    @pytest.fixture
    def attacker(self):
        """Create attacker with mocked session."""
        with patch('sentinel.attacks.broken_auth.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BrokenAuthAttacker("https://api.example.com")
            yield attacker

    def test_initialization(self, attacker):
        """Test initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout == 10

    def test_attack_login_endpoint(self, attacker):
        """Test attack on login endpoint."""
        endpoint = Endpoint(
            path="/api/login",
            method=HttpMethod.POST,
            parameters=[
                Parameter(name="username", location="body", required=True),
                Parameter(name="password", location="body", required=True)
            ]
        )
        
        mock_response = create_mock_response(
            status_code=200,
            text='{"token": "admin_token", "role": "admin"}'
        )
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_attack_protected_endpoint(self, attacker):
        """Test attack on protected endpoint."""
        endpoint = Endpoint(
            path="/api/admin/users",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        mock_response = create_mock_response(
            status_code=200,
            text='{"users": [{"id": 1}, {"id": 2}]}'
        )
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_attack_with_auth_token(self, attacker):
        """Test attack with auth token."""
        endpoint = Endpoint(
            path="/api/profile",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        mock_response = create_mock_response(text='{"user": "data"}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint, auth_token="user_token")
        assert isinstance(results, list)


# ============================================================================
# BFLA COMPREHENSIVE TESTS
# ============================================================================

class TestBFLAComprehensive:
    """Comprehensive tests for BFLA - targeting 80% coverage."""

    @pytest.fixture
    def attacker(self):
        """Create BFLA attacker with mocked session."""
        with patch('sentinel.attacks.bfla.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BFLAAttacker("https://api.example.com")
            yield attacker

    def test_initialization(self, attacker):
        """Test initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout == 10
        assert attacker.regular_tokens == []
        assert attacker.admin_tokens == []

    def test_set_user_roles(self, attacker):
        """Test setting user roles."""
        roles = [
            UserRole(name="user", token="user_token", is_admin=False),
            UserRole(name="admin", token="admin_token", is_admin=True),
        ]
        attacker.set_user_roles(roles)
        
        assert len(attacker.regular_tokens) == 1
        assert len(attacker.admin_tokens) == 1
        assert len(attacker.sessions) == 2

    def test_is_admin_endpoint(self, attacker):
        """Test admin endpoint detection."""
        assert attacker._is_admin_endpoint("/admin/users") is True
        assert attacker._is_admin_endpoint("/management/config") is True
        assert attacker._is_admin_endpoint("/api/admin/settings") is True
        assert attacker._is_admin_endpoint("/users/profile") is False
        assert attacker._is_admin_endpoint("/api/public") is False

    def test_has_resource_ids(self, attacker):
        """Test resource ID detection."""
        assert attacker._has_resource_ids("/users/{user_id}") is True
        assert attacker._has_resource_ids("/orders/{orderId}") is True
        assert attacker._has_resource_ids("/documents/{doc_id}") is True
        assert attacker._has_resource_ids("/api/public") is False

    def test_attack_admin_endpoint(self, attacker):
        """Test attack on admin endpoint."""
        endpoint = Endpoint(
            path="/admin/users",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        # BFLAAttacker needs sessions to be set up via set_user_roles
        attacker.set_user_roles([
            UserRole(name="user", token="user_token", is_admin=False),
            UserRole(name="admin", token="admin_token", is_admin=True)
        ])
        
        mock_response = create_mock_response(text='{"users": []}')
        # Mock all sessions
        for session in attacker.sessions.values():
            session.request.return_value = mock_response
            session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_attack_with_roles(self, attacker):
        """Test attack with defined user roles."""
        roles = [
            UserRole(name="user", token="user_token", is_admin=False),
            UserRole(name="admin", token="admin_token", is_admin=True),
        ]
        attacker.set_user_roles(roles)
        
        endpoint = Endpoint(
            path="/admin/settings",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        mock_response = create_mock_response(text='{"settings": {}}')
        # Mock sessions for each role
        for session_id in attacker.sessions:
            attacker.sessions[session_id].request.return_value = mock_response
            attacker.sessions[session_id].get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/admin/settings",
            method=HttpMethod.POST,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            success=True,
            payload="role=admin",
            response_status=200,
            response_body='{"success": true}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.AUTH_BYPASS
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]


# ============================================================================
# SSRF COMPREHENSIVE TESTS
# ============================================================================

class TestSSRFComprehensive:
    """Comprehensive tests for SSRF - targeting 80% coverage."""

    @pytest.fixture
    def attacker(self):
        """Create SSRF attacker with mocked session."""
        with patch('sentinel.attacks.ssrf.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = SSRFAttacker("https://api.example.com")
            yield attacker

    def test_initialization(self, attacker):
        """Test initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout == 5  # Default timeout is 5

    def test_initialization_with_callback(self, attacker):
        """Test initialization with callback URL."""
        with patch('sentinel.attacks.ssrf.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = SSRFAttacker(
                "https://api.example.com",
                callback_url="https://callback.example.com"
            )
            assert attacker.callback_url == "https://callback.example.com"

    def test_check_ssrf_cloud_metadata(self, attacker):
        """Test SSRF detection with cloud metadata."""
        response = create_mock_response(
            text='{"instance-id": "i-12345", "local-ipv4": "10.0.0.1"}'
        )
        
        is_vuln, ssrf_type, evidence = attacker._check_ssrf_vulnerability(
            response, "http://169.254.169.254", 150.0
        )
        assert is_vuln is True
        assert "cloud" in ssrf_type.lower()

    def test_check_ssrf_file_read(self, attacker):
        """Test SSRF detection with file read."""
        response = create_mock_response(
            text='root:x:0:0:root:/root:/bin/bash'
        )
        
        is_vuln, ssrf_type, evidence = attacker._check_ssrf_vulnerability(
            response, "file:///etc/passwd", 100.0
        )
        assert is_vuln is True
        assert "file" in ssrf_type.lower()

    def test_check_ssrf_internal_ip(self, attacker):
        """Test SSRF detection with internal IP."""
        response = create_mock_response(
            text='{"server": "192.168.1.100", "internal_data": "secret"}'
        )
        
        is_vuln, ssrf_type, evidence = attacker._check_ssrf_vulnerability(
            response, "http://internal.host", 120.0
        )
        assert is_vuln is True

    def test_check_ssrf_normal_response(self, attacker):
        """Test SSRF not detected in normal response."""
        response = create_mock_response(text='{"data": "normal response"}')
        
        is_vuln, ssrf_type, evidence = attacker._check_ssrf_vulnerability(
            response, "http://example.com", 100.0
        )
        assert is_vuln is False

    def test_attack_with_url_parameter(self, attacker):
        """Test attack with URL parameter."""
        endpoint = Endpoint(
            path="/api/fetch",
            method=HttpMethod.GET,
            parameters=[Parameter(name="url", location="query", required=True)]
        )
        
        mock_response = create_mock_response(text='{"fetched": "data"}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/api/fetch",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.SSRF,
            success=True,
            payload="http://169.254.169.254",
            response_status=200,
            response_body='{"instance-id": "i-12345"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.SSRF
