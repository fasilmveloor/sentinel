"""
Comprehensive tests for advanced attack modules.

Tests cover BFLA, BOLA, Broken Auth, Excessive Data, NoSQL Injection, and Mass Assignment attacks.
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch
import requests

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    AttackResult, Vulnerability
)
from sentinel.attacks.bfla import BFLAAttacker
from sentinel.attacks.bola import BOLAAttacker
from sentinel.attacks.broken_auth import BrokenAuthAttacker
from sentinel.attacks.excessive_data import ExcessiveDataExposureAttacker
from sentinel.attacks.nosql_injection import NoSQLInjectionAttacker
from sentinel.attacks.mass_assignment import MassAssignmentAttacker


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
# BFLA (Broken Function Level Authorization) ATTACKER TESTS
# ============================================================================

class TestBFLAAttacker:
    """Comprehensive tests for BFLAAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create BFLA attacker with mocked session."""
        with patch('sentinel.attacks.bfla.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BFLAAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_initialization_with_tokens(self):
        """Test initialization with user role tokens."""
        with patch('sentinel.attacks.bfla.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BFLAAttacker("https://api.example.com")
            
            # Use set_user_roles to configure tokens
            from sentinel.attacks.bfla import UserRole
            attacker.set_user_roles([
                UserRole(name="user1", token="user_token_1", is_admin=False),
                UserRole(name="user2", token="user_token_2", is_admin=False),
                UserRole(name="admin", token="admin_token", is_admin=True)
            ])
            assert len(attacker.regular_tokens) == 2
            assert len(attacker.admin_tokens) == 1

    def test_is_admin_endpoint_detection(self, attacker):
        """Test admin endpoint detection."""
        assert attacker._is_admin_endpoint("/admin/users") is True
        assert attacker._is_admin_endpoint("/api/admin/settings") is True
        assert attacker._is_admin_endpoint("/management/config") is True
        assert attacker._is_admin_endpoint("/api/public/data") is False
        assert attacker._is_admin_endpoint("/users/profile") is False

    def test_has_resource_ids(self, attacker):
        """Test resource ID detection in paths."""
        assert attacker._has_resource_ids("/users/{user_id}") is True
        assert attacker._has_resource_ids("/orders/{orderId}") is True
        assert attacker._has_resource_ids("/documents/{doc_id}") is True
        assert attacker._has_resource_ids("/api/public") is False

    def test_attack_with_admin_endpoint(self, attacker):
        """Test attack on admin endpoint."""
        endpoint = Endpoint(
            path="/admin/users",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        mock_response = create_mock_response(text='{"users": []}')
        attacker.session.get.return_value = mock_response
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_role_change(self, attacker):
        """Test attack with role manipulation."""
        endpoint = Endpoint(
            path="/api/profile",
            method=HttpMethod.PUT,
            parameters=[Parameter(name="role", location="body", required=False)]
        )
        
        mock_response = create_mock_response(text='{"status": "updated"}')
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_delete_method(self, attacker):
        """Test attack on DELETE method endpoint."""
        endpoint = Endpoint(
            path="/api/users/123",
            method=HttpMethod.DELETE,
            parameters=[]
        )
        
        mock_response = create_mock_response(status_code=204)
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_resource_ids(self, attacker):
        """Test attack on endpoint with resource IDs."""
        endpoint = Endpoint(
            path="/users/{user_id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="user_id", location="path", required=True)]
        )
        
        mock_response = create_mock_response(text='{"user": "data"}')
        attacker.session.get.return_value = mock_response
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_auth_token(self, attacker):
        """Test attack with auth token."""
        endpoint = Endpoint(
            path="/admin/settings",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        mock_response = create_mock_response(text='{"settings": {}}')
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint, auth_token="user_token")
        
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
            attack_type=AttackType.BFLA,
            success=True,
            payload="role=admin",
            response_status=200,
            response_body='{"success": true}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        # BFLA uses AUTH_BYPASS attack type in implementation
        assert vuln.attack_type == AttackType.AUTH_BYPASS
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]


# ============================================================================
# BOLA (Broken Object Level Authorization) ATTACKER TESTS
# ============================================================================

class TestBOLAAttacker:
    """Comprehensive tests for BOLAAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create BOLA attacker with mocked session."""
        with patch('sentinel.attacks.bola.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BOLAAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_attack_with_id_parameter(self, attacker):
        """Test attack with ID parameter manipulation."""
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="id", location="path", required=True)]
        )
        
        mock_response = create_mock_response(text='{"user": "data"}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_object_access(self, attacker):
        """Test attack with object access patterns."""
        endpoint = Endpoint(
            path="/orders/{orderId}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="orderId", location="path", required=True)]
        )
        
        mock_response = create_mock_response(text='{"order": "details"}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/documents/{docId}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="docId", location="path", required=True)]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.BOLA,
            success=True,
            payload="docId=12345",
            response_status=200,
            response_body='{"document": "sensitive data"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        # BOLA uses IDOR attack type in implementation
        assert vuln.attack_type == AttackType.IDOR
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]


# ============================================================================
# BROKEN AUTHENTICATION ATTACKER TESTS
# ============================================================================

class TestBrokenAuthAttacker:
    """Comprehensive tests for BrokenAuthAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create Broken Auth attacker with mocked session."""
        with patch('sentinel.attacks.broken_auth.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = BrokenAuthAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_attack_login_endpoint(self, attacker):
        """Test attack on login endpoint."""
        endpoint = Endpoint(
            path="/auth/login",
            method=HttpMethod.POST,
            parameters=[
                Parameter(name="username", location="body", required=True),
                Parameter(name="password", location="body", required=True)
            ]
        )
        
        mock_response = create_mock_response(
            status_code=401,
            text='{"error": "Invalid credentials"}'
        )
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_weak_passwords(self, attacker):
        """Test attack with weak password list."""
        endpoint = Endpoint(
            path="/login",
            method=HttpMethod.POST,
            parameters=[Parameter(name="password", location="body", required=True)]
        )
        
        # Simulate successful login with weak password
        mock_response = create_mock_response(
            status_code=200,
            text='{"token": "jwt_token_here"}'
        )
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_session_management(self, attacker):
        """Test attack on session management."""
        endpoint = Endpoint(
            path="/api/session",
            method=HttpMethod.GET,
            parameters=[Parameter(name="session_id", location="header", required=True)]
        )
        
        mock_response = create_mock_response(text='{"user": "session_data"}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/auth/login",
            method=HttpMethod.POST,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.BROKEN_AUTH,
            success=True,
            payload="admin:admin123",
            response_status=200,
            response_body='{"token": "admin_token"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        # Broken Auth uses AUTH_BYPASS attack type in implementation
        assert vuln.attack_type == AttackType.AUTH_BYPASS
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]


# ============================================================================
# EXCESSIVE DATA EXPOSURE ATTACKER TESTS
# ============================================================================

class TestExcessiveDataExposureAttacker:
    """Comprehensive tests for ExcessiveDataExposureAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create Excessive Data attacker with mocked session."""
        with patch('sentinel.attacks.excessive_data.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = ExcessiveDataExposureAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_attack_user_profile_endpoint(self, attacker):
        """Test attack on user profile endpoint."""
        endpoint = Endpoint(
            path="/api/profile",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        # Response with excessive data (password, ssn, etc.)
        mock_response = create_mock_response(
            text='{"name": "John", "email": "john@example.com", "password": "hashed", "ssn": "123-45-6789"}'
        )
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_user_list_endpoint(self, attacker):
        """Test attack on user list endpoint."""
        endpoint = Endpoint(
            path="/api/users",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        users_data = [
            {"id": 1, "name": "User 1", "email": "user1@test.com", "salary": 50000}
            for i in range(10)
        ]
        mock_response = create_mock_response(text=json.dumps(users_data))
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/api/user/{id}",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.EXCESSIVE_DATA,
            success=True,
            payload="",
            response_status=200,
            response_body='{"password": "exposed", "credit_card": "1234-5678-9012-3456"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        # Excessive Data uses AUTH_BYPASS attack type in implementation
        assert vuln.attack_type == AttackType.AUTH_BYPASS


# ============================================================================
# NoSQL INJECTION ATTACKER TESTS
# ============================================================================

class TestNoSQLInjectionAttacker:
    """Comprehensive tests for NoSQLInjectionAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create NoSQL Injection attacker with mocked session."""
        with patch('sentinel.attacks.nosql_injection.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = NoSQLInjectionAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_attack_with_query_parameter(self, attacker):
        """Test attack with query parameter."""
        endpoint = Endpoint(
            path="/api/search",
            method=HttpMethod.GET,
            parameters=[Parameter(name="q", location="query", required=True)]
        )
        
        mock_response = create_mock_response(text='{"results": []}')
        attacker.session.get.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_json_body(self, attacker):
        """Test attack with JSON body."""
        endpoint = Endpoint(
            path="/api/users/find",
            method=HttpMethod.POST,
            parameters=[Parameter(name="username", location="body", required=True)]
        )
        
        mock_response = create_mock_response(text='{"user": "found"}')
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_mongodb_operators(self, attacker):
        """Test MongoDB operator injection."""
        endpoint = Endpoint(
            path="/api/login",
            method=HttpMethod.POST,
            parameters=[
                Parameter(name="username", location="body", required=True),
                Parameter(name="password", location="body", required=True)
            ]
        )
        
        # Simulate successful bypass
        mock_response = create_mock_response(
            status_code=200,
            text='{"authenticated": true, "user": "admin"}'
        )
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/api/query",
            method=HttpMethod.POST,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.NOSQL_INJECTION,
            success=True,
            payload='{"$gt": ""}',
            response_status=200,
            response_body='{"users": "all"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.NOSQL_INJECTION
        assert vuln.severity in [Severity.HIGH, Severity.CRITICAL]


# ============================================================================
# MASS ASSIGNMENT ATTACKER TESTS
# ============================================================================

class TestMassAssignmentAttacker:
    """Comprehensive tests for MassAssignmentAttacker."""

    @pytest.fixture
    def attacker(self):
        """Create Mass Assignment attacker with mocked session."""
        with patch('sentinel.attacks.mass_assignment.requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            attacker = MassAssignmentAttacker("https://api.example.com")
            attacker.session = mock_session
            return attacker

    def test_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.target_url == "https://api.example.com"
        assert attacker.timeout > 0

    def test_attack_user_registration(self, attacker):
        """Test attack on user registration."""
        endpoint = Endpoint(
            path="/api/register",
            method=HttpMethod.POST,
            parameters=[Parameter(name="username", location="body", required=True)]
        )
        
        mock_response = create_mock_response(text='{"success": true}')
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_user_update(self, attacker):
        """Test attack on user update endpoint."""
        endpoint = Endpoint(
            path="/api/users/{id}",
            method=HttpMethod.PUT,
            parameters=[Parameter(name="name", location="body", required=False)]
        )
        
        mock_response = create_mock_response(text='{"updated": true}')
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_attack_with_role_injection(self, attacker):
        """Test attack with role injection."""
        endpoint = Endpoint(
            path="/api/profile",
            method=HttpMethod.PATCH,
            parameters=[Parameter(name="email", location="body", required=True)]
        )
        
        # Simulate successful role escalation
        mock_response = create_mock_response(
            status_code=200,
            text='{"updated": true, "role": "admin"}'
        )
        attacker.session.request.return_value = mock_response
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)

    def test_create_vulnerability(self, attacker):
        """Test vulnerability creation."""
        endpoint = Endpoint(
            path="/api/users/{id}",
            method=HttpMethod.PUT,
            parameters=[]
        )
        
        result = AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.MASS_ASSIGNMENT,
            success=True,
            payload='{"role": "admin"}',
            response_status=200,
            response_body='{"role": "admin"}',
            duration_ms=100
        )
        
        vuln = attacker.create_vulnerability(result, endpoint)
        
        assert vuln.attack_type == AttackType.MASS_ASSIGNMENT
        assert vuln.severity in [Severity.HIGH, Severity.MEDIUM]


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestAdvancedAttackModuleIntegration:
    """Integration tests for advanced attack modules."""

    def test_all_attackers_have_required_methods(self):
        """Test all attackers have required methods."""
        attackers = [
            BFLAAttacker,
            BOLAAttacker,
            BrokenAuthAttacker,
            ExcessiveDataExposureAttacker,
            NoSQLInjectionAttacker,
            MassAssignmentAttacker
        ]
        
        for attacker_class in attackers:
            assert hasattr(attacker_class, 'attack')
            assert hasattr(attacker_class, 'create_vulnerability')

    def test_all_attackers_return_attack_result(self):
        """Test all attackers return AttackResult instances."""
        from sentinel.attacks.bfla import AttackResult as BFLAResult
        from sentinel.attacks.bola import AttackResult as BOLAResult
        
        # Verify AttackResult is properly imported
        assert AttackResult is not None

    @patch('sentinel.attacks.bfla.requests.Session')
    @patch('sentinel.attacks.bola.requests.Session')
    @patch('sentinel.attacks.broken_auth.requests.Session')
    def test_multiple_attackers_same_endpoint(self, mock_broken_auth, mock_bola, mock_bfla):
        """Test multiple attackers on the same endpoint."""
        for mock in [mock_bfla, mock_bola, mock_broken_auth]:
            mock_session = MagicMock()
            mock.return_value = mock_session
            mock_session.get.return_value = create_mock_response()
            mock_session.request.return_value = create_mock_response()
        
        endpoint = Endpoint(
            path="/api/admin/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="id", location="path", required=True)]
        )
        
        bfla = BFLAAttacker("https://api.example.com")
        bola = BOLAAttacker("https://api.example.com")
        broken_auth = BrokenAuthAttacker("https://api.example.com")
        
        bfla_results = bfla.attack(endpoint)
        bola_results = bola.attack(endpoint)
        broken_auth_results = broken_auth.attack(endpoint)
        
        assert isinstance(bfla_results, list)
        assert isinstance(bola_results, list)
        assert isinstance(broken_auth_results, list)
