"""
Unit tests for Sentinel IDOR Attack Module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import httpx

from sentinel.attacks.idor import IDORAttacker
from sentinel.models import Endpoint, HttpMethod, AttackType, Severity, Parameter, AttackResult


# ==================== Fixtures ====================

@pytest.fixture
def idor_attacker():
    """Create IDOR attacker instance."""
    return IDORAttacker("http://localhost:8000", timeout=5)


@pytest.fixture
def sample_endpoint():
    """Create sample endpoint with ID parameter."""
    return Endpoint(
        path="/users/{id}",
        method=HttpMethod.GET,
        parameters=[
            Parameter(name="id", location="path", required=True, param_type="integer")
        ]
    )


@pytest.fixture
def endpoint_with_query_id():
    """Create endpoint with query parameter ID."""
    return Endpoint(
        path="/api/profile",
        method=HttpMethod.GET,
        parameters=[
            Parameter(name="user_id", location="query", required=False, param_type="integer")
        ]
    )


# ==================== IDORAttacker Tests ====================

class TestIDORAttacker:
    """Tests for IDOR attacker."""
    
    def test_create_attacker(self, idor_attacker):
        """Test creating IDOR attacker."""
        assert idor_attacker is not None
        assert idor_attacker.target_url == "http://localhost:8000"
    
    def test_attacker_has_attack_method(self, idor_attacker):
        """Test that attacker has attack method."""
        assert hasattr(idor_attacker, 'attack')
    
    def test_attacker_has_create_vulnerability(self, idor_attacker):
        """Test that attacker has create_vulnerability method."""
        assert hasattr(idor_attacker, 'create_vulnerability')
    
    def test_attacker_has_id_patterns(self, idor_attacker):
        """Test that attacker has ID patterns."""
        assert hasattr(idor_attacker, 'ID_PATTERNS')
    
    def test_attacker_has_id_param_names(self, idor_attacker):
        """Test that attacker has ID parameter names."""
        assert hasattr(idor_attacker, 'ID_PARAM_NAMES')
    
    def test_attacker_has_session(self, idor_attacker):
        """Test that attacker has httpx session."""
        assert hasattr(idor_attacker, 'session')
    
    def test_attacker_has_timeout(self, idor_attacker):
        """Test that attacker has timeout."""
        assert idor_attacker.timeout == 5
    
    @patch('httpx.Client.request')
    def test_attack_with_path_param(self, mock_request, idor_attacker, sample_endpoint):
        """Test attack with path parameter."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 1, "name": "User"}
        mock_response.text = '{"id": 1, "name": "User"}'
        mock_request.return_value = mock_response
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_attack_returns_results(self, mock_request, idor_attacker, sample_endpoint):
        """Test that attack returns results."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.text = '{"data": "test"}'
        mock_request.return_value = mock_response
        
        results = idor_attacker.attack(sample_endpoint)
        
        assert isinstance(results, list)
    
    def test_create_vulnerability(self, idor_attacker, sample_endpoint):
        """Test creating vulnerability from attack result."""
        result = AttackResult(
            endpoint=sample_endpoint,
            attack_type=AttackType.IDOR,
            payload="id=2",
            success=True,
            response_status=200,
            response_body='{"id": 2, "name": "Other User"}'
        )
        
        vuln = idor_attacker.create_vulnerability(result, sample_endpoint)
        
        assert vuln is not None
        assert vuln.attack_type == AttackType.IDOR


# ==================== Edge Cases ====================

class TestIDOREdgeCases:
    """Tests for edge cases in IDOR attacks."""
    
    def test_empty_endpoint(self, idor_attacker):
        """Test with empty endpoint."""
        endpoint = Endpoint(
            path="/test",
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = list(idor_attacker.attack(endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_error_response(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling error response."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_request.return_value = mock_response
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_unauthorized_response(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling 401 response."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_request.return_value = mock_response
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_forbidden_response(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling 403 response."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_request.return_value = mock_response
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_not_found_response(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling 404 response."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_request.return_value = mock_response
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_timeout_handling(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling timeout."""
        mock_request.side_effect = httpx.TimeoutException("Timeout")
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        # Should handle gracefully
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_connection_error(self, mock_request, idor_attacker, sample_endpoint):
        """Test handling connection error."""
        mock_request.side_effect = httpx.ConnectError("Connection failed")
        
        results = list(idor_attacker.attack(sample_endpoint))
        
        # Should handle gracefully
        assert isinstance(results, list)


# ==================== ID Parameter Detection Tests ====================

class TestIDPatterns:
    """Tests for ID pattern matching."""
    
    def test_id_param_names_exist(self, idor_attacker):
        """Test ID param names are defined."""
        assert idor_attacker.ID_PARAM_NAMES is not None
        assert isinstance(idor_attacker.ID_PARAM_NAMES, (list, set, tuple))
    
    def test_id_patterns_exist(self, idor_attacker):
        """Test ID patterns are defined."""
        assert idor_attacker.ID_PATTERNS is not None


# ==================== Multiple Endpoint Tests ====================

class TestMultipleEndpoints:
    """Tests for multiple endpoint scenarios."""
    
    @patch('httpx.Client.request')
    def test_post_endpoint(self, mock_request, idor_attacker):
        """Test POST endpoint."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.text = '{"id": 1}'
        mock_request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/users",
            method=HttpMethod.POST,
            parameters=[]
        )
        
        results = list(idor_attacker.attack(endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_put_endpoint(self, mock_request, idor_attacker):
        """Test PUT endpoint."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"id": 1}'
        mock_request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.PUT,
            parameters=[Parameter(name="id", location="path", required=True)]
        )
        
        results = list(idor_attacker.attack(endpoint))
        
        assert isinstance(results, list)
    
    @patch('httpx.Client.request')
    def test_delete_endpoint(self, mock_request, idor_attacker):
        """Test DELETE endpoint."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ''
        mock_request.return_value = mock_response
        
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.DELETE,
            parameters=[Parameter(name="id", location="path", required=True)]
        )
        
        results = list(idor_attacker.attack(endpoint))
        
        assert isinstance(results, list)
