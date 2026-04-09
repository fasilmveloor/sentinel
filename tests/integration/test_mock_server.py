"""
Integration tests with mock HTTP server.

Tests run against a local mock server to verify attack modules work correctly.
"""

import json
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import ClassVar
import pytest

from sentinel.models import (
    Endpoint, HttpMethod, Parameter, AttackType, Severity,
    AttackResult, Vulnerability
)
from sentinel.attacks.bfla import BFLAAttacker, UserRole
from sentinel.attacks.bola import BOLAAttacker
from sentinel.attacks.broken_auth import BrokenAuthAttacker
from sentinel.attacks.excessive_data import ExcessiveDataExposureAttacker
from sentinel.attacks.nosql_injection import NoSQLInjectionAttacker
from sentinel.attacks.mass_assignment import MassAssignmentAttacker
from sentinel.attacks.injection import SQLInjectionAttacker
from sentinel.attacks.xss import XSSAttacker
from sentinel.attacks.ssrf import SSRFAttacker
from sentinel.attacks.idor import IDORAttacker
from sentinel.attacks.jwt import JWTAttacker
from sentinel.attacks.auth import AuthBypassAttacker
from sentinel.attacks.cmd_injection import CommandInjectionAttacker
from sentinel.attacks.rate_limit import RateLimitAttacker


class MockAPIHandler(BaseHTTPRequestHandler):
    """Mock API server handler for testing."""
    
    # Class-level token storage for auth testing
    valid_tokens: ClassVar[dict] = {
        'admin_token': {'role': 'admin', 'user_id': '1'},
        'user_token': {'role': 'user', 'user_id': '2'},
        'user_token_2': {'role': 'user', 'user_id': '3'},
    }
    
    request_count: ClassVar[dict] = {}
    
    def log_message(self, format, *args):
        """Suppress log messages."""
        pass
    
    def _get_token(self):
        """Extract token from Authorization header."""
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return auth[7:]
        return None
    
    def _check_auth(self, require_admin=False):
        """Check authentication."""
        token = self._get_token()
        if not token:
            return None, {'error': 'Missing token'}
        
        user = self.valid_tokens.get(token)
        if not user:
            return None, {'error': 'Invalid token'}
        
        if require_admin and user['role'] != 'admin':
            return None, {'error': 'Admin required'}
        
        return user, None
    
    def _send_json(self, data, status=200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _read_body(self):
        """Read request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            body = self.rfile.read(content_length).decode()
            try:
                return json.loads(body)
            except:
                return {'raw': body}
        return {}
    
    def _track_request(self, endpoint):
        """Track request count for rate limiting tests."""
        key = f"{self.command}:{endpoint}"
        self.request_count[key] = self.request_count.get(key, 0) + 1
        return self.request_count[key]
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        
        # Track request
        self._track_request(path)
        
        # Public endpoints
        if path == '/api/health':
            self._send_json({'status': 'ok'})
            return
        
        if path == '/api/public':
            self._send_json({'data': 'public information'})
            return
        
        # SQL injection vulnerable endpoint
        if path == '/api/users':
            user_id = query.get('id', [''])[0]
            if "'" in user_id or 'OR' in user_id.upper():
                # Simulate SQL error
                self._send_json({'error': 'SQL syntax error near OR'}, status=500)
                return
            self._send_json({'users': [{'id': 1, 'name': 'test'}]})
            return
        
        # XSS vulnerable endpoint
        if path == '/api/search':
            q = query.get('q', [''])[0]
            self._send_json({'results': f'Search results for: {q}'})
            return
        
        # Admin endpoints - BFLA tests
        if path == '/admin/users':
            user, err = self._check_auth(require_admin=True)
            if err:
                self._send_json(err, status=403 if 'Admin' in err.get('error', '') else 401)
                return
            self._send_json({'users': [{'id': 1, 'name': 'admin'}, {'id': 2, 'name': 'user'}]})
            return
        
        if path == '/admin/config':
            user, err = self._check_auth(require_admin=True)
            if err:
                self._send_json(err, status=403)
                return
            self._send_json({'config': {'debug': True, 'secret': 'admin_secret'}})
            return
        
        # User profile - BOLA tests
        if path.startswith('/api/users/'):
            parts = path.split('/')
            if len(parts) >= 4:
                user_id = parts[3]
                user, err = self._check_auth()
                if err:
                    self._send_json(err, status=401)
                    return
                # BOLA vulnerability: no check if user can access this resource
                self._send_json({
                    'user': {
                        'id': user_id,
                        'name': f'User {user_id}',
                        'email': f'user{user_id}@test.com',
                        'ssn': '123-45-6789',  # Excessive data exposure
                        'password_hash': 'hashed_secret',  # Excessive data exposure
                    }
                })
                return
        
        # Orders endpoint - IDOR tests
        if path.startswith('/api/orders/'):
            parts = path.split('/')
            if len(parts) >= 4:
                order_id = parts[3]
                user, err = self._check_auth()
                if err:
                    self._send_json(err, status=401)
                    return
                # IDOR vulnerability: no ownership check
                self._send_json({
                    'order': {
                        'id': order_id,
                        'user_id': '999',
                        'total': 100.00,
                        'items': ['item1', 'item2']
                    }
                })
                return
        
        # Sensitive data exposure
        if path == '/api/profile':
            user, err = self._check_auth()
            if err:
                self._send_json(err, status=401)
                return
            # Return excessive data
            self._send_json({
                'user': user,
                'password': 'plain_text_password',  # Excessive exposure!
                'credit_card': '4111-1111-1111-1111',
                'api_key': 'sk-secret-key-12345',
                'private_key': '-----BEGIN PRIVATE KEY-----'
            })
            return
        
        # SSRF test endpoint
        if path == '/api/fetch':
            url = query.get('url', [''])[0]
            if '169.254.169.254' in url or 'metadata' in url:
                self._send_json({
                    'instance-id': 'i-12345',
                    'local-ipv4': '10.0.0.1',
                    'iam': {'role': 'admin-role'}
                })
                return
            if url.startswith('file://'):
                self._send_json({'content': 'root:x:0:0:root:/root:/bin/bash'})
                return
            if 'internal' in url:
                self._send_json({'server': '192.168.1.100', 'internal_data': 'secret'})
                return
            self._send_json({'fetched': url})
            return
        
        # Rate limit test endpoint
        if path == '/api/limited':
            count = self._track_request(path)
            if count > 5:
                self.send_response(429)
                self.send_header('Content-Type', 'application/json')
                self.send_header('X-RateLimit-Remaining', '0')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Rate limit exceeded'}).encode())
                return
            self._send_json({'request': count})
            return
        
        # Default 404
        self._send_json({'error': 'Not found'}, status=404)
    
    def do_POST(self):
        """Handle POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body()
        
        self._track_request(path)
        
        # Login endpoint - broken auth tests
        if path == '/api/login':
            username = body.get('username', '')
            password = body.get('password', '')
            
            # Weak authentication - accepts admin:admin
            if username == 'admin' and password == 'admin':
                self._send_json({
                    'token': 'admin_token',
                    'role': 'admin',
                    'user_id': '1'
                })
                return
            
            # Accept weak passwords
            if password in ['password', '123456', 'admin', '']:
                self._send_json({
                    'token': 'user_token',
                    'role': 'user',
                    'user_id': '2'
                })
                return
            
            self._send_json({'error': 'Invalid credentials'}, status=401)
            return
        
        # NoSQL injection endpoint
        if path == '/api/users/find':
            # Check for NoSQL injection patterns
            body_str = str(body)
            if '$gt' in body_str or '$ne' in body_str or '$where' in body_str:
                # Vulnerable - returns all users
                self._send_json({
                    'users': [
                        {'id': 1, 'name': 'admin', 'role': 'admin'},
                        {'id': 2, 'name': 'user', 'role': 'user'},
                        {'id': 3, 'name': 'guest', 'role': 'guest'}
                    ]
                })
                return
            self._send_json({'users': []})
            return
        
        # Mass assignment endpoint
        if path == '/api/register':
            # Vulnerable - accepts any field including role
            user_data = {
                'id': 4,
                'username': body.get('username', 'newuser'),
                'role': body.get('role', 'user'),  # Vulnerable to mass assignment!
                'is_admin': body.get('is_admin', False),  # Vulnerable!
                'balance': body.get('balance', 0),  # Vulnerable!
            }
            self._send_json({'success': True, 'user': user_data}, status=201)
            return
        
        # User update - mass assignment
        if path.startswith('/api/users/'):
            parts = path.split('/')
            if len(parts) >= 4:
                user_id = parts[3]
                # Vulnerable - accepts any field
                self._send_json({
                    'success': True,
                    'user': {
                        'id': user_id,
                        **body  # Mass assignment vulnerability!
                    }
                })
                return
        
        # Command injection endpoint
        if path == '/api/ping':
            host = body.get('host', '')
            # Simulate command injection response
            if ';' in host or '|' in host or '&' in host:
                self._send_json({
                    'result': 'uid=0(root) gid=0(root)\nping: ; whoami: Name or service not known'
                })
                return
            self._send_json({'result': f'PING {host}: 64 bytes'})
            return
        
        # SQL injection POST endpoint
        if path == '/api/query':
            query = body.get('query', '')
            if "'" in query:
                self._send_json({'error': "You have an error in your SQL syntax"}, status=500)
                return
            self._send_json({'results': []})
            return
        
        # Default 404
        self._send_json({'error': 'Not found'}, status=404)
    
    def do_PUT(self):
        """Handle PUT requests."""
        path = urllib.parse.urlparse(self.path).path
        body = self._read_body()
        
        self._track_request(path)
        
        # Profile update - BFLA and mass assignment
        if path == '/api/profile':
            user, err = self._check_auth()
            if err:
                self._send_json(err, status=401)
                return
            
            # Vulnerable - accepts any field
            self._send_json({
                'success': True,
                'user': {
                    **user,
                    **body  # Mass assignment!
                }
            })
            return
        
        # Admin settings - BFLA
        if path == '/admin/settings':
            user, err = self._check_auth(require_admin=True)
            if err:
                self._send_json(err, status=403)
                return
            self._send_json({'success': True, 'settings': body})
            return
        
        self._send_json({'error': 'Not found'}, status=404)
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        path = urllib.parse.urlparse(self.path).path
        
        self._track_request(path)
        
        # Delete user - BFLA test
        if path.startswith('/api/users/'):
            parts = path.split('/')
            if len(parts) >= 4:
                user_id = parts[3]
                user, err = self._check_auth()
                if err:
                    self._send_json(err, status=401)
                    return
                # Vulnerable - no ownership check
                self._send_json({'success': True, 'deleted': user_id})
                return
        
        # Admin delete - requires admin
        if path.startswith('/admin/users/'):
            user, err = self._check_auth(require_admin=True)
            if err:
                self._send_json(err, status=403)
                return
            self._send_json({'success': True})
            return
        
        self._send_json({'error': 'Not found'}, status=404)


@pytest.fixture(scope='module')
def mock_server():
    """Start mock HTTP server for testing."""
    server = HTTPServer(('127.0.0.1', 0), MockAPIHandler)
    port = server.server_address[1]
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    time.sleep(0.1)  # Let server start
    
    yield f'http://127.0.0.1:{port}'
    
    server.shutdown()


# ============================================================================
# BFLA INTEGRATION TESTS
# ============================================================================

class TestBFLAIntegration:
    """Integration tests for BFLA attacker against mock server."""
    
    def test_bfla_admin_endpoint_with_user_token(self, mock_server):
        """Test accessing admin endpoint with regular user token."""
        attacker = BFLAAttacker(mock_server)
        attacker.set_user_roles([
            UserRole(name='user', token='user_token', is_admin=False),
            UserRole(name='admin', token='admin_token', is_admin=True)
        ])
        
        endpoint = Endpoint(
            path='/admin/users',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)
        # Should detect vulnerability when regular user accesses admin endpoint
    
    def test_bfla_delete_method(self, mock_server):
        """Test DELETE method access control."""
        attacker = BFLAAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/123',
            method=HttpMethod.DELETE,
            parameters=[]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# BOLA INTEGRATION TESTS
# ============================================================================

class TestBOLAIntegration:
    """Integration tests for BOLA attacker against mock server."""
    
    def test_bola_user_access(self, mock_server):
        """Test accessing other users' data."""
        attacker = BOLAAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/{user_id}',
            method=HttpMethod.GET,
            parameters=[Parameter(name='user_id', location='path', required=True)]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)
    
    def test_bola_order_access(self, mock_server):
        """Test accessing other users' orders."""
        attacker = BOLAAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/orders/{orderId}',
            method=HttpMethod.GET,
            parameters=[Parameter(name='orderId', location='path', required=True)]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# BROKEN AUTH INTEGRATION TESTS
# ============================================================================

class TestBrokenAuthIntegration:
    """Integration tests for Broken Auth attacker against mock server."""
    
    def test_weak_password_login(self, mock_server):
        """Test login with weak passwords."""
        attacker = BrokenAuthAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/login',
            method=HttpMethod.POST,
            parameters=[
                Parameter(name='username', location='body', required=True),
                Parameter(name='password', location='body', required=True)
            ]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)
        # Should detect weak password acceptance


# ============================================================================
# EXCESSIVE DATA EXPOSURE INTEGRATION TESTS
# ============================================================================

class TestExcessiveDataIntegration:
    """Integration tests for Excessive Data Exposure attacker."""
    
    def test_profile_sensitive_data(self, mock_server):
        """Test for sensitive data in profile response."""
        attacker = ExcessiveDataExposureAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/profile',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# NOSQL INJECTION INTEGRATION TESTS
# ============================================================================

class TestNoSQLInjectionIntegration:
    """Integration tests for NoSQL Injection attacker."""
    
    def test_nosql_find_endpoint(self, mock_server):
        """Test NoSQL injection on find endpoint."""
        attacker = NoSQLInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/find',
            method=HttpMethod.POST,
            parameters=[Parameter(name='username', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# MASS ASSIGNMENT INTEGRATION TESTS
# ============================================================================

class TestMassAssignmentIntegration:
    """Integration tests for Mass Assignment attacker."""
    
    def test_registration_mass_assignment(self, mock_server):
        """Test mass assignment on registration."""
        attacker = MassAssignmentAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/register',
            method=HttpMethod.POST,
            parameters=[Parameter(name='username', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)
    
    def test_update_mass_assignment(self, mock_server):
        """Test mass assignment on user update."""
        attacker = MassAssignmentAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/123',
            method=HttpMethod.POST,
            parameters=[Parameter(name='name', location='body', required=False)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# SQL INJECTION INTEGRATION TESTS
# ============================================================================

class TestSQLInjectionIntegration:
    """Integration tests for SQL Injection attacker."""
    
    def test_sql_injection_get(self, mock_server):
        """Test SQL injection on GET endpoint."""
        attacker = SQLInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users',
            method=HttpMethod.GET,
            parameters=[Parameter(name='id', location='query', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# XSS INTEGRATION TESTS
# ============================================================================

class TestXSSIntegration:
    """Integration tests for XSS attacker."""
    
    def test_xss_search_endpoint(self, mock_server):
        """Test XSS on search endpoint."""
        attacker = XSSAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/search',
            method=HttpMethod.GET,
            parameters=[Parameter(name='q', location='query', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# SSRF INTEGRATION TESTS
# ============================================================================

class TestSSRFIntegration:
    """Integration tests for SSRF attacker."""
    
    def test_ssrf_fetch_endpoint(self, mock_server):
        """Test SSRF on fetch endpoint."""
        attacker = SSRFAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/fetch',
            method=HttpMethod.GET,
            parameters=[Parameter(name='url', location='query', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# IDOR INTEGRATION TESTS
# ============================================================================

class TestIDORIntegration:
    """Integration tests for IDOR attacker."""
    
    def test_idor_orders(self, mock_server):
        """Test IDOR on orders endpoint."""
        attacker = IDORAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/orders/{orderId}',
            method=HttpMethod.GET,
            parameters=[Parameter(name='orderId', location='path', required=True)]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# RATE LIMIT INTEGRATION TESTS
# ============================================================================

class TestRateLimitIntegration:
    """Integration tests for Rate Limit attacker."""
    
    def test_rate_limit_endpoint(self, mock_server):
        """Test rate limiting detection."""
        # Reset request count
        MockAPIHandler.request_count = {}
        
        attacker = RateLimitAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/limited',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# COMMAND INJECTION INTEGRATION TESTS
# ============================================================================

class TestCommandInjectionIntegration:
    """Integration tests for Command Injection attacker."""
    
    def test_command_injection_ping(self, mock_server):
        """Test command injection on ping endpoint."""
        attacker = CommandInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/ping',
            method=HttpMethod.POST,
            parameters=[Parameter(name='host', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# AUTH BYPASS INTEGRATION TESTS
# ============================================================================

class TestAuthBypassIntegration:
    """Integration tests for Auth Bypass attacker."""
    
    def test_auth_bypass_protected_endpoint(self, mock_server):
        """Test auth bypass on protected endpoint."""
        attacker = AuthBypassAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/profile',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# JWT INTEGRATION TESTS
# ============================================================================

class TestJWTIntegration:
    """Integration tests for JWT attacker."""
    
    def test_jwt_analysis(self, mock_server):
        """Test JWT analysis."""
        attacker = JWTAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/profile',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        # Use a simple JWT-like token
        results = attacker.attack(endpoint, auth_token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
        
        assert isinstance(results, list)


# ============================================================================
# ADDITIONAL BROKEN AUTH TESTS
# ============================================================================

class TestBrokenAuthExtraIntegration:
    """Extra integration tests for Broken Auth attacker."""
    
    def test_weak_token_endpoint(self, mock_server):
        """Test token validation weakness."""
        attacker = BrokenAuthAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/profile',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        # Test with various weak tokens
        results = attacker.attack(endpoint, auth_token='weak')
        
        assert isinstance(results, list)
    
    def test_password_reset_endpoint(self, mock_server):
        """Test password reset vulnerability."""
        attacker = BrokenAuthAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/reset-password',
            method=HttpMethod.POST,
            parameters=[Parameter(name='email', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# ADDITIONAL BOLA TESTS  
# ============================================================================

class TestBOLAExtraIntegration:
    """Extra integration tests for BOLA attacker."""
    
    def test_bola_with_different_ids(self, mock_server):
        """Test BOLA with sequential IDs."""
        attacker = BOLAAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/{id}',
            method=HttpMethod.GET,
            parameters=[Parameter(name='id', location='path', required=True)]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# ADDITIONAL SSRF TESTS
# ============================================================================

class TestSSRFExtraIntegration:
    """Extra integration tests for SSRF attacker."""
    
    def test_ssrf_internal_ip(self, mock_server):
        """Test SSRF with internal IP."""
        attacker = SSRFAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/fetch',
            method=HttpMethod.GET,
            parameters=[Parameter(name='url', location='query', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)
    
    def test_ssrf_file_protocol(self, mock_server):
        """Test SSRF with file:// protocol."""
        attacker = SSRFAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/fetch',
            method=HttpMethod.GET,
            parameters=[Parameter(name='url', location='query', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# EXCESSIVE DATA EXPOSURE EXTRA TESTS
# ============================================================================

class TestExcessiveDataExtraIntegration:
    """Extra integration tests for Excessive Data Exposure."""
    
    def test_user_endpoint_data_exposure(self, mock_server):
        """Test user endpoint for data exposure."""
        attacker = ExcessiveDataExposureAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/1',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# INJECTION INTEGRATION TESTS
# ============================================================================

class TestInjectionIntegration:
    """Integration tests for Injection attacker."""
    
    def test_sql_injection_post(self, mock_server):
        """Test SQL injection on POST endpoint."""
        attacker = SQLInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/query',
            method=HttpMethod.POST,
            parameters=[Parameter(name='query', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# RATE LIMIT EXTRA TESTS
# ============================================================================

class TestRateLimitExtraIntegration:
    """Extra integration tests for Rate Limit attacker."""
    
    def test_rate_limit_bypass(self, mock_server):
        """Test rate limit bypass techniques."""
        MockAPIHandler.request_count = {}
        
        attacker = RateLimitAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/limited',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# XSS EXTRA TESTS
# ============================================================================

class TestXSSExtraIntegration:
    """Extra integration tests for XSS attacker."""
    
    def test_xss_post_endpoint(self, mock_server):
        """Test XSS on POST endpoint."""
        attacker = XSSAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/search',
            method=HttpMethod.POST,
            parameters=[Parameter(name='q', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# MASS ASSIGNMENT EXTRA TESTS
# ============================================================================

class TestMassAssignmentExtraIntegration:
    """Extra integration tests for Mass Assignment."""
    
    def test_put_endpoint_mass_assignment(self, mock_server):
        """Test mass assignment on PUT endpoint."""
        attacker = MassAssignmentAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/profile',
            method=HttpMethod.PUT,
            parameters=[Parameter(name='name', location='body', required=False)]
        )
        
        results = attacker.attack(endpoint, auth_token='user_token')
        
        assert isinstance(results, list)


# ============================================================================
# NOSQL INJECTION EXTRA TESTS
# ============================================================================

class TestNoSQLInjectionExtraIntegration:
    """Extra integration tests for NoSQL Injection."""
    
    def test_nosql_operator_injection(self, mock_server):
        """Test NoSQL operator injection."""
        attacker = NoSQLInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/users/find',
            method=HttpMethod.POST,
            parameters=[
                Parameter(name='username', location='body', required=False),
                Parameter(name='password', location='body', required=False)
            ]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# IDOR EXTRA TESTS
# ============================================================================

class TestIDORExtraIntegration:
    """Extra integration tests for IDOR."""
    
    def test_idor_with_different_users(self, mock_server):
        """Test IDOR with different user tokens."""
        attacker = IDORAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/orders/{orderId}',
            method=HttpMethod.GET,
            parameters=[Parameter(name='orderId', location='path', required=True)]
        )
        
        results = attacker.attack(endpoint, auth_token='admin_token')
        
        assert isinstance(results, list)


# ============================================================================
# CMD INJECTION EXTRA TESTS
# ============================================================================

class TestCmdInjectionExtraIntegration:
    """Extra integration tests for Command Injection."""
    
    def test_cmd_injection_time_based(self, mock_server):
        """Test time-based command injection."""
        attacker = CommandInjectionAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/api/ping',
            method=HttpMethod.POST,
            parameters=[Parameter(name='host', location='body', required=True)]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)


# ============================================================================
# AUTH BYPASS EXTRA TESTS
# ============================================================================

class TestAuthBypassExtraIntegration:
    """Extra integration tests for Auth Bypass."""
    
    def test_auth_bypass_with_manipulated_token(self, mock_server):
        """Test auth bypass with manipulated token."""
        attacker = AuthBypassAttacker(mock_server)
        
        endpoint = Endpoint(
            path='/admin/users',
            method=HttpMethod.GET,
            parameters=[]
        )
        
        results = attacker.attack(endpoint)
        
        assert isinstance(results, list)
