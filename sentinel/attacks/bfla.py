"""
BFLA (Broken Function Level Authorization) Detection Module.

Tests API endpoints for BFLA vulnerabilities by:
- Testing admin endpoints with regular user credentials
- Detecting missing function-level authorization
- Testing horizontal and vertical privilege escalation
"""

import time
import json
import re
from typing import Optional
from dataclasses import dataclass
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Severity,
    Vulnerability
)


@dataclass
class UserRole:
    """User role for testing."""
    name: str
    token: str
    is_admin: bool = False


class BFLAAttacker:
    """Detects Broken Function Level Authorization vulnerabilities.
    
    BFLA occurs when regular users can access administrative functions
    that should be restricted to privileged users.
    """
    
    # Admin endpoint patterns to test
    ADMIN_PATH_PATTERNS = [
        # Direct admin paths
        r'/admin',
        r'/administration',
        r'/manage',
        r'/management',
        r'/backend',
        r'/control',
        
        # Admin operations
        r'/delete',
        r'/remove',
        r'/purge',
        r'/destroy',
        
        # User management
        r'/users/all',
        r'/users/list',
        r'/users/\d+',
        r'/all',
        r'/list',
        
        # System operations
        r'/config',
        r'/settings',
        r'/system',
        r'/internal',
        
        # Dangerous operations
        r'/export',
        r'/import',
        r'/bulk',
        r'/batch',
        r'/execute',
        r'/run',
    ]
    
    # HTTP methods that often require elevated privileges
    PRIVILEGED_METHODS = ['DELETE', 'PUT']
    
    # Parameters that suggest admin operations
    ADMIN_PARAM_NAMES = [
        'is_admin', 'isAdmin', 'role', 'user_role',
        'permissions', 'access_level', 'privileges'
    ]
    
    # Expected admin-only endpoints in common APIs
    COMMON_ADMIN_ENDPOINTS = [
        '/api/admin/users',
        '/api/admin/config',
        '/api/users/all',
        '/api/management/users',
        '/workshop/api/management/users/all',
        '/identity/api/admin',
        '/community/api/admin',
        '/api/v1/admin',
        '/api/v2/admin',
    ]
    
    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the BFLA detector.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.user_roles: list[UserRole] = []
        self.admin_tokens: list[str] = []
        self.regular_tokens: list[str] = []
        self.sessions: dict[str, requests.Session] = {}
    
    def set_user_roles(self, roles: list[UserRole]):
        """Set user roles for testing.
        
        Args:
            roles: List of UserRole objects with tokens and admin status
        """
        self.user_roles = roles
        
        for role in roles:
            if role.is_admin:
                self.admin_tokens.append(role.token)
            else:
                self.regular_tokens.append(role.token)
            
            # Create session for each role
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Sentinel/1.0 BFLA Scanner',
                'Accept': 'application/json',
                'Authorization': f"Bearer {role.token}"
            })
            self.sessions[role.name] = session
    
    def attack(
        self,
        endpoint: Endpoint,
        auth_token: Optional[str] = None,
        parameters_to_test: Optional[list[str]] = None
    ) -> list[AttackResult]:
        """Perform BFLA attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            auth_token: Authentication token (treated as regular user)
            parameters_to_test: Not used for this attack type
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Handle API misuse
        if auth_token is not None and isinstance(auth_token, list):
            parameters_to_test = auth_token
            auth_token = None
        
        # Check if this endpoint looks like an admin endpoint
        is_admin_endpoint = self._is_admin_endpoint(endpoint.path)
        
        # Check for dangerous methods
        is_dangerous_method = endpoint.method.value in self.PRIVILEGED_METHODS
        
        if not self.regular_tokens and auth_token:
            # Single token mode - test without distinguishing roles
            return self._test_single_token(endpoint, auth_token)
        
        # Test with regular user tokens on admin endpoints
        if is_admin_endpoint or is_dangerous_method:
            for token in self.regular_tokens:
                result = self._test_privilege_escalation(endpoint, token, "regular_user")
                if result and result.success:
                    results.append(result)
        
        # Test for horizontal privilege escalation (same role, different resource)
        if self._has_resource_ids(endpoint.path):
            for token in self.regular_tokens:
                result = self._test_horizontal_escalation(endpoint, token)
                if result:
                    results.append(result)
        
        # Test discovered admin endpoints with regular user
        results.extend(self._test_admin_endpoints_discovery(endpoint))
        
        return results
    
    def _is_admin_endpoint(self, path: str) -> bool:
        """Check if path looks like an admin endpoint."""
        path_lower = path.lower()
        
        for pattern in self.ADMIN_PATH_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        
        return False
    
    def _has_resource_ids(self, path: str) -> bool:
        """Check if path contains resource IDs."""
        return bool(re.search(r'\{[^}]+_?id\}', path.lower()))
    
    def _test_single_token(
        self,
        endpoint: Endpoint,
        token: str
    ) -> list[AttackResult]:
        """Test with a single token when no role distinction available."""
        results: list[AttackResult] = []
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Sentinel/1.0 BFLA Scanner',
            'Accept': 'application/json',
            'Authorization': f"Bearer {token}"
        })
        
        # Test if endpoint is accessible without proper role check
        if self._is_admin_endpoint(endpoint.path):
            try:
                url = f"{self.target_url}{endpoint.path}"
                start_time = time.time()
                
                response = session.request(
                    endpoint.method.value,
                    url,
                    timeout=self.timeout
                )
                
                duration_ms = (time.time() - start_time) * 1000
                
                # If we get 200, it's accessible (potential BFLA)
                is_vulnerable = response.status_code in [200, 201, 202, 204]
                
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=is_vulnerable,
                    payload=f"Admin endpoint accessible with token",
                    response_status=response.status_code,
                    response_body=response.text[:500],
                    duration_ms=duration_ms
                ))
                
            except Exception as e:
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=False,
                    payload="Admin endpoint test",
                    error_message=str(e)
                ))
        
        return results
    
    def _test_privilege_escalation(
        self,
        endpoint: Endpoint,
        token: str,
        role_name: str
    ) -> Optional[AttackResult]:
        """Test if regular user can access admin functions."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Sentinel/1.0 BFLA Scanner',
            'Accept': 'application/json',
            'Authorization': f"Bearer {token}"
        })
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            start_time = time.time()
            
            # Build request body if needed
            body = {}
            for param in endpoint.parameters:
                if param.location == 'body':
                    body[param.name] = param.example if param.example else self._get_default(param)
            
            response = session.request(
                endpoint.method.value,
                url,
                json=body if body else None,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for unauthorized access
            is_vulnerable = self._is_bfla_vulnerable(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=is_vulnerable,
                payload=f"Regular user '{role_name}' accessing admin endpoint",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=False,
                payload=f"Role: {role_name}",
                error_message=str(e)
            )
    
    def _test_horizontal_escalation(
        self,
        endpoint: Endpoint,
        token: str
    ) -> Optional[AttackResult]:
        """Test horizontal privilege escalation."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Sentinel/1.0 BFLA Scanner',
            'Accept': 'application/json',
            'Authorization': f"Bearer {token}"
        })
        
        # Test with different resource IDs
        test_ids = ['1', '2', '100', '999']
        
        for test_id in test_ids:
            try:
                # Replace path parameters with test ID
                modified_path = re.sub(r'\{[^}]+\}', test_id, endpoint.path)
                url = f"{self.target_url}{modified_path}"
                
                response = session.request(
                    endpoint.method.value,
                    url,
                    timeout=self.timeout
                )
                
                if self._is_bfla_vulnerable(response):
                    return AttackResult(
                        endpoint=endpoint,
                        attack_type=AttackType.AUTH_BYPASS,
                        success=True,
                        payload=f"Horizontal escalation with ID: {test_id}",
                        response_status=response.status_code,
                        response_body=response.text[:500]
                    )
                    
            except Exception:
                pass
        
        return None
    
    def _test_admin_endpoints_discovery(
        self,
        known_endpoint: Endpoint
    ) -> list[AttackResult]:
        """Discover and test common admin endpoints."""
        results: list[AttackResult] = []
        
        # Only test if we have regular user tokens
        if not self.regular_tokens:
            return results
        
        for admin_path in self.COMMON_ADMIN_ENDPOINTS:
            for token in self.regular_tokens:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Sentinel/1.0 BFLA Scanner',
                    'Accept': 'application/json',
                    'Authorization': f"Bearer {token}"
                })
                
                try:
                    url = f"{self.target_url}{admin_path}"
                    start_time = time.time()
                    
                    response = session.get(url, timeout=self.timeout)
                    duration_ms = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        # Create a synthetic endpoint for reporting
                        synthetic_endpoint = Endpoint(
                            path=admin_path,
                            method=known_endpoint.method,
                            parameters=[]
                        )
                        
                        results.append(AttackResult(
                            endpoint=synthetic_endpoint,
                            attack_type=AttackType.AUTH_BYPASS,
                            success=True,
                            payload=f"Discovered admin endpoint accessible to regular user",
                            response_status=response.status_code,
                            response_body=response.text[:500],
                            duration_ms=duration_ms
                        ))
                        
                except Exception:
                    pass
        
        return results
    
    def _is_bfla_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates BFLA vulnerability."""
        # Success codes without proper authorization
        if response.status_code in [200, 201, 202, 204]:
            # Check for error indicators in response
            try:
                data = response.json()
                data_str = json.dumps(data).lower()
                
                # Check for explicit authorization error
                auth_error_indicators = [
                    'unauthorized', 'forbidden', 'access denied',
                    'permission denied', 'not authorized', 'insufficient'
                ]
                
                if any(indicator in data_str for indicator in auth_error_indicators):
                    return False
                
                # Data returned suggests successful unauthorized access
                if isinstance(data, dict) and ('data' in data or 'items' in data or 'id' in data):
                    return True
                
                if isinstance(data, list) and len(data) > 0:
                    return True
                    
            except:
                # Non-JSON success response
                if len(response.text) > 0:
                    return True
        
        return False
    
    def _get_default(self, param) -> any:
        """Get default value for parameter type."""
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
        }
        return defaults.get(param.param_type, 'test')
    
    def create_vulnerability(
        self,
        result: AttackResult,
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            severity=Severity.HIGH,
            title=f"BFLA in {endpoint.full_path}",
            description=(
                f"Broken Function Level Authorization (BFLA) vulnerability detected. "
                f"The API endpoint does not properly enforce role-based access control, "
                f"allowing regular users to access administrative functions. "
                f"This enables privilege escalation and unauthorized actions."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Attack: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Regular user successfully accessed admin function."
            ),
            recommendation=(
                "1. Implement proper role-based access control (RBAC)\n"
                "2. Deny by default - require explicit permission grants\n"
                "3. Validate user role/permissions for every API call\n"
                "4. Use middleware for centralized authorization checks\n"
                "5. Log all authorization failures for monitoring\n"
                "6. Apply principle of least privilege\n"
                "7. Separate admin endpoints from user endpoints\n"
                "8. Use API gateways for centralized access control"
            ),
            cwe_id="CWE-285",
            owasp_category="API5:2023 - Broken Function Level Authorization",
            response_evidence=result.response_body
        )
