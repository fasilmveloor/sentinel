"""
IDOR (Insecure Direct Object Reference) attack module.

Tests API endpoints for IDOR vulnerabilities by:
- Incrementing/decrementing resource IDs
- Accessing other users' resources
- Testing predictable resource identifiers
"""

import time
from typing import Any, Optional
import requests
import re

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Parameter,
    Severity,
    Vulnerability
)


class IDORAttacker:
    """Performs IDOR attacks on API endpoints."""
    
    # Common ID patterns to try
    ID_PATTERNS = [
        # Numeric IDs
        "1", "2", "3", "0", "-1", "999999",
        # UUIDs (test versions)
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-0000-000000000001",
        # Common test values
        "admin", "test", "user", "guest",
        # MongoDB ObjectIds (fake)
        "507f1f77bcf86cd799439011",
        "507f191e810c19729de860ea",
    ]
    
    # Parameters that commonly contain IDs
    ID_PARAM_NAMES = [
        'id', 'user_id', 'userId', 'user', 'account', 'account_id',
        'order', 'order_id', 'orderId', 'file', 'file_id', 'document',
        'profile', 'profile_id', 'resource', 'resource_id', 'item',
        'item_id', 'post', 'post_id', 'comment', 'comment_id'
    ]
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the IDOR attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/0.1.0 Security Scanner',
            'Accept': 'application/json'
        })
        self.original_responses: dict[str, Any] = {}
    
    def attack(
        self, 
        endpoint: Endpoint,
        auth_token: Optional[str] = None,
        parameters_to_test: Optional[list[str]] = None
    ) -> list[AttackResult]:
        """Perform IDOR attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            auth_token: Valid auth token for testing
            parameters_to_test: Specific parameters to test
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Add auth token if provided
        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"
        
        # Find ID parameters in the endpoint
        id_params = self._find_id_parameters(endpoint, parameters_to_test)
        
        if not id_params:
            # Try path-based IDOR (IDs in path)
            path_ids = self._extract_path_ids(endpoint.path)
            for path_id in path_ids:
                for new_id in self.ID_PATTERNS:
                    result = self._test_path_idor(endpoint, path_id, new_id)
                    results.append(result)
        else:
            for param in id_params:
                for new_id in self.ID_PATTERNS:
                    result = self._test_param_idor(endpoint, param, new_id)
                    results.append(result)
        
        return results
    
    def _find_id_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Find parameters that likely contain IDs."""
        id_params = []
        
        for param in endpoint.parameters:
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            # Check if parameter name suggests it's an ID
            if any(id_name in param.name.lower() for id_name in ['id', '_id', 'id_']):
                id_params.append(param)
            # Check if param type is integer (likely an ID)
            elif param.param_type == 'integer':
                id_params.append(param)
            # Check known ID parameter names
            elif param.name.lower() in self.ID_PARAM_NAMES:
                id_params.append(param)
        
        return id_params
    
    def _extract_path_ids(self, path: str) -> list[str]:
        """Extract ID placeholders from path."""
        # Find {id} style parameters
        pattern = r'\{([^}]+)\}'
        matches = re.findall(pattern, path)
        
        # Filter to likely ID parameters
        return [m for m in matches if any(id_word in m.lower() for id_word in ['id', 'user', 'account'])]
    
    def _test_param_idor(
        self, 
        endpoint: Endpoint, 
        param: Parameter, 
        new_id: str
    ) -> AttackResult:
        """Test IDOR by modifying a parameter ID."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            # Build parameters with modified ID
            params = {}
            body = {}
            
            for p in endpoint.parameters:
                if p.name == param.name:
                    if p.location == 'query':
                        params[p.name] = new_id
                    else:
                        body[p.name] = new_id
                else:
                    # Use example or default
                    default = p.example if p.example else self._get_default_value(p)
                    if p.location == 'query':
                        params[p.name] = default
                    else:
                        body[p.name] = default
            
            # Make request
            if endpoint.method.value == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    params=params,
                    json=body,
                    timeout=self.timeout
                )
            
            duration_ms = (time.time() - start_time) * 1000
            is_vulnerable = self._is_idor_vulnerable(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=is_vulnerable,
                payload=f"{param.name}={new_id}",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=False,
                payload=f"{param.name}={new_id}",
                error_message="Request timed out"
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=False,
                payload=f"{param.name}={new_id}",
                error_message=str(e)
            )
    
    def _test_path_idor(
        self, 
        endpoint: Endpoint, 
        path_param: str, 
        new_id: str
    ) -> AttackResult:
        """Test IDOR by modifying path parameter."""
        start_time = time.time()
        
        try:
            # Replace path parameter with test ID
            modified_path = endpoint.path.replace(f"{{{path_param}}}", new_id)
            url = self._build_url(modified_path)
            
            # Build any query parameters
            params = {}
            for p in endpoint.parameters:
                if p.location == 'query' and p.example:
                    params[p.name] = p.example
            
            response = self.session.request(
                endpoint.method.value,
                url,
                params=params,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            is_vulnerable = self._is_idor_vulnerable(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=is_vulnerable,
                payload=f"Path {path_param}={new_id}",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=False,
                payload=f"Path {path_param}={new_id}",
                error_message="Request timed out"
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.IDOR,
                success=False,
                payload=f"Path {path_param}={new_id}",
                error_message=str(e)
            )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _get_default_value(self, param: Parameter) -> Any:
        """Get default value for a parameter type."""
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
        }
        return defaults.get(param.param_type, 'test')
    
    def _is_idor_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates IDOR vulnerability."""
        # Successful access to resource that shouldn't be accessible
        if response.status_code == 200:
            try:
                data = response.json()
                
                # Check for data that looks like another user's data
                if isinstance(data, dict):
                    sensitive_fields = ['email', 'password', 'ssn', 'credit_card', 'phone', 'address']
                    if any(field in str(data).lower() for field in sensitive_fields):
                        return True
                
                # List of multiple records might indicate data leak
                if isinstance(data, list) and len(data) > 0:
                    return True
                    
            except:
                # Non-JSON response with 200 could still be vulnerable
                if len(response.text) > 0:
                    return True
        
        # 201 Created suggests we created/accessed something
        if response.status_code == 201:
            return True
        
        return False
    
    def create_vulnerability(
        self, 
        result: AttackResult, 
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.IDOR,
            severity=Severity.HIGH,
            title=f"IDOR Vulnerability in {endpoint.full_path}",
            description=(
                f"Insecure Direct Object Reference (IDOR) vulnerability detected. "
                f"The endpoint allows access to resources belonging to other users "
                f"by manipulating the resource identifier. This can lead to "
                f"unauthorized access to sensitive data."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Successfully accessed another user's resource."
            ),
            recommendation=(
                "1. Implement proper authorization checks for every resource access\n"
                "2. Use indirect references (maps/tokens) instead of direct IDs\n"
                "3. Verify the authenticated user owns or has access to the requested resource\n"
                "4. Implement object-level permissions\n"
                "5. Use access control lists (ACLs) for resource protection\n"
                "6. Log all access attempts for auditing"
            ),
            cwe_id="CWE-639",
            owasp_category="A01:2021 - Broken Access Control",
            response_evidence=result.response_body
        )
