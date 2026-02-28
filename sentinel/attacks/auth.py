"""
Authentication Bypass attack module.

Tests API endpoints for authentication vulnerabilities by:
- Accessing protected endpoints without tokens
- Using invalid/expired tokens
- Testing token manipulation
"""

import time
from typing import Any, Optional
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Severity,
    Vulnerability
)


class AuthBypassAttacker:
    """Performs authentication bypass attacks on API endpoints."""
    
    # Test tokens for bypass attempts
    TEST_TOKENS = [
        # No token
        None,
        # Empty token
        "",
        # Invalid tokens
        "invalid",
        "Bearer invalid",
        "Bearer abc123",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        # Common test tokens
        "test",
        "admin",
        "12345",
        # Null bytes
        "Bearer \x00",
        # SQL injection in token
        "' OR '1'='1",
        "admin'--",
        # JWT-like tokens with manipulation
        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    ]
    
    # Common authorization headers
    AUTH_HEADERS = [
        "Authorization",
        "X-Auth-Token",
        "X-API-Key",
        "X-Access-Token",
        "Api-Key",
        "Token",
    ]
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the auth bypass attacker.
        
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
    
    def attack(
        self, 
        endpoint: Endpoint,
        valid_token: Optional[str] = None,
        parameters_to_test: Optional[list[str]] = None
    ) -> list[AttackResult]:
        """Perform authentication bypass attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            valid_token: A valid token to compare against (optional)
            parameters_to_test: Specific parameters to test (not used for auth)
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Only test endpoints that should require auth
        if not endpoint.requires_auth:
            # Still test - might be protected but not marked in spec
            pass
        
        # Test without any authentication
        result = self._test_no_auth(endpoint)
        results.append(result)
        
        # Test with invalid tokens
        for token in self.TEST_TOKENS:
            if token is None:
                continue  # Already tested no auth
            
            result = self._test_invalid_token(endpoint, token)
            results.append(result)
        
        # Test with manipulated tokens if we have a valid one
        if valid_token:
            for manipulated in self._manipulate_token(valid_token):
                result = self._test_invalid_token(endpoint, manipulated)
                results.append(result)
        
        return results
    
    def _test_no_auth(self, endpoint: Endpoint) -> AttackResult:
        """Test endpoint without any authentication."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            # Remove any existing auth headers
            headers = {
                k: v for k, v in self.session.headers.items()
                if k.lower() not in [h.lower() for h in self.AUTH_HEADERS]
            }
            
            response = self.session.request(
                endpoint.method.value,
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            is_vulnerable = self._is_auth_bypass(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=is_vulnerable,
                payload="No authentication",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=False,
                payload="No authentication",
                error_message="Request timed out"
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=False,
                payload="No authentication",
                error_message=str(e)
            )
    
    def _test_invalid_token(self, endpoint: Endpoint, token: str) -> AttackResult:
        """Test endpoint with an invalid token."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            headers = dict(self.session.headers)
            headers['Authorization'] = f"Bearer {token}" if not token.startswith('Bearer') else token
            
            response = self.session.request(
                endpoint.method.value,
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            is_vulnerable = self._is_auth_bypass(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=is_vulnerable,
                payload=f"Invalid token: {token[:50]}...",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=False,
                payload=f"Invalid token: {token[:50]}...",
                error_message="Request timed out"
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.AUTH_BYPASS,
                success=False,
                payload=f"Invalid token: {token[:50]}...",
                error_message=str(e)
            )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _is_auth_bypass(self, response: requests.Response) -> bool:
        """Check if response indicates successful auth bypass."""
        # Success status codes when should be unauthorized
        if response.status_code in [200, 201, 202, 204]:
            return True
        
        # Redirect to authorized area instead of login
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if 'login' not in location.lower() and 'auth' not in location.lower():
                return True
        
        return False
    
    def _manipulate_token(self, token: str) -> list[str]:
        """Generate manipulated versions of a valid token."""
        manipulated = []
        
        # Remove last character
        if len(token) > 1:
            manipulated.append(token[:-1])
        
        # Change case
        if token.isalpha():
            manipulated.append(token.upper())
            manipulated.append(token.lower())
        
        # Add common suffixes
        manipulated.append(token + "1")
        manipulated.append(token + "admin")
        
        # JWT manipulation (if looks like JWT)
        if token.count('.') == 2:
            parts = token.split('.')
            # Try removing signature
            manipulated.append(f"{parts[0]}.{parts[1]}.")
            # Try empty signature
            manipulated.append(f"{parts[0]}.{parts[1]}.signature")
        
        return manipulated
    
    def create_vulnerability(
        self, 
        result: AttackResult, 
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            severity=Severity.CRITICAL,
            title=f"Authentication Bypass in {endpoint.full_path}",
            description=(
                f"Authentication bypass vulnerability detected. The endpoint allows "
                f"access without valid authentication credentials. This allows "
                f"unauthorized access to protected resources and sensitive data."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Successfully accessed protected endpoint without valid credentials."
            ),
            recommendation=(
                "1. Implement proper authentication middleware\n"
                "2. Validate tokens on every request\n"
                "3. Use a proven authentication library (Auth0, Passport, etc.)\n"
                "4. Ensure all protected endpoints check authentication\n"
                "5. Log and monitor authentication failures\n"
                "6. Implement rate limiting on authentication endpoints"
            ),
            cwe_id="CWE-306",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            response_evidence=result.response_body
        )
