"""
Rate Limit Detection module.

Tests API endpoints for rate limiting vulnerabilities by sending
multiple requests and analyzing response patterns.
"""

import time
from typing import Any, Optional
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Severity,
    Vulnerability,
    RateLimitResult
)


class RateLimitAttacker:
    """Detects rate limiting issues on API endpoints."""
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the rate limit detector.
        
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
    
    def attack(self, endpoint: Endpoint, parameters_to_test: Optional[list[str]] = None) -> list[AttackResult]:
        """Perform rate limit testing on an endpoint.
        
        Args:
            endpoint: The endpoint to test
            parameters_to_test: Not used for rate limiting
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Test without rate limit bypass attempts
        result = self._test_basic_rate_limit(endpoint)
        results.append(result)
        
        # If rate limiting exists, test bypass techniques
        if result.extra_data and result.extra_data.get('rate_limited'):
            bypass_results = self._test_rate_limit_bypass(endpoint)
            results.extend(bypass_results)
        
        return results
    
    def _test_basic_rate_limit(self, endpoint: Endpoint) -> AttackResult:
        """Test basic rate limiting by sending multiple requests."""
        start_time = time.time()
        
        requests_made = 0
        blocked_after = None
        status_codes = []
        first_blocked_time = None
        
        # Send 50 requests rapidly
        for i in range(50):
            try:
                url = self._build_url(endpoint.path)
                
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    timeout=self.timeout
                )
                
                requests_made += 1
                status_codes.append(response.status_code)
                
                # Check for rate limit indicators
                if self._is_rate_limited(response):
                    if blocked_after is None:
                        blocked_after = i + 1
                        first_blocked_time = time.time() - start_time
                    # Continue to see if it stays blocked
                    
            except requests.exceptions.RequestException:
                # Connection errors might indicate blocking
                if blocked_after is None:
                    blocked_after = i + 1
                    first_blocked_time = time.time() - start_time
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Analyze results
        is_vulnerable = blocked_after is None or blocked_after > 20
        
        if blocked_after and blocked_after <= 10:
            # Good rate limiting
            severity = "good"
        elif blocked_after and blocked_after <= 30:
            # Moderate rate limiting
            severity = "moderate"
        else:
            # Weak or no rate limiting
            severity = "weak"
        
        return AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.RATE_LIMIT,
            success=is_vulnerable,
            payload=f"{requests_made} requests sent",
            response_status=status_codes[-1] if status_codes else None,
            duration_ms=duration_ms,
            extra_data={
                'requests_made': requests_made,
                'blocked_after': blocked_after,
                'severity': severity,
                'status_codes': status_codes[:10],  # First 10 status codes
                'rate_limited': blocked_after is not None
            }
        )
    
    def _test_rate_limit_bypass(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test various rate limit bypass techniques."""
        results = []
        
        # Bypass technique 1: IP rotation simulation
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Real-IP': '192.168.1.1'},
            {'X-Originating-IP': '172.16.0.1'},
            {'X-Client-IP': '10.1.1.1'},
            {'Client-IP': '10.2.2.2'},
        ]
        
        for headers in bypass_headers[:3]:  # Test first 3
            result = self._test_bypass_with_headers(endpoint, headers)
            results.append(result)
        
        # Bypass technique 2: Case manipulation
        case_bypass_headers = [
            {'X-FORWARDED-FOR': '10.0.0.1'},
            {'x-forwarded-for': '10.0.0.1'},
        ]
        
        for headers in case_bypass_headers:
            result = self._test_bypass_with_headers(endpoint, headers)
            results.append(result)
        
        return results
    
    def _test_bypass_with_headers(self, endpoint: Endpoint, extra_headers: dict) -> AttackResult:
        """Test rate limit bypass with custom headers."""
        start_time = time.time()
        
        success_count = 0
        blocked_count = 0
        requests_made = 0
        
        # Send 20 requests with bypass headers
        for i in range(20):
            try:
                url = self._build_url(endpoint.path)
                
                # Rotate IP in header
                headers = extra_headers.copy()
                if 'X-Forwarded-For' in headers:
                    headers['X-Forwarded-For'] = f"10.0.{i}.{i+1}"
                elif 'X-Real-IP' in headers:
                    headers['X-Real-IP'] = f"192.168.{i}.{i+1}"
                
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                requests_made += 1
                
                if self._is_rate_limited(response):
                    blocked_count += 1
                else:
                    success_count += 1
                    
            except requests.exceptions.RequestException:
                blocked_count += 1
        
        duration_ms = (time.time() - start_time) * 1000
        
        # If more than 80% success, bypass worked
        bypass_success = success_count > 16
        
        return AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.RATE_LIMIT,
            success=bypass_success,
            payload=f"Bypass attempt with headers: {extra_headers}",
            response_status=200,
            duration_ms=duration_ms,
            extra_data={
                'bypass_technique': 'header_manipulation',
                'headers_used': extra_headers,
                'success_count': success_count,
                'blocked_count': blocked_count,
                'bypass_worked': bypass_success
            }
        )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _is_rate_limited(self, response: requests.Response) -> bool:
        """Check if response indicates rate limiting."""
        # Check status codes
        if response.status_code == 429:
            return True
        
        # Check headers
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'X-Rate-Limit',
            'RateLimit-Limit',
        ]
        
        for header in rate_limit_headers:
            if header in response.headers:
                return True
        
        # Check response body for rate limit messages
        rate_limit_indicators = [
            'rate limit',
            'too many requests',
            'limit exceeded',
            'throttl',
            'quota exceeded',
            'slow down',
            'try again later',
        ]
        
        response_text = response.text.lower()
        for indicator in rate_limit_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        extra = result.extra_data or {}
        
        # Determine severity based on findings
        severity = Severity.MEDIUM
        
        if extra.get('bypass_worked'):
            severity = Severity.HIGH
            title = f"Rate Limit Bypass in {endpoint.full_path}"
            description = (
                "Rate limiting can be bypassed using header manipulation. "
                "The application accepts X-Forwarded-For, X-Real-IP or similar "
                "headers to identify clients, which can be easily spoofed."
            )
            recommendation = (
                "1. Do not trust client-provided headers for rate limiting\n"
                "2. Use the actual client IP from the TCP connection\n"
                "3. Implement rate limiting at the API gateway/CDN level\n"
                "4. Consider using API keys for identification\n"
                "5. Implement distributed rate limiting for scaled deployments"
            )
        elif not extra.get('rate_limited'):
            severity = Severity.HIGH
            title = f"Missing Rate Limiting on {endpoint.full_path}"
            description = (
                "No rate limiting detected on this endpoint. "
                "Attackers can make unlimited requests, potentially leading to "
                "brute force attacks, credential stuffing, or denial of service."
            )
            recommendation = (
                "1. Implement rate limiting on all sensitive endpoints\n"
                "2. Set appropriate limits (e.g., 100 requests/minute)\n"
                "3. Return 429 status code when limit is exceeded\n"
                "4. Include Retry-After header\n"
                "5. Consider rate limiting by API key, not just IP"
            )
        elif extra.get('blocked_after', 0) > 30:
            severity = Severity.MEDIUM
            title = f"Weak Rate Limiting on {endpoint.full_path}"
            description = (
                f"Rate limiting is in place but allows too many requests "
                f"({extra.get('blocked_after')} requests before blocking). "
                f"This may still allow brute force or enumeration attacks."
            )
            recommendation = (
                "1. Reduce the rate limit threshold\n"
                "2. Implement progressive delays for repeated violations\n"
                "3. Add CAPTCHA after certain threshold\n"
                "4. Monitor and alert on suspicious request patterns"
            )
        else:
            title = f"Rate Limiting Detected on {endpoint.full_path}"
            description = (
                "Rate limiting is properly implemented on this endpoint. "
                f"Blocked after {extra.get('blocked_after', 'N/A')} requests."
            )
            severity = Severity.INFO
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.RATE_LIMIT,
            severity=severity,
            title=title,
            description=description,
            payload=result.payload or "",
            proof_of_concept=(
                f"Endpoint: {endpoint.method.value} {endpoint.path}\n"
                f"Requests Made: {extra.get('requests_made', 'N/A')}\n"
                f"Blocked After: {extra.get('blocked_after', 'N/A')} requests\n"
                f"Bypass Attempted: {'Yes' if extra.get('bypass_technique') else 'No'}\n"
                f"Bypass Success: {'Yes' if extra.get('bypass_worked') else 'No'}"
            ),
            recommendation=recommendation,
            cwe_id="CWE-770" if not extra.get('rate_limited') else "CWE-799",
            owasp_category="A04:2021 - Insecure Design",
            response_evidence=None,
            cvss_score=7.5 if extra.get('bypass_worked') else 5.3
        )
