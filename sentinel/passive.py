"""
Passive Scanner for Sentinel.

Analyzes HTTP traffic and API responses without actively sending attack payloads.
Similar to OWASP ZAP's passive scanning capabilities.

v2.5 Feature: Agentic OWASP ZAP
"""

import re
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from .models import Endpoint, Severity


class PassiveFindingType(Enum):
    """Types of passive findings."""
    # Information Disclosure
    VERSION_DISCLOSURE = "version_disclosure"
    FRAMEWORK_DISCLOSURE = "framework_disclosure"
    SERVER_HEADER = "server_header"
    DEBUG_INFO = "debug_info"
    STACK_TRACE = "stack_trace"
    
    # Security Headers
    MISSING_SECURITY_HEADER = "missing_security_header"
    INSECURE_HEADER = "insecure_header"
    CORS_MISCONFIG = "cors_misconfig"
    
    # Sensitive Data
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    CREDENTIAL_LEAK = "credential_leak"
    TOKEN_EXPOSURE = "token_exposure"
    PII_EXPOSURE = "pii_exposure"
    
    # Authentication/Session
    WEAK_AUTH = "weak_authentication"
    SESSION_ISSUE = "session_issue"
    COOKIE_SECURITY = "cookie_security"
    
    # API Specific
    EXCESSIVE_DATA = "excessive_data"
    RATE_LIMIT_MISSING = "rate_limit_missing"
    CACHE_CONTROL = "cache_control_issue"
    
    # Content Issues
    ERROR_MESSAGE = "error_message"
    INSECURE_LINK = "insecure_link"
    MIXED_CONTENT = "mixed_content"


@dataclass
class PassiveFinding:
    """A finding from passive scanning."""
    finding_type: PassiveFindingType
    severity: Severity
    title: str
    description: str
    evidence: str
    location: str  # header, body, url
    remediation: str
    confidence: float = 0.8
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None


class PassiveScanner:
    """
    Passive security scanner that analyzes HTTP traffic.
    
    Detects security issues without sending any attack payloads.
    """
    
    # Security headers that should be present
    RECOMMENDED_SECURITY_HEADERS = {
        'X-Content-Type-Options': {
            'severity': Severity.LOW,
            'description': 'Missing X-Content-Type-Options header (prevents MIME sniffing)',
            'remediation': 'Add "X-Content-Type-Options: nosniff" header'
        },
        'X-Frame-Options': {
            'severity': Severity.LOW,
            'description': 'Missing X-Frame-Options header (clickjacking protection)',
            'remediation': 'Add "X-Frame-Options: DENY" or "SAMEORIGIN" header'
        },
        'Strict-Transport-Security': {
            'severity': Severity.MEDIUM,
            'description': 'Missing HSTS header (HTTPS downgrade attacks possible)',
            'remediation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header'
        },
        'Content-Security-Policy': {
            'severity': Severity.MEDIUM,
            'description': 'Missing Content-Security-Policy header (XSS protection)',
            'remediation': 'Add Content-Security-Policy header with appropriate directives'
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'Missing X-XSS-Protection header (legacy XSS filter)',
            'remediation': 'Add "X-XSS-Protection: 1; mode=block" header'
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Missing Referrer-Policy header (information leakage)',
            'remediation': 'Add "Referrer-Policy: strict-origin-when-cross-origin" header'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': 'Missing Permissions-Policy header (browser feature control)',
            'remediation': 'Add Permissions-Policy header to restrict browser features'
        }
    }
    
    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = [
        # API Keys and Tokens
        (r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
         'API Key', Severity.HIGH, 'CWE-798'),
        (r'(?i)(secret[_-]?key|secretkey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
         'Secret Key', Severity.HIGH, 'CWE-798'),
        (r'(?i)(access[_-]?token|accesstoken)["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
         'Access Token', Severity.HIGH, 'CWE-798'),
        (r'(?i)(auth[_-]?token|authtoken)["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
         'Auth Token', Severity.HIGH, 'CWE-798'),
        
        # Passwords
        (r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\']{4,})["\']?',
         'Password', Severity.CRITICAL, 'CWE-798'),
        
        # AWS Keys
        (r'AKIA[0-9A-Z]{16}',
         'AWS Access Key', Severity.CRITICAL, 'CWE-798'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',
         'AWS Secret Key', Severity.CRITICAL, 'CWE-798'),
        
        # Private Keys
        (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
         'Private Key', Severity.CRITICAL, 'CWE-798'),
        
        # JWT Tokens
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
         'JWT Token', Severity.MEDIUM, 'CWE-798'),
        
        # Credit Cards
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
         'Credit Card Number', Severity.CRITICAL, 'CWE-798'),
        
        # SSN
        (r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
         'Social Security Number', Severity.CRITICAL, 'CWE-359'),
        
        # Email addresses (potential PII)
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
         'Email Address', Severity.LOW, 'CWE-359'),
        
        # IP addresses (internal)
        (r'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
         'Internal IP Address', Severity.MEDIUM, 'CWE-200'),
        
        # Database connection strings
        (r'(?i)(mysql|postgres|mongodb|redis)://[^\s"\']+',
         'Database Connection String', Severity.CRITICAL, 'CWE-798'),
        
        # Generic secrets
        (r'(?i)(secret|private|confidential)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?',
         'Secret Value', Severity.HIGH, 'CWE-798'),
    ]
    
    # Server version patterns
    VERSION_PATTERNS = [
        (r'Server:\s*([A-Za-z-]+)/([0-9.]+)', 'Server'),
        (r'X-Powered-By:\s*([A-Za-z-]+)/([0-9.]+)', 'X-Powered-By'),
        (r'X-AspNet-Version:\s*([0-9.]+)', 'ASP.NET'),
        (r'X-Runtime:\s*([0-9.]+)', 'Runtime'),
    ]
    
    # Framework fingerprint patterns
    FRAMEWORK_PATTERNS = [
        (r'laravel_session', 'Laravel', Severity.INFO),
        (r'PHPSESSID', 'PHP', Severity.INFO),
        (r'JSESSIONID', 'Java/JSP', Severity.INFO),
        (r'ASP\.NET_SessionId', 'ASP.NET', Severity.INFO),
        (r'__cfduid', 'Cloudflare', Severity.INFO),
        (r'csrftoken', 'Django', Severity.INFO),
        (r'_rails_session', 'Ruby on Rails', Severity.INFO),
        (r'connect\.sid', 'Express.js/Node.js', Severity.INFO),
    ]
    
    # Error patterns indicating vulnerability
    ERROR_PATTERNS = [
        (r'SQL syntax.*?MySQL', 'MySQL Error', Severity.MEDIUM, 'CWE-209'),
        (r'ORA-\d{5}', 'Oracle Error', Severity.MEDIUM, 'CWE-209'),
        (r'PostgreSQL.*?ERROR', 'PostgreSQL Error', Severity.MEDIUM, 'CWE-209'),
        (r'MongoDB.*?Error', 'MongoDB Error', Severity.MEDIUM, 'CWE-209'),
        (r'StackTrace|Stack trace|at [a-zA-Z0-9.]+\([a-zA-Z0-9.]+:\d+\)',
         'Stack Trace', Severity.MEDIUM, 'CWE-209'),
        (r'debug.*?mode|debug.*?enabled', 'Debug Mode', Severity.MEDIUM, 'CWE-209'),
        (r'Exception.*?:\s*.*?\n', 'Exception Details', Severity.MEDIUM, 'CWE-209'),
        (r'Warning:\s*.*?\s*on line \d+', 'PHP Warning', Severity.LOW, 'CWE-209'),
        (r'Fatal error:\s*', 'PHP Fatal Error', Severity.MEDIUM, 'CWE-209'),
    ]
    
    def __init__(self):
        self.findings: list[PassiveFinding] = []
    
    def analyze_response(
        self,
        url: str,
        method: str,
        request_headers: dict,
        response_headers: dict,
        response_body: str,
        status_code: int
    ) -> list[PassiveFinding]:
        """
        Analyze an HTTP response for security issues.
        
        Args:
            url: Request URL
            method: HTTP method
            request_headers: Request headers
            response_headers: Response headers
            response_body: Response body (string)
            status_code: HTTP status code
            
        Returns:
            List of passive findings
        """
        findings = []
        
        # Check security headers
        findings.extend(self._check_security_headers(response_headers, url))
        
        # Check for sensitive data in response
        findings.extend(self._check_sensitive_data(response_body, url))
        
        # Check for version disclosure
        findings.extend(self._check_version_disclosure(response_headers, url))
        
        # Check for framework disclosure
        findings.extend(self._check_framework_disclosure(response_headers, response_body, url))
        
        # Check for error messages
        findings.extend(self._check_error_messages(response_body, url))
        
        # Check CORS configuration
        findings.extend(self._check_cors(response_headers, url))
        
        # Check cookie security
        findings.extend(self._check_cookies(response_headers, url))
        
        # Check cache control
        findings.extend(self._check_cache_control(response_headers, url))
        
        return findings
    
    def _check_security_headers(self, headers: dict, url: str) -> list[PassiveFinding]:
        """Check for missing security headers."""
        findings = []
        
        for header_name, info in self.RECOMMENDED_SECURITY_HEADERS.items():
            if header_name.lower() not in [h.lower() for h in headers.keys()]:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.MISSING_SECURITY_HEADER,
                    severity=info['severity'],
                    title=f"Missing {header_name} Header",
                    description=info['description'],
                    evidence=f"Header {header_name} not found in response",
                    location='header',
                    remediation=info['remediation'],
                    confidence=0.9,
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    def _check_sensitive_data(self, body: str, url: str) -> list[PassiveFinding]:
        """Check for sensitive data in response body."""
        findings = []
        
        for pattern, name, severity, cwe in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                # Filter out common false positives
                filtered_matches = self._filter_false_positives(matches, name)
                
                if filtered_matches:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.SENSITIVE_DATA_EXPOSURE,
                        severity=severity,
                        title=f"Potential {name} Exposed",
                        description=f"Response contains potential {name} in body",
                        evidence=f"Found {len(filtered_matches)} match(es) for {name} pattern",
                        location='body',
                        remediation=f"Remove {name} from response or encrypt sensitive data",
                        confidence=0.7,
                        cwe_id=int(cwe.split('-')[1]) if '-' in cwe else int(cwe),
                        owasp_category='A01:2021 - Broken Access Control'
                    ))
        
        return findings
    
    def _filter_false_positives(self, matches: list, data_type: str) -> list:
        """Filter out common false positives."""
        # Placeholder values that are not real secrets
        placeholders = {
            'xxx', 'placeholder', 'example', 'sample', 'test', 'dummy',
            'your_key_here', 'insert_key', 'changeme', 'default'
        }
        
        filtered = []
        for match in matches:
            if isinstance(match, tuple):
                match = match[-1] if match else ''
            
            match_lower = match.lower()
            if not any(p in match_lower for p in placeholders):
                filtered.append(match)
        
        return filtered
    
    def _check_version_disclosure(self, headers: dict, url: str) -> list[PassiveFinding]:
        """Check for server version disclosure."""
        findings = []
        
        for pattern, source in self.VERSION_PATTERNS:
            for header, value in headers.items():
                match = re.search(pattern, f"{header}: {value}", re.IGNORECASE)
                if match:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.VERSION_DISCLOSURE,
                        severity=Severity.LOW,
                        title=f"{source} Version Disclosure",
                        description=f"Server discloses {source} version in response headers",
                        evidence=f"{header}: {value}",
                        location='header',
                        remediation=f"Configure server to hide {source} version information",
                        confidence=0.95,
                        cwe_id=200,
                        owasp_category='A05:2021 - Security Misconfiguration'
                    ))
        
        return findings
    
    def _check_framework_disclosure(self, headers: dict, body: str, url: str) -> list[PassiveFinding]:
        """Check for framework fingerprint disclosure."""
        findings = []
        
        combined = str(headers) + body
        
        for pattern, framework, severity in self.FRAMEWORK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.FRAMEWORK_DISCLOSURE,
                    severity=severity,
                    title=f"{framework} Framework Detected",
                    description=f"Application appears to use {framework} framework",
                    evidence=f"Found {pattern} pattern in response",
                    location='body',
                    remediation="Consider obscuring framework information",
                    confidence=0.8,
                    cwe_id=200,
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    def _check_error_messages(self, body: str, url: str) -> list[PassiveFinding]:
        """Check for sensitive error messages."""
        findings = []
        
        for pattern, error_type, severity, cwe in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.ERROR_MESSAGE,
                    severity=severity,
                    title=f"{error_type} Exposed",
                    description="Response contains detailed error information",
                    evidence=f"Found {error_type} pattern in response body",
                    location='body',
                    remediation="Disable detailed error messages in production, use generic error pages",
                    confidence=0.9,
                    cwe_id=int(cwe.split('-')[1]) if '-' in cwe else int(cwe),
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    def _check_cors(self, headers: dict, url: str) -> list[PassiveFinding]:
        """Check for CORS misconfiguration."""
        findings = []
        
        cors_headers = {k.lower(): v for k, v in headers.items()}
        
        # Check for overly permissive CORS
        acao = cors_headers.get('access-control-allow-origin', '')
        
        if acao == '*':
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.CORS_MISCONFIG,
                severity=Severity.MEDIUM,
                title="Overly Permissive CORS Policy",
                description="Access-Control-Allow-Origin header is set to wildcard (*)",
                evidence="Access-Control-Allow-Origin: *",
                location='header',
                remediation="Restrict CORS to trusted origins only",
                confidence=0.95,
                cwe_id=942,
                owasp_category='A01:2021 - Broken Access Control'
            ))
        
        # Check for credentials with wildcard
        acac = cors_headers.get('access-control-allow-credentials', '')
        if acao == '*' and acac.lower() == 'true':
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.CORS_MISCONFIG,
                severity=Severity.HIGH,
                title="Dangerous CORS Configuration",
                description="CORS allows credentials with wildcard origin - critical security issue",
                evidence=f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                location='header',
                remediation="Never use wildcard origin when credentials are allowed",
                confidence=1.0,
                cwe_id=942,
                owasp_category='A01:2021 - Broken Access Control'
            ))
        
        return findings
    
    def _check_cookies(self, headers: dict, url: str) -> list[PassiveFinding]:
        """Check cookie security attributes."""
        findings = []
        
        set_cookie = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
        
        if set_cookie:
            cookies = [set_cookie] if isinstance(set_cookie, str) else set_cookie
            
            for cookie in cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split('=')[0] if '=' in cookie else cookie
                
                # Check Secure flag
                if 'secure' not in cookie_lower and 'https' in url.lower():
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.COOKIE_SECURITY,
                        severity=Severity.MEDIUM,
                        title=f"Cookie Missing Secure Flag: {cookie_name}",
                        description="Cookie set without Secure flag over HTTPS",
                        evidence=cookie[:100],
                        location='header',
                        remediation="Add Secure flag to cookie attribute",
                        confidence=0.9,
                        cwe_id=614,
                        owasp_category='A05:2021 - Security Misconfiguration'
                    ))
                
                # Check HttpOnly flag
                if 'httponly' not in cookie_lower:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.COOKIE_SECURITY,
                        severity=Severity.LOW,
                        title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        description="Cookie set without HttpOnly flag (XSS can access)",
                        evidence=cookie[:100],
                        location='header',
                        remediation="Add HttpOnly flag to cookie attribute",
                        confidence=0.9,
                        cwe_id=1004,
                        owasp_category='A05:2021 - Security Misconfiguration'
                    ))
                
                # Check SameSite attribute
                if 'samesite' not in cookie_lower:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.COOKIE_SECURITY,
                        severity=Severity.LOW,
                        title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                        description="Cookie set without SameSite attribute (CSRF risk)",
                        evidence=cookie[:100],
                        location='header',
                        remediation="Add SameSite=Strict or SameSite=Lax to cookie",
                        confidence=0.9,
                        cwe_id=1275,
                        owasp_category='A01:2021 - Broken Access Control'
                    ))
        
        return findings
    
    def _check_cache_control(self, headers: dict, url: str) -> list[PassiveFinding]:
        """Check cache control headers."""
        findings = []
        
        cache_control = headers.get('Cache-Control', '') or headers.get('cache-control', '')
        
        # Check if sensitive data might be cached
        if not cache_control or 'private' not in cache_control.lower():
            pragma = headers.get('Pragma', '') or headers.get('pragma', '')
            expires = headers.get('Expires', '') or headers.get('expires', '')
            
            if not cache_control and not pragma:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CACHE_CONTROL,
                    severity=Severity.LOW,
                    title="Missing Cache-Control Header",
                    description="Response may be cached by browsers and proxies",
                    evidence="No Cache-Control header found",
                    location='header',
                    remediation="Add 'Cache-Control: no-store, no-cache, private' for sensitive data",
                    confidence=0.8,
                    cwe_id=525,
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    def analyze_request(
        self,
        url: str,
        method: str,
        headers: dict,
        body: Optional[str] = None
    ) -> list[PassiveFinding]:
        """
        Analyze an HTTP request for security issues.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            body: Optional request body
            
        Returns:
            List of passive findings
        """
        findings = []
        
        # Check for sensitive data in URL
        url_findings = self._check_sensitive_data(url, url)
        for f in url_findings:
            f.location = 'url'
            f.title = f"{f.title} (in URL)"
            findings.append(f)
        
        # Check for sensitive data in request body
        if body:
            body_findings = self._check_sensitive_data(body, url)
            for f in body_findings:
                f.location = 'request_body'
                f.title = f"{f.title} (in request body)"
                findings.append(f)
        
        # Check for insecure cookies being sent
        cookie_header = headers.get('Cookie', '') or headers.get('cookie', '')
        if cookie_header and url.startswith('http://'):
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.INSECURE_LINK,
                severity=Severity.MEDIUM,
                title="Cookies Sent Over HTTP",
                description="Session cookies transmitted over unencrypted HTTP",
                evidence=f"Cookies sent to {url}",
                location='header',
                remediation="Use HTTPS for all requests involving cookies",
                confidence=0.95,
                cwe_id=311,
                owasp_category='A02:2021 - Cryptographic Failures'
            ))
        
        return findings


def create_passive_scanner() -> PassiveScanner:
    """Create a new passive scanner instance."""
    return PassiveScanner()
