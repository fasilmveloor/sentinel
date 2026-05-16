"""
BOLA (Broken Object Level Authorization) / Advanced IDOR Detection Module.

Tests API endpoints for BOLA vulnerabilities by:
- Multi-user authenticated testing
- Comparing responses between different users
- Detecting unauthorized access to other users' resources
- Testing with various ID types (numeric, UUID, ObjectId)
"""

import json
import re
import time
from dataclasses import dataclass
from typing import Any

import requests

from ..models import AttackResult, AttackType, Endpoint, Severity, Vulnerability


@dataclass
class UserCredentials:
    """User credentials for multi-user testing."""
    user_id: str
    email: str
    token: str
    username: str = ""


class BOLAAttacker:
    """Performs BOLA (Broken Object Level Authorization) attacks on API endpoints.

    This is a more advanced IDOR detection that:
    1. Uses multiple authenticated users
    2. Compares responses between users
    3. Detects unauthorized data access
    """

    # Common ID patterns
    NUMERIC_IDS = ["1", "2", "3", "0", "100", "999", "1000"]
    UUID_IDS = [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    ]

    # Parameters that commonly contain resource IDs
    RESOURCE_ID_PARAMS = [
        'id', 'user_id', 'userId', 'user', 'account_id', 'accountId',
        'order_id', 'orderId', 'order', 'vehicle_id', 'vehicleId',
        'video_id', 'videoId', 'post_id', 'postId', 'comment_id',
        'report_id', 'reportId', 'mechanic_id', 'mechanicId',
        'product_id', 'productId', 'coupon', 'coupon_code'
    ]

    # Sensitive fields that indicate data exposure
    SENSITIVE_FIELDS = [
        'email', 'password', 'token', 'ssn', 'credit_card', 'phone',
        'address', 'name', 'firstname', 'lastname', 'username',
        'api_key', 'secret', 'private', 'balance', 'account'
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the BOLA attacker.

        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.sessions: dict[str, requests.Session] = {}
        self.discovered_resources: dict[str, list[str]] = {}
        self.credentials: list[UserCredentials] = []

    def set_credentials(self, credentials: list[UserCredentials]):
        """Set user credentials for multi-user testing.

        Args:
            credentials: List of UserCredentials for testing
        """
        self.credentials = credentials
        for cred in credentials:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Sentinel/1.0 BOLA Scanner',
                'Accept': 'application/json',
                'Authorization': f"Bearer {cred.token}"
            })
            self.sessions[cred.user_id] = session

    def attack(
        self,
        endpoint: Endpoint,
        auth_token: str | None = None,
        parameters_to_test: list[str] | None = None
    ) -> list[AttackResult]:
        """Perform BOLA attacks on an endpoint.

        Args:
            endpoint: The endpoint to attack
            auth_token: Fallback auth token if no multi-user setup
            parameters_to_test: Specific parameters to test

        Returns:
            List of attack results
        """
        results: list[AttackResult] = []

        # Handle API misuse (list passed as auth_token)
        if auth_token is not None and isinstance(auth_token, list):
            auth_token = None

        # Setup fallback session if no multi-user credentials
        if not self.sessions and auth_token:
            self._setup_fallback_session(auth_token)

        # Extract resource IDs from path
        path_ids = self._extract_path_ids(endpoint.path)
        concrete_id = self._extract_concrete_id(endpoint.path)

        # Step 1: Discover resources with each user
        if endpoint.method.value == 'GET':
            discovered = self._discover_resources(endpoint)
            for resource_id in discovered:
                results.extend(self._test_resource_access(endpoint, resource_id, path_ids))

        # Step 2: Test path-based IDOR
        for path_id in path_ids:
            results.extend(self._test_path_bola(endpoint, path_id))

        # Step 2b: Test concrete IDs already present in the path
        if concrete_id:
            results.extend(self._test_concrete_path_bola(endpoint, concrete_id))

        # Step 3: Test with discovered IDs from other endpoints
        for _resource_type, resource_ids in self.discovered_resources.items():
            results.extend(self._test_discovered_ids(endpoint, resource_ids, path_ids))

        return results

    def _setup_fallback_session(self, auth_token: str):
        """Setup a single session for basic testing."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Sentinel/1.0 BOLA Scanner',
            'Accept': 'application/json',
            'Authorization': f"Bearer {auth_token}"
        })
        self.sessions['default'] = session

    def _extract_path_ids(self, path: str) -> list[str]:
        """Extract ID parameter names from path."""
        pattern = r'\{([^}]+)\}'
        matches = re.findall(pattern, path)
        return [m for m in matches if any(
            id_word in m.lower()
            for id_word in ['id', 'user', 'account', 'vehicle', 'order', 'video', 'post', 'report']
        )]

    def _extract_concrete_id(self, path: str) -> str | None:
        """Extract a concrete numeric ID from the path when present."""
        matches = re.findall(r'/(\d+)(?:/|$)', path)
        return matches[-1] if matches else None

    def _is_sensitive_data(self, response_text: str) -> bool:
        """Check whether the response exposes user-related data."""
        response_lower = response_text.lower()
        return any(field in response_lower for field in ["email", "username", "account", "user"])

    def _extract_evidence_excerpt(self, response_text: str) -> str | None:
        """Extract a focused evidence snippet around sensitive fields."""
        response_lower = response_text.lower()
        for field in ["email", "username", "account", "user"]:
            index = response_lower.find(field)
            if index != -1:
                start = max(index - 40, 0)
                end = min(index + 160, len(response_text))
                return response_text[start:end]
        return response_text[:200] if response_text else None

    def _responses_equivalent(self, a: str, b: str) -> bool:
        """Compare two response bodies semantically when possible."""
        try:
            a_json = json.loads(a)
            b_json = json.loads(b)
            return a_json == b_json
        except Exception:
            return a.strip() == b.strip()

    def _build_attack_result(
        self,
        endpoint: Endpoint,
        payload: str,
        url: str,
        response: requests.Response | None = None,
        error_message: str | None = None,
        duration_ms: float | None = None,
        success: bool = False,
    ) -> AttackResult:
        """Create a BOLA result with proof fields."""
        response_text = response.text[:500] if response is not None else None
        evidence_excerpt = None
        if response is not None and success:
            evidence_excerpt = self._extract_evidence_excerpt(response.text)

        return AttackResult(
            endpoint=endpoint,
            attack_type=AttackType.BOLA,
            success=success,
            payload=payload,
            request_url=url,
            request_method=endpoint.method.value,
            response_status=response.status_code if response is not None else None,
            response_body=response_text,
            evidence_excerpt=evidence_excerpt,
            duration_ms=duration_ms,
            error_message=error_message,
        )

    def _discover_resources(self, endpoint: Endpoint) -> list[str]:
        """Try to discover resource IDs from list endpoints."""
        discovered = []

        # Common list endpoint patterns
        list_paths = [
            "/identity/api/v2/vehicle/vehicles",
            "/identity/api/v2/user/videos",
            "/workshop/api/shop/orders",
            "/workshop/api/shop/orders/all",
            "/community/api/v2/community/posts/recent",
            "/workshop/api/mechanic/mechanic_report",
        ]

        for _session_id, session in self.sessions.items():
            for path in list_paths:
                try:
                    url = f"{self.target_url}{path}"
                    response = session.get(url, timeout=self.timeout)

                    if response.status_code == 200:
                        data = response.json()
                        ids = self._extract_ids_from_response(data)
                        discovered.extend(ids)

                        # Store for later use
                        resource_type = path.split('/')[-1]
                        if resource_type not in self.discovered_resources:
                            self.discovered_resources[resource_type] = []
                        self.discovered_resources[resource_type].extend(ids)

                except Exception:
                    pass

        return list(set(discovered))

    def _extract_ids_from_response(self, data: Any) -> list[str]:
        """Extract resource IDs from API response."""
        ids = []

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key in ['id', 'vehicle_id', 'video_id', 'order_id', 'post_id', 'report_id', 'user_id']:
                        if key in item and item[key]:
                            ids.append(str(item[key]))

        elif isinstance(data, dict):
            # Check for nested data
            for key, value in data.items():
                if key in ['data', 'items', 'results', 'vehicles', 'videos', 'orders', 'posts']:
                    ids.extend(self._extract_ids_from_response(value))
                elif key.endswith('_id') or key == 'id':
                    ids.append(str(value))

        return ids

    def _test_resource_access(
        self,
        endpoint: Endpoint,
        resource_id: str,
        path_ids: list[str]
    ) -> list[AttackResult]:
        """Test if users can access each other's resources."""
        results = []

        if len(self.sessions) < 2:
            # Single user mode - just test access
            return self._test_single_user_access(endpoint, resource_id, path_ids)

        # Multi-user testing
        user_responses = {}

        for session_id, session in self.sessions.items():
            try:
                # Build URL with resource ID
                path = endpoint.path
                for path_id in path_ids:
                    path = path.replace(f"{{{path_id}}}", resource_id)

                url = f"{self.target_url}{path}"
                response = session.get(url, timeout=self.timeout)

                if response.status_code == 200:
                    user_responses[session_id] = {
                        'status': response.status_code,
                        'data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                        'size': len(response.text)
                    }
            except Exception:
                pass

        # Analyze responses
        if len(user_responses) > 1:
            # Check if all users got the same data
            sizes = [r['size'] for r in user_responses.values()]

            # If responses are similar, there might be a BOLA
            if len(set(sizes)) == 1:
                # All users got same response - potential BOLA
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.IDOR,
                    success=True,
                    payload=f"Resource ID: {resource_id}",
                    response_status=200,
                    response_body=f"All {len(user_responses)} users could access resource",
                    error_message="BOLA: Multiple users can access same resource"
                ))

        return results

    def _test_single_user_access(
        self,
        endpoint: Endpoint,
        resource_id: str,
        path_ids: list[str]
    ) -> list[AttackResult]:
        """Test access with a single user session."""
        results = []
        session = list(self.sessions.values())[0]

        # Test various ID manipulations
        test_ids = self._generate_test_ids(resource_id)

        for test_id in test_ids:
            try:
                path = endpoint.path
                for path_id in path_ids:
                    path = path.replace(f"{{{path_id}}}", test_id)

                url = f"{self.target_url}{path}"
                start_time = time.time()
                response = session.get(url, timeout=self.timeout)
                duration_ms = (time.time() - start_time) * 1000

                is_vulnerable = self._is_bola_vulnerable(response, test_id)

                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.IDOR,
                    success=is_vulnerable,
                    payload=f"Resource ID: {test_id}",
                    response_status=response.status_code,
                    response_body=response.text[:500],
                    duration_ms=duration_ms
                ))

            except Exception as e:
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.IDOR,
                    success=False,
                    payload=f"Resource ID: {test_id}",
                    error_message=str(e)
                ))

        return results

    def _test_concrete_path_bola(
        self,
        endpoint: Endpoint,
        original_id: str,
    ) -> list[AttackResult]:
        """Test BOLA against an endpoint that already contains a concrete ID."""
        results: list[AttackResult] = []
        if not self.sessions:
            return results

        session = list(self.sessions.values())[0]
        baseline_url = f"{self.target_url}{endpoint.path}"

        try:
            baseline_response = session.request(
                endpoint.method.value,
                baseline_url,
                timeout=self.timeout
            )
        except Exception:
            baseline_response = None

        for new_id in self._generate_test_ids(original_id):
            modified_path = re.sub(rf'/{re.escape(original_id)}(?:/|$)', f'/{new_id}', endpoint.path, count=1)
            if modified_path == endpoint.path:
                continue

            url = f"{self.target_url}{modified_path}"
            try:
                start_time = time.time()
                attack_response = session.request(
                    endpoint.method.value,
                    url,
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                success = (
                    attack_response.status_code in [200, 201]
                    and self._is_sensitive_data(attack_response.text)
                    and baseline_response is not None
                    and not self._responses_equivalent(baseline_response.text, attack_response.text)
                )
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=f"id_swap: {original_id} -> {new_id}",
                        url=url,
                        response=attack_response,
                        duration_ms=duration_ms,
                        success=success,
                        error_message=(
                            "Unauthorized object access with valid authentication"
                            if success else (
                                "Missing valid baseline for comparison"
                                if baseline_response is None else None
                            )
                        ),
                    )
                )
            except Exception as exc:
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=f"id_swap: {original_id} -> {new_id}",
                        url=url,
                        error_message=str(exc),
                        success=False,
                    )
                )

        return results

    def _test_path_bola(
        self,
        endpoint: Endpoint,
        path_param: str
    ) -> list[AttackResult]:
        """Test BOLA by manipulating path parameters."""
        results = []
        if not self.sessions:
            return results

        session = list(self.sessions.values())[0]
        original_id = None
        for candidate in self.NUMERIC_IDS:
            baseline_path = endpoint.path.replace(f"{{{path_param}}}", candidate)
            baseline_url = f"{self.target_url}{baseline_path}"
            try:
                baseline_response = session.request(
                    endpoint.method.value,
                    baseline_url,
                    timeout=self.timeout
                )
                if baseline_response.status_code in [200, 201]:
                    original_id = candidate
                    break
            except Exception:
                continue

        if original_id is None:
            return results

        baseline_path = endpoint.path.replace(f"{{{path_param}}}", original_id)
        baseline_url = f"{self.target_url}{baseline_path}"
        try:
            baseline_response = session.request(
                endpoint.method.value,
                baseline_url,
                timeout=self.timeout
            )
        except Exception:
            baseline_response = None

        for test_id in self._generate_test_ids(original_id):
            modified_path = endpoint.path.replace(f"{{{path_param}}}", test_id)
            url = f"{self.target_url}{modified_path}"

            try:
                start_time = time.time()
                attack_response = session.request(
                    endpoint.method.value,
                    url,
                    timeout=self.timeout
                )
                duration_ms = (time.time() - start_time) * 1000
                success = (
                    attack_response.status_code in [200, 201]
                    and self._is_sensitive_data(attack_response.text)
                    and baseline_response is not None
                    and not self._responses_equivalent(baseline_response.text, attack_response.text)
                )
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=f"id_swap: {original_id} -> {test_id}",
                        url=url,
                        response=attack_response,
                        duration_ms=duration_ms,
                        success=success,
                        error_message=(
                            "Unauthorized object access with valid authentication"
                            if success else (
                                "Missing valid baseline for comparison"
                                if baseline_response is None else None
                            )
                        ),
                    )
                )
            except Exception as exc:
                results.append(
                    self._build_attack_result(
                        endpoint=endpoint,
                        payload=f"id_swap: {original_id} -> {test_id}",
                        url=url,
                        error_message=str(exc),
                        success=False,
                    )
                )

        return results

    def _test_discovered_ids(
        self,
        endpoint: Endpoint,
        resource_ids: list[str],
        path_ids: list[str]
    ) -> list[AttackResult]:
        """Test with IDs discovered from other endpoints."""
        results = []

        for resource_id in resource_ids[:10]:  # Limit to prevent too many requests
            results.extend(self._test_resource_access(endpoint, resource_id, path_ids))

        return results

    def _generate_test_ids(self, original_id: str) -> list[str]:
        """Generate test IDs based on original ID type."""
        test_ids = []

        # Always test adjacent IDs
        try:
            if original_id.isdigit():
                num = int(original_id)
                test_ids.extend([
                    str(num - 1), str(num + 1),
                    str(num + 100), str(num - 100),
                    "0", "1", "999999"
                ])
        except Exception:
            pass

        # Add common test values
        test_ids.extend(self.NUMERIC_IDS)

        # If it looks like UUID, test other UUIDs
        if '-' in original_id and len(original_id) == 36:
            test_ids.extend(self.UUID_IDS)

        return list(set(test_ids))

    def _is_bola_vulnerable(self, response: requests.Response, test_id: str) -> bool:
        """Check if response indicates BOLA vulnerability."""
        # Status codes that indicate successful access
        if response.status_code not in [200, 201, 202]:
            return False

        try:
            data = response.json()

            # Check for sensitive data exposure
            data_str = json.dumps(data).lower()
            if any(field in data_str for field in self.SENSITIVE_FIELDS):
                return True

            # Check if response contains actual data (not just empty object)
            if isinstance(data, dict) and len(data) > 2:
                return True

            if isinstance(data, list) and len(data) > 0:
                return True

        except Exception:
            # Non-JSON with content
            if len(response.text) > 100:
                return True

        return False

    def create_vulnerability(
        self,
        result: AttackResult,
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.IDOR,
            severity=Severity.HIGH,
            title=f"BOLA Vulnerability in {endpoint.full_path}",
            description=(
                "Broken Object Level Authorization (BOLA) vulnerability detected. "
                "The API endpoint fails to properly verify that the authenticated user "
                "has permission to access the requested resource. An attacker can access, "
                "modify, or delete resources belonging to other users by manipulating "
                "resource identifiers in API requests."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {result.request_method} {result.request_url}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Evidence: {result.evidence_excerpt}\n"
                f"Successfully accessed resource without proper authorization."
            ),
            recommendation=(
                "1. Implement object-level authorization checks for every API endpoint\n"
                "2. Verify user ownership before granting access to any resource\n"
                "3. Use indirect references (tokens) instead of direct database IDs\n"
                "4. Implement access control lists (ACLs) for fine-grained permissions\n"
                "5. Log all access attempts for security monitoring\n"
                "6. Consider using a policy engine like Open Policy Agent (OPA)"
            ),
            cwe_id="CWE-639",
            owasp_category="API1:2023 - Broken Object Level Authorization",
            response_evidence=result.evidence_excerpt or result.response_body
        )
