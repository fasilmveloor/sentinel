"""
Excessive Data Exposure Detection Module.

Tests API endpoints for data overexposure by:
- Analyzing response content for sensitive fields
- Comparing response size against expected size
- Detecting PII/Sensitive data in responses
- Finding hidden/internal properties
"""

import json
import time
from typing import Any

import requests

from ..models import AttackResult, AttackType, Endpoint, Severity, Vulnerability


class ExcessiveDataExposureAttacker:
    """Detects excessive data exposure vulnerabilities in API responses.

    Excessive Data Exposure occurs when an API returns more data than
    necessary, potentially exposing sensitive information.
    """

    # Sensitive field patterns (PII and sensitive data)
    PII_FIELDS = [
        # Personal identifiers
        'ssn', 'social_security', 'national_id', 'passport', 'driver_license',
        'tax_id', 'national_insurance', 'citizenship',

        # Contact info
        'email', 'email_address', 'phone', 'phone_number', 'mobile',
        'address', 'street', 'city', 'state', 'zip', 'postal', 'country',

        # Names
        'firstname', 'first_name', 'lastname', 'last_name', 'full_name',
        'name', 'username', 'nickname', 'display_name',

        # Authentication
        'password', 'passwd', 'pwd', 'pass', 'secret', 'api_key', 'apikey',
        'token', 'jwt', 'session', 'auth', 'credential', 'private_key',

        # Financial
        'credit_card', 'card_number', 'cvv', 'cvc', 'expiry', 'exp_date',
        'bank_account', 'routing_number', 'iban', 'swift', 'balance',
        'salary', 'income', 'transaction',

        # Health
        'medical', 'health', 'diagnosis', 'prescription', 'patient',

        # Other sensitive
        'dob', 'date_of_birth', 'birthday', 'age', 'gender', 'sex',
        'race', 'ethnicity', 'religion', 'sexual_orientation',
        'ip_address', 'mac_address', 'device_id', 'imei'
    ]

    # Internal properties that shouldn't be exposed
    INTERNAL_FIELDS = [
        '_id', '__v', '_class', '_type', 'internal_id', 'db_id',
        'created_at', 'updated_at', 'deleted_at', 'is_deleted',
        'version', 'schema_version', 'migration_id',
        'owner_id', 'creator_id', 'organization_id', 'tenant_id',
        'audit_log', 'change_history', 'metadata', 'meta',
        'is_admin', 'is_superuser', 'role_id', 'permission_id',
        'stripe_id', 'payment_id', 'subscription_id',
        'last_login', 'login_count', 'failed_attempts',
        'reset_token', 'verification_token', 'invite_token'
    ]

    # Fields that suggest overexposure when returned in bulk
    BULK_EXPOSURE_FIELDS = [
        'users', 'accounts', 'customers', 'members', 'employees',
        'transactions', 'orders', 'payments', 'records'
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """Initialize the Excessive Data Exposure detector.

        Args:
            target_url: Base URL of the target API
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sentinel/1.0 Data Exposure Scanner',
            'Accept': 'application/json'
        })

    def attack(
        self,
        endpoint: Endpoint,
        auth_token: str | None = None,
        parameters_to_test: list[str] | None = None
    ) -> list[AttackResult]:
        """Perform excessive data exposure analysis on an endpoint.

        Args:
            endpoint: The endpoint to analyze
            auth_token: Authentication token for the request
            parameters_to_test: Not used for this attack type

        Returns:
            List of attack results
        """
        results: list[AttackResult] = []

        # Handle API misuse
        if auth_token is not None and isinstance(auth_token, list):
            auth_token = None

        if auth_token:
            self.session.headers['Authorization'] = f"Bearer {auth_token}"

        # Make the request and analyze response
        response = self._make_request(endpoint)

        if response:
            # Analyze response for excessive data
            analysis = self._analyze_response(response, endpoint)

            if analysis['has_excessive_data']:
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,  # Using as closest match
                    success=True,
                    payload="Response Analysis",
                    response_status=response.status_code,
                    response_body=json.dumps(analysis['findings'])[:500],
                    error_message=f"Excessive data exposure: {analysis['summary']}"
                ))

            # Also check for internal property exposure
            internal_findings = self._check_internal_properties(response)
            if internal_findings:
                results.append(AttackResult(
                    endpoint=endpoint,
                    attack_type=AttackType.AUTH_BYPASS,
                    success=True,
                    payload="Internal Property Check",
                    response_status=response.status_code,
                    response_body=json.dumps(internal_findings)[:500],
                    error_message=f"Internal properties exposed: {list(internal_findings.keys())}"
                ))

        return results

    def _make_request(self, endpoint: Endpoint) -> requests.Response | None:
        """Make a request to the endpoint."""
        try:
            url = f"{self.target_url}{endpoint.path}"

            # Build parameters
            params = {}
            json_body = None

            for param in endpoint.parameters:
                if param.location == 'query':
                    params[param.name] = param.example if param.example else self._get_default(param)
                elif param.location == 'body' and param.example:
                    json_body = param.example

            time.time()
            response = self.session.request(
                endpoint.method.value,
                url,
                params=params,
                json=json_body,
                timeout=self.timeout
            )

            return response

        except Exception:
            return None

    def _get_default(self, param) -> Any:
        """Get default value for parameter."""
        defaults = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
        }
        return defaults.get(param.param_type, 'test')

    def _analyze_response(
        self,
        response: requests.Response,
        endpoint: Endpoint
    ) -> dict:
        """Analyze response for excessive data exposure."""
        analysis = {
            'has_excessive_data': False,
            'findings': [],
            'summary': ''
        }

        if response.status_code not in [200, 201]:
            return analysis

        try:
            data = response.json()
        except Exception:
            return analysis

        # Flatten nested data for analysis
        flat_data = self._flatten_dict(data)

        # Check for PII fields
        pii_found = []
        for key in flat_data.keys():
            key_lower = key.lower()
            for pii_field in self.PII_FIELDS:
                if pii_field in key_lower:
                    pii_found.append(key)
                    break

        if pii_found:
            analysis['has_excessive_data'] = True
            analysis['findings'].append({
                'type': 'PII_EXPOSURE',
                'fields': pii_found[:10],  # Limit for readability
                'count': len(pii_found)
            })

        # Check for bulk data exposure
        if isinstance(data, list):
            if len(data) > 10:
                analysis['has_excessive_data'] = True
                analysis['findings'].append({
                    'type': 'BULK_DATA',
                    'count': len(data),
                    'message': f'API returns {len(data)} records without pagination'
                })

            # Check if each record contains sensitive data
            if len(data) > 0 and isinstance(data[0], dict):
                sensitive_in_records = []
                for key in data[0].keys():
                    key_lower = key.lower()
                    if any(pii in key_lower for pii in self.PII_FIELDS):
                        sensitive_in_records.append(key)

                if sensitive_in_records:
                    analysis['has_excessive_data'] = True
                    analysis['findings'].append({
                        'type': 'BULK_PII_EXPOSURE',
                        'fields': sensitive_in_records,
                        'record_count': len(data),
                        'message': f'PII fields exposed in {len(data)} records'
                    })

        # Check for nested user data
        if isinstance(data, dict):
            for key in self.BULK_EXPOSURE_FIELDS:
                if key in data and isinstance(data[key], list):
                    if len(data[key]) > 0:
                        analysis['has_excessive_data'] = True
                        analysis['findings'].append({
                            'type': 'NESTED_BULK_DATA',
                            'field': key,
                            'count': len(data[key])
                        })

        # Generate summary
        if analysis['findings']:
            summaries = []
            for finding in analysis['findings']:
                if finding['type'] == 'PII_EXPOSURE':
                    summaries.append(f"PII fields exposed: {', '.join(finding['fields'][:5])}")
                elif finding['type'] == 'BULK_PII_EXPOSURE':
                    summaries.append(f"Bulk PII in {finding['record_count']} records")
                elif finding['type'] == 'BULK_DATA':
                    summaries.append(f"Unpaginated list of {finding['count']} records")
                elif finding['type'] == 'NESTED_BULK_DATA':
                    summaries.append(f"Nested list '{finding['field']}' with {finding['count']} items")

            analysis['summary'] = '; '.join(summaries)

        return analysis

    def _check_internal_properties(self, response: requests.Response) -> dict:
        """Check for internal property exposure."""
        findings = {}

        if response.status_code not in [200, 201]:
            return findings

        try:
            data = response.json()
            flat_data = self._flatten_dict(data)

            for key, value in flat_data.items():
                key_lower = key.lower()
                for internal_field in self.INTERNAL_FIELDS:
                    if internal_field in key_lower:
                        # Mask sensitive values
                        if isinstance(value, str) and len(value) > 20:
                            findings[key] = f"{value[:10]}...{value[-5:]}"
                        else:
                            findings[key] = value

        except Exception:
            pass

        return findings

    def _flatten_dict(self, d: Any, parent_key: str = '', sep: str = '.') -> dict:
        """Flatten nested dictionary for analysis."""
        items = []

        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(self._flatten_dict(v, new_key, sep).items())
                elif isinstance(v, list):
                    if len(v) > 0 and isinstance(v[0], dict):
                        # Sample first item from list
                        items.extend(self._flatten_dict(v[0], f"{new_key}[0]", sep).items())
                    else:
                        items.append((new_key, v))
                else:
                    items.append((new_key, v))
        elif isinstance(d, list):
            for i, item in enumerate(d[:3]):  # Sample first 3 items
                if isinstance(item, dict):
                    items.extend(self._flatten_dict(item, f"[{i}]", sep).items())

        return dict(items)

    def create_vulnerability(
        self,
        result: AttackResult,
        endpoint: Endpoint
    ) -> Vulnerability:
        """Create a Vulnerability object from an attack result."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            severity=Severity.MEDIUM,
            title=f"Excessive Data Exposure in {endpoint.full_path}",
            description=(
                f"The API endpoint returns more data than necessary, potentially "
                f"exposing sensitive user information. {result.error_message or ''} "
                f"This violates the principle of data minimization and could lead to "
                f"privacy violations and data leaks."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {endpoint.method.value} {endpoint.path}\n"
                f"Response analysis revealed excessive data exposure.\n"
                f"Exposed fields: {result.response_body[:200]}"
            ),
            recommendation=(
                "1. Implement response filtering to return only necessary fields\n"
                "2. Use DTOs (Data Transfer Objects) to shape responses\n"
                "3. Apply field-level authorization checks\n"
                "4. Implement GraphQL-like field selection for clients\n"
                "5. Never return internal properties like IDs, versions, timestamps\n"
                "6. Add pagination for list endpoints\n"
                "7. Review all API responses for sensitive data exposure"
            ),
            cwe_id="CWE-200",
            owasp_category="API3:2023 - Broken Object Property Level Authorization",
            response_evidence=result.response_body
        )
