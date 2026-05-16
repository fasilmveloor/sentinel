"""
Vulnerability Deduplication System.

Addresses the issue of counting payload variations as separate vulnerabilities.
Groups findings by: endpoint + vulnerability type + root cause.

This ensures:
- One finding per unique vulnerability
- Multiple evidence items aggregated
- Confidence scoring based on evidence quality
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from .models import AttackResult, AttackType, Endpoint, Severity, Vulnerability


@dataclass
class Evidence:
    """Evidence for a vulnerability finding."""
    payload: str
    response_status: int
    response_preview: str
    technique: str
    duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class GroupedVulnerability:
    """A vulnerability with aggregated evidence."""
    endpoint: Endpoint
    attack_type: AttackType
    root_cause: str
    severity: Severity
    confidence: float
    evidence_list: list[Evidence] = field(default_factory=list)
    title: str = ""
    description: str = ""
    recommendation: str = ""
    cwe_id: str | None = None
    owasp_category: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_list)

    def add_evidence(self, result: AttackResult, technique: str = "unknown"):
        """Add evidence from an attack result."""
        evidence = Evidence(
            payload=result.payload or "",
            response_status=result.response_status or 0,
            response_preview=(result.response_body or "")[:200],
            technique=technique,
            duration_ms=result.duration_ms or 0
        )
        self.evidence_list.append(evidence)
        self.confidence = min(1.0, 0.5 + (self.evidence_count * 0.1))


class VulnerabilityDeduplicator:
    """Deduplicates vulnerability findings by root cause, not payload."""

    def __init__(self):
        self.findings: dict[str, GroupedVulnerability] = {}

    def _generate_finding_key(
        self,
        endpoint: Endpoint,
        attack_type: AttackType,
        root_cause: str
    ) -> str:
        endpoint_id = f"{endpoint.method.value}:{endpoint.path}"
        key_data = f"{endpoint_id}|{attack_type.value}|{root_cause}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def _determine_root_cause(
        self,
        attack_type: AttackType,
        result: AttackResult
    ) -> str:
        extra_data = result.extra_data or {}

        if attack_type == AttackType.SQL_INJECTION:
            technique = extra_data.get('technique', 'error_based')
            if 'time_based' in technique:
                return "sql_injection_time_based_blind"
            elif 'boolean' in technique:
                return "sql_injection_boolean_blind"
            elif 'union' in technique:
                return "sql_injection_union_based"
            else:
                return "sql_injection_error_based"

        elif attack_type == AttackType.SSRF:
            ssrf_type = extra_data.get('ssrf_type', 'basic')
            if 'cloud_metadata' in ssrf_type:
                return "ssrf_cloud_metadata_access"
            elif 'file_read' in ssrf_type:
                return "ssrf_file_read"
            elif 'network_scan' in ssrf_type:
                return "ssrf_internal_network_access"
            elif 'blind' in ssrf_type:
                return "ssrf_blind"
            else:
                return "ssrf_basic"

        elif attack_type == AttackType.AUTH_BYPASS:
            if result.response_status == 200:
                if not result.payload or result.payload == "none":
                    return "auth_missing_token_accepted"
                elif "none" in str(result.payload).lower():
                    return "auth_jwt_none_algorithm"
                else:
                    return "auth_invalid_token_accepted"
            return "auth_bypass_unknown"

        elif attack_type == AttackType.JWT:
            vuln_type = extra_data.get('vulnerability_type', '')
            if 'none' in vuln_type.lower():
                return "jwt_none_algorithm_accepted"
            elif 'weak' in vuln_type.lower():
                return "jwt_weak_secret"
            elif 'confusion' in vuln_type.lower():
                return "jwt_algorithm_confusion"
            else:
                return "jwt_validation_flaw"

        elif attack_type == AttackType.XSS:
            context = extra_data.get('xss_context', 'unknown')
            return f"xss_{context}_context"

        elif attack_type == AttackType.RATE_LIMIT:
            return "rate_limit_missing"

        elif attack_type == AttackType.IDOR:
            return "idor_missing_authorization"

        elif attack_type == AttackType.BOLA:
            return "bola_missing_object_authorization"

        elif attack_type == AttackType.BFLA:
            return "bfla_missing_function_authorization"

        elif attack_type == AttackType.MASS_ASSIGNMENT:
            return "mass_assignment_unfiltered_properties"

        elif attack_type == AttackType.EXCESSIVE_DATA:
            return "excessive_data_exposure"

        elif attack_type == AttackType.NOSQL_INJECTION:
            technique = extra_data.get('technique', 'operator')
            return f"nosql_injection_{technique}"

        elif attack_type == AttackType.CMD_INJECTION:
            return "command_injection"

        else:
            return f"{attack_type.value}_unknown"

    def add_finding(
        self,
        result: AttackResult,
        endpoint: Endpoint,
        technique: str = "unknown"
    ) -> bool:
        root_cause = self._determine_root_cause(result.attack_type, result)
        key = self._generate_finding_key(endpoint, result.attack_type, root_cause)

        if key in self.findings:
            self.findings[key].add_evidence(result, technique)
            return False
        else:
            extra_data = result.extra_data or {}
            severity = self._determine_severity(
                result.attack_type, root_cause, endpoint, extra_data
            )
            confidence = self._calculate_initial_confidence(result, extra_data)

            grouped = GroupedVulnerability(
                endpoint=endpoint,
                attack_type=result.attack_type,
                root_cause=root_cause,
                severity=severity,
                confidence=confidence,
                title=self._generate_title(endpoint, result.attack_type, root_cause),
                description=self._generate_description(endpoint, result.attack_type, root_cause),
                recommendation=self._get_recommendation(result.attack_type, root_cause),
                cwe_id=self._get_cwe_id(result.attack_type, root_cause),
                owasp_category=self._get_owasp_category(result.attack_type),
                references=self._get_references(result.attack_type)
            )
            grouped.add_evidence(result, technique)
            self.findings[key] = grouped
            return True

    def _determine_severity(
        self,
        attack_type: AttackType,
        root_cause: str,
        endpoint: Endpoint,
        extra_data: dict
    ) -> Severity:
        base_severity = {
            AttackType.SQL_INJECTION: Severity.HIGH,
            AttackType.NOSQL_INJECTION: Severity.HIGH,
            AttackType.SSRF: Severity.HIGH,
            AttackType.AUTH_BYPASS: Severity.HIGH,
            AttackType.JWT: Severity.HIGH,
            AttackType.CMD_INJECTION: Severity.CRITICAL,
            AttackType.BOLA: Severity.HIGH,
            AttackType.BFLA: Severity.HIGH,
            AttackType.XSS: Severity.MEDIUM,
            AttackType.IDOR: Severity.HIGH,
            AttackType.RATE_LIMIT: Severity.LOW,
            AttackType.MASS_ASSIGNMENT: Severity.MEDIUM,
            AttackType.EXCESSIVE_DATA: Severity.MEDIUM,
        }.get(attack_type, Severity.MEDIUM)

        if 'cloud_metadata' in root_cause:
            base_severity = Severity.CRITICAL
        elif 'file_read' in root_cause:
            base_severity = Severity.CRITICAL

        path_lower = endpoint.path.lower()
        if '/admin' in path_lower or '/manage' in path_lower:
            if base_severity == Severity.MEDIUM:
                base_severity = Severity.HIGH
            elif base_severity == Severity.HIGH:
                base_severity = Severity.CRITICAL
        elif '/login' in path_lower or '/auth' in path_lower:
            if base_severity == Severity.MEDIUM:
                base_severity = Severity.HIGH

        if attack_type == AttackType.RATE_LIMIT:
            if '/login' in path_lower or '/auth' in path_lower:
                base_severity = Severity.HIGH
            elif '/admin' in path_lower:
                base_severity = Severity.MEDIUM
            else:
                base_severity = Severity.LOW

        return base_severity

    def _calculate_initial_confidence(self, result: AttackResult, extra_data: dict) -> float:
        confidence = 0.5
        if result.response_status == 200:
            confidence += 0.2
        elif result.response_status in [201, 202, 204]:
            confidence += 0.15
        if result.response_body:
            body_lower = result.response_body.lower()
            if any(err in body_lower for err in ['error', 'exception', 'sql', 'syntax']):
                confidence += 0.1
        if extra_data:
            confidence += 0.1
        if result.duration_ms and result.duration_ms > 1000:
            confidence += 0.05
        return min(1.0, confidence)

    def _generate_title(self, endpoint: Endpoint, attack_type: AttackType, root_cause: str) -> str:
        root_cause_readable = root_cause.replace('_', ' ').title()
        return f"{root_cause_readable} in {endpoint.method.value} {endpoint.path}"

    def _generate_description(self, endpoint: Endpoint, attack_type: AttackType, root_cause: str) -> str:
        return f"{attack_type.value.replace('_', ' ').title()} vulnerability detected in {endpoint.path}."

    def _get_recommendation(self, attack_type: AttackType, root_cause: str) -> str:
        recommendations = {
            'sql_injection': "Use parameterized queries and input validation.",
            'ssrf': "Implement URL allowlists and block internal IP ranges.",
            'auth': "Implement proper authentication validation on all protected endpoints.",
            'jwt': "Validate JWT algorithm and signature. Reject 'none' algorithm.",
            'rate_limit': "Implement rate limiting per user/IP with appropriate thresholds.",
        }
        for key, rec in recommendations.items():
            if key in root_cause:
                return rec
        return "Review and remediate the identified security issue."

    def _get_cwe_id(self, attack_type: AttackType, root_cause: str) -> str:
        cwe_mapping = {
            'sql_injection': "CWE-89",
            'ssrf': "CWE-918",
            'auth': "CWE-306",
            'jwt': "CWE-287",
            'xss': "CWE-79",
            'idor': "CWE-639",
            'rate_limit': "CWE-770",
            'cmd': "CWE-78",
            'nosql': "CWE-943",
        }
        for key, cwe in cwe_mapping.items():
            if key in root_cause:
                return cwe
        return "CWE-200"

    def _get_owasp_category(self, attack_type: AttackType) -> str:
        owasp_mapping = {
            AttackType.SQL_INJECTION: "A03:2021 - Injection",
            AttackType.NOSQL_INJECTION: "A03:2021 - Injection",
            AttackType.SSRF: "A10:2021 - SSRF",
            AttackType.AUTH_BYPASS: "A07:2021 - Auth Failures",
            AttackType.JWT: "A07:2021 - Auth Failures",
            AttackType.XSS: "A03:2021 - Injection",
            AttackType.IDOR: "A01:2021 - Broken Access Control",
            AttackType.BOLA: "API1:2023 - BOLA",
            AttackType.BFLA: "API5:2023 - BFLA",
            AttackType.RATE_LIMIT: "API4:2023 - Rate Limiting",
            AttackType.EXCESSIVE_DATA: "API3:2023 - Excessive Data",
            AttackType.MASS_ASSIGNMENT: "API6:2023 - Mass Assignment",
        }
        return owasp_mapping.get(attack_type, "A01:2021 - Broken Access Control")

    def _get_references(self, attack_type: AttackType) -> list[str]:
        references = {
            AttackType.SQL_INJECTION: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
            ],
            AttackType.SSRF: [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            ],
        }
        return references.get(attack_type, [])

    def get_unique_vulnerabilities(self) -> list[GroupedVulnerability]:
        return list(self.findings.values())

    def get_statistics(self) -> dict:
        vulns = self.get_unique_vulnerabilities()
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }
        for v in vulns:
            severity_counts[v.severity] += 1
        return {
            'total_unique': len(vulns),
            'severity_distribution': severity_counts,
            'by_attack_type': self._count_by_attack_type(vulns),
            'average_confidence': sum(v.confidence for v in vulns) / len(vulns) if vulns else 0,
        }

    def _count_by_attack_type(self, vulns: list[GroupedVulnerability]) -> dict:
        counts = {}
        for v in vulns:
            key = v.attack_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_vulnerability_models(self) -> list[Vulnerability]:
        models = []
        for grouped in self.get_unique_vulnerabilities():
            poc_lines = [
                f"Endpoint: {grouped.endpoint.method.value} {grouped.endpoint.path}",
                f"Root Cause: {grouped.root_cause}",
                f"Confidence: {grouped.confidence:.0%}",
                f"Evidence Count: {grouped.evidence_count}",
            ]

            vuln = Vulnerability(
                endpoint=grouped.endpoint,
                attack_type=grouped.attack_type,
                severity=grouped.severity,
                title=grouped.title,
                description=grouped.description,
                payload=grouped.evidence_list[0].payload if grouped.evidence_list else "",
                proof_of_concept="\n".join(poc_lines),
                recommendation=grouped.recommendation,
                cwe_id=grouped.cwe_id,
                owasp_category=grouped.owasp_category,
                references=grouped.references,
                cvss_score=self._severity_to_cvss(grouped.severity)
            )
            models.append(vuln)
        return models

    def _severity_to_cvss(self, severity: Severity) -> float:
        mapping = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0,
        }
        return mapping.get(severity, 5.0)
