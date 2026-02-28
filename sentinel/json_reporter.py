"""
JSON and SARIF Report generators for Sentinel scan results.

Generates machine-readable reports for CI/CD integration.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from sentinel.models import (
    ScanResult,
    Vulnerability,
    Severity,
    AttackType,
    Endpoint
)


class JSONReporter:
    """Generates JSON reports for programmatic access."""
    
    def __init__(self, output_path: str = "sentinel_report.json"):
        """Initialize the JSON reporter."""
        self.output_path = Path(output_path)
    
    def generate(self, scan_result: ScanResult) -> dict:
        """Generate a JSON report.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            Dictionary representation of the report
        """
        return {
            "version": "2.0.0",
            "scan_info": {
                "target": scan_result.config.target_url,
                "swagger_path": scan_result.config.swagger_path,
                "scan_date": datetime.now().isoformat(),
                "duration_seconds": scan_result.duration_seconds,
                "total_requests": scan_result.total_requests
            },
            "summary": {
                "endpoints_tested": len(scan_result.endpoints_tested),
                "vulnerabilities_found": scan_result.vulnerability_count,
                "by_severity": {
                    "critical": scan_result.critical_count,
                    "high": scan_result.high_count,
                    "medium": scan_result.medium_count,
                    "low": scan_result.low_count,
                    "info": scan_result.info_count
                },
                "by_attack_type": self._count_by_attack_type(scan_result.vulnerabilities)
            },
            "endpoints": [
                {
                    "method": ep.method.value,
                    "path": ep.path,
                    "requires_auth": ep.requires_auth,
                    "parameters": [
                        {
                            "name": p.name,
                            "location": p.location,
                            "required": p.required,
                            "type": p.param_type
                        }
                        for p in ep.parameters
                    ]
                }
                for ep in scan_result.endpoints_tested
            ],
            "vulnerabilities": [
                self._vulnerability_to_dict(vuln, i)
                for i, vuln in enumerate(scan_result.vulnerabilities, 1)
            ],
            "ai_decisions": scan_result.ai_decisions
        }
    
    def save(self, scan_result: ScanResult) -> str:
        """Generate and save the report to a file.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            Path to the saved report file
        """
        content = self.generate(scan_result)
        
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(content, f, indent=2)
        
        return str(self.output_path)
    
    def _count_by_attack_type(self, vulnerabilities: list[Vulnerability]) -> dict:
        """Count vulnerabilities by attack type."""
        counts = {}
        for vuln in vulnerabilities:
            attack_name = vuln.attack_type.value
            counts[attack_name] = counts.get(attack_name, 0) + 1
        return counts
    
    def _vulnerability_to_dict(self, vuln: Vulnerability, index: int) -> dict:
        """Convert vulnerability to dictionary."""
        return {
            "id": f"SEN-{index:03d}",
            "title": vuln.title,
            "severity": vuln.severity.value,
            "attack_type": vuln.attack_type.value,
            "endpoint": {
                "method": vuln.endpoint.method.value,
                "path": vuln.endpoint.path
            },
            "description": vuln.description,
            "payload": vuln.payload,
            "proof_of_concept": vuln.proof_of_concept,
            "recommendation": vuln.recommendation,
            "cwe_id": vuln.cwe_id,
            "owasp_category": vuln.owasp_category,
            "cvss_score": vuln.cvss_score,
            "references": vuln.references
        }


class SARIFReporter:
    """Generates SARIF reports for GitHub Code Scanning integration."""
    
    def __init__(self, output_path: str = "sentinel_report.sarif"):
        """Initialize the SARIF reporter."""
        self.output_path = Path(output_path)
    
    def generate(self, scan_result: ScanResult) -> dict:
        """Generate a SARIF report.
        
        SARIF (Static Analysis Results Interchange Format) is a standard
        format for static analysis tools, supported by GitHub Code Scanning.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            SARIF-compliant dictionary
        """
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinel",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/yourusername/sentinel",
                            "rules": self._generate_rules(scan_result.vulnerabilities),
                            "organization": "Sentinel Security"
                        }
                    },
                    "results": self._generate_results(scan_result.vulnerabilities),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            "measurement": {
                                "duration": scan_result.duration_seconds
                            }
                        }
                    ],
                    "properties": {
                        "target": scan_result.config.target_url,
                        "total_requests": scan_result.total_requests,
                        "endpoints_tested": len(scan_result.endpoints_tested)
                    }
                }
            ]
        }
    
    def save(self, scan_result: ScanResult) -> str:
        """Generate and save the SARIF report."""
        content = self.generate(scan_result)
        
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(content, f, indent=2)
        
        return str(self.output_path)
    
    def _generate_rules(self, vulnerabilities: list[Vulnerability]) -> list:
        """Generate SARIF rules from vulnerabilities."""
        # Group by attack type for unique rules
        rules_map = {}
        
        for vuln in vulnerabilities:
            rule_id = self._get_rule_id(vuln.attack_type)
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": self._get_rule_name(vuln.attack_type),
                    "shortDescription": {
                        "text": self._get_rule_description(vuln.attack_type)
                    },
                    "fullDescription": {
                        "text": self._get_rule_full_description(vuln.attack_type)
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(vuln.severity)
                    },
                    "helpUri": self._get_help_uri(vuln.attack_type),
                    "properties": {
                        "tags": [
                            "security",
                            "api",
                            vuln.attack_type.value,
                            vuln.owasp_category or "unknown"
                        ],
                        "cwe": vuln.cwe_id
                    }
                }
        
        return list(rules_map.values())
    
    def _generate_results(self, vulnerabilities: list[Vulnerability]) -> list:
        """Generate SARIF results from vulnerabilities."""
        results = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            result = {
                "ruleId": self._get_rule_id(vuln.attack_type),
                "ruleIndex": 0,
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {
                    "text": vuln.description,
                    "markdown": f"**{vuln.title}**\n\n{vuln.description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.endpoint.path
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": vuln.endpoint.method.value,
                                "kind": "function"
                            }
                        ]
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": str(hash(vuln.endpoint.full_path + vuln.attack_type.value))
                },
                "properties": {
                    "severity": vuln.severity.value,
                    "attack_type": vuln.attack_type.value,
                    "payload": vuln.payload,
                    "proof_of_concept": vuln.proof_of_concept,
                    "recommendation": vuln.recommendation,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "cvss_score": vuln.cvss_score
                }
            }
            
            # Add code flows for complex vulnerabilities
            if vuln.proof_of_concept:
                result["codeFlows"] = [
                    {
                        "message": {
                            "text": "Attack flow"
                        },
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "location": {
                                            "message": {
                                                "text": step
                                            }
                                        }
                                    }
                                    for step in vuln.proof_of_concept.split('\n')[:5]
                                    if step.strip()
                                ]
                            }
                        ]
                    }
                ]
            
            results.append(result)
        
        return results
    
    def _get_rule_id(self, attack_type: AttackType) -> str:
        """Get SARIF rule ID for attack type."""
        return f"SEN{attack_type.value.upper()}"
    
    def _get_rule_name(self, attack_type: AttackType) -> str:
        """Get rule name for attack type."""
        names = {
            AttackType.SQL_INJECTION: "SQL Injection Detection",
            AttackType.XSS: "Cross-Site Scripting Detection",
            AttackType.AUTH_BYPASS: "Authentication Bypass Detection",
            AttackType.IDOR: "Insecure Direct Object Reference Detection",
            AttackType.SSRF: "Server-Side Request Forgery Detection",
            AttackType.JWT: "JWT Vulnerability Detection",
            AttackType.CMD_INJECTION: "Command Injection Detection",
            AttackType.RATE_LIMIT: "Rate Limit Issue Detection",
            AttackType.XXE: "XML External Entity Detection",
            AttackType.PATH_TRAVERSAL: "Path Traversal Detection"
        }
        return names.get(attack_type, attack_type.value.title())
    
    def _get_rule_description(self, attack_type: AttackType) -> str:
        """Get short rule description."""
        descriptions = {
            AttackType.SQL_INJECTION: "Detects SQL injection vulnerabilities in API endpoints",
            AttackType.XSS: "Detects Cross-Site Scripting vulnerabilities",
            AttackType.AUTH_BYPASS: "Detects authentication bypass vulnerabilities",
            AttackType.IDOR: "Detects Insecure Direct Object Reference vulnerabilities",
            AttackType.SSRF: "Detects Server-Side Request Forgery vulnerabilities",
            AttackType.JWT: "Detects JWT security vulnerabilities",
            AttackType.CMD_INJECTION: "Detects OS command injection vulnerabilities",
            AttackType.RATE_LIMIT: "Detects rate limiting issues",
        }
        return descriptions.get(attack_type, f"Detects {attack_type.value} vulnerabilities")
    
    def _get_rule_full_description(self, attack_type: AttackType) -> str:
        """Get full rule description."""
        return self._get_rule_description(attack_type) + " in API endpoints."
    
    def _get_help_uri(self, attack_type: AttackType) -> str:
        """Get help URI for attack type."""
        uris = {
            AttackType.SQL_INJECTION: "https://owasp.org/www-community/attacks/SQL_Injection",
            AttackType.XSS: "https://owasp.org/www-community/attacks/xss/",
            AttackType.AUTH_BYPASS: "https://owasp.org/www-community/Broken_Authentication",
            AttackType.IDOR: "https://owasp.org/www-community/Top_10/2013-A4-Insecure_Direct_Object_References",
            AttackType.SSRF: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            AttackType.JWT: "https://auth0.com/blog/jwt-authentication-best-practices/",
            AttackType.CMD_INJECTION: "https://owasp.org/www-community/attacks/Command_Injection",
            AttackType.RATE_LIMIT: "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
        }
        return uris.get(attack_type, "https://owasp.org/")
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "warning")


class JUnitReporter:
    """Generates JUnit XML reports for CI/CD integration."""
    
    def __init__(self, output_path: str = "sentinel_report.xml"):
        """Initialize the JUnit reporter."""
        self.output_path = Path(output_path)
    
    def generate(self, scan_result: ScanResult) -> str:
        """Generate a JUnit XML report."""
        # Build test cases for each vulnerability
        test_cases = []
        
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            test_case = f'''    <testcase name="{self._escape_xml(vuln.title)}" classname="sentinel.{vuln.attack_type.value}" time="0.1">
      <failure message="{self._escape_xml(vuln.description[:200])}" type="{vuln.severity.value.upper()}">
{self._escape_xml(vuln.proof_of_concept)}
      </failure>
    </testcase>'''
            test_cases.append(test_case)
        
        # Build test cases for clean endpoints (no vulnerabilities)
        vulnerable_endpoints = {v.endpoint.full_path for v in scan_result.vulnerabilities}
        for ep in scan_result.endpoints_tested:
            if ep.full_path not in vulnerable_endpoints:
                test_cases.append(f'''    <testcase name="Security test for {ep.method.value} {ep.path}" classname="sentinel.security" time="0.1" />''')
        
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Sentinel Security Scan" tests="{len(test_cases)}" failures="{scan_result.vulnerability_count}" errors="0" skipped="0" time="{scan_result.duration_seconds}">
{chr(10).join(test_cases)}
</testsuite>'''
    
    def save(self, scan_result: ScanResult) -> str:
        """Generate and save the JUnit report."""
        content = self.generate(scan_result)
        
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(self.output_path)
    
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        if not text:
            return ""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def generate_json_report(scan_result: ScanResult, output_path: str = "sentinel_report.json") -> str:
    """Generate and save a JSON report."""
    reporter = JSONReporter(output_path)
    return reporter.save(scan_result)


def generate_sarif_report(scan_result: ScanResult, output_path: str = "sentinel_report.sarif") -> str:
    """Generate and save a SARIF report."""
    reporter = SARIFReporter(output_path)
    return reporter.save(scan_result)


def generate_junit_report(scan_result: ScanResult, output_path: str = "sentinel_report.xml") -> str:
    """Generate and save a JUnit XML report."""
    reporter = JUnitReporter(output_path)
    return reporter.save(scan_result)
