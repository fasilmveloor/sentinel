"""
Markdown report generator for Sentinel scan results.

Generates detailed, actionable security reports in Markdown format.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import (
    ScanResult,
    Vulnerability,
    Severity,
    AttackType,
    Endpoint
)


class Reporter:
    """Generates Markdown security reports."""
    
    def __init__(self, output_path: str = "sentinel_report.md"):
        """Initialize the reporter.
        
        Args:
            output_path: Path to write the report file
        """
        self.output_path = Path(output_path)
    
    def generate(self, scan_result: ScanResult) -> str:
        """Generate a complete Markdown report.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            The generated Markdown content
        """
        sections = [
            self._generate_header(scan_result),
            self._generate_summary(scan_result),
            self._generate_vulnerabilities(scan_result),
            self._generate_endpoints_tested(scan_result),
            self._generate_recommendations(scan_result),
            self._generate_footer(scan_result)
        ]
        
        content = "\n\n".join(sections)
        return content
    
    def save(self, scan_result: ScanResult) -> str:
        """Generate and save the report to a file.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            Path to the saved report file
        """
        content = self.generate(scan_result)
        
        # Ensure parent directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write the file
        self.output_path.write_text(content, encoding='utf-8')
        
        return str(self.output_path)
    
    def _generate_header(self, scan_result: ScanResult) -> str:
        """Generate the report header."""
        return f"""# 🛡️ Sentinel Security Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target:** {scan_result.config.target_url}  
**Swagger Spec:** {scan_result.config.swagger_path}  
**Scan Duration:** {scan_result.duration_seconds:.2f} seconds"""
    
    def _generate_summary(self, scan_result: ScanResult) -> str:
        """Generate the executive summary section."""
        vuln_count = scan_result.vulnerability_count
        
        # Severity emoji mapping
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵"
        }
        
        summary = f"""## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Endpoints Tested | {len(scan_result.endpoints_tested)} |
| Total Requests Made | {scan_result.total_requests} |
| Vulnerabilities Found | {vuln_count} |
| Critical | {scan_result.critical_count} |
| High | {scan_result.high_count} |
| Medium | {scan_result.medium_count} |
| Low | {scan_result.low_count} |"""
        
        if vuln_count > 0:
            summary += f"\n\n### ⚠️ Risk Assessment\n\n"
            if scan_result.critical_count > 0:
                summary += "**CRITICAL RISK:** Immediate action required. Critical vulnerabilities found.\n\n"
            elif scan_result.high_count > 0:
                summary += "**HIGH RISK:** Urgent remediation recommended.\n\n"
            elif scan_result.medium_count > 0:
                summary += "**MEDIUM RISK:** Plan remediation in near-term sprint.\n\n"
            else:
                summary += "**LOW RISK:** Minor issues found. Address in regular maintenance.\n\n"
        else:
            summary += "\n\n✅ **No vulnerabilities detected.** Your API appears secure against tested attack types."
        
        return summary
    
    def _generate_vulnerabilities(self, scan_result: ScanResult) -> str:
        """Generate the detailed vulnerabilities section."""
        if not scan_result.vulnerabilities:
            return """## 🔍 Vulnerabilities

No vulnerabilities were found during this scan."""
        
        sections = ["## 🔍 Vulnerabilities Found\n"]
        
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            sections.append(self._format_vulnerability(vuln, i))
        
        return "\n\n---\n\n".join(sections)
    
    def _format_vulnerability(self, vuln: Vulnerability, index: int) -> str:
        """Format a single vulnerability for the report."""
        severity_emoji = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🔵 LOW"
        }
        
        section = f"""### {index}. {vuln.title}

| Attribute | Value |
|-----------|-------|
| Severity | {severity_emoji.get(vuln.severity, vuln.severity.value)} |
| Attack Type | {vuln.attack_type.value} |
| Endpoint | `{vuln.endpoint.full_path}` |
| CWE | {vuln.cwe_id or 'N/A'} |
| OWASP | {vuln.owasp_category or 'N/A'} |

#### 📝 Description

{vuln.description}

#### 💣 Proof of Concept

```
{vuln.proof_of_concept}
```

#### 🔧 Recommendation

{vuln.recommendation}"""
        
        if vuln.response_evidence:
            section += f"""

#### 📋 Response Evidence

```
{vuln.response_evidence[:500]}
```"""
        
        return section
    
    def _generate_endpoints_tested(self, scan_result: ScanResult) -> str:
        """Generate the list of tested endpoints."""
        if not scan_result.endpoints_tested:
            return ""
        
        section = """## 📋 Endpoints Tested

| # | Method | Path | Auth Required | Attacks |
|---|--------|------|---------------|---------|"""
        
        for i, endpoint in enumerate(scan_result.endpoints_tested, 1):
            auth = "✓" if endpoint.requires_auth else "✗"
            attacks = ", ".join([a.value for a in AttackType])
            section += f"\n| {i} | `{endpoint.method.value}` | `{endpoint.path}` | {auth} | {attacks} |"
        
        return section
    
    def _generate_recommendations(self, scan_result: ScanResult) -> str:
        """Generate overall recommendations section."""
        section = """## 💡 General Recommendations

### Security Best Practices

1. **Input Validation**
   - Validate and sanitize all user inputs
   - Use allowlists for expected input formats
   - Reject unexpected input patterns

2. **Authentication & Authorization**
   - Implement robust authentication for all sensitive endpoints
   - Use proven libraries (OAuth 2.0, JWT with proper validation)
   - Verify authorization on every request

3. **Data Protection**
   - Never expose internal IDs directly
   - Implement proper access controls
   - Log and monitor all access attempts

4. **API Security**
   - Rate limit all endpoints
   - Use HTTPS exclusively
   - Implement proper CORS policies
   - Version your APIs

### Next Steps

1. Address critical and high severity issues immediately
2. Create tickets for medium and low severity issues
3. Schedule regular security scans
4. Consider professional penetration testing for production APIs"""
        
        return section
    
    def _generate_footer(self, scan_result: ScanResult) -> str:
        """Generate the report footer."""
        return f"""---

*Report generated by [Sentinel](https://github.com/yourusername/sentinel) v0.1.0*  
*AI-powered API Security Testing Tool*

**Disclaimer:** This is an automated security assessment. Manual verification is recommended for all findings. This tool does not guarantee complete security coverage."""


def generate_report(scan_result: ScanResult, output_path: str = "sentinel_report.md") -> str:
    """Convenience function to generate and save a report.
    
    Args:
        scan_result: The scan result to report on
        output_path: Path to save the report
        
    Returns:
        Path to the saved report
    """
    reporter = Reporter(output_path)
    return reporter.save(scan_result)
