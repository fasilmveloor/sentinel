"""
HTML Report generator for Sentinel scan results.

Generates visual, interactive HTML reports with charts and detailed findings.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
import base64

from ..models import (
    ScanResult,
    Vulnerability,
    Severity,
    AttackType,
    Endpoint
)


class HTMLReporter:
    """Generates HTML security reports with interactive features."""
    
    def __init__(self, output_path: str = "sentinel_report.html"):
        """Initialize the HTML reporter.
        
        Args:
            output_path: Path to write the report file
        """
        self.output_path = Path(output_path)
    
    def generate(self, scan_result: ScanResult) -> str:
        """Generate a complete HTML report.
        
        Args:
            scan_result: The scan result to report on
            
        Returns:
            The generated HTML content
        """
        html = self._get_html_template(scan_result)
        return html
    
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
    
    def _get_html_template(self, result: ScanResult) -> str:
        """Get the complete HTML template."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            min-height: 100vh;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header-meta {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            margin-top: 20px;
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .meta-item span {{
            color: #00d4ff;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card.critical {{ border-left: 4px solid #ff4757; }}
        .stat-card.high {{ border-left: 4px solid #ff6b35; }}
        .stat-card.medium {{ border-left: 4px solid #ffa502; }}
        .stat-card.low {{ border-left: 4px solid #2ed573; }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .stat-number {{ color: #ff4757; }}
        .stat-card.high .stat-number {{ color: #ff6b35; }}
        .stat-card.medium .stat-number {{ color: #ffa502; }}
        .stat-card.low .stat-number {{ color: #2ed573; }}
        
        .stat-label {{
            color: #a4a4a4;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Charts Section */
        .charts-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .chart-card {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .chart-card h3 {{
            margin-bottom: 20px;
            color: #00d4ff;
        }}
        
        .chart-container {{
            position: relative;
            height: 250px;
        }}
        
        /* Vulnerabilities Section */
        .vuln-section {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .vuln-section h2 {{
            margin-bottom: 25px;
            color: #00d4ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .vuln-item {{
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 4px solid;
            transition: transform 0.2s ease;
        }}
        
        .vuln-item:hover {{
            transform: translateX(5px);
        }}
        
        .vuln-item.critical {{ border-left-color: #ff4757; }}
        .vuln-item.high {{ border-left-color: #ff6b35; }}
        .vuln-item.medium {{ border-left-color: #ffa502; }}
        .vuln-item.low {{ border-left-color: #2ed573; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .vuln-title {{
            font-size: 1.3em;
            font-weight: 600;
        }}
        
        .vuln-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .vuln-badge.critical {{ background: #ff4757; }}
        .vuln-badge.high {{ background: #ff6b35; }}
        .vuln-badge.medium {{ background: #ffa502; }}
        .vuln-badge.low {{ background: #2ed573; }}
        
        .vuln-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            font-size: 0.9em;
        }}
        
        .vuln-meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .vuln-description {{
            color: #b4b4b4;
            margin-bottom: 20px;
            line-height: 1.7;
        }}
        
        .vuln-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }}
        
        .vuln-detail-box {{
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 8px;
        }}
        
        .vuln-detail-box h4 {{
            color: #00d4ff;
            margin-bottom: 10px;
            font-size: 0.9em;
        }}
        
        .vuln-detail-box pre {{
            background: #0a0a0a;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Fira Code', monospace;
            font-size: 0.85em;
            line-height: 1.5;
        }}
        
        /* Endpoints Table */
        .endpoints-section {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .endpoints-section h2 {{
            margin-bottom: 25px;
            color: #00d4ff;
        }}
        
        .endpoint-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .endpoint-table th,
        .endpoint-table td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .endpoint-table th {{
            background: rgba(0, 0, 0, 0.3);
            color: #00d4ff;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        
        .endpoint-table tr:hover {{
            background: rgba(0, 212, 255, 0.1);
        }}
        
        .method-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .method-get {{ background: #2ed573; color: #000; }}
        .method-post {{ background: #00d4ff; color: #000; }}
        .method-put {{ background: #ffa502; color: #000; }}
        .method-patch {{ background: #ff6b35; color: #000; }}
        .method-delete {{ background: #ff4757; color: #fff; }}
        
        .auth-icon {{
            font-size: 1.2em;
        }}
        
        .auth-required {{ color: #ffa502; }}
        .auth-not-required {{ color: #ff4757; }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #6a6a6a;
            font-size: 0.9em;
        }}
        
        .footer a {{
            color: #00d4ff;
            text-decoration: none;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .charts-section {{
                grid-template-columns: 1fr;
            }}
            
            .vuln-details {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Sentinel Security Report</h1>
            <p>Comprehensive API Security Assessment</p>
            <div class="header-meta">
                <div class="meta-item">
                    <span>📅</span> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div class="meta-item">
                    <span>🎯</span> Target: {result.config.target_url}
                </div>
                <div class="meta-item">
                    <span>⏱️</span> Duration: {result.duration_seconds:.2f}s
                </div>
                <div class="meta-item">
                    <span>📊</span> Total Requests: {result.total_requests}
                </div>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{len(result.endpoints_tested)}</div>
                <div class="stat-label">Endpoints Tested</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number">{result.critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{result.high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{result.medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{result.low_count}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-section">
            <div class="chart-card">
                <h3>📈 Vulnerabilities by Severity</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>🎯 Vulnerabilities by Attack Type</h3>
                <div class="chart-container">
                    <canvas id="typeChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities -->
        <div class="vuln-section">
            <h2>🔍 Vulnerabilities Found ({result.vulnerability_count})</h2>
            {self._generate_vulnerability_items(result.vulnerabilities)}
        </div>
        
        <!-- Endpoints Tested -->
        <div class="endpoints-section">
            <h2>📋 Endpoints Tested ({len(result.endpoints_tested)})</h2>
            {self._generate_endpoints_table(result.endpoints_tested)}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by <a href="#">Sentinel</a> v2.0.0 - AI-Powered API Security Testing</p>
            <p style="margin-top: 10px; font-size: 0.8em;">
                ⚠️ This is an automated assessment. Manual verification is recommended.
            </p>
        </div>
    </div>
    
    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{result.critical_count}, {result.high_count}, {result.medium_count}, {result.low_count}],
                    backgroundColor: ['#ff4757', '#ff6b35', '#ffa502', '#2ed573'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#e4e4e4' }}
                    }}
                }}
            }}
        }});
        
        // Attack Type Chart
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: {self._get_attack_type_labels(result)},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {self._get_attack_type_data(result)},
                    backgroundColor: '#00d4ff',
                    borderWidth: 0,
                    borderRadius: 5
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ color: '#a4a4a4' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#a4a4a4' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''
    
    def _generate_vulnerability_items(self, vulnerabilities: list[Vulnerability]) -> str:
        """Generate HTML for vulnerability items."""
        if not vulnerabilities:
            return '<p style="color: #2ed573; font-size: 1.2em;">✅ No vulnerabilities found!</p>'
        
        items = []
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.severity.value
            items.append(f'''
            <div class="vuln-item {severity_class}">
                <div class="vuln-header">
                    <div class="vuln-title">{i}. {vuln.title}</div>
                    <span class="vuln-badge {severity_class}">{vuln.severity.value.upper()}</span>
                </div>
                <div class="vuln-meta">
                    <div class="vuln-meta-item">
                        <span>🎯</span> {vuln.attack_type.value}
                    </div>
                    <div class="vuln-meta-item">
                        <span>📍</span> {vuln.endpoint.full_path}
                    </div>
                    <div class="vuln-meta-item">
                        <span>🏷️</span> {vuln.cwe_id or 'N/A'}
                    </div>
                </div>
                <p class="vuln-description">{vuln.description}</p>
                <div class="vuln-details">
                    <div class="vuln-detail-box">
                        <h4>💥 Proof of Concept</h4>
                        <pre>{self._escape_html(vuln.proof_of_concept)}</pre>
                    </div>
                    <div class="vuln-detail-box">
                        <h4>🛡️ Recommendation</h4>
                        <pre>{self._escape_html(vuln.recommendation)}</pre>
                    </div>
                </div>
            </div>
            ''')
        
        return '\n'.join(items)
    
    def _generate_endpoints_table(self, endpoints: list[Endpoint]) -> str:
        """Generate HTML for endpoints table."""
        rows = []
        for ep in endpoints:
            method_class = f"method-{ep.method.value.lower()}"
            auth_icon = "🔒" if ep.requires_auth else "🔓"
            auth_class = "auth-required" if ep.requires_auth else "auth-not-required"
            
            rows.append(f'''
            <tr>
                <td><span class="method-badge {method_class}">{ep.method.value}</span></td>
                <td><code>{ep.path}</code></td>
                <td><span class="auth-icon {auth_class}">{auth_icon}</span></td>
            </tr>
            ''')
        
        return f'''
        <table class="endpoint-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Auth</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        '''
    
    def _get_attack_type_labels(self, result: ScanResult) -> str:
        """Get attack type labels for chart."""
        type_counts = {}
        for vuln in result.vulnerabilities:
            type_name = vuln.attack_type.value.replace('_', ' ').title()
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        return str(list(type_counts.keys()))
    
    def _get_attack_type_data(self, result: ScanResult) -> str:
        """Get attack type data for chart."""
        type_counts = {}
        for vuln in result.vulnerabilities:
            type_name = vuln.attack_type.value.replace('_', ' ').title()
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        return str(list(type_counts.values()))
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#039;'))


def generate_html_report(scan_result: ScanResult, output_path: str = "sentinel_report.html") -> str:
    """Convenience function to generate and save an HTML report.
    
    Args:
        scan_result: The scan result to report on
        output_path: Path to save the report
        
    Returns:
        Path to the saved report
    """
    reporter = HTMLReporter(output_path)
    return reporter.save(scan_result)
