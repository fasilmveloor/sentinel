"""
Terminal Reporter Module.

Provides clean, professional terminal output for scan results with:
- Proper deduplication display
- Severity distribution
- Grouped findings by endpoint
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ScanResult, Vulnerability

console = Console()


def print_scan_summary(result: "ScanResult", stats: dict = None):
    """Print comprehensive scan summary with deduplication stats."""
    console.print()
    console.rule("[bold green]Scan Complete[/bold green]")
    console.print()
    
    # Main summary table
    summary_table = Table(title="Results Summary", show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan", width=25)
    summary_table.add_column("Value", style="green", justify="right")
    
    summary_table.add_row("Endpoints Tested", str(len(result.endpoints_tested)))
    summary_table.add_row("Total Requests", str(result.total_requests))
    summary_table.add_row("Scan Duration", f"{result.duration_seconds:.2f}s")
    
    if stats:
        summary_table.add_row("Attack Results", str(stats.get('total_attack_results', 0)))
        summary_table.add_row("Unique Vulnerabilities", str(stats.get('total_unique', 0)))
    
    console.print(summary_table)
    console.print()
    
    # Severity distribution with visual bar
    severity_table = Table(title="Severity Distribution", show_header=True)
    severity_table.add_column("Severity", style="white", width=12)
    severity_table.add_column("Count", justify="right", width=8)
    severity_table.add_column("Visual", width=30)
    
    severities = [
        ("CRITICAL", result.critical_count, "red", "🔴"),
        ("HIGH", result.high_count, "orange1", "🟠"),
        ("MEDIUM", result.medium_count, "yellow", "🟡"),
        ("LOW", result.low_count, "blue", "🔵"),
        ("INFO", result.info_count, "dim", "ℹ️"),
    ]
    
    total = max(1, result.vulnerability_count)
    
    for name, count, color, emoji in severities:
        bar_width = int((count / total) * 20) if count > 0 else 0
        bar = "█" * bar_width + "░" * (20 - bar_width)
        severity_table.add_row(
            f"[{color}]{emoji} {name}[/{color}]",
            str(count),
            f"[{color}]{bar}[/{color}]"
        )
    
    console.print(severity_table)
    console.print()


def print_vulnerabilities_grouped(vulnerabilities: list["Vulnerability"], max_display: int = 25, verbose: bool = False):
    """Print vulnerabilities grouped by endpoint."""
    if not vulnerabilities:
        console.print("\n[green]✅ No vulnerabilities found![/green]\n")
        return
    
    console.print()
    console.rule(f"[bold red]Vulnerabilities Found: {len(vulnerabilities)}[/bold red]")
    console.print()
    
    try:
        from collections import defaultdict
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            try:
                key = f"{vuln.endpoint.method.value} {vuln.endpoint.path}"
                grouped[key].append(vuln)
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]Warning: Could not group vulnerability: {e}[/yellow]")
                continue
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        displayed = 0
        for endpoint_key in sorted(grouped.keys()):
            if displayed >= max_display:
                remaining = len(vulnerabilities) - displayed
                console.print(f"\n[yellow]... and {remaining} more vulnerabilities[/yellow]")
                break
            
            vulns = grouped[endpoint_key]
            vulns.sort(key=lambda v: severity_order.get(v.severity.value, 5))
            
            console.print(f"\n[bold cyan]━━━ {endpoint_key} ━━━[/bold cyan]")
            
            for vuln in vulns:
                if displayed >= max_display:
                    break
                
                displayed += 1
                sev_colors = {
                    "critical": "red", "high": "orange1",
                    "medium": "yellow", "low": "blue", "info": "dim"
                }
                try:
                    color = sev_colors.get(vuln.severity.value, "white")
                    console.print(f"  [{color}]●[/{color}] [{color}]{vuln.severity.value.upper()}[/{color}] {vuln.title}")
                    console.print(f"    [dim]CWE: {vuln.cwe_id} | OWASP: {vuln.owasp_category}[/dim]")
                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]Warning: Could not display vulnerability: {e}[/yellow]")
                    continue
    except Exception as e:
        console.print(f"[red]Error displaying vulnerabilities: {e}[/red]")


def print_deduplication_summary(stats: dict):
    """Print deduplication statistics."""
    console.print()
    
    dedup_table = Table(title="Deduplication Statistics", show_header=False)
    dedup_table.add_column("Metric", style="cyan")
    dedup_table.add_column("Value", style="green")
    
    dedup_table.add_row("Attack Results Processed", str(stats.get('total_attack_results', 0)))
    dedup_table.add_row("Unique Vulnerabilities", str(stats.get('total_unique', 0)))
    dedup_table.add_row("Duplicates Removed", str(stats.get('total_attack_results', 0) - stats.get('total_unique', 0)))
    dedup_table.add_row("Average Confidence", f"{stats.get('average_confidence', 0):.0%}")
    
    console.print(dedup_table)


def print_final_status(result: "ScanResult"):
    """Print final exit status."""
    console.print()
    
    if result.critical_count > 0:
        console.print("[bold red]❌ CRITICAL vulnerabilities detected! Immediate remediation required.[/bold red]")
    elif result.high_count > 0:
        console.print("[bold orange1]⚠️  HIGH severity vulnerabilities found. Urgent attention needed.[/bold orange1]")
    elif result.medium_count > 0:
        console.print("[bold yellow]⚡ MEDIUM severity issues detected. Plan remediation.[/bold yellow]")
    else:
        console.print("[bold green]✅ Scan complete. No critical/high/medium issues found.[/bold green]")
    
    console.print()
