"""
Sentinel CLI - AI-powered API Security Testing Tool

Main entry point for the Sentinel security scanner.
"""

import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich import print as rprint

from . import __version__
from .models import (
    AttackType,
    ScanConfig,
    ScanResult,
    Endpoint,
    Vulnerability,
    Severity
)
from .parser import SwaggerParser, get_sample_endpoint_values
from .agent import SentinelAgent, AIAgentError
from .attacks import SQLInjectionAttacker, AuthBypassAttacker, IDORAttacker
from .reporter import Reporter


console = Console()


def print_banner():
    """Print the Sentinel banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███████╗███████╗███╗   ██╗ ██████╗███████╗██████╗          ║
    ║   ██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗         ║
    ║   ███████╗█████╗  ██╔██╗ ██║██║     █████╗  ██████╔╝         ║
    ║   ╚════██║██╔══╝  ██║╚██╗██║██║     ██╔══╝  ██╔══██╗         ║
    ║   ███████║███████╗██║ ╚████║╚██████╗███████╗██║  ██║         ║
    ║   ╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝         ║
    ║                                                               ║
    ║           AI-Powered API Security Testing Tool                ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def print_summary(result: ScanResult):
    """Print a summary table of the scan results."""
    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Endpoints Tested", str(len(result.endpoints_tested)))
    table.add_row("Total Requests", str(result.total_requests))
    table.add_row("Vulnerabilities Found", str(result.vulnerability_count))
    table.add_row("Critical", str(result.critical_count), style="red" if result.critical_count > 0 else None)
    table.add_row("High", str(result.high_count), style="orange1" if result.high_count > 0 else None)
    table.add_row("Medium", str(result.medium_count), style="yellow" if result.medium_count > 0 else None)
    table.add_row("Low", str(result.low_count), style="blue" if result.low_count > 0 else None)
    table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    
    console.print(table)


def print_vulnerabilities(vulnerabilities: list[Vulnerability]):
    """Print found vulnerabilities."""
    if not vulnerabilities:
        console.print("\n✅ [green]No vulnerabilities found![/green]\n")
        return
    
    console.print(f"\n⚠️  [bold red]Found {len(vulnerabilities)} vulnerabilities:[/bold red]\n")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue"
        }
        color = severity_colors.get(vuln.severity, "white")
        
        panel = Panel(
            f"[bold]{vuln.description}[/bold]\n\n"
            f"Endpoint: [cyan]{vuln.endpoint.full_path}[/cyan]\n"
            f"Attack: {vuln.attack_type.value}\n"
            f"Payload: [dim]{vuln.payload[:50]}...[/dim]",
            title=f"[{color}]{i}. {vuln.title}[/{color}]",
            border_style=color
        )
        console.print(panel)


@click.group()
@click.version_option(version=__version__)
def cli():
    """Sentinel - AI-powered API Security Testing Tool."""
    pass


@cli.command()
@click.option(
    '--swagger', '-s',
    required=True,
    type=click.Path(exists=True),
    help='Path to OpenAPI/Swagger specification file (YAML or JSON)'
)
@click.option(
    '--target', '-t',
    required=True,
    help='Target API base URL (e.g., http://localhost:8000)'
)
@click.option(
    '--output', '-o',
    default='sentinel_report.md',
    help='Output path for the Markdown report'
)
@click.option(
    '--attacks', '-a',
    multiple=True,
    type=click.Choice(['sql_injection', 'auth_bypass', 'idor']),
    default=['sql_injection', 'auth_bypass', 'idor'],
    help='Attack types to perform (can specify multiple)'
)
@click.option(
    '--timeout',
    default=5,
    help='Request timeout in seconds'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose output'
)
@click.option(
    '--no-ai',
    is_flag=True,
    help='Disable AI analysis (use rule-based decisions)'
)
@click.option(
    '--max-endpoints',
    default=50,
    help='Maximum number of endpoints to test'
)
def scan(
    swagger: str,
    target: str,
    output: str,
    attacks: tuple,
    timeout: int,
    verbose: bool,
    no_ai: bool,
    max_endpoints: int
):
    """
    Run a security scan against the target API.
    
    Example:
        sentinel scan --swagger api.yaml --target http://localhost:8000
    """
    print_banner()
    
    start_time = time.time()
    
    # Create scan configuration
    config = ScanConfig(
        target_url=target,
        swagger_path=swagger,
        output_path=output,
        attack_types=[AttackType(a) for a in attacks],
        timeout=timeout,
        verbose=verbose,
        max_endpoints=max_endpoints
    )
    
    # Initialize result
    result = ScanResult(config=config)
    
    try:
        # Step 1: Parse Swagger specification
        console.print("\n📋 [bold]Parsing Swagger specification...[/bold]")
        
        parser = SwaggerParser(swagger)
        endpoints = parser.parse()
        
        if not endpoints:
            console.print("[red]No endpoints found in specification.[/red]")
            sys.exit(1)
        
        # Limit endpoints
        if len(endpoints) > max_endpoints:
            console.print(f"[yellow]Limiting to {max_endpoints} endpoints (found {len(endpoints)})[/yellow]")
            endpoints = endpoints[:max_endpoints]
        
        result.endpoints_tested = endpoints
        console.print(f"[green]Found {len(endpoints)} endpoints to test[/green]")
        
        if verbose:
            for ep in endpoints:
                console.print(f"  • {ep.method.value} {ep.path}")
        
        # Step 2: Initialize AI Agent (if enabled)
        agent = None
        if not no_ai:
            try:
                console.print("\n🤖 [bold]Initializing AI agent...[/bold]")
                agent = SentinelAgent()
                console.print("[green]AI agent initialized[/green]")
            except AIAgentError as e:
                console.print(f"[yellow]AI agent unavailable: {e}[/yellow]")
                console.print("[yellow]Falling back to rule-based decisions[/yellow]")
        
        # Step 3: Initialize attackers
        console.print("\n⚔️  [bold]Initializing attack modules...[/bold]")
        
        sql_attacker = SQLInjectionAttacker(target, timeout)
        auth_attacker = AuthBypassAttacker(target, timeout)
        idor_attacker = IDORAttacker(target, timeout)
        
        console.print("[green]Attack modules ready[/green]")
        
        # Step 4: Run attacks
        console.print("\n🚀 [bold]Starting security scan...[/bold]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            main_task = progress.add_task(
                "[cyan]Scanning endpoints...", 
                total=len(endpoints)
            )
            
            for endpoint in endpoints:
                progress.update(
                    main_task, 
                    description=f"[cyan]Testing {endpoint.method.value} {endpoint.path}[/cyan]"
                )
                
                # Get AI recommendation or use defaults
                if agent:
                    decision = agent.analyze_endpoint(endpoint)
                    result.ai_decisions.append({
                        'endpoint': endpoint.full_path,
                        'attacks': [a.value for a in decision.recommended_attacks],
                        'reasoning': decision.reasoning
                    })
                    attack_types = decision.recommended_attacks
                    params_to_test = decision.parameters_to_test
                else:
                    attack_types = config.attack_types
                    params_to_test = None
                
                # Run each attack type
                for attack_type in attack_types:
                    if attack_type not in config.attack_types:
                        continue
                    
                    if attack_type == AttackType.SQL_INJECTION:
                        attack_results = sql_attacker.attack(endpoint, params_to_test)
                        result.attack_results.extend(attack_results)
                        result.total_requests += len(attack_results)
                        
                        # Check for vulnerabilities
                        for ar in attack_results:
                            if ar.success:
                                vuln = sql_attacker.create_vulnerability(ar, endpoint)
                                result.vulnerabilities.append(vuln)
                    
                    elif attack_type == AttackType.AUTH_BYPASS:
                        attack_results = auth_attacker.attack(endpoint)
                        result.attack_results.extend(attack_results)
                        result.total_requests += len(attack_results)
                        
                        for ar in attack_results:
                            if ar.success:
                                vuln = auth_attacker.create_vulnerability(ar, endpoint)
                                result.vulnerabilities.append(vuln)
                    
                    elif attack_type == AttackType.IDOR:
                        attack_results = idor_attacker.attack(endpoint)
                        result.attack_results.extend(attack_results)
                        result.total_requests += len(attack_results)
                        
                        for ar in attack_results:
                            if ar.success:
                                vuln = idor_attacker.create_vulnerability(ar, endpoint)
                                result.vulnerabilities.append(vuln)
                
                progress.advance(main_task)
                
                # Small delay between endpoints
                time.sleep(config.rate_limit_delay)
        
        # Step 5: Generate report
        console.print("\n📝 [bold]Generating security report...[/bold]")
        
        result.duration_seconds = time.time() - start_time
        reporter = Reporter(output)
        report_path = reporter.save(result)
        
        console.print(f"[green]Report saved to: {report_path}[/green]")
        
        # Step 6: Print summary
        print_summary(result)
        print_vulnerabilities(result.vulnerabilities)
        
        # Exit with appropriate code
        if result.critical_count > 0:
            console.print("\n[bold red]❌ Critical vulnerabilities found! Immediate action required.[/bold red]")
            sys.exit(2)
        elif result.high_count > 0:
            console.print("\n[bold orange1]⚠️  High severity vulnerabilities found. Urgent remediation needed.[/bold orange1]")
            sys.exit(1)
        else:
            console.print("\n[bold green]✅ Scan complete. No critical or high severity issues found.[/bold green]")
            sys.exit(0)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)


@cli.command()
def list_attacks():
    """List available attack types."""
    table = Table(title="Available Attack Types")
    table.add_column("Attack Type", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("CWE", style="yellow")
    
    table.add_row(
        "sql_injection",
        "SQL and NoSQL injection testing",
        "CWE-89"
    )
    table.add_row(
        "auth_bypass",
        "Authentication bypass testing",
        "CWE-306"
    )
    table.add_row(
        "idor",
        "Insecure Direct Object Reference",
        "CWE-639"
    )
    
    console.print(table)


@cli.command()
@click.argument('swagger', type=click.Path(exists=True))
def inspect(swagger: str):
    """Inspect an OpenAPI/Swagger specification.
    
    Shows all endpoints and their details without running attacks.
    """
    print_banner()
    
    try:
        parser = SwaggerParser(swagger)
        endpoints = parser.parse()
        info = parser.get_info()
        
        # Print API info
        console.print(f"\n[bold]API: {info.get('title', 'Unknown')}[/bold]")
        console.print(f"Version: {info.get('version', 'Unknown')}")
        console.print(f"Description: {info.get('description', 'N/A')}\n")
        
        # Print endpoints table
        table = Table(title=f"Endpoints ({len(endpoints)} found)")
        table.add_column("Method", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Auth", style="yellow")
        table.add_column("Parameters", style="magenta")
        
        for endpoint in endpoints:
            auth = "🔒" if endpoint.requires_auth else "🔓"
            params = ", ".join([p.name for p in endpoint.parameters]) or "-"
            table.add_row(
                endpoint.method.value,
                endpoint.path,
                auth,
                params
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error parsing specification: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
