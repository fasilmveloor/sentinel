"""
Sentinel CLI - AI-Native API Security Testing Tool

Main entry point for the Sentinel security scanner.

Features:
- Multi-Agent System (Planner, Executor, Analyzer)
- 8 Attack Types
- Multi-LLM Support (Gemini, OpenAI, Claude, Ollama)
- Passive Security Scanner
- Attack Chain Discovery
- Natural Language Chat Interface
- Authentication Handler
- Proxy Mode
- Plugin System
- Multiple report formats (Markdown, HTML, JSON, SARIF, JUnit)
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
    Severity,
    LLMProvider,
    ReportFormat
)
from .parser import SwaggerParser, get_sample_endpoint_values
from .agent import SentinelAgent, AIAgentError
from .attacks import (
    SQLInjectionAttacker,
    AuthBypassAttacker,
    IDORAttacker,
    XSSAttacker,
    SSRFAttacker,
    JWTAttacker,
    CommandInjectionAttacker,
    RateLimitAttacker
)
from .reporter import Reporter
from .html_reporter import HTMLReporter
from .json_reporter import JSONReporter, SARIFReporter, JUnitReporter

# v2.5 Agentic imports
from .autonomous import AutonomousScanner, run_autonomous_scan
from .passive import PassiveScanner, create_passive_scanner
from .chat import SentinelChat, run_interactive_session

# v3.0 Enterprise imports
from .auth import (
    AuthHandler, AuthConfig, AuthType, AuthManager,
    create_bearer_auth, create_basic_auth, create_api_key_auth
)
from .proxy import SentinelProxy, ProxyConfig, create_proxy
from .plugin import (
    PluginManager, PluginType, get_plugin_manager,
    create_attack_plugin_template, create_passive_plugin_template
)


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
    ║       AI-Native API Security v1.0                            ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def print_banner_v25():
    """Print the Sentinel v2.5 Agentic banner."""
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
    ║       AI-Native API Security v1.0                            ║
    ║                                                               ║
    ║   🤖 Multi-Agent System      💬 Natural Language Interface   ║
    ║   🔗 Attack Chain Discovery   🔍 Passive Security Scanner     ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def print_summary(result: ScanResult):
    """Print a summary table of the scan results."""
    table = Table(title="📊 Scan Summary", show_header=True, header_style="bold magenta")
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
            f"[bold]{vuln.description[:200]}...[/bold]\n\n"
            f"Endpoint: [cyan]{vuln.endpoint.full_path}[/cyan]\n"
            f"Attack: {vuln.attack_type.value}\n"
            f"Payload: [dim]{vuln.payload[:50] if vuln.payload else 'N/A'}...[/dim]",
            title=f"[{color}]{i}. {vuln.title}[/{color}]",
            border_style=color
        )
        console.print(panel)


def get_severity_emoji(severity: Severity) -> str:
    """Get emoji for severity level."""
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "ℹ️"
    }.get(severity, "⚪")


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
    help='Output path for the report'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['markdown', 'html', 'json', 'sarif', 'junit']),
    default='markdown',
    help='Report format'
)
@click.option(
    '--attacks', '-a',
    multiple=True,
    type=click.Choice(['sql_injection', 'auth_bypass', 'idor', 'xss', 'ssrf', 'jwt', 'cmd_injection', 'rate_limit']),
    default=['sql_injection', 'auth_bypass', 'idor', 'xss', 'ssrf', 'jwt', 'cmd_injection', 'rate_limit'],
    help='Attack types to perform (can specify multiple)'
)
@click.option(
    '--llm',
    type=click.Choice(['gemini', 'openai', 'claude', 'local']),
    default='gemini',
    help='LLM provider for AI analysis'
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
@click.option(
    '--auth-token',
    help='Pre-authenticated token for testing (Bearer token)'
)
def scan(
    swagger: str,
    target: str,
    output: str,
    format: str,
    attacks: tuple,
    llm: str,
    timeout: int,
    verbose: bool,
    no_ai: bool,
    max_endpoints: int,
    auth_token: Optional[str]
):
    """
    Run a security scan against the target API.
    
    Example:
        sentinel scan --swagger api.yaml --target http://localhost:8000
    """
    print_banner()
    
    start_time = time.time()
    
    # Map LLM provider
    llm_providers = {
        'gemini': LLMProvider.GEMINI,
        'openai': LLMProvider.OPENAI,
        'claude': LLMProvider.CLAUDE,
        'local': LLMProvider.LOCAL
    }
    
    # Map report format
    report_formats = {
        'markdown': ReportFormat.MARKDOWN,
        'html': ReportFormat.HTML,
        'json': ReportFormat.JSON,
        'sarif': ReportFormat.SARIF,
        'junit': ReportFormat.JUNIT
    }
    
    # Create scan configuration
    config = ScanConfig(
        target_url=target,
        swagger_path=swagger,
        output_path=output,
        output_format=report_formats[format],
        attack_types=[AttackType(a) for a in attacks],
        timeout=timeout,
        verbose=verbose,
        max_endpoints=max_endpoints,
        llm_provider=llm_providers[llm],
        auth_token=auth_token
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
                console.print(f"\n🤖 [bold]Initializing AI agent ({llm})...[/bold]")
                agent = SentinelAgent(provider=llm_providers[llm])
                console.print("[green]AI agent initialized[/green]")
            except AIAgentError as e:
                console.print(f"[yellow]AI agent unavailable: {e}[/yellow]")
                console.print("[yellow]Falling back to rule-based decisions[/yellow]")
        
        # Step 3: Initialize attackers
        console.print("\n⚔️  [bold]Initializing attack modules...[/bold]")
        
        attackers = {}
        attack_modules = [
            ('SQL Injection', AttackType.SQL_INJECTION, lambda: SQLInjectionAttacker(target, timeout)),
            ('XSS', AttackType.XSS, lambda: XSSAttacker(target, timeout)),
            ('Auth Bypass', AttackType.AUTH_BYPASS, lambda: AuthBypassAttacker(target, timeout)),
            ('IDOR', AttackType.IDOR, lambda: IDORAttacker(target, timeout)),
            ('SSRF', AttackType.SSRF, lambda: SSRFAttacker(target, timeout)),
            ('JWT', AttackType.JWT, lambda: JWTAttacker(target, timeout)),
            ('Command Injection', AttackType.CMD_INJECTION, lambda: CommandInjectionAttacker(target, timeout)),
            ('Rate Limit', AttackType.RATE_LIMIT, lambda: RateLimitAttacker(target, timeout)),
        ]
        
        for name, attack_type, attacker_factory in attack_modules:
            if attack_type in config.attack_types:
                attackers[attack_type] = attacker_factory()
                console.print(f"  ✓ {name}")
        
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
                    
                    if attack_type not in attackers:
                        continue
                    
                    attacker = attackers[attack_type]
                    
                    # Run attack
                    if attack_type == AttackType.JWT:
                        attack_results = attacker.attack(endpoint, auth_token)
                    else:
                        attack_results = attacker.attack(endpoint, params_to_test)
                    
                    result.attack_results.extend(attack_results)
                    result.total_requests += len(attack_results)
                    
                    # Check for vulnerabilities
                    for ar in attack_results:
                        if ar.success:
                            try:
                                vuln = attacker.create_vulnerability(ar, endpoint)
                                result.vulnerabilities.append(vuln)
                            except Exception as e:
                                if verbose:
                                    console.print(f"[yellow]Warning: Could not create vulnerability: {e}[/yellow]")
                
                progress.advance(main_task)
                
                # Small delay between endpoints
                time.sleep(config.rate_limit_delay)
        
        # Step 5: Generate report
        console.print(f"\n📝 [bold]Generating {format} report...[/bold]")
        
        result.duration_seconds = time.time() - start_time
        
        # Generate appropriate report format
        if format == 'html':
            reporter = HTMLReporter(output)
        elif format == 'json':
            reporter = JSONReporter(output)
        elif format == 'sarif':
            reporter = SARIFReporter(output)
        elif format == 'junit':
            reporter = JUnitReporter(output)
        else:
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
@click.option(
    '--swagger', '-s',
    required=True,
    type=click.Path(exists=True),
    help='Path to OpenAPI/Swagger specification file'
)
@click.option(
    '--target', '-t',
    required=True,
    help='Target API base URL'
)
@click.option(
    '--llm',
    type=click.Choice(['gemini', 'openai', 'claude', 'local']),
    default='gemini',
    help='LLM provider for AI agent'
)
@click.option(
    '--auth-token',
    help='Authentication token (Bearer token)'
)
@click.option(
    '--max-concurrent',
    default=5,
    help='Maximum concurrent attacks'
)
@click.option(
    '--output', '-o',
    default='autonomous_report.md',
    help='Output report path'
)
def autonomous(
    swagger: str,
    target: str,
    llm: str,
    auth_token: Optional[str],
    max_concurrent: int,
    output: str
):
    """
    Run an autonomous AI-powered scan.
    
    The AI agent will:
    - Plan the optimal attack strategy
    - Execute attacks in priority order
    - Analyze results and discover attack chains
    - Generate comprehensive report
    
    Example:
        sentinel autonomous -s api.yaml -t https://api.example.com
    """
    import asyncio
    
    print_banner_v25()
    
    llm_providers = {
        'gemini': LLMProvider.GEMINI,
        'openai': LLMProvider.OPENAI,
        'claude': LLMProvider.CLAUDE,
        'local': LLMProvider.LOCAL
    }
    
    console.print("\n🧠 [bold]Initializing Autonomous Scanner...[/bold]")
    console.print(f"   LLM Provider: {llm}")
    console.print(f"   Target: {target}")
    console.print(f"   Spec: {swagger}")
    
    try:
        # Parse endpoints
        parser = SwaggerParser(swagger)
        endpoints = parser.parse()
        
        if not endpoints:
            console.print("[red]No endpoints found in specification.[/red]")
            sys.exit(1)
        
        console.print(f"[green]Found {len(endpoints)} endpoints[/green]")
        
        # Setup auth headers
        headers = {}
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        # Run autonomous scan
        console.print("\n🚀 [bold]Starting Autonomous Scan...[/bold]\n")
        
        async def run_scan():
            return await run_autonomous_scan(
                endpoints=endpoints,
                base_url=target,
                headers=headers,
                ai_provider=llm_providers[llm]
            )
        
        result = asyncio.run(run_scan())
        
        # Display results
        console.print("\n" + "="*60)
        console.print("📊 [bold]Autonomous Scan Complete[/bold]")
        console.print("="*60 + "\n")
        
        # Summary
        summary_table = Table(title="Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Endpoints Scanned", str(result.endpoints_scanned))
        summary_table.add_row("Total Requests", str(result.total_requests))
        summary_table.add_row("Findings", str(len(result.findings)))
        summary_table.add_row("Attack Chains", str(len(result.attack_chains)))
        summary_table.add_row("Duration", str(result.end_time - result.start_time).split('.')[0] if result.end_time else "N/A")
        
        console.print(summary_table)
        
        # Attack Chains
        if result.attack_chains:
            console.print("\n🔗 [bold red]Attack Chains Discovered:[/bold red]\n")
            for chain in result.attack_chains:
                chain_panel = Panel(
                    f"[bold]{chain.description}[/bold]\n\n"
                    f"Exploit Path:\n{chain.exploit_path}",
                    title=f"⚡ {chain.name} ({chain.severity.value.upper()})",
                    border_style="red" if chain.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow"
                )
                console.print(chain_panel)
        
        # Findings summary
        if result.summary:
            severity_table = Table(title="Findings by Severity")
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="green")
            
            for sev in ['critical', 'high', 'medium', 'low']:
                count = result.summary.get(sev, 0)
                if count > 0:
                    severity_table.add_row(sev.upper(), str(count))
            
            console.print(severity_table)
        
        # Generate report
        console.print(f"\n📝 [bold]Generating report: {output}[/bold]")
        
        # Create report content
        report_content = f"""# Sentinel Autonomous Scan Report

**Generated**: {result.start_time.isoformat()}
**Target**: {target}
**Status**: {result.state.value}

## Summary

- **Endpoints Scanned**: {result.endpoints_scanned}
- **Total Requests**: {result.total_requests}
- **Findings**: {len(result.findings)}
- **Attack Chains**: {len(result.attack_chains)}

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | {result.summary.get('critical', 0)} |
| High | {result.summary.get('high', 0)} |
| Medium | {result.summary.get('medium', 0)} |
| Low | {result.summary.get('low', 0)} |

"""
        
        if result.attack_chains:
            report_content += "## Attack Chains\n\n"
            for chain in result.attack_chains:
                report_content += f"### {chain.name}\n\n"
                report_content += f"**Severity**: {chain.severity.value}\n\n"
                report_content += f"{chain.description}\n\n"
                report_content += f"**Exploit Path**:\n```\n{chain.exploit_path}\n```\n\n"
        
        with open(output, 'w') as f:
            f.write(report_content)
        
        console.print(f"[green]Report saved to: {output}[/green]")
        
        # Exit code
        critical = result.summary.get('critical', 0)
        high = result.summary.get('high', 0)
        
        if critical > 0:
            console.print("\n[bold red]❌ Critical vulnerabilities found![/bold red]")
            sys.exit(2)
        elif high > 0:
            console.print("\n[bold orange1]⚠️ High severity vulnerabilities found![/bold orange1]")
            sys.exit(1)
        else:
            console.print("\n[bold green]✅ No critical or high severity issues found.[/bold green]")
            sys.exit(0)
            
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
def chat():
    """
    Start an interactive chat session with Sentinel AI.
    
    Use natural language to:
    - Scan APIs
    - Analyze endpoints
    - Get security recommendations
    - Generate reports
    
    Example:
        sentinel chat
        > Scan https://api.example.com
        > Explain SQL injection
        > Suggest tests for my API
    """
    print_banner_v25()
    console.print("\n💬 [bold]Starting Interactive Chat Mode...[/bold]")
    console.print("[dim]Type 'exit' to quit, 'help' for commands[/dim]\n")
    
    try:
        run_interactive_session()
    except Exception as e:
        console.print(f"\n[red]Error starting chat: {e}[/red]")
        console.print("[yellow]Make sure you have an API key configured.[/yellow]")
        console.print("[yellow]Set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY environment variable.[/yellow]")
        sys.exit(1)


@cli.command()
@click.option(
    '--url', '-u',
    required=True,
    help='URL to analyze'
)
@click.option(
    '--output', '-o',
    help='Output file for passive scan report'
)
def passive(url: str, output: Optional[str]):
    """
    Run a passive security scan on a URL.
    
    Analyzes HTTP responses without sending attack payloads.
    Checks for:
    - Missing security headers
    - Sensitive data exposure
    - Server version disclosure
    - CORS misconfigurations
    - Cookie security issues
    
    Example:
        sentinel passive -u https://api.example.com
    """
    import requests
    
    print_banner()
    console.print(f"\n🔍 [bold]Passive Security Scan[/bold]")
    console.print(f"   Target: {url}\n")
    
    try:
        # Make request
        console.print("📡 [bold]Fetching URL...[/bold]")
        response = requests.get(url, timeout=10)
        
        # Run passive scanner
        scanner = create_passive_scanner()
        findings = scanner.analyze_response(
            url=url,
            method='GET',
            request_headers={},
            response_headers=dict(response.headers),
            response_body=response.text,
            status_code=response.status_code
        )
        
        # Display results
        console.print(f"\n[bold]Analysis Complete: {len(findings)} findings[/bold]\n")
        
        if not findings:
            console.print("[green]✅ No security issues detected![/green]")
            return
        
        # Group by severity
        findings_table = Table(title="Passive Findings")
        findings_table.add_column("Severity", style="cyan")
        findings_table.add_column("Finding", style="white")
        findings_table.add_column("Description", style="yellow")
        
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99)
        
        for finding in sorted_findings:
            sev_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue"
            }.get(finding.severity, "white")
            
            findings_table.add_row(
                f"[{sev_color}]{finding.severity.value.upper()}[/{sev_color}]",
                finding.title,
                finding.description[:60] + "..." if len(finding.description) > 60 else finding.description
            )
        
        console.print(findings_table)
        
        # Detailed findings
        console.print("\n[bold]Details:[/bold]\n")
        for finding in sorted_findings[:10]:  # Show top 10
            sev_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue"
            }.get(finding.severity, "white")
            
            panel = Panel(
                f"{finding.description}\n\n"
                f"[bold]Evidence:[/bold] {finding.evidence}\n"
                f"[bold]Remediation:[/bold] {finding.remediation}\n"
                f"[bold]Location:[/bold] {finding.location}",
                title=f"[{sev_color}]{finding.title}[/{sev_color}]",
                border_style=sev_color
            )
            console.print(panel)
        
        # Save report if requested
        if output:
            report_content = f"""# Passive Security Scan Report

**URL**: {url}
**Status Code**: {response.status_code}
**Findings**: {len(findings)}

## Findings

"""
            for f in sorted_findings:
                report_content += f"### {f.title}\n\n"
                report_content += f"- **Severity**: {f.severity.value}\n"
                report_content += f"- **Description**: {f.description}\n"
                report_content += f"- **Evidence**: {f.evidence}\n"
                report_content += f"- **Remediation**: {f.remediation}\n\n"
            
            with open(output, 'w') as f:
                f.write(report_content)
            console.print(f"\n[green]Report saved to: {output}[/green]")
            
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def list_attacks():
    """List available attack types."""
    table = Table(title="Available Attack Types (v2.0)")
    table.add_column("Attack Type", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("OWASP", style="yellow")
    table.add_column("CWE", style="magenta")
    
    attacks_info = [
        ("sql_injection", "SQL and NoSQL injection testing", "A03:2021", "CWE-89"),
        ("xss", "Cross-Site Scripting testing", "A03:2021", "CWE-79"),
        ("auth_bypass", "Authentication bypass testing", "A07:2021", "CWE-306"),
        ("idor", "Insecure Direct Object Reference", "A01:2021", "CWE-639"),
        ("ssrf", "Server-Side Request Forgery", "A10:2021", "CWE-918"),
        ("jwt", "JWT vulnerability testing", "A07:2021", "CWE-287"),
        ("cmd_injection", "OS command injection", "A03:2021", "CWE-78"),
        ("rate_limit", "Rate limiting detection", "A04:2021", "CWE-770"),
    ]
    
    console.print("\n[bold cyan]v2.5 Agentic Features:[/bold cyan]")
    console.print("  • Autonomous scanning with AI planning")
    console.print("  • Attack chain discovery")
    console.print("  • Passive security scanning")
    console.print("  • Interactive chat mode\n")
    
    for attack, desc, owasp, cwe in attacks_info:
        table.add_row(attack, desc, owasp, cwe)
    
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


@cli.command()
def version():
    """Show version information."""
    console.print(f"\n[bold]Sentinel v{__version__}[/bold]")
    console.print("[cyan]AI-Native API Security Tool[/cyan]")
    console.print("\n[bold]Features:[/bold]")
    console.print("  🤖 Autonomous AI Scanner")
    console.print("  💬 Interactive Chat Mode")
    console.print("  🔗 Attack Chain Discovery")
    console.print("  🔍 Passive Security Scanner")
    console.print("  🔐 Authentication Handler")
    console.print("  🌐 Proxy Mode")
    console.print("  🔌 Plugin System")
    console.print("  📊 Multi-Format Reports\n")


# ==================== v3.0 PROXY COMMAND ====================

@cli.command()
@click.option(
    '--host', '-h',
    default='127.0.0.1',
    help='Proxy host address'
)
@click.option(
    '--port', '-p',
    default=8080,
    help='Proxy port'
)
@click.option(
    '--output', '-o',
    help='Output file for captured traffic'
)
@click.option(
    '--extract-spec',
    is_flag=True,
    help='Extract OpenAPI spec from traffic'
)
def proxy(host: str, port: int, output: Optional[str], extract_spec: bool):
    """
    Start an intercepting proxy for traffic analysis.
    
    The proxy will intercept HTTP traffic and perform passive security analysis.
    Configure your browser or application to use this proxy.
    
    Example:
        sentinel proxy --port 8080
    """
    print_banner_v25()
    console.print(f"\n🌐 [bold]Starting Proxy Server[/bold]")
    console.print(f"   Host: {host}")
    console.print(f" Port: {port}\n")
    
    console.print("[yellow]Configure your client to use this proxy:[/yellow]")
    console.print(f"  HTTP Proxy: {host}:{port}")
    console.print(f"  HTTPS Proxy: {host}:{port}\n")
    
    console.print("[bold]Press Ctrl+C to stop the proxy[/bold]\n")
    
    try:
        # Create and start proxy
        config = ProxyConfig(
            host=host,
            port=port,
            passive_scan=True,
            detect_api=True
        )
        
        proxy_server = create_proxy(
            host=config.host,
            port=config.port,
            passive_scan=config.passive_scan
        )
        
        # Start in non-blocking mode first to show stats
        proxy_server.start(blocking=False)
        
        # Keep running and show periodic stats
        import time
        while proxy_server.state.value == "running":
            time.sleep(5)
            stats = proxy_server.get_stats()
            console.print(f"[dim]Traffic: {stats['total_flows']} flows, "
                         f"{stats['unique_endpoints']} endpoints[/dim]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping proxy...[/yellow]")
        
        if extract_spec and proxy_server:
            spec = proxy_server.extract_openapi_spec()
            spec_file = output or "extracted_api.json"
            import json
            with open(spec_file, 'w') as f:
                json.dump(spec, f, indent=2)
            console.print(f"[green]OpenAPI spec saved to: {spec_file}[/green]")
        
        if output and proxy_server:
            flows = proxy_server.get_flows()
            import json
            traffic_data = []
            for flow in flows:
                traffic_data.append({
                    "id": flow.id,
                    "method": flow.request.method,
                    "url": flow.request.url,
                    "status": flow.response.status_code if flow.response else None,
                    "findings": len(flow.request.passive_findings) + 
                               (len(flow.response.passive_findings) if flow.response else 0)
                })
            with open(output, 'w') as f:
                json.dump(traffic_data, f, indent=2)
            console.print(f"[green]Traffic saved to: {output}[/green]")
        
        if proxy_server:
            proxy_server.stop()
        
        console.print("[green]Proxy stopped.[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# ==================== v3.0 PLUGIN COMMANDS ====================

@cli.group()
def plugin():
    """Manage Sentinel plugins."""
    pass


@plugin.command()
def list():
    """List all registered plugins."""
    console.print("\n[bold]🔌 Registered Plugins[/bold]\n")
    
    manager = get_plugin_manager()
    plugins = manager.list_plugins()
    
    if not plugins:
        console.print("[yellow]No plugins registered.[/yellow]")
        return
    
    table = Table()
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Enabled", style="magenta")
    table.add_column("Description", style="white")
    
    for p in plugins:
        enabled = "✅" if p["enabled"] else "❌"
        table.add_row(
            p["name"],
            p["version"],
            p["type"],
            enabled,
            p["description"][:40] + "..." if len(p["description"]) > 40 else p["description"]
        )
    
    console.print(table)


@plugin.command()
@click.argument('path', type=click.Path(exists=True))
def load(path: str):
    """Load a plugin from a file path."""
    console.print(f"\n[bold]Loading plugin: {path}[/bold]")
    
    manager = get_plugin_manager()
    plugin = manager.load_plugin(path)
    
    if plugin:
        console.print(f"[green]✅ Plugin loaded: {plugin.INFO.name}[/green]")
    else:
        console.print("[red]❌ Failed to load plugin[/red]")
        sys.exit(1)


@plugin.command()
@click.option(
    '--name', '-n',
    required=True,
    help='Plugin name'
)
@click.option(
    '--type', '-t',
    type=click.Choice(['attack', 'passive']),
    default='attack',
    help='Plugin type to create'
)
@click.option(
    '--output', '-o',
    default='.',
    help='Output directory'
)
def create(name: str, type: str, output: str):
    """Create a new plugin template."""
    console.print(f"\n[bold]Creating {type} plugin: {name}[/bold]")
    
    try:
        if type == 'attack':
            path = create_attack_plugin_template(name, output)
        else:
            path = create_passive_plugin_template(name, output)
        
        console.print(f"[green]✅ Plugin template created: {path}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error creating plugin: {e}[/red]")
        sys.exit(1)


@plugin.command()
@click.argument('name')
def enable(name: str):
    """Enable a plugin."""
    manager = get_plugin_manager()
    manager.enable_plugin(name)
    console.print(f"[green]✅ Plugin enabled: {name}[/green]")


@plugin.command()
@click.argument('name')
def disable(name: str):
    """Disable a plugin."""
    manager = get_plugin_manager()
    manager.disable_plugin(name)
    console.print(f"[yellow]Plugin disabled: {name}[/yellow]")


# ==================== v3.0 AUTH COMMAND ====================

@cli.command()
@click.option(
    '--type', '-t',
    type=click.Choice(['bearer', 'basic', 'api_key', 'oauth2']),
    required=True,
    help='Authentication type'
)
@click.option(
    '--token',
    help='Bearer token (for bearer auth)'
)
@click.option(
    '--username', '-u',
    help='Username (for basic auth)'
)
@click.option(
    '--password', '-p',
    help='Password (for basic auth)'
)
@click.option(
    '--api-key',
    help='API key (for api_key auth)'
)
@click.option(
    '--header-name',
    default='X-API-Key',
    help='Header name for API key'
)
@click.option(
    '--token-url',
    help='OAuth2 token URL'
)
@click.option(
    '--client-id',
    help='OAuth2 client ID'
)
@click.option(
    '--client-secret',
    help='OAuth2 client secret'
)
@click.option(
    '--test-url',
    help='URL to test authentication'
)
def auth(
    type: str,
    token: Optional[str],
    username: Optional[str],
    password: Optional[str],
    api_key: Optional[str],
    header_name: str,
    token_url: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    test_url: Optional[str]
):
    """
    Test and manage authentication.
    
    Configure authentication for API security testing.
    
    Example:
        sentinel auth --type bearer --token "your_token" --test-url https://api.example.com
    """
    console.print(f"\n🔐 [bold]Authentication Configuration[/bold]\n")
    
    try:
        handler = None
        
        if type == 'bearer':
            if not token:
                console.print("[red]Error: --token required for bearer auth[/red]")
                sys.exit(1)
            handler = create_bearer_auth(token)
            console.print(f"  Type: Bearer Token")
            console.print(f"  Token: {token[:20]}...")
            
        elif type == 'basic':
            if not username or not password:
                console.print("[red]Error: --username and --password required for basic auth[/red]")
                sys.exit(1)
            handler = create_basic_auth(username, password)
            console.print(f"  Type: Basic Authentication")
            console.print(f"  Username: {username}")
            
        elif type == 'api_key':
            if not api_key:
                console.print("[red]Error: --api-key required for api_key auth[/red]")
                sys.exit(1)
            handler = create_api_key_auth(api_key, header_name)
            console.print(f"  Type: API Key")
            console.print(f"  Header: {header_name}")
            console.print(f"  Key: {api_key[:20]}...")
            
        elif type == 'oauth2':
            if not all([token_url, client_id, client_secret]):
                console.print("[red]Error: --token-url, --client-id, --client-secret required for oauth2[/red]")
                sys.exit(1)
            config = AuthConfig(
                auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
                oauth_token_url=token_url,
                oauth_client_id=client_id,
                oauth_client_secret=client_secret
            )
            handler = AuthHandler(config)
            console.print(f"  Type: OAuth2 Client Credentials")
            console.print(f"  Token URL: {token_url}")
            console.print(f"  Client ID: {client_id}")
        
        # Test authentication if URL provided
        if test_url and handler:
            console.print(f"\n📡 [bold]Testing authentication...[/bold]")
            
            import requests
            headers = handler.authenticate()
            response = requests.get(test_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                console.print(f"[green]✅ Authentication successful![/green]")
                console.print(f"   Status: {response.status_code}")
            elif response.status_code == 401:
                console.print(f"[red]❌ Authentication failed![/red]")
                console.print(f"   Status: {response.status_code} - Unauthorized")
            else:
                console.print(f"[yellow]⚠️ Unexpected response[/yellow]")
                console.print(f"   Status: {response.status_code}")
        
        console.print()
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
