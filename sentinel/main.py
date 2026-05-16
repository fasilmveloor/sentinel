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

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from . import __version__
from .agent import AIAgentError, SentinelAgent
from .attacks import (
    AuthBypassAttacker,
    BFLAAttacker,
    # v1.0.0 Enhanced Modules
    BOLAAttacker,
    BrokenAuthAttacker,
    CommandInjectionAttacker,
    ExcessiveDataExposureAttacker,
    IDORAttacker,
    JWTAttacker,
    MassAssignmentAttacker,
    NoSQLInjectionAttacker,
    RateLimitAttacker,
    SQLInjectionAttacker,
    SSRFAttacker,
    XSSAttacker,
)

# v3.0 Enterprise imports
from .auth import (
    AuthConfig,
    AuthHandler,
    AuthType,
    create_api_key_auth,
    create_basic_auth,
    create_bearer_auth,
)

# v1.0.0 Benchmark Framework imports
from .benchmarks import (
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkTarget,
    GroundTruthDatabase,
)
from .chat import run_interactive_session
from .html_reporter import HTMLReporter
from .json_reporter import JSONReporter, JUnitReporter, SARIFReporter
from .models import (
    AttackType,
    Endpoint,
    LLMProvider,
    ReportFormat,
    ScanConfig,
    ScanResult,
    ScanTask,
    Severity,
    Vulnerability,
)

# v3 Autonomous imports
from .orchestrator import SentinelOrchestrator
from .parser import SwaggerParseError, SwaggerParser
from .passive import create_passive_scanner
from .plugin import (
    create_attack_plugin_template,
    create_passive_plugin_template,
    get_plugin_manager,
)

# v1.0.0 Postman Collection imports
from .postman import (
    PostmanGenerator,
    PostmanParseError,
    PostmanParser,
    convert_openapi_to_postman,
)
from .proxy import ProxyConfig, create_proxy
from .reporter import Reporter

console = Console()


def print_banner():
    """Print the Sentinel banner."""
    banner = """
    ╔═════════════════════════════════════════════════════════════════════╗
    ║                                                                     ║
    ║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗       ║
    ║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║       ║
    ║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║       ║
    ║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║       ║
    ║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████║  ║
    ║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝  ║
    ║                                                                     ║
    ║            AI-Native API Security v1.0                              ║
    ║                                                                     ║
    ╚═════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def print_banner_v25():
    """Print the Sentinel v2.5 Agentic banner."""
    banner = """
    ╔═════════════════════════════════════════════════════════════════════╗
    ║                                                                     ║
    ║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗       ║
    ║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║       ║
    ║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║       ║
    ║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║       ║
    ║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████║  ║
    ║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝  ║
    ║                                                                     ║
    ║       AI-Native API Security v1.0                                   ║
    ║                                                                     ║
    ║   🤖 Multi-Agent System      💬 Natural Language Interface          ║
    ║   🔗 Attack Chain Discovery   🔍 Passive Security Scanner           ║
    ╚═════════════════════════════════════════════════════════════════════╝
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


def _seed_autonomous_tasks(
    orchestrator: SentinelOrchestrator,
    endpoints: list[Endpoint],
    agent: SentinelAgent | None,
    auth_token: str | None,
) -> list[dict]:
    """Seed the orchestrator queue from endpoint analysis decisions."""
    ai_decisions: list[dict] = []

    for endpoint in endpoints:
        if agent:
            decision = agent.analyze_endpoint(endpoint)
            attack_types = decision.recommended_attacks
            parameters = decision.parameters_to_test
            ai_decisions.append({
                'endpoint': endpoint.full_path,
                'attacks': [attack.value for attack in attack_types],
                'reasoning': decision.reasoning,
            })
        else:
            attack_types = list(AttackType)
            parameters = [parameter.name for parameter in endpoint.parameters]

        for attack_type in attack_types:
            artifacts = {}
            if auth_token and attack_type in orchestrator.AUTH_TOKEN_ATTACKS:
                artifacts["auth_token"] = auth_token

            orchestrator.push_task(
                ScanTask(
                    endpoint=endpoint,
                    attack_type=attack_type,
                    parameters=parameters,
                    artifacts=artifacts,
                    reason="initial analysis",
                )
            )

    return ai_decisions


def _build_scan_result(
    target: str,
    swagger: str,
    output: str,
    report_format: ReportFormat,
    timeout: int,
    llm_provider: LLMProvider,
    endpoints: list[Endpoint],
    attack_results: list,
    vulnerabilities: list[Vulnerability],
    ai_decisions: list[dict],
    start_time: float,
    auth_token: str | None = None,
) -> ScanResult:
    """Convert orchestrator output into the existing ScanResult model."""
    config = ScanConfig(
        target_url=target,
        swagger_path=swagger,
        output_path=output,
        output_format=report_format,
        attack_types=list(AttackType),
        timeout=timeout,
        verbose=False,
        max_endpoints=len(endpoints),
        llm_provider=llm_provider,
        auth_token=auth_token,
    )
    result = ScanResult(config=config)
    result.endpoints_tested = endpoints
    result.attack_results = attack_results
    result.vulnerabilities = vulnerabilities
    result.total_requests = len(attack_results)
    result.duration_seconds = time.time() - start_time
    result.ai_decisions = ai_decisions

    return result


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
    type=click.Choice([
        'sql_injection', 'auth_bypass', 'idor', 'xss', 'ssrf', 'jwt', 'cmd_injection', 'rate_limit',
        # v1.0.0 Enhanced Attacks
        'bola', 'excessive_data', 'mass_assignment', 'bfla', 'nosql_injection', 'broken_auth'
    ]),
    default=['sql_injection', 'auth_bypass', 'idor', 'xss', 'ssrf', 'jwt', 'cmd_injection', 'rate_limit',
             'bola', 'excessive_data', 'mass_assignment', 'bfla', 'nosql_injection', 'broken_auth'],
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
    auth_token: str | None
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
            # Core Attack Modules
            ('SQL Injection', AttackType.SQL_INJECTION, lambda: SQLInjectionAttacker(target, timeout)),
            ('XSS', AttackType.XSS, lambda: XSSAttacker(target, timeout)),
            ('Auth Bypass', AttackType.AUTH_BYPASS, lambda: AuthBypassAttacker(target, timeout)),
            ('IDOR', AttackType.IDOR, lambda: IDORAttacker(target, timeout)),
            ('SSRF', AttackType.SSRF, lambda: SSRFAttacker(target, timeout)),
            ('JWT', AttackType.JWT, lambda: JWTAttacker(target, timeout)),
            ('Command Injection', AttackType.CMD_INJECTION, lambda: CommandInjectionAttacker(target, timeout)),
            ('Rate Limit', AttackType.RATE_LIMIT, lambda: RateLimitAttacker(target, timeout)),
            # v1.0.0 Enhanced Modules
            ('BOLA/IDOR Advanced', AttackType.BOLA, lambda: BOLAAttacker(target, timeout)),
            ('Excessive Data Exposure', AttackType.EXCESSIVE_DATA, lambda: ExcessiveDataExposureAttacker(target, timeout)),
            ('Mass Assignment', AttackType.MASS_ASSIGNMENT, lambda: MassAssignmentAttacker(target, timeout)),
            ('BFLA', AttackType.BFLA, lambda: BFLAAttacker(target, timeout)),
            ('NoSQL Injection', AttackType.NOSQL_INJECTION, lambda: NoSQLInjectionAttacker(target, timeout)),
            ('Broken Auth', AttackType.BROKEN_AUTH, lambda: BrokenAuthAttacker(target, timeout)),
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
                    elif attack_type == AttackType.AUTH_BYPASS:
                        attack_results = attacker.attack(endpoint, auth_token)
                    elif attack_type == AttackType.BROKEN_AUTH:
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
                                result.add_vulnerability(vuln)
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
    except SwaggerParseError as e:
        # User-facing parse errors - show clean message without traceback
        console.print("\n[red]❌ Parse Error:[/red]")
        for line in str(e).split('\n'):
            console.print(f"   {line}")
        sys.exit(1)
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
    auth_token: str | None,
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
        start_time = time.time()

        # Parse endpoints
        parser = SwaggerParser(swagger)
        endpoints = parser.parse()

        if not endpoints:
            console.print("[red]No endpoints found in specification.[/red]")
            sys.exit(1)

        console.print(f"[green]Found {len(endpoints)} endpoints[/green]")

        # Initialize planner
        agent = None
        try:
            agent = SentinelAgent(provider=llm_providers[llm])
        except AIAgentError as e:
            console.print(f"[yellow]AI agent unavailable: {e}[/yellow]")
            console.print("[yellow]Falling back to rule-based seeding[/yellow]")

        orchestrator = SentinelOrchestrator(
            target_url=target,
            timeout=5,
            max_iterations=max(len(endpoints) * 2, 5),
            max_tasks=max(len(endpoints) * 4, 50),
            endpoints=endpoints,
        )
        ai_decisions = _seed_autonomous_tasks(orchestrator, endpoints, agent, auth_token)

        console.print("\n🚀 [bold]Starting Autonomous Scan...[/bold]\n")

        attack_results = orchestrator.run()
        result = _build_scan_result(
            target=target,
            swagger=swagger,
            output=output,
            report_format=ReportFormat.MARKDOWN,
            timeout=5,
            llm_provider=llm_providers[llm],
            endpoints=endpoints,
            attack_results=attack_results,
            vulnerabilities=orchestrator.vulnerabilities,
            ai_decisions=ai_decisions,
            start_time=start_time,
            auth_token=auth_token,
        )

        # Display results
        console.print("\n" + "="*60)
        console.print("📊 [bold]Autonomous Scan Complete[/bold]")
        console.print("="*60 + "\n")

        # Summary
        summary_table = Table(title="Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("Endpoints Scanned", str(len(result.endpoints_tested)))
        summary_table.add_row("Total Requests", str(result.total_requests))
        summary_table.add_row("Findings", str(result.vulnerability_count))
        summary_table.add_row("Attack Chains", "0")
        summary_table.add_row("Duration", f"{result.duration_seconds:.2f}s")

        console.print(summary_table)

        severity_table = Table(title="Findings by Severity")
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="green")
        severity_table.add_row("CRITICAL", str(result.critical_count))
        severity_table.add_row("HIGH", str(result.high_count))
        severity_table.add_row("MEDIUM", str(result.medium_count))
        severity_table.add_row("LOW", str(result.low_count))
        console.print(severity_table)

        # Generate report
        console.print(f"\n📝 [bold]Generating report: {output}[/bold]")

        reporter = Reporter(output)
        report_path = reporter.save(result)
        console.print(f"[green]Report saved to: {report_path}[/green]")

        # Exit code
        critical = result.critical_count
        high = result.high_count

        if critical > 0:
            console.print("\n[bold red]❌ Critical vulnerabilities found![/bold red]")
            sys.exit(2)
        elif high > 0:
            console.print("\n[bold orange1]⚠️ High severity vulnerabilities found![/bold orange1]")
            sys.exit(1)
        else:
            console.print("\n[bold green]✅ No critical or high severity issues found.[/bold green]")
            sys.exit(0)

    except SwaggerParseError as e:
        console.print("\n[red]❌ Parse Error:[/red]")
        for line in str(e).split('\n'):
            console.print(f"   {line}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
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
def passive(url: str, output: str | None):
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
    console.print("\n🔍 [bold]Passive Security Scan[/bold]")
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
    table = Table(title="Available Attack Types (v1.0.0)")
    table.add_column("Attack Type", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("OWASP", style="yellow")
    table.add_column("CWE", style="magenta")

    attacks_info = [
        # Core Attack Types
        ("sql_injection", "SQL injection testing", "A03:2021", "CWE-89"),
        ("xss", "Cross-Site Scripting testing", "A03:2021", "CWE-79"),
        ("auth_bypass", "Authentication bypass testing", "A07:2021", "CWE-306"),
        ("idor", "Insecure Direct Object Reference", "A01:2021", "CWE-639"),
        ("ssrf", "Server-Side Request Forgery", "A10:2021", "CWE-918"),
        ("jwt", "JWT vulnerability testing", "A07:2021", "CWE-287"),
        ("cmd_injection", "OS command injection", "A03:2021", "CWE-78"),
        ("rate_limit", "Rate limiting detection", "A04:2021", "CWE-770"),
        # v1.0.0 Enhanced Attack Types
        ("bola", "Broken Object Level Authorization", "API1:2023", "CWE-639"),
        ("excessive_data", "Excessive Data Exposure", "API3:2023", "CWE-200"),
        ("mass_assignment", "Mass Assignment vulnerability", "API6:2023", "CWE-915"),
        ("bfla", "Broken Function Level Authorization", "API5:2023", "CWE-285"),
        ("nosql_injection", "NoSQL injection testing", "A03:2021", "CWE-943"),
        ("broken_auth", "Broken Authentication flows", "API7:2023", "CWE-287"),
    ]

    console.print("\n[bold cyan]v1.0.0 Enhanced Detection:[/bold cyan]")
    console.print("  • BOLA/IDOR with multi-user testing")
    console.print("  • Excessive Data Exposure detection")
    console.print("  • Mass Assignment vulnerability detection")
    console.print("  • BFLA (Broken Function Level Authorization)")
    console.print("  • NoSQL Injection testing")
    console.print("  • Broken Authentication flow testing\n")

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

    except SwaggerParseError as e:
        console.print("\n[red]❌ Parse Error:[/red]")
        for line in str(e).split('\n'):
            console.print(f"   {line}")
        sys.exit(1)
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
def proxy(host: str, port: int, output: str | None, extract_spec: bool):
    """
    Start an intercepting proxy for traffic analysis.

    The proxy will intercept HTTP traffic and perform passive security analysis.
    Configure your browser or application to use this proxy.

    Example:
        sentinel proxy --port 8080
    """
    print_banner_v25()
    console.print("\n🌐 [bold]Starting Proxy Server[/bold]")
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
    token: str | None,
    username: str | None,
    password: str | None,
    api_key: str | None,
    header_name: str,
    token_url: str | None,
    client_id: str | None,
    client_secret: str | None,
    test_url: str | None
):
    """
    Test and manage authentication.

    Configure authentication for API security testing.

    Example:
        sentinel auth --type bearer --token "your_token" --test-url https://api.example.com
    """
    console.print("\n🔐 [bold]Authentication Configuration[/bold]\n")

    try:
        handler = None

        if type == 'bearer':
            if not token:
                console.print("[red]Error: --token required for bearer auth[/red]")
                sys.exit(1)
            handler = create_bearer_auth(token)
            console.print("  Type: Bearer Token")
            console.print(f"  Token: {token[:20]}...")

        elif type == 'basic':
            if not username or not password:
                console.print("[red]Error: --username and --password required for basic auth[/red]")
                sys.exit(1)
            handler = create_basic_auth(username, password)
            console.print("  Type: Basic Authentication")
            console.print(f"  Username: {username}")

        elif type == 'api_key':
            if not api_key:
                console.print("[red]Error: --api-key required for api_key auth[/red]")
                sys.exit(1)
            handler = create_api_key_auth(api_key, header_name)
            console.print("  Type: API Key")
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
            console.print("  Type: OAuth2 Client Credentials")
            console.print(f"  Token URL: {token_url}")
            console.print(f"  Client ID: {client_id}")

        # Test authentication if URL provided
        if test_url and handler:
            console.print("\n📡 [bold]Testing authentication...[/bold]")

            import requests
            headers = handler.authenticate()
            response = requests.get(test_url, headers=headers, timeout=10)

            if response.status_code == 200:
                console.print("[green]✅ Authentication successful![/green]")
                console.print(f"   Status: {response.status_code}")
            elif response.status_code == 401:
                console.print("[red]❌ Authentication failed![/red]")
                console.print(f"   Status: {response.status_code} - Unauthorized")
            else:
                console.print("[yellow]⚠️ Unexpected response[/yellow]")
                console.print(f"   Status: {response.status_code}")

        console.print()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# ==================== v1.0.0 POSTMAN COLLECTION COMMANDS ====================

@cli.group()
def postman():
    """Postman Collection import/export commands."""
    pass


@postman.command('import')
@click.argument('collection', type=click.Path(exists=True))
@click.option(
    '--target', '-t',
    help='Target API base URL for scanning'
)
@click.option(
    '--output', '-o',
    help='Output file for scan report'
)
@click.option(
    '--scan',
    is_flag=True,
    help='Run security scan after importing'
)
def import_collection(collection: str, target: str | None, output: str | None, scan: bool):
    """
    Import a Postman collection for security testing.

    Parses a Postman Collection v2.0/v2.1 file and extracts endpoints
    for security analysis.

    Example:
        sentinel postman import my_collection.json
        sentinel postman import my_collection.json --target https://api.example.com --scan
    """
    print_banner()
    console.print("\n📦 [bold]Importing Postman Collection[/bold]")
    console.print(f"   File: {collection}\n")

    try:
        # Parse the collection
        parser = PostmanParser(collection)
        endpoints = parser.parse()
        full_info = parser.parse_full()

        # Display collection info
        info = full_info['info']
        console.print(f"\n[bold]Collection: {info['name']}[/bold]")
        if info.get('description'):
            console.print(f"Description: {info['description']}")
        console.print(f"Version: {parser.version}")
        console.print(f"Endpoints found: {len(endpoints)}")

        if full_info.get('variables'):
            console.print(f"Variables: {len(full_info['variables'])}")

        # Display endpoints table
        table = Table(title=f"Extracted Endpoints ({len(endpoints)})")
        table.add_column("Method", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Auth", style="yellow")
        table.add_column("Parameters", style="magenta")

        for endpoint in endpoints[:50]:  # Limit display
            auth = "🔒" if endpoint.requires_auth else "🔓"
            params = ", ".join([p.name for p in endpoint.parameters[:3]]) or "-"
            if len(endpoint.parameters) > 3:
                params += f" +{len(endpoint.parameters) - 3}"
            table.add_row(
                endpoint.method.value,
                endpoint.path,
                auth,
                params
            )

        console.print(table)

        if len(endpoints) > 50:
            console.print(f"[dim]... and {len(endpoints) - 50} more endpoints[/dim]")

        # Get base URL from collection if available
        base_url = target or parser.get_base_url()
        if base_url:
            console.print(f"\n[cyan]Detected base URL: {base_url}[/cyan]")

        # Run scan if requested
        if scan and target:
            console.print("\n🚀 [bold]Starting security scan...[/bold]")
            console.print("[yellow]Use the 'scan' command with --swagger for full scanning capabilities[/yellow]")

        # Save endpoints to file if output specified
        if output:
            import json
            endpoints_data = [ep.model_dump() for ep in endpoints]
            with open(output, 'w') as f:
                json.dump(endpoints_data, f, indent=2, default=str)
            console.print(f"\n[green]Endpoints saved to: {output}[/green]")

    except PostmanParseError as e:
        console.print(f"\n[red]Parse error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@postman.command('export')
@click.option(
    '--swagger', '-s',
    type=click.Path(exists=True),
    help='Path to OpenAPI/Swagger specification to convert'
)
@click.option(
    '--collection', '-c',
    type=click.Path(exists=True),
    help='Path to existing Postman collection to extend'
)
@click.option(
    '--output', '-o',
    required=True,
    help='Output file for Postman collection'
)
@click.option(
    '--name', '-n',
    default='Sentinel Export',
    help='Collection name'
)
@click.option(
    '--base-url', '-u',
    help='Base URL for the API'
)
def export_collection(
    swagger: str | None,
    collection: str | None,
    output: str,
    name: str,
    base_url: str | None
):
    """
    Export endpoints to a Postman collection.

    Creates a Postman Collection v2.1 file from an OpenAPI specification
    or extends an existing Postman collection.

    Example:
        sentinel postman export --swagger api.yaml --output collection.json
        sentinel postman export --swagger api.yaml -n "My API" -u https://api.example.com -o my_api.json
    """
    print_banner()
    console.print("\n📤 [bold]Exporting to Postman Collection[/bold]")

    try:
        endpoints = []

        if swagger:
            console.print(f"   Source: OpenAPI ({swagger})")
            from .parser import SwaggerParser
            parser = SwaggerParser(swagger)
            endpoints = parser.parse()

            # Get base URL from spec if not provided
            if not base_url:
                base_url = parser.get_base_url() or "{{base_url}}"

            # Use API title for collection name if not provided
            if name == 'Sentinel Export':
                info = parser.get_info()
                name = info.get('title', 'Sentinel Export')

            console.print(f"   Endpoints: {len(endpoints)}")

        elif collection:
            console.print(f"   Source: Postman ({collection})")
            parser = PostmanParser(collection)
            endpoints = parser.parse()
            console.print(f"   Endpoints: {len(endpoints)}")

        else:
            console.print("[red]Error: Either --swagger or --collection must be specified[/red]")
            sys.exit(1)

        if not endpoints:
            console.print("[red]No endpoints found to export[/red]")
            sys.exit(1)

        # Generate collection
        generator = PostmanGenerator(name=name)
        postman_collection = generator.from_endpoints(
            endpoints=endpoints,
            base_url=base_url or "{{base_url}}"
        )

        # Save collection
        output_path = generator.save(postman_collection, output)

        console.print("\n[green]✅ Collection exported successfully![/green]")
        console.print(f"   Name: {name}")
        console.print(f"   Endpoints: {len(endpoints)}")
        console.print(f"   Output: {output_path}")
        console.print("\n[dim]Import this collection into Postman to test your API[/dim]")

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@postman.command('convert')
@click.argument('input', type=click.Path(exists=True))
@click.option(
    '--output', '-o',
    required=True,
    help='Output file for converted collection'
)
@click.option(
    '--name', '-n',
    help='Collection name (defaults to API title)'
)
@click.option(
    '--base-url', '-u',
    help='Base URL for the API'
)
def convert_spec(input: str, output: str, name: str | None, base_url: str | None):
    """
    Convert between OpenAPI/Swagger and Postman Collection formats.

    Supports:
    - OpenAPI/Swagger YAML/JSON → Postman Collection
    - Postman Collection → Postman Collection (normalize/repair)

    Example:
        sentinel postman convert api.yaml -o collection.json
        sentinel postman convert api.json -o collection.json -n "My API"
    """
    print_banner()
    console.print("\n🔄 [bold]Converting Specification[/bold]")
    console.print(f"   Input: {input}")
    console.print(f"   Output: {output}\n")

    try:
        # Determine input type
        import json

        import yaml
        content = Path(input).read_text()

        is_openapi = False
        try:
            data = json.loads(content) if content.strip().startswith('{') else yaml.safe_load(content)
            if 'openapi' in data or 'swagger' in data:
                is_openapi = True
        except Exception:
            pass

        # Try YAML if JSON parse fails
        if not is_openapi and ('openapi:' in content or 'swagger:' in content):
            is_openapi = True

        if is_openapi:
            console.print("[cyan]Detected: OpenAPI/Swagger specification[/cyan]")

            # Convert OpenAPI to Postman
            collection = convert_openapi_to_postman(
                openapi_path=input,
                output_path=output,
                name=name,
                base_url=base_url
            )

            console.print("\n[green]✅ Converted to Postman Collection![/green]")
            console.print(f"   Collection: {collection.get('info', {}).get('name', 'Unknown')}")
            console.print(f"   Output: {output}")
        else:
            console.print("[cyan]Detected: Postman Collection[/cyan]")

            # Parse and regenerate the collection (normalize/repair)
            parser = PostmanParser(input)
            endpoints = parser.parse()
            info = parser.parse_full()['info']

            generator = PostmanGenerator(name=name or info.get('name', 'Converted Collection'))
            collection = generator.from_endpoints(
                endpoints=endpoints,
                base_url=base_url or parser.get_base_url() or "{{base_url}}"
            )
            generator.save(collection, output)

            console.print("\n[green]✅ Collection normalized![/green]")
            console.print(f"   Endpoints: {len(endpoints)}")
            console.print(f"   Output: {output}")

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


# ==================== v1.0.0 BENCHMARK COMMANDS ====================

@cli.group()
def benchmark():
    """Run benchmarks against vulnerable applications."""
    pass


@benchmark.command('run')
@click.option(
    '--target', '-t',
    type=click.Choice(['crapi', 'juice_shop', 'owasp_benchmark', 'all']),
    default='all',
    help='Benchmark target to run'
)
@click.option(
    '--url', '-u',
    help='Target URL (overrides default)'
)
@click.option(
    '--output', '-o',
    default='benchmark_results.json',
    help='Output file for results'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose output'
)
def run_benchmark(target: str, url: str | None, output: str, verbose: bool):
    """
    Run security benchmark against vulnerable applications.

    Measures Sentinel's detection capabilities against known vulnerabilities.

    Available targets:
    - crapi: OWASP crAPI (API-specific vulnerabilities)
    - juice_shop: OWASP Juice Shop (web application)
    - owasp_benchmark: OWASP Benchmark Java (comprehensive test suite)
    - all: Run all benchmarks

    Example:
        sentinel benchmark run --target crapi --url http://localhost:8888
        sentinel benchmark run --target all
    """
    import asyncio
    import json

    print_banner()
    console.print("\n📊 [bold]Running Security Benchmarks[/bold]")
    console.print(f"   Target: {target}")
    console.print(f"   Output: {output}\n")

    async def execute_benchmark():
        results = []
        runner = BenchmarkRunner()

        # Define targets and their default URLs
        targets_config = {
            'crapi': {'url': url or 'http://localhost:8888', 'name': 'OWASP crAPI'},
            'juice_shop': {'url': url or 'http://localhost:3000', 'name': 'OWASP Juice Shop'},
            'owasp_benchmark': {'url': url or 'http://localhost:8080', 'name': 'OWASP Benchmark Java'}
        }

        # Determine which targets to run
        if target == 'all':
            to_run = list(targets_config.keys())
        else:
            to_run = [target]

        for t in to_run:
            config = targets_config[t]
            console.print(f"\n[target] [bold cyan]Running benchmark: {config['name']}[/bold cyan]")
            console.print(f"   URL: {config['url']}")

            try:
                result = await runner.run_benchmark(
                    target=BenchmarkTarget(t),
                    base_url=config['url'],
                    verbose=verbose
                )
                results.append(result)

                # Display results
                _display_benchmark_result(result)

            except Exception as e:
                console.print(f"[red]Error running benchmark: {e}[/red]")
                if verbose:
                    console.print_exception()

        return results

    try:
        results = asyncio.run(execute_benchmark())

        # Generate overall summary
        if results:
            console.print("\n" + "="*60)
            console.print("📈 [bold]Overall Benchmark Summary[/bold]")
            console.print("="*60 + "\n")

            summary_table = Table(title="Benchmark Results")
            summary_table.add_column("Target", style="cyan")
            summary_table.add_column("Total Vulns", style="white")
            summary_table.add_column("Detected", style="green")
            summary_table.add_column("Precision", style="yellow")
            summary_table.add_column("Recall", style="magenta")
            summary_table.add_column("F1 Score", style="blue")

            for r in results:
                summary_table.add_row(
                    r.target.value,
                    str(r.total_vulnerabilities),
                    str(r.detected_vulnerabilities),
                    f"{r.precision:.2%}",
                    f"{r.recall:.2%}",
                    f"{r.f1_score:.2%}"
                )

            console.print(summary_table)

            # Save results
            results_data = []
            for r in results:
                results_data.append({
                    "target": r.target.value,
                    "total_vulnerabilities": r.total_vulnerabilities,
                    "detected_vulnerabilities": r.detected_vulnerabilities,
                    "true_positives": r.true_positives,
                    "false_positives": r.false_positives,
                    "false_negatives": r.false_negatives,
                    "precision": r.precision,
                    "recall": r.recall,
                    "f1_score": r.f1_score,
                    "detection_rate": r.detection_rate,
                    "duration_seconds": r.duration_seconds
                })

            with open(output, 'w') as f:
                json.dump({
                    "sentinel_version": __version__,
                    "timestamp": time.time(),
                    "results": results_data
                }, f, indent=2)

            console.print(f"\n[green]Results saved to: {output}[/green]")

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


def _display_benchmark_result(result: BenchmarkResult):
    """Display benchmark result in a formatted table."""
    table = Table(title=f"Results for {result.target.value}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Vulnerabilities", str(result.total_vulnerabilities))
    table.add_row("Detected", str(result.detected_vulnerabilities))
    table.add_row("True Positives", str(result.true_positives))
    table.add_row("False Positives", str(result.false_positives))
    table.add_row("False Negatives", str(result.false_negatives))
    table.add_row("Precision", f"{result.precision:.2%}")
    table.add_row("Recall", f"{result.recall:.2%}")
    table.add_row("F1 Score", f"{result.f1_score:.2%}")
    table.add_row("Duration", f"{result.duration_seconds:.2f}s")

    console.print(table)

    # Category breakdown
    if result.category_results:
        cat_table = Table(title="Detection by Category")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Total", style="white")
        cat_table.add_column("Detected", style="green")
        cat_table.add_column("Rate", style="yellow")

        for cat, data in result.category_results.items():
            if data["total"] > 0:
                rate = data["true_positives"] / data["total"] if data["total"] > 0 else 0
                cat_table.add_row(
                    cat,
                    str(data["total"]),
                    str(data["detected"]),
                    f"{rate:.0%}"
                )

        console.print(cat_table)


@benchmark.command('list')
def list_benchmarks():
    """List available benchmark targets and their details."""
    print_banner()
    console.print("\n📋 [bold]Available Benchmark Targets[/bold]\n")

    targets_info = [
        ("crapi", "OWASP crAPI", "http://localhost:8888",
         "Modern REST API with OWASP API Top 10 vulnerabilities",
         "13 known vulnerabilities"),
        ("juice_shop", "OWASP Juice Shop", "http://localhost:3000",
         "Node.js web application with 100+ vulnerabilities",
         "22 known vulnerabilities (subset)"),
        ("owasp_benchmark", "OWASP Benchmark Java", "http://localhost:8080",
         "Java test suite with thousands of test cases",
         "13 known vulnerabilities (subset)")
    ]

    table = Table()
    table.add_column("Target", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Default URL", style="yellow")
    table.add_column("Description", style="white")
    table.add_column("Vulns", style="magenta")

    for target, name, url, desc, vulns in targets_info:
        table.add_row(target, name, url, desc[:40] + "...", vulns)

    console.print(table)

    console.print("\n[bold]Metrics Calculated:[/bold]")
    console.print("  • Detection Rate - Percentage of known vulnerabilities found")
    console.print("  • Precision - True Positives / (True Positives + False Positives)")
    console.print("  • Recall - True Positives / (True Positives + False Negatives)")
    console.print("  • F1 Score - Harmonic mean of Precision and Recall")


@benchmark.command('ground-truth')
@click.option(
    '--target', '-t',
    type=click.Choice(['crapi', 'juice_shop', 'owasp_benchmark', 'all']),
    default='all',
    help='Target to show ground truth for'
)
def show_ground_truth(target: str):
    """Show ground truth vulnerabilities for benchmark targets."""
    print_banner()
    console.print("\n🔍 [bold]Ground Truth Database[/bold]\n")

    db = GroundTruthDatabase()

    targets_to_show = [target] if target != 'all' else ['crapi', 'juice_shop', 'owasp_benchmark']

    for t in targets_to_show:
        vulns = db.get_vulnerabilities(BenchmarkTarget(t))

        console.print(f"\n[bold cyan]{t.upper()} ({len(vulns)} vulnerabilities)[/bold cyan]")

        table = Table()
        table.add_column("ID", style="dim")
        table.add_column("Category", style="cyan")
        table.add_column("Endpoint", style="green")
        table.add_column("Method", style="yellow")
        table.add_column("CWE", style="magenta")
        table.add_column("Severity", style="red")

        for v in vulns[:20]:  # Show first 20
            table.add_row(
                v.vuln_id,
                v.category.value,
                v.endpoint[:30] + "..." if len(v.endpoint) > 30 else v.endpoint,
                v.method,
                v.cwe,
                v.severity.value.upper()
            )

        console.print(table)

        if len(vulns) > 20:
            console.print(f"[dim]... and {len(vulns) - 20} more[/dim]")


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
