"""
Sentinel - AI-Native API Security Testing Tool

An AI-first approach to API vulnerability assessment with multi-agent architecture.

Features:
- Multi-Agent System (Planner, Executor, Analyzer)
- 8 Attack Types (SQLi, XSS, SSRF, JWT, CMD Injection, Auth Bypass, IDOR, Rate Limit)
- Multi-LLM Support (Gemini, OpenAI, Claude, Ollama)
- Passive Security Scanner (22+ checks)
- Attack Chain Discovery
- Natural Language Chat Interface
- Authentication Handler (10+ types)
- Proxy Mode for traffic interception
- Plugin System for extensibility
- Multiple report formats (Markdown, HTML, JSON, SARIF, JUnit)
"""

__version__ = "2.0.0"
__author__ = "Sentinel Team"

# Core modules
from .agent import SentinelAgent, create_agent
from .models import AttackResult, AttackType, Endpoint, HttpMethod, LLMProvider, ScanTask, Severity
from .parser import SwaggerParser  # Also exported as OpenAPIParser for compatibility

OpenAPIParser = SwaggerParser  # Alias for backwards compatibility
# v3.0 Enterprise Features
from .auth import (
    AuthConfig,
    AuthenticationError,
    AuthHandler,
    AuthManager,
    AuthType,
    create_api_key_auth,
    create_basic_auth,
    create_bearer_auth,
    create_oauth2_client_credentials,
    create_session_auth,
    detect_auth_type,
)

# v1.0.0 Benchmark Framework
from .benchmarks import (
    BenchmarkCategory,
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkTarget,
    GroundTruthDatabase,
    GroundTruthVulnerability,
    run_all_benchmarks,
    run_crapi_benchmark,
    run_juice_shop_benchmark,
    run_owasp_benchmark,
)
from .chat import (
    ChatIntent,
    ChatResponse,
    SentinelChat,
    create_chat_interface,
    run_interactive_session,
)
from .orchestrator import SentinelOrchestrator
from .passive import PassiveFinding, PassiveFindingType, PassiveScanner, create_passive_scanner
from .plugin import (
    AnalyzerPlugin,
    AttackPlugin,
    BasePlugin,
    PassivePlugin,
    PluginContext,
    PluginInfo,
    PluginManager,
    PluginPriority,
    PluginType,
    ReporterPlugin,
    create_attack_plugin_template,
    create_passive_plugin_template,
    get_plugin_manager,
)

# v1.0.0 Postman Collection Support
from .postman import (
    PostmanAuthType,
    PostmanGenerator,
    PostmanParseError,
    PostmanParser,
    PostmanRequest,
    PostmanVariable,
    convert_openapi_to_postman,
    generate_postman_collection,
    parse_postman,
)
from .proxy import (
    InterceptedRequest,
    InterceptedResponse,
    ProxyConfig,
    ProxyTrafficStore,
    SentinelProxy,
    TrafficAnalyzer,
    TrafficFlow,
    create_proxy,
)
from .reporter import Reporter as MarkdownReporter  # Alias for clarity
from .scan_context import ScanContext
from .tasks import TaskQueue

__all__ = [
    # Models
    'Endpoint',
    'AttackResult',
    'AttackType',
    'Severity',
    'HttpMethod',
    'LLMProvider',
    'ScanTask',
    'TaskQueue',
    'ScanContext',
    'SentinelOrchestrator',

    # Core
    'SentinelAgent',
    'create_agent',
    'OpenAPIParser',
    'MarkdownReporter',

    # Passive Scanner
    'PassiveScanner',
    'PassiveFinding',
    'PassiveFindingType',
    'create_passive_scanner',

    # Chat Interface
    'SentinelChat',
    'ChatIntent',
    'ChatResponse',
    'create_chat_interface',
    'run_interactive_session',

    # v3.0 Authentication
    'AuthHandler',
    'AuthManager',
    'AuthConfig',
    'AuthType',
    'AuthenticationError',
    'create_api_key_auth',
    'create_bearer_auth',
    'create_basic_auth',
    'create_oauth2_client_credentials',
    'create_session_auth',
    'detect_auth_type',

    # v3.0 Proxy
    'SentinelProxy',
    'ProxyConfig',
    'ProxyTrafficStore',
    'TrafficAnalyzer',
    'TrafficFlow',
    'InterceptedRequest',
    'InterceptedResponse',
    'create_proxy',

    # v3.0 Plugins
    'BasePlugin',
    'AttackPlugin',
    'ReporterPlugin',
    'AnalyzerPlugin',
    'PassivePlugin',
    'PluginManager',
    'PluginInfo',
    'PluginType',
    'PluginPriority',
    'PluginContext',
    'get_plugin_manager',
    'create_attack_plugin_template',
    'create_passive_plugin_template',

    # v1.0.0 Postman Collection
    'PostmanParser',
    'PostmanGenerator',
    'PostmanParseError',
    'PostmanVariable',
    'PostmanRequest',
    'PostmanAuthType',
    'parse_postman',
    'generate_postman_collection',
    'convert_openapi_to_postman',

    # v1.0.0 Benchmark Framework
    'BenchmarkTarget',
    'BenchmarkCategory',
    'BenchmarkRunner',
    'BenchmarkResult',
    'BenchmarkReport',
    'GroundTruthDatabase',
    'GroundTruthVulnerability',
    'run_crapi_benchmark',
    'run_juice_shop_benchmark',
    'run_owasp_benchmark',
    'run_all_benchmarks'
]
