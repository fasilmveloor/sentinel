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

__version__ = "1.0.0"
__author__ = "Sentinel Team"

# Core modules
from .models import (
    Endpoint,
    AttackResult,
    AttackType,
    Severity,
    HttpMethod,
    LLMProvider
)
from .agent import SentinelAgent, create_agent
from .parser import SwaggerParser  # Also exported as OpenAPIParser for compatibility
OpenAPIParser = SwaggerParser  # Alias for backwards compatibility
from .reporter import Reporter as MarkdownReporter  # Alias for clarity

# v2.5 Agentic Features
from .autonomous import (
    AutonomousScanner,
    PlannerAgent,
    ExecutorAgent,
    AnalyzerAgent,
    ScanPlan,
    AttackChain,
    AutonomousScanResult,
    run_autonomous_scan
)
from .passive import (
    PassiveScanner,
    PassiveFinding,
    PassiveFindingType,
    create_passive_scanner
)
from .chat import (
    SentinelChat,
    ChatIntent,
    ChatResponse,
    create_chat_interface,
    run_interactive_session
)

# v3.0 Enterprise Features
from .auth import (
    AuthHandler,
    AuthManager,
    AuthConfig,
    AuthType,
    AuthenticationError,
    create_api_key_auth,
    create_bearer_auth,
    create_basic_auth,
    create_oauth2_client_credentials,
    create_session_auth,
    detect_auth_type
)
from .proxy import (
    SentinelProxy,
    ProxyConfig,
    ProxyTrafficStore,
    TrafficAnalyzer,
    TrafficFlow,
    InterceptedRequest,
    InterceptedResponse,
    create_proxy
)
from .plugin import (
    BasePlugin,
    AttackPlugin,
    ReporterPlugin,
    AnalyzerPlugin,
    PassivePlugin,
    PluginManager,
    PluginInfo,
    PluginType,
    PluginPriority,
    PluginContext,
    get_plugin_manager,
    create_attack_plugin_template,
    create_passive_plugin_template
)

__all__ = [
    # Models
    'Endpoint',
    'AttackResult',
    'AttackType',
    'Severity',
    'HttpMethod',
    'LLMProvider',
    
    # Core
    'SentinelAgent',
    'create_agent',
    'OpenAPIParser',
    'MarkdownReporter',
    
    # v2.5 Agentic
    'AutonomousScanner',
    'PlannerAgent',
    'ExecutorAgent',
    'AnalyzerAgent',
    'ScanPlan',
    'AttackChain',
    'AutonomousScanResult',
    'run_autonomous_scan',
    
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
    'create_passive_plugin_template'
]
