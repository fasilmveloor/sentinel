"""
Interactive Chat Mode for Sentinel.

Provides a natural language interface for API security testing.
Users can describe what they want to test in plain English.

v2.5 Feature: Agentic OWASP ZAP
"""

import json
import re
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from .models import Endpoint, AttackType, Severity, LLMProvider
from .agent import SentinelAgent, create_agent
from .parser import SwaggerParser as OpenAPIParser
from .autonomous import AutonomousScanner, AutonomousScanResult


class ChatIntent(Enum):
    """User intent classification."""
    SCAN_API = "scan_api"
    ANALYZE_ENDPOINT = "analyze_endpoint"
    EXPLAIN_FINDING = "explain_finding"
    SUGGEST_TEST = "suggest_test"
    HELP = "help"
    STATUS = "status"
    REPORT = "report"
    UNKNOWN = "unknown"


@dataclass
class ChatResponse:
    """Response from chat interaction."""
    message: str
    intent: ChatIntent
    action_taken: bool = False
    follow_up_suggestions: list[str] = None
    data: Optional[dict] = None
    
    def __post_init__(self):
        if self.follow_up_suggestions is None:
            self.follow_up_suggestions = []


class SentinelChat:
    """
    Natural language interface for Sentinel security testing.
    
    Allows users to interact with the security tool using conversational commands.
    """
    
    SYSTEM_PROMPT = """You are Sentinel, an AI-powered API security testing assistant. You help security professionals and developers test their APIs for vulnerabilities.

You can understand natural language requests and translate them into security testing actions. Be helpful, professional, and security-focused.

Available capabilities:
1. Scan APIs - Run comprehensive security scans on API endpoints
2. Analyze endpoints - Explain security implications of specific endpoints
3. Explain findings - Provide detailed explanations of vulnerabilities
4. Suggest tests - Recommend specific security tests based on context
5. Generate reports - Create security reports from scan results
6. Answer questions - Help with API security concepts

When users ask to scan an API, extract:
- Target URL or API spec file
- Authentication details (if mentioned)
- Specific tests they want (if mentioned)

Respond naturally but be concise. When appropriate, suggest follow-up actions.

Current context:
{context}"""

    INTENT_PROMPT = """Classify the user's intent from their message:

Message: "{message}"

Possible intents:
- scan_api: User wants to scan/test an API
- analyze_endpoint: User asks about a specific endpoint
- explain_finding: User wants explanation of a vulnerability
- suggest_test: User wants recommendations for testing
- help: User needs help or instructions
- status: User wants to know current status
- report: User wants a report
- unknown: Cannot determine intent

Respond in JSON:
{"intent": "intent_name", "confidence": 0.0-1.0, "extracted_info": {"url": "...", "endpoint": "...", "attack_type": "..."}}"""

    SCAN_PROMPT = """The user wants to scan an API. Extract the following information from their request:

Request: "{message}"

Extract:
1. Target URL (if provided)
2. API specification file (if mentioned)
3. Authentication method (if mentioned: bearer token, API key, basic auth, etc.)
4. Specific attack types to run (if mentioned)
5. Any exclusions or constraints

Respond in JSON:
{
    "target_url": "extracted url or null",
    "spec_file": "file path or null",
    "auth": {
        "type": "bearer/api_key/basic/none",
        "value": "extracted value or null"
    },
    "attack_types": ["list", "of", "types"],
    "exclusions": ["paths to exclude"],
    "scan_scope": "quick/full/custom"
}"""

    EXPLAIN_PROMPT = """Explain this security finding in detail:

Finding: {finding}

Provide:
1. What this vulnerability means
2. Why it's a security risk
3. How an attacker could exploit it
4. How to fix it
5. Related CWE/OWASP references

Be educational but concise. Use markdown formatting."""

    SUGGEST_PROMPT = """Based on this API information, suggest the most effective security tests:

API Info: {api_info}

Consider:
1. Which attack types are most relevant
2. Which endpoints are highest risk
3. What authentication tests to run
4. Any business logic concerns

Respond in JSON:
{
    "priority_tests": [
        {"test": "attack_type", "target": "endpoint", "reasoning": "why"}
    ],
    "risk_areas": ["area1", "area2"],
    "estimated_time": "X minutes"
}"""

    def __init__(
        self,
        ai_provider: LLMProvider = LLMProvider.GEMINI,
        api_key: Optional[str] = None
    ):
        self.ai_agent = create_agent(ai_provider, api_key)
        self.scanner: Optional[AutonomousScanner] = None
        self.last_scan_result: Optional[AutonomousScanResult] = None
        self.endpoints: list[Endpoint] = []
        self.context: dict = {}
        self.conversation_history: list[dict] = []
    
    def chat(self, message: str) -> ChatResponse:
        """
        Process a natural language message and respond.
        
        Args:
            message: User's message
            
        Returns:
            ChatResponse with the assistant's reply
        """
        # Add to history
        self.conversation_history.append({"role": "user", "content": message})
        
        # Classify intent
        intent = self._classify_intent(message)
        
        # Handle based on intent
        if intent['intent'] == ChatIntent.SCAN_API:
            return self._handle_scan_request(message, intent)
        elif intent['intent'] == ChatIntent.ANALYZE_ENDPOINT:
            return self._handle_analyze_request(message)
        elif intent['intent'] == ChatIntent.EXPLAIN_FINDING:
            return self._handle_explain_request(message)
        elif intent['intent'] == ChatIntent.SUGGEST_TEST:
            return self._handle_suggest_request(message)
        elif intent['intent'] == ChatIntent.HELP:
            return self._handle_help_request()
        elif intent['intent'] == ChatIntent.STATUS:
            return self._handle_status_request()
        elif intent['intent'] == ChatIntent.REPORT:
            return self._handle_report_request(message)
        else:
            return self._handle_unknown(message)
    
    def _classify_intent(self, message: str) -> dict:
        """Classify the user's intent from their message."""
        message_lower = message.lower()
        
        # Rule-based classification for common patterns
        scan_keywords = ['scan', 'test', 'check', 'attack', 'audit', 'analyze', 'run', 'pentest']
        if any(kw in message_lower for kw in scan_keywords):
            return {'intent': ChatIntent.SCAN_API, 'confidence': 0.8}
        
        help_keywords = ['help', 'how do', 'how to', 'what can', 'usage', 'guide']
        if any(kw in message_lower for kw in help_keywords):
            return {'intent': ChatIntent.HELP, 'confidence': 0.9}
        
        status_keywords = ['status', 'progress', 'current', 'ongoing']
        if any(kw in message_lower for kw in status_keywords):
            return {'intent': ChatIntent.STATUS, 'confidence': 0.8}
        
        report_keywords = ['report', 'summary', 'findings', 'results']
        if any(kw in message_lower for kw in report_keywords):
            return {'intent': ChatIntent.REPORT, 'confidence': 0.8}
        
        explain_keywords = ['explain', 'what is', 'tell me about', 'what does', 'why is']
        if any(kw in message_lower for kw in explain_keywords):
            return {'intent': ChatIntent.EXPLAIN_FINDING, 'confidence': 0.7}
        
        suggest_keywords = ['suggest', 'recommend', 'what should', 'what tests']
        if any(kw in message_lower for kw in suggest_keywords):
            return {'intent': ChatIntent.SUGGEST_TEST, 'confidence': 0.8}
        
        # Use AI for ambiguous cases
        try:
            response = self.ai_agent.active_provider.generate(
                self.INTENT_PROMPT.format(message=message),
                "You are an intent classifier. Respond only with JSON."
            )
            
            # Parse response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group(0))
                return {
                    'intent': ChatIntent(data.get('intent', 'unknown')),
                    'confidence': data.get('confidence', 0.5),
                    'extracted_info': data.get('extracted_info', {})
                }
        except Exception:
            pass
        
        return {'intent': ChatIntent.UNKNOWN, 'confidence': 0.3}
    
    def _handle_scan_request(self, message: str, intent: dict) -> ChatResponse:
        """Handle a request to scan an API."""
        
        # Extract scan parameters
        scan_params = self._extract_scan_params(message)
        
        if not scan_params.get('target_url') and not scan_params.get('spec_file'):
            return ChatResponse(
                message="I'd be happy to help you scan an API! Please provide:\n\n"
                       "1. **Target URL** - e.g., `https://api.example.com`\n"
                       "2. **Or an OpenAPI spec file** - e.g., `api.yaml` or `swagger.json`\n\n"
                       "You can also specify:\n"
                       "- Authentication: `--auth bearer:your_token`\n"
                       "- Specific tests: `--attacks sql,xss,auth`\n"
                       "- Example: `Scan https://api.example.com with bearer token abc123`",
                intent=ChatIntent.SCAN_API,
                follow_up_suggestions=[
                    "Scan https://api.example.com",
                    "Run a quick security test on my API",
                    "Full penetration test with all attack types"
                ]
            )
        
        # Confirm scan parameters
        response_msg = f"🎯 **Scan Configuration**\n\n"
        response_msg += f"- **Target**: {scan_params.get('target_url', 'From spec file')}\n"
        
        if scan_params.get('auth'):
            response_msg += f"- **Auth**: {scan_params['auth'].get('type', 'None')}\n"
        
        if scan_params.get('attack_types'):
            response_msg += f"- **Tests**: {', '.join(scan_params['attack_types'])}\n"
        else:
            response_msg += f"- **Tests**: All available attacks\n"
        
        response_msg += f"\nTo start the scan, run:\n```bash\n"
        response_msg += f"sentinel scan {scan_params.get('target_url', 'api.yaml')}\n"
        auth = scan_params.get('auth') or {}
        if auth.get('type') == 'bearer':
            response_msg += f"  --auth-type bearer --auth-token {scan_params['auth'].get('value', 'TOKEN')}\n"
        response_msg += "```\n"
        
        # Store context
        self.context['last_scan_params'] = scan_params
        
        return ChatResponse(
            message=response_msg,
            intent=ChatIntent.SCAN_API,
            action_taken=True,
            data=scan_params,
            follow_up_suggestions=[
                "Run the scan now",
                "Explain each attack type",
                "Focus on authentication tests only"
            ]
        )
    
    def _extract_scan_params(self, message: str) -> dict:
        """Extract scan parameters from message."""
        params = {
            'target_url': None,
            'spec_file': None,
            'auth': None,
            'attack_types': [],
            'exclusions': []
        }
        
        # Extract URL
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        url_match = re.search(url_pattern, message)
        if url_match:
            params['target_url'] = url_match.group(0)
        
        # Extract auth
        if 'bearer' in message.lower():
            bearer_match = re.search(r'bearer[:\s]+([a-zA-Z0-9_\-\.]+)', message, re.IGNORECASE)
            params['auth'] = {
                'type': 'bearer',
                'value': bearer_match.group(1) if bearer_match else None
            }
        elif 'api key' in message.lower():
            params['auth'] = {'type': 'api_key', 'value': None}
        elif 'basic auth' in message.lower():
            params['auth'] = {'type': 'basic', 'value': None}
        
        # Extract attack types
        attack_keywords = {
            'sql': AttackType.SQL_INJECTION,
            'xss': AttackType.XSS,
            'ssrf': AttackType.SSRF,
            'jwt': AttackType.JWT,
            'auth': AttackType.AUTH_BYPASS,
            'idor': AttackType.IDOR,
            'command': AttackType.CMD_INJECTION,
            'rate': AttackType.RATE_LIMIT
        }
        
        for keyword, attack_type in attack_keywords.items():
            if keyword in message.lower():
                params['attack_types'].append(attack_type.value)
        
        # Extract spec file
        spec_pattern = r'[\w\-]+\.(yaml|yml|json)'
        spec_match = re.search(spec_pattern, message)
        if spec_match and not params['target_url']:
            params['spec_file'] = spec_match.group(0)
        
        return params
    
    def _handle_analyze_request(self, message: str) -> ChatResponse:
        """Handle a request to analyze an endpoint."""
        
        if not self.endpoints:
            return ChatResponse(
                message="I don't have any endpoints loaded yet. Please:\n\n"
                       "1. Load an OpenAPI spec: `Load api.yaml`\n"
                       "2. Or scan an API first: `Scan https://api.example.com`",
                intent=ChatIntent.ANALYZE_ENDPOINT,
                follow_up_suggestions=[
                    "Load my OpenAPI spec",
                    "Scan an API first"
                ]
            )
        
        # Find mentioned endpoint
        endpoint = self._find_endpoint_in_message(message)
        
        if not endpoint:
            endpoint_list = "\n".join([f"- {e.method.value} {e.path}" for e in self.endpoints[:10]])
            return ChatResponse(
                message=f"Which endpoint would you like me to analyze?\n\n"
                       f"**Available endpoints:**\n{endpoint_list}\n"
                       f"\nAsk about a specific one, e.g., 'Analyze POST /api/users'",
                intent=ChatIntent.ANALYZE_ENDPOINT,
                data={'endpoints': [{'method': e.method.value, 'path': e.path} for e in self.endpoints]}
            )
        
        # Analyze the endpoint
        analysis = self._analyze_endpoint_security(endpoint)
        
        return ChatResponse(
            message=f"🔍 **Analysis: {endpoint.method.value} {endpoint.path}**\n\n{analysis}",
            intent=ChatIntent.ANALYZE_ENDPOINT,
            action_taken=True,
            data={'endpoint': f"{endpoint.method.value} {endpoint.path}"}
        )
    
    def _find_endpoint_in_message(self, message: str) -> Optional[Endpoint]:
        """Find a mentioned endpoint in the message."""
        message_lower = message.lower()
        
        for endpoint in self.endpoints:
            if endpoint.path.lower() in message_lower:
                return endpoint
            # Check for path patterns
            if f"{endpoint.method.value.lower()} {endpoint.path.lower()}" in message_lower:
                return endpoint
        
        return None
    
    def _analyze_endpoint_security(self, endpoint: Endpoint) -> str:
        """Analyze security aspects of an endpoint."""
        analysis = []
        
        # Method analysis
        dangerous_methods = ['DELETE', 'PUT', 'PATCH']
        if endpoint.method.value in dangerous_methods:
            analysis.append(f"⚠️ **{endpoint.method.value}** can modify/delete data")
        
        # Auth analysis
        if endpoint.requires_auth:
            analysis.append("🔒 Requires authentication - test for auth bypass")
        else:
            analysis.append("🔓 No authentication required - check if intended")
        
        # Parameter analysis
        if endpoint.parameters:
            param_names = [p.name for p in endpoint.parameters]
            analysis.append(f"📝 Parameters: {', '.join(param_names)} - test for injection")
            
            id_params = [p.name for p in endpoint.parameters if 'id' in p.name.lower()]
            if id_params:
                analysis.append(f"🎯 ID parameters ({', '.join(id_params)}) - test for IDOR")
        
        # Body analysis
        if endpoint.request_body:
            analysis.append("📦 Has request body - test for injection, XSS")
        
        return "\n".join(analysis) if analysis else "No significant security concerns identified."
    
    def _handle_explain_request(self, message: str) -> ChatResponse:
        """Handle a request to explain a finding or concept."""
        
        # Check for specific vulnerability mention
        vuln_keywords = {
            'sql injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'ssrf': 'Server-Side Request Forgery (SSRF)',
            'idor': 'Insecure Direct Object Reference (IDOR)',
            'jwt': 'JWT Vulnerabilities',
            'auth bypass': 'Authentication Bypass',
            'command injection': 'OS Command Injection',
            'rate limit': 'Rate Limiting Issues'
        }
        
        topic = None
        for keyword, name in vuln_keywords.items():
            if keyword in message.lower():
                topic = name
                break
        
        if not topic:
            topic = "API Security Testing"
        
        # Generate explanation using AI
        try:
            explanation = self.ai_agent.active_provider.generate(
                f"Explain {topic} in the context of API security testing. "
                f"Include: what it is, why it's dangerous, how to test for it, how to fix it. "
                f"Be concise and use markdown.",
                "You are a security educator."
            )
        except Exception:
            explanation = self._get_cached_explanation(topic)
        
        return ChatResponse(
            message=f"📚 **{topic}**\n\n{explanation}",
            intent=ChatIntent.EXPLAIN_FINDING,
            follow_up_suggestions=[
                f"How do I test for {topic}?",
                f"Show me example payloads",
                "What are the OWASP categories?"
            ]
        )
    
    def _get_cached_explanation(self, topic: str) -> str:
        """Get a cached explanation for common topics."""
        explanations = {
            'SQL Injection': """
SQL Injection occurs when untrusted data is included in a SQL query without proper sanitization.

**Danger**: Attackers can read, modify, or delete database data.

**Testing**: Try payloads like `' OR '1'='1` in parameters.

**Fix**: Use parameterized queries/prepared statements.""",
            
            'Cross-Site Scripting (XSS)': """
XSS occurs when untrusted data is included in a web page without proper escaping.

**Danger**: Attackers can steal sessions, redirect users, deface sites.

**Testing**: Try payloads like `<script>alert(1)</script>` in parameters.

**Fix**: Encode output based on context (HTML, JavaScript, URL).""",
            
            'API Security Testing': """
API security testing involves identifying vulnerabilities in application programming interfaces.

**Key areas to test**:
1. Authentication & Authorization
2. Input validation (injection)
3. Rate limiting
4. Data exposure
5. Business logic flaws

**Tools**: Sentinel automates these tests using AI-guided attack strategies."""
        }
        
        return explanations.get(topic, f"Detailed explanation for {topic}")
    
    def _handle_suggest_request(self, message: str) -> ChatResponse:
        """Handle a request for test suggestions."""
        
        suggestions = []
        
        if self.endpoints:
            # Analyze endpoints for suggestions
            auth_endpoints = [e for e in self.endpoints if e.requires_auth]
            if auth_endpoints:
                suggestions.append("🔑 **Auth Tests**: Test authentication bypass on protected endpoints")
            
            param_endpoints = [e for e in self.endpoints if e.parameters]
            if param_endpoints:
                suggestions.append("💉 **Injection Tests**: SQL/XSS testing on endpoints with parameters")
            
            id_endpoints = [e for e in self.endpoints if any('id' in p.name.lower() for p in e.parameters)]
            if id_endpoints:
                suggestions.append("🎯 **IDOR Tests**: Test ID manipulation on endpoints with ID parameters")
            
            suggestions.append("⚡ **Rate Limit**: Test for rate limiting on all endpoints")
        else:
            suggestions = [
                "Load an OpenAPI spec to get endpoint-specific suggestions",
                "Run a quick scan to identify high-risk areas",
                "Focus on authentication endpoints first"
            ]
        
        return ChatResponse(
            message=f"💡 **Suggested Security Tests**\n\n" + "\n".join(suggestions),
            intent=ChatIntent.SUGGEST_TEST,
            follow_up_suggestions=[
                "Run these tests now",
                "Tell me more about auth testing",
                "Prioritize by severity"
            ]
        )
    
    def _handle_help_request(self) -> ChatResponse:
        """Handle a help request."""
        
        help_text = """
# 🛡️ Sentinel - AI-Powered API Security Testing

I'm your AI security assistant. Here's what I can do:

## Commands

| Command | Description |
|---------|-------------|
| `Scan <url>` | Run a security scan on an API |
| `Analyze <endpoint>` | Get security analysis of an endpoint |
| `Explain <vuln>` | Learn about a vulnerability type |
| `Suggest tests` | Get test recommendations |
| `Status` | Check scan progress |
| `Report` | Generate a security report |

## Examples

```
Scan https://api.example.com
Scan api.yaml with bearer token mytoken123
Analyze POST /api/users
Explain SQL injection
Suggest tests for my API
```

## Tips

1. **Start with a quick scan** to identify obvious issues
2. **Focus on auth endpoints** - they're often vulnerable
3. **Review all findings** - even low severity can indicate larger issues
4. **Run full scans** before production deployments
"""
        
        return ChatResponse(
            message=help_text,
            intent=ChatIntent.HELP,
            follow_up_suggestions=[
                "Scan my API",
                "What attack types are available?",
                "How does AI-powered testing work?"
            ]
        )
    
    def _handle_status_request(self) -> ChatResponse:
        """Handle a status request."""
        
        status = {
            'endpoints_loaded': len(self.endpoints),
            'last_scan': self.last_scan_result is not None,
            'context': bool(self.context)
        }
        
        if self.last_scan_result:
            status['findings'] = len(self.last_scan_result.findings)
            status['attack_chains'] = len(self.last_scan_result.attack_chains)
            status['status'] = self.last_scan_result.state.value
        
        status_msg = "📊 **Current Status**\n\n"
        status_msg += f"- **Endpoints loaded**: {status['endpoints_loaded']}\n"
        status_msg += f"- **Scan completed**: {'Yes' if status['last_scan'] else 'No'}\n"
        
        if self.last_scan_result:
            status_msg += f"- **Findings**: {status['findings']}\n"
            status_msg += f"- **Attack chains**: {status['attack_chains']}\n"
            status_msg += f"- **State**: {status['status']}\n"
        
        return ChatResponse(
            message=status_msg,
            intent=ChatIntent.STATUS,
            data=status
        )
    
    def _handle_report_request(self, message: str) -> ChatResponse:
        """Handle a report request."""
        
        if not self.last_scan_result:
            return ChatResponse(
                message="No scan results available. Run a scan first:\n\n"
                       "```\n"
                       "sentinel scan https://api.example.com\n"
                       "```",
                intent=ChatIntent.REPORT,
                follow_up_suggestions=[
                    "Run a scan first",
                    "Load previous scan results"
                ]
            )
        
        # Generate summary
        summary = self.last_scan_result.summary
        report = "📋 **Security Scan Report**\n\n"
        report += f"**Summary:**\n"
        report += f"- Critical: {summary.get('critical', 0)}\n"
        report += f"- High: {summary.get('high', 0)}\n"
        report += f"- Medium: {summary.get('medium', 0)}\n"
        report += f"- Low: {summary.get('low', 0)}\n\n"
        
        if self.last_scan_result.attack_chains:
            report += "**Attack Chains Discovered:**\n"
            for chain in self.last_scan_result.attack_chains:
                report += f"- {chain.name} ({chain.severity.value})\n"
        
        return ChatResponse(
            message=report,
            intent=ChatIntent.REPORT,
            action_taken=True,
            data={'summary': summary}
        )
    
    def _handle_unknown(self, message: str) -> ChatResponse:
        """Handle unknown/unrecognized messages."""
        
        return ChatResponse(
            message="I'm not sure what you're asking. Try:\n\n"
                   "- `Scan https://api.example.com` - Scan an API\n"
                   "- `Explain SQL injection` - Learn about vulnerabilities\n"
                   "- `Suggest tests` - Get recommendations\n"
                   "- `Help` - See all commands",
            intent=ChatIntent.UNKNOWN,
            follow_up_suggestions=[
                "Help me get started",
                "Scan my API",
                "What can you do?"
            ]
        )
    
    def load_endpoints(self, endpoints: list[Endpoint]):
        """Load endpoints into context."""
        self.endpoints = endpoints
        self.context['endpoints_loaded'] = True
    
    def set_scan_result(self, result: AutonomousScanResult):
        """Set the last scan result."""
        self.last_scan_result = result


def create_chat_interface(
    ai_provider: LLMProvider = LLMProvider.GEMINI,
    api_key: Optional[str] = None
) -> SentinelChat:
    """Create a chat interface instance."""
    return SentinelChat(ai_provider=ai_provider, api_key=api_key)


def run_interactive_session(
    ai_provider: LLMProvider = LLMProvider.GEMINI,
    api_key: Optional[str] = None
):
    """
    Run an interactive chat session.
    
    Usage:
        from sentinel.chat import run_interactive_session
        run_interactive_session()
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    
    console = Console()
    chat = create_chat_interface(ai_provider, api_key)
    
    console.print(Panel.fit(
        "[bold green]Sentinel Chat[/bold green] - AI-Powered API Security Testing\n"
        "Type 'exit' to quit, 'help' for commands",
        title="🛡️ Sentinel"
    ))
    
    while True:
        try:
            user_input = console.input("\n[bold blue]You:[/bold blue] ")
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                console.print("[yellow]Goodbye! Stay secure! 👋[/yellow]")
                break
            
            response = chat.chat(user_input)
            
            console.print(f"\n[bold green]Sentinel:[/bold green]")
            console.print(Markdown(response.message))
            
            if response.follow_up_suggestions:
                console.print("\n[dim]Suggestions:[/dim]")
                for suggestion in response.follow_up_suggestions[:3]:
                    console.print(f"  • {suggestion}")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Goodbye! Stay secure! 👋[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
