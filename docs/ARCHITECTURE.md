# Sentinel Architecture

> This document describes the actual architecture of Sentinel v2.0.0.

## Overview

Sentinel is a **single-LLM planning agent** that analyzes API endpoints and executes security tests. It follows a straightforward pipeline architecture:

```
OpenAPI Spec → Parser → AI Agent → Attack Modules → Reporter
```

## Core Components

### 1. CLI Layer (`main.py`)

The entry point using Click for command-line interface and Rich for terminal UI.

```python
@click.group()
def cli():
    """Sentinel - AI-powered API Security Testing Tool."""

@cli.command()
def scan(...):
    # Main scan workflow
    # 1. Parse Swagger
    # 2. Initialize AI Agent
    # 3. Initialize Attackers
    # 4. Run Attacks
    # 5. Generate Report
```

**Commands:**
- `scan` - Run security scan
- `inspect` - View OpenAPI spec details
- `list-attacks` - Show available attack types
- `version` - Display version info

### 2. OpenAPI Parser (`parser.py`)

Parses OpenAPI/Swagger specifications into Pydantic models.

```python
class SwaggerParser:
    def __init__(self, spec_path: str):
        self.spec_path = spec_path

    def parse(self) -> list[Endpoint]:
        # Parse YAML/JSON
        # Extract endpoints, parameters, security schemes
        # Return list of Endpoint objects
```

**Supported Formats:**
- OpenAPI 3.0.x (YAML/JSON)
- Swagger 2.0 (YAML/JSON)

### 3. AI Agent (`agent.py`)

The core decision-making component. **This is NOT a multi-agent system** - it's a single LLM call per endpoint.

```python
class SentinelAgent:
    def __init__(self, provider: LLMProvider, api_key: str):
        # Initialize LLM providers
        # Set up fallback chain

    def analyze_endpoint(self, endpoint: Endpoint) -> AIAttackDecision:
        # 1. Build prompt with endpoint details
        # 2. Call LLM API
        # 3. Parse JSON response
        # 4. Return attack recommendations
```

**LLM Provider Architecture:**

```python
class BaseLLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

class GeminiProvider(BaseLLMProvider): ...
class OpenAIProvider(BaseLLMProvider): ...
class ClaudeProvider(BaseLLMProvider): ...
class LocalLLMProvider(BaseLLMProvider): ...  # Ollama
```

**Fallback Mechanism:**
1. Try preferred provider
2. Fall back to other available providers
3. If all AI fails, use rule-based decision

**Rule-based Fallback:**
```python
def _fallback_decision(self, endpoint: Endpoint) -> AIAttackDecision:
    # If endpoint has parameters → SQL Injection, XSS
    # If endpoint requires auth → Auth Bypass, JWT
    # If path contains {id} → IDOR
    # If parameter name contains 'url' → SSRF
    # Always → Rate Limit
```

### 4. Attack Modules (`attacks/`)

Each attack type is a separate module with a consistent interface.

```python
class BaseAttacker(ABC):
    def __init__(self, target_url: str, timeout: int):
        self.target_url = target_url
        self.timeout = timeout

    @abstractmethod
    def attack(self, endpoint: Endpoint, params: list[str]) -> list[AttackResult]: ...

    @abstractmethod
    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability: ...
```

**Implemented Attackers:**

| Module | Class | Attack Type |
|--------|-------|-------------|
| `injection.py` | `SQLInjectionAttacker` | SQL/NoSQL Injection |
| `xss.py` | `XSSAttacker` | Cross-Site Scripting |
| `ssrf.py` | `SSRFAttacker` | Server-Side Request Forgery |
| `jwt.py` | `JWTAttacker` | JWT Vulnerabilities |
| `cmd_injection.py` | `CommandInjectionAttacker` | OS Command Injection |
| `auth.py` | `AuthBypassAttacker` | Authentication Bypass |
| `idor.py` | `IDORAttacker` | Insecure Direct Object Reference |
| `rate_limit.py` | `RateLimitAttacker` | Rate Limit Detection |

### 5. Reporters (`reporter.py`, `html_reporter.py`, `json_reporter.py`)

Generate output in multiple formats.

```python
class Reporter:
    def save(self, result: ScanResult) -> str:
        # Generate Markdown report

class HTMLReporter:
    def save(self, result: ScanResult) -> str:
        # Generate styled HTML report

class JSONReporter:
    def save(self, result: ScanResult) -> str:
        # Generate JSON report

class SARIFReporter:
    def save(self, result: ScanResult) -> str:
        # Generate SARIF for GitHub Code Scanning

class JUnitReporter:
    def save(self, result: ScanResult) -> str:
        # Generate JUnit XML for CI/CD
```

## Data Models (`models.py`)

All data structures are defined using Pydantic for type safety and validation.

### Core Models

```python
class Endpoint(BaseModel):
    path: str
    method: HttpMethod
    parameters: list[Parameter]
    security: Optional[list[dict]]
    # ...

class AttackResult(BaseModel):
    endpoint: Endpoint
    attack_type: AttackType
    success: bool
    payload: Optional[str]
    response_status: Optional[int]
    # ...

class Vulnerability(BaseModel):
    endpoint: Endpoint
    attack_type: AttackType
    severity: Severity
    title: str
    description: str
    proof_of_concept: str
    recommendation: str
    # ...

class ScanResult(BaseModel):
    config: ScanConfig
    endpoints_tested: list[Endpoint]
    vulnerabilities: list[Vulnerability]
    attack_results: list[AttackResult]
    # ...
```

## Scan Workflow

```
┌──────────────────────────────────────────────────────────────┐
│ 1. PARSE                                                     │
│     Read OpenAPI spec → Extract endpoints → Validate         │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. ANALYZE (per endpoint)                                    │
│     Build prompt → Call LLM → Parse decision                 │
│     OR fallback to rule-based decision                       │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. ATTACK (per endpoint, per recommended attack)             │
│     Generate payloads → Send requests → Check responses      │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. REPORT                                                    │
│     Aggregate results → Generate report → Save to file       │
└──────────────────────────────────────────────────────────────┘
```

## What This Architecture Does NOT Have

To be completely transparent about the current limitations:

### ❌ Multi-Agent System

The current architecture is a **single-LLM, plan-then-execute** pattern:

```
Endpoint → LLM Decision → Execute Attacks → Results
         ↑                              ↓
         └──── No feedback loop ────────┘
```

A true multi-agent system would look like:

```
                    ┌─────────────┐
                    │   Planner   │
                    │    Agent    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ Executor │ │ Executor │ │ Executor │
        │ Agent 1  │ │ Agent 2  │ │ Agent 3  │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
              │            │            │
              └────────────┼────────────┘
                           ▼
                    ┌─────────────┐
                    │  Analyzer   │
                    │    Agent    │
                    └──────┬──────┘
                           │
                    (feedback to Planner)
```

This is **planned for v3.0** but not yet implemented.

### ❌ Attack Chain Discovery

Attack chain discovery would require:
1. Running an initial attack
2. Analyzing the result
3. Deciding on follow-up attacks based on findings
4. Repeating until no more attacks are viable

Currently, all attacks are decided upfront with no iteration.

### ❌ Proxy Mode

A proxy mode would intercept traffic between client and server:

```
Client ←→ Sentinel Proxy ←→ Target Server
              │
              ▼
         Log & Analyze
```

This would enable:
- Passive vulnerability scanning
- Traffic analysis
- Request modification

This is **planned for v4.0**.

### ❌ Plugin System

A plugin system would allow custom attack modules:

```python
# Hypothetical plugin API (not implemented)
class CustomAttackPlugin(BasePlugin):
    name = "custom_attack"
    description = "My custom attack"

    def should_run(self, endpoint: Endpoint) -> bool:
        return True

    def execute(self, endpoint: Endpoint) -> list[AttackResult]:
        # Custom logic
        pass
```

This is **planned for v3.0**.

## Design Decisions

### Why Python?

- Rich security testing ecosystem (requests, beautifulsoup4, etc.)
- Strong AI/ML library support (google-generativeai, openai, anthropic)
- Quick prototyping and iteration
- Easy to extend and customize

### Why Pydantic?

- Type safety with runtime validation
- Automatic JSON serialization
- Clear data contracts
- IDE support and autocompletion

### Why Click + Rich?

- Click: Industry-standard CLI framework
- Rich: Beautiful terminal output without external dependencies
- Both are well-maintained and widely used

### Why Single-LLM Agent?

For v2.0, simplicity was prioritized over sophistication:

| Aspect | Single-LLM | Multi-Agent |
|--------|------------|-------------|
| Complexity | Low | High |
| Cost per endpoint | 1 API call | 3-10 API calls |
| Latency | Low | High |
| Debugging | Easy | Difficult |
| Capability | Good | Better |

Multi-agent is planned for v3.0 when the foundation is more mature.

## Extension Points

### Adding a New LLM Provider

```python
class MyCustomProvider(BaseLLMProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str, system_prompt: str) -> str:
        # Call your LLM API
        return response_text
```

### Adding a New Attack Type

```python
class MyCustomAttacker(BaseAttacker):
    def attack(self, endpoint: Endpoint, params: list[str]) -> list[AttackResult]:
        results = []
        for payload in self.payloads:
            # Send request with payload
            # Check for vulnerability indicators
            results.append(AttackResult(...))
        return results

    def create_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        return Vulnerability(
            title="Custom Vulnerability",
            description="...",
            # ...
        )
```

### Adding a New Report Format

```python
class MyCustomReporter:
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)

    def save(self, result: ScanResult) -> str:
        # Generate custom format
        content = self.generate(result)
        self.output_path.write_text(content)
        return str(self.output_path)
```

## Performance Considerations

### Current Limitations

1. **Sequential Execution**: Attacks run one after another, not in parallel
2. **No Caching**: Each endpoint is analyzed independently
3. **Rate Limiting**: Built-in delays between requests

### Optimization Opportunities

1. **Async HTTP**: Use `aiohttp` instead of `requests`
2. **Parallel Attacks**: Use `asyncio.gather()` for concurrent attacks
3. **Result Caching**: Cache AI decisions for similar endpoints

## Security Considerations

### Responsible Disclosure

- Only test APIs you own or have permission to test
- The included test server has intentional vulnerabilities for learning
- Do not use against production systems without authorization

### Data Handling

- API keys are read from environment variables
- No credentials are stored in configuration files
- Reports may contain sensitive data - handle appropriately

---

*This document accurately reflects the v2.0.0 codebase. Features described as "planned" are not yet implemented.*
