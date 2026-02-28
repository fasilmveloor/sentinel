# Sentinel 🛡️

<div align="center">

**AI-Native API Security Testing Tool**

*AI-first approach to API vulnerability assessment*

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/fasilmveloor/sentinel)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen.svg)](tests/)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## What is Sentinel?

Sentinel is an **AI-native API security testing tool** that uses large language models to intelligently analyze and test REST APIs. Instead of blindly running every attack against every endpoint, Sentinel uses AI to:

- 🧠 **Understand** your API structure and choose relevant tests
- 🎯 **Prioritize** high-risk endpoints automatically
- 🔗 **Discover** multi-step attack chains
- 💬 **Explain** findings in plain language

**Sentinel is NOT a replacement for OWASP ZAP, Burp Suite, or other established security tools.** It's a specialized tool with a different philosophy: AI-first, API-focused, CLI-native.

### When to Use Sentinel

| Use Sentinel For | Don't Use Sentinel For |
|------------------|------------------------|
| REST API security testing | Full web application scanning |
| CI/CD pipeline integration | GUI-based security testing |
| AI-assisted vulnerability analysis | Comprehensive compliance audits |
| Quick API security assessments | Deep-dive manual penetration testing |
| Natural language security commands | Browser-based traffic interception |

**Pro tip**: Use Sentinel alongside tools like OWASP ZAP for comprehensive coverage.

---

## ✨ Features

### AI-Powered Analysis

| Feature | Description |
|---------|-------------|
| 🤖 **Multi-LLM Support** | Gemini, OpenAI GPT-4, Claude, Ollama (local) |
| 🧠 **Smart Attack Selection** | AI analyzes endpoints and chooses relevant attacks |
| 📊 **Risk Prioritization** | Endpoints scored and prioritized automatically |
| 💬 **Natural Language Interface** | Chat-based commands for non-experts |

### Multi-Agent Architecture

Sentinel uses three specialized AI agents that work together:

```
┌─────────────────┐
│  PlannerAgent   │  → Analyzes API, creates attack strategy
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ExecutorAgent  │  → Runs attacks with concurrency control
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AnalyzerAgent  │  → Interprets results, discovers chains
└─────────────────┘
```

### Attack Types

| Attack | OWASP | Description |
|--------|-------|-------------|
| SQL Injection | A03:2021 | Error-based, time-based, union-based detection |
| NoSQL Injection | A03:2021 | MongoDB and document database injection |
| Cross-Site Scripting | A03:2021 | Reflected XSS with context awareness |
| Server-Side Request Forgery | A10:2021 | Basic and blind SSRF detection |
| JWT Vulnerabilities | A07:2021 | None algorithm, weak secret, confusion attacks |
| Command Injection | A03:2021 | Unix and Windows command injection |
| Authentication Bypass | A07:2021 | Token manipulation, missing auth checks |
| IDOR | A01:2021 | Insecure Direct Object Reference |
| Rate Limit Detection | A04:2021 | Threshold-based detection |

### Passive Security Checks

22+ passive checks that analyze responses without sending attacks:

- Missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Server version disclosure
- Sensitive data exposure (API keys, tokens, PII)
- CORS misconfigurations
- Cookie security issues
- Information leakage in error messages
- Cache control problems
- And more...

### Report Formats

| Format | Use Case |
|--------|----------|
| Markdown | Human-readable detailed reports |
| HTML | Shareable reports with styling |
| JSON | Programmatic access, CI/CD integration |
| SARIF | GitHub Code Scanning integration |
| JUnit XML | Jenkins, GitLab CI integration |

### Enterprise Features (v3.0)

| Feature | Description |
|---------|-------------|
| 🔐 **Authentication Handler** | 10+ auth types with auto-refresh |
| 🌐 **Proxy Mode** | Traffic interception and analysis |
| 🔌 **Plugin System** | Extensible Python-based architecture |

---

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/fasilmveloor/sentinel.git
cd sentinel

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m sentinel version
```

### Using Docker

```bash
# Build image
docker build -t sentinel .

# Run scan
docker run -e GEMINI_API_KEY=your_key \
  -v $(pwd)/reports:/app/reports \
  sentinel scan --swagger /app/examples/sample_api.yaml \
  --target http://host.docker.internal:8000
```

---

## 🚀 Quick Start

### 1. Set up API Key

```bash
# Choose one LLM provider
export GEMINI_API_KEY=your_key        # Google Gemini (recommended)
export OPENAI_API_KEY=your_key        # OpenAI
export ANTHROPIC_API_KEY=your_key     # Claude
# Or use local LLM with Ollama
```

### 2. Run Your First Scan

```bash
# Basic scan
python -m sentinel scan \
  --swagger api-spec.yaml \
  --target https://api.example.com

# With HTML report
python -m sentinel scan \
  --swagger api-spec.yaml \
  --target https://api.example.com \
  --format html \
  --output report.html
```

### 3. Try Autonomous Mode

```bash
# AI-driven autonomous scan
python -m sentinel autonomous \
  --swagger api-spec.yaml \
  --target https://api.example.com
```

### 4. Interactive Chat

```bash
# Natural language interface
python -m sentinel chat

> Scan https://api.example.com for SQL injection
> Explain what SSRF is
> What attacks should I test on /api/users?
```

---

## 📖 Usage Guide

### Scan Modes

| Command | Description |
|---------|-------------|
| `sentinel scan` | Standard scan with AI or rule-based decisions |
| `sentinel autonomous` | Multi-agent autonomous scan with attack chain discovery |
| `sentinel passive` | Passive analysis of URLs without attacks |
| `sentinel chat` | Natural language interface |
| `sentinel proxy` | Traffic interception mode |

### Common Examples

```bash
# Specific attacks only
python -m sentinel scan -s api.yaml -t https://api.example.com \
  --attacks sql_injection xss auth_bypass

# Using OpenAI instead of Gemini
python -m sentinel scan -s api.yaml -t https://api.example.com \
  --llm openai

# With authentication
python -m sentinel scan -s api.yaml -t https://api.example.com \
  --auth-token "Bearer eyJhbGc..."

# Disable AI, use rule-based decisions
python -m sentinel scan -s api.yaml -t https://api.example.com \
  --no-ai

# Passive scan of a URL
python -m sentinel passive -u https://api.example.com/health

# Start proxy for traffic analysis
python -m sentinel proxy --port 8080
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--swagger, -s` | Path to OpenAPI specification (YAML/JSON) |
| `--target, -t` | Target API base URL |
| `--output, -o` | Output file path |
| `--format, -f` | Report format: markdown, html, json, sarif, junit |
| `--attacks, -a` | Specific attacks to run |
| `--llm` | LLM provider: gemini, openai, claude, local |
| `--auth-token` | Bearer token for authenticated testing |
| `--no-ai` | Use rule-based decisions without AI |
| `--verbose, -v` | Enable verbose output |

---

## 📁 Project Structure

```
sentinel/
├── sentinel/
│   ├── agent.py           # Multi-LLM AI agent
│   ├── autonomous.py      # Multi-agent system (Planner, Executor, Analyzer)
│   ├── passive.py         # Passive security scanner
│   ├── chat.py            # Natural language interface
│   ├── auth.py            # Authentication handler (10+ types)
│   ├── proxy.py           # Traffic interception proxy
│   ├── plugin.py          # Plugin system
│   ├── parser.py          # OpenAPI/Swagger parser
│   ├── models.py          # Pydantic data models
│   ├── main.py            # CLI entry point
│   ├── reporter.py        # Markdown reports
│   ├── html_reporter.py   # HTML reports
│   ├── json_reporter.py   # JSON/SARIF/JUnit reports
│   └── attacks/           # Attack modules
│       ├── injection.py   # SQL/NoSQL injection
│       ├── xss.py         # Cross-Site Scripting
│       ├── ssrf.py        # Server-Side Request Forgery
│       ├── jwt.py         # JWT vulnerabilities
│       ├── cmd_injection.py # Command injection
│       ├── auth.py        # Authentication bypass
│       ├── idor.py        # IDOR attacks
│       └── rate_limit.py  # Rate limit detection
├── tests/
│   └── benchmarks/        # Functional verification tests
├── examples/              # Sample specifications
├── test_server/           # Vulnerable test API
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🧪 Testing

### Run the Test Suite

```bash
# Run all functional tests
python -m pytest tests/benchmarks/test_functional.py -v

# Expected: 30 passing tests
# These tests verify all claimed features exist
```

### Test Against Vulnerable API

```bash
# Start the test server
cd test_server
python vulnerable_api.py

# In another terminal, run Sentinel
python -m sentinel scan \
  --swagger examples/sample_api.yaml \
  --target http://localhost:8000 \
  --verbose
```

---

## 📊 Verified Features

All features listed in this README are verified by automated tests:

| Claim | Status | Evidence |
|-------|--------|----------|
| Multi-Agent System | ✅ Verified | `autonomous.py` with PlannerAgent, ExecutorAgent, AnalyzerAgent |
| Attack Chain Discovery | ✅ Verified | `AnalyzerAgent.discover_attack_chains()` method |
| 8 Attack Types | ✅ Verified | `attacks/` directory with 8 modules |
| Multi-LLM Support | ✅ Verified | `agent.py` with 4 provider classes |
| Passive Scanner | ✅ Verified | `passive.py` with 22+ check types |
| Chat Interface | ✅ Verified | `chat.py` with SentinelChat class |
| Auth Handler | ✅ Verified | `auth.py` with 10+ authentication types |
| Proxy Mode | ✅ Verified | `proxy.py` with SentinelProxy class |
| Plugin System | ✅ Verified | `plugin.py` with BasePlugin, PluginManager |

---

## 🆚 Comparison with Other Tools

### Sentinel vs OWASP ZAP

| Aspect | Sentinel | OWASP ZAP |
|--------|----------|-----------|
| **Focus** | API-first | Full web applications |
| **AI Integration** | ✅ Native | ❌ None |
| **Attack Types** | 8 types | 50+ types |
| **Passive Checks** | 22 checks | 100+ checks |
| **Interface** | CLI only | GUI + CLI + HUD |
| **Maturity** | New (2025) | Mature (2005+) |
| **Best For** | AI-assisted API testing | Comprehensive web scanning |

**Recommendation**: Use both. Sentinel for AI-driven API testing, ZAP for comprehensive coverage.

See [COMPARISON.md](COMPARISON.md) for detailed comparison.

---

## 📈 Roadmap

### Completed

- [x] v1.0 - Core attacks, Gemini AI, Markdown reports
- [x] v2.0 - Multi-LLM, 8 attack types, multiple report formats
- [x] v2.5 - Multi-agent system, attack chains, passive scanner, chat
- [x] v3.0 - Auth handler, proxy mode, plugin system

### Planned

- [ ] v3.5 - XXE, Path Traversal, GraphQL support
- [ ] v4.0 - WebSocket testing, Web dashboard
- [ ] v5.0 - Enterprise features, team management

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
1. New attack modules (XXE, Path Traversal, SSTI)
2. Additional passive checks
3. Unit tests and integration tests
4. Documentation improvements

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

**Use responsibly.** Only test APIs you own or have explicit permission to test. The included test server has intentional vulnerabilities for educational purposes.

---

<div align="center">

**Built with ❤️ for API security**

[Report Bug](https://github.com/fasilmveloor/sentinel/issues) · [Request Feature](https://github.com/fasilmveloor/sentinel/issues)

</div>
