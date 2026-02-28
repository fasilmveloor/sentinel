# Sentinel Roadmap

> **Current Version: v2.0.0** | This document tracks planned features and their implementation status.

## Version History

| Version | Status | Description |
|---------|--------|-------------|
| v1.0 | ✅ Released | Core attacks (SQLi, Auth Bypass, IDOR), Gemini AI, Markdown reports |
| v2.0 | ✅ Released | 8 attack types, Multi-LLM, HTML/JSON/SARIF/JUnit reports |
| v2.5 | 🔜 Planned | Additional attacks, GraphQL support |
| v3.0 | 📋 Future | Multi-agent architecture, Plugin system |
| v4.0 | 📋 Future | Proxy mode, Web dashboard |

---

## ✅ v1.0 - MVP (Completed)

**Release Date:** Initial Release

### Core Infrastructure
- [x] CLI Interface with Click + Rich UI
- [x] OpenAPI/Swagger Parser (YAML/JSON)
- [x] Pydantic Data Models
- [x] Environment Configuration
- [x] Error Handling & Retry Logic

### Attack Modules
- [x] SQL Injection (error-based, time-based, union-based)
- [x] NoSQL Injection (MongoDB patterns)
- [x] Authentication Bypass
- [x] IDOR (Insecure Direct Object Reference)

### AI & Intelligence
- [x] Gemini AI Integration
- [x] Rule-based Fallback Logic
- [x] Endpoint Risk Analysis

### Output & Reporting
- [x] Markdown Reports
- [x] CLI Summary Tables
- [x] CI/CD Exit Codes

### Testing
- [x] Vulnerable Test API Server
- [x] Sample OpenAPI Specification
- [x] Sample Report Examples

---

## ✅ v2.0 - Attack Expansion (Completed)

**Release Date:** Current Version

### New Attack Types
- [x] XSS (Cross-Site Scripting)
- [x] SSRF (Server-Side Request Forgery)
- [x] JWT Vulnerability Testing
- [x] Command Injection
- [x] Rate Limit Detection

### Multi-LLM Support
- [x] OpenAI GPT Integration
- [x] Anthropic Claude Integration
- [x] Local LLM Support (Ollama)
- [x] Abstract BaseLLMProvider Architecture
- [x] Provider Fallback Chain

### Report Formats
- [x] HTML Reports with Styling
- [x] JSON Reports (machine-readable)
- [x] SARIF Reports (GitHub Code Scanning)
- [x] JUnit XML Reports (CI/CD integration)

### Infrastructure
- [x] Docker Support (Dockerfile)
- [x] Docker Compose Configuration
- [x] Exponential Backoff Retry

---

## 🔜 v2.5 - Advanced Detection (Next)

**Target:** Q2 2026

### Additional Attack Types
- [ ] XXE (XML External Entity)
- [ ] Path Traversal
- [ ] LDAP Injection
- [ ] Template Injection (SSTI)
- [ ] HTTP Request Smuggling

### GraphQL Security
- [ ] GraphQL Introspection Analysis
- [ ] GraphQL Injection Testing
- [ ] Depth Limit Detection
- [ ] Field Suggestion Exposure

### WebSocket Security
- [ ] WebSocket Authentication Testing
- [ ] Cross-Site WebSocket Hijacking
- [ ] WebSocket Injection Testing

### Enhanced Detection
- [ ] Blind Vulnerability Detection
- [ ] Time-based Detection Improvements
- [ ] Out-of-Band (OOB) Detection
- [ ] Differential Response Analysis

---

## 📋 v3.0 - Multi-Agent Architecture (Future)

**Target:** Q3-Q4 2026

> **Note:** This is the most requested feature but requires significant architectural changes.

### Multi-Agent System
- [ ] Planner Agent - Analyzes target and creates attack plan
- [ ] Executor Agent - Runs attacks with specialized skills
- [ ] Analyzer Agent - Interprets results and suggests follow-ups
- [ ] Agent Communication Protocol
- [ ] Feedback Loop Between Agents

### Attack Chain Discovery
- [ ] Sequential Attack Execution
- [ ] Result-Driven Attack Selection
- [ ] Vulnerability Correlation
- [ ] Chain Visualization

### Plugin System
- [ ] Plugin Architecture Design
- [ ] Custom Attack Module API
- [ ] Plugin Discovery & Loading
- [ ] Plugin Configuration
- [ ] Community Plugin Repository

### Business Logic Analysis
- [ ] Workflow Analysis
- [ ] State Machine Detection
- [ ] Privilege Escalation Chains
- [ ] Data Flow Analysis

---

## 📋 v4.0 - Proxy & Dashboard (Future)

**Target:** 2027

### Proxy Mode
- [ ] HTTP/HTTPS Proxy Server
- [ ] Traffic Interception
- [ ] Request/Response Logging
- [ ] Passive Vulnerability Scanning
- [ ] Traffic Replay

### Web Dashboard
- [ ] React/Vue Frontend
- [ ] Real-time Scan Progress
- [ ] Historical Scan Comparison
- [ ] Vulnerability Management
- [ ] Team Collaboration

### CI/CD Deep Integration
- [ ] GitHub Actions Action
- [ ] GitLab CI Templates
- [ ] Jenkins Plugin
- [ ] PR Comment Integration
- [ ] Baseline Comparison

---

## 📋 v5.0 - Enterprise (Future)

**Target:** TBD

### Distribution
- [ ] PyPI Package Publication
- [ ] Homebrew Formula
- [ ] Binary Releases (PyInstaller)
- [ ] Helm Charts (Kubernetes)

### Enterprise Features
- [ ] User Management
- [ ] Role-Based Access Control
- [ ] Audit Logging
- [ ] SSO Integration (SAML/OIDC)
- [ ] Database Backend (PostgreSQL)

### Integrations
- [ ] Jira Integration
- [ ] Slack/Teams Notifications
- [ ] DefectDojo Import
- [ ] Burp Suite Export

---

## Architecture Decisions

### Why Single-LLM Planning Agent (v2.0)?

The current architecture uses a single LLM call to analyze each endpoint and decide which attacks to run. This approach was chosen because:

1. **Simplicity** - Easy to understand and debug
2. **Cost** - Single API call per endpoint vs. multiple agent interactions
3. **Speed** - No latency from agent-to-agent communication
4. **Reliability** - Fewer failure points

### Why Plan Multi-Agent (v3.0+)?

Multi-agent architecture is planned for v3.0 because:

1. **Specialization** - Different agents can excel at different tasks
2. **Parallelism** - Multiple agents can work simultaneously
3. **Learning** - Agents can learn from each other's results
4. **Complexity** - Required for attack chain discovery

---

## Contributing

Want to help implement these features? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas for contribution:
1. **v2.5 Attack Types** - XXE, Path Traversal, Template Injection
2. **GraphQL Support** - Parser and attack modules
3. **Documentation** - API reference, tutorials
4. **Testing** - Unit tests, integration tests

---

*Last Updated: 2026*
*Version: 2.0.0*
