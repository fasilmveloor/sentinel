# Sentinel 🛡️

**AI-powered API security testing tool**

Sentinel reads your OpenAPI/Swagger specification, uses AI to determine the optimal attack strategy, and automatically tests your API endpoints for security vulnerabilities.

## ✨ Features

- 🤖 **AI-Driven Attack Strategy** - Gemini AI analyzes your API and decides which attacks to run
- 📋 **OpenAPI/Swagger Parsing** - Automatically understands your API structure
- 🎯 **SQL Injection Testing** - Detects SQL and NoSQL injection vulnerabilities
- 🔐 **Auth Bypass Detection** - Finds endpoints with missing or weak authentication
- 🔍 **IDOR Testing** - Identifies Insecure Direct Object Reference vulnerabilities
- 📊 **Markdown Reports** - Clear, actionable reports with proof-of-concept exploits

## 🚀 Quick Start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/sentinel.git
cd sentinel
pip install -r requirements.txt

# 2. Set your Gemini API key
cp .env.example .env
# Edit .env and add your API key from https://makersuite.google.com/app/apikey

# 3. Run a scan
python -m sentinel scan --swagger examples/sample_api.yaml --target http://localhost:8000
```

## 📖 Usage

```bash
# Basic scan
python -m sentinel scan --swagger api.yaml --target http://localhost:3000

# With custom output
python -m sentinel scan --swagger api.yaml --target http://localhost:3000 --output report.md

# Verbose mode
python -m sentinel scan --swagger api.yaml --target http://localhost:3000 --verbose
```

## 🎯 Attack Types (MVP)

| Attack Type | Description |
|-------------|-------------|
| **SQL Injection** | Tests for SQL and NoSQL injection in query params and body |
| **Auth Bypass** | Tests protected endpoints without/with invalid tokens |
| **IDOR** | Tests for insecure direct object references by manipulating IDs |

## 📁 Project Structure

```
sentinel/
├── sentinel/
│   ├── __init__.py
│   ├── main.py          # CLI entry point
│   ├── models.py        # Data structures
│   ├── parser.py        # OpenAPI/Swagger parser
│   ├── agent.py         # AI agent (Gemini)
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── injection.py # SQL injection attacks
│   │   ├── auth.py      # Auth bypass attacks
│   │   └── idor.py      # IDOR attacks
│   └── reporter.py      # Markdown report generator
├── patterns/
│   └── injection.yaml   # Attack payload patterns
├── examples/
│   └── sample_api.yaml  # Example OpenAPI spec
└── test_server/
    └── vulnerable_api.py # Vulnerable FastAPI for testing
```

## 🧪 Testing

```bash
# Start the vulnerable test API
cd test_server
python vulnerable_api.py

# In another terminal, run Sentinel
python -m sentinel scan --swagger examples/sample_api.yaml --target http://localhost:8000
```

## 📊 Sample Output

```markdown
# Sentinel Security Report

## Summary
- **Total Endpoints Tested:** 5
- **Vulnerabilities Found:** 3
- **Scan Duration:** 45 seconds

## Vulnerabilities

### 1. SQL Injection in /api/users
- **Severity:** HIGH
- **Endpoint:** GET /api/users?id=1
- **Payload:** `1' OR '1'='1`
- **Proof of Concept:** ...
```

## 🔮 Roadmap

- [ ] XSS testing
- [ ] SSRF testing
- [ ] OpenAI/Anthropic support
- [ ] Async attack execution
- [ ] CI/CD integration
- [ ] HTML reports

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines first.

## 📄 License

MIT License - see LICENSE file for details.

---

Built with ❤️ by security engineers who believe in automated testing for everyone.
