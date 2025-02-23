# Sentinel Configuration

This file contains configuration options for Sentinel security scanner.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | Yes* | Google Gemini API key for AI analysis |
| `HTTP_PROXY` | No | HTTP proxy URL |
| `HTTPS_PROXY` | No | HTTPS proxy URL |

*Required for AI-powered analysis. Can run without AI using `--no-ai` flag.

## Configuration File (Optional)

Create a `.sentinel.yaml` file in your project root:

```yaml
# Sentinel Configuration
api:
  timeout: 5
  rate_limit: 0.5  # seconds between requests

ai:
  enabled: true
  model: gemini-pro
  temperature: 0.3

attacks:
  sql_injection:
    enabled: true
    payloads_file: patterns/injection.yaml
  
  auth_bypass:
    enabled: true
    test_tokens:
      - ""
      - "invalid"
      - "Bearer test"
  
  idor:
    enabled: true
    test_ids:
      - "1"
      - "2"
      - "admin"

reporting:
  format: markdown
  output_path: sentinel_report.md
  include_evidence: true
```

## CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--swagger` | `-s` | Path to OpenAPI spec | Required |
| `--target` | `-t` | Target API URL | Required |
| `--output` | `-o` | Report output path | sentinel_report.md |
| `--attacks` | `-a` | Attack types to run | All |
| `--timeout` | | Request timeout (sec) | 5 |
| `--verbose` | `-v` | Enable verbose output | False |
| `--no-ai` | | Disable AI analysis | False |
| `--max-endpoints` | | Max endpoints to test | 50 |

## Attack Types

- `sql_injection` - SQL and NoSQL injection testing
- `auth_bypass` - Authentication bypass testing
- `idor` - Insecure Direct Object Reference testing

## Example Commands

```bash
# Basic scan
python -m sentinel scan -s api.yaml -t http://localhost:8000

# Specific attacks only
python -m sentinel scan -s api.yaml -t http://localhost:8000 -a sql_injection -a auth_bypass

# Without AI
python -m sentinel scan -s api.yaml -t http://localhost:8000 --no-ai

# Verbose mode
python -m sentinel scan -s api.yaml -t http://localhost:8000 -v
```
