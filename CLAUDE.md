# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sentinel is an autonomous API security testing tool for OpenAPI-described services. It combines an AI-assisted planning layer with a bounded execution loop, shared scan context, and deterministic attack modules.

Core execution model: `task -> execute -> learn -> follow-up`

The key design constraint: AI is NOT used inside attack modules. Chaining is deterministic, and the loop is bounded.

## Commands

Run tests:
```bash
pytest -q
pytest -q tests/unit        # Unit tests only
pytest -q tests/integration # Integration tests only
pytest -q tests/e2e          # End-to-end tests
```

Run specific test file:
```bash
pytest tests/unit/test_task_queue.py -v
```

Run linting:
```bash
ruff check sentinel/
mypy sentinel/ --ignore-missing-imports
```

Run a scan:
```bash
python -m sentinel scan --swagger api-spec.yaml --target https://api.example.com
python -m sentinel autonomous --swagger api-spec.yaml --target https://api.example.com --auth-token YOUR_TOKEN
```

Start the vulnerable test server:
```bash
cd test_server && python vulnerable_api.py
```

Run benchmarks:
```bash
python scripts/run_benchmarks.py --target crapi
```

## Architecture

```
OpenAPI Spec -> Parser -> TaskQueue -> SentinelOrchestrator -> Attack Modules
                                          |
                                          v
                                    ScanContext
                                          |
                                          v
                                  follow-up tasks
```

Core components in `sentinel/`:

- **orchestrator.py**: `SentinelOrchestrator` - bounded loop that executes tasks, updates context, and enqueues follow-ups
- **scan_context.py**: `ScanContext` - shared state (discovered IDs, tokens, findings, executed task signatures)
- **tasks.py**: `TaskQueue` - deduplicated FIFO queue of scan tasks
- **parser.py**: converts OpenAPI documents into `Endpoint` objects
- **attacks/**: deterministic attack modules (SQL injection, IDOR, BOLA, BFLA, broken auth, XSS, SSRF, etc.)
- **reporter.py**, **json_reporter.py**, **html_reporter.py**: output formatters

The autonomous mode allows chaining: e.g., SQLi discovers an ID → enqueues IDOR follow-up → probes object access.

## Testing Structure

- `tests/unit/`: task signatures, queue behavior, scan context extraction, loop controls
- `tests/integration/`: mock attackers, validate loop/chaining behavior without real HTTP
- `tests/e2e/`: local test server for end-to-end autonomous behavior verification