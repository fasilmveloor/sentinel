# Sentinel

Sentinel is an autonomous API security tester for OpenAPI-described services. It combines an AI-assisted planning layer with a bounded execution loop, shared scan context, and deterministic attack modules.

Core idea:

```text
task -> execute -> learn -> follow-up
```

Sentinel does not put AI inside the execution layer. Attack modules stay deterministic. The autonomous behavior comes from the loop around them.

## Overview

Sentinel v3 scans APIs as a bounded autonomous system:

- seed tasks from API structure
- execute deterministic attacks
- learn from responses through shared context
- enqueue follow-up work when new artifacts appear

Example chain:

```text
SQLi -> extract ID -> enqueue IDOR -> probe object access
```

This keeps execution predictable while still allowing multi-step exploration.

## Key Features

- Autonomous loop with explicit limits on iterations and executed tasks
- Context-driven chaining using `ScanContext`
- Deterministic attack modules with no AI inside execution
- Deduplicated task scheduling through `TaskQueue`
- AI-assisted planning and prioritization outside the execution layer
- Multiple report formats and CLI workflows

## How It Works

High-level flow:

```text
OpenAPI -> Parser -> TaskQueue -> SentinelOrchestrator -> Attack Modules -> ScanContext -> follow-up tasks -> Reporter
```

Main runtime pieces:

- `TaskQueue`: deduplicated FIFO queue of scan tasks
- `ScanContext`: shared state for discovered IDs, tokens, findings, and executed task signatures
- `SentinelOrchestrator`: bounded loop that executes tasks, updates context, and applies simple chaining rules

Current Tier 1 chaining is intentionally simple:

- if the scan discovers IDs, Sentinel can enqueue IDOR follow-up tasks for matching endpoints

## Usage

Install dependencies:

```bash
pyenv activate env
pip install -r requirements.txt
```

If you use the project pyenv environment, activate it before running Sentinel or pytest:

```bash
pyenv activate env
```

Run a standard scan:

```bash
python -m sentinel scan \
  --swagger api-spec.yaml \
  --target https://api.example.com
```

Run autonomous mode:

```bash
python -m sentinel autonomous \
  --swagger api-spec.yaml \
  --target https://api.example.com
```

Autonomous mode still uses deterministic attack modules. The difference is that Sentinel can learn from intermediate results and schedule follow-up work instead of stopping after a single plan/execute pass.

Example with authentication:

```bash
python -m sentinel autonomous \
  --swagger api-spec.yaml \
  --target https://api.example.com \
  --auth-token YOUR_TOKEN
```

Common options:

- `--swagger`, `-s`: OpenAPI specification path
- `--target`, `-t`: base URL of the target API
- `--auth-token`: bearer token for authenticated testing
- `--llm`: planning provider (`gemini`, `openai`, `claude`, `local`)
- `--format`, `-f`: report format
- `--output`, `-o`: report path

## Architecture

Sentinel v3 keeps the execution layer simple:

```text
OpenAPI Spec
  -> Parser
  -> seed tasks
  -> TaskQueue
  -> SentinelOrchestrator
      -> execute attack
      -> update ScanContext
      -> enqueue follow-up tasks
  -> Reporter
```

Important constraints:

- AI is not used inside attack modules
- chaining is deterministic
- the loop is bounded
- backward-compatible scan mode is preserved

## Project Structure

```text
sentinel/
├── sentinel/
│   ├── agent.py
│   ├── autonomous.py
│   ├── orchestrator.py
│   ├── scan_context.py
│   ├── tasks.py
│   ├── parser.py
│   ├── models.py
│   ├── main.py
│   ├── reporter.py
│   ├── html_reporter.py
│   ├── json_reporter.py
│   └── attacks/
├── docs/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
└── test_server/
```

## Testing

Run tests from the project root:

```bash
pyenv activate env
pytest -q
```

Run specific layers:

```bash
pytest -q tests/unit
pytest -q tests/integration
pytest -q tests/e2e
```

Testing approach:

- unit tests cover task signatures, queue behavior, scan context extraction, and loop controls
- integration tests mock attackers and validate loop/chaining behavior without real HTTP
- e2e tests use the local test server to verify autonomous behavior end to end

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Autonomous Mode](docs/autonomous_mode.md)
- [Testing](docs/testing.md)
