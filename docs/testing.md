# Testing

Sentinel uses a layered test structure:

```text
tests/
  unit/
  integration/
  e2e/
```

## Test Types

### Unit

Small focused tests for:

- `ScanTask`
- `TaskQueue`
- `ScanContext`
- `SentinelOrchestrator` loop controls

### Integration

Integration tests mock attackers and validate:

- loop behavior
- context updates
- follow-up task creation

These tests should not rely on real network calls.

### E2E

E2E tests run against the local test server and verify:

- artifact extraction
- follow-up execution
- bounded loop behavior

## Running Tests

Activate the project environment first if you use pyenv:

```bash
pyenv activate env
```

Then run:

```bash
pytest -q
```

Or by layer:

```bash
pytest -q tests/unit
pytest -q tests/integration
pytest -q tests/e2e
```

## Mocking Strategy

- prefer mocked attackers for unit and integration tests
- avoid real HTTP outside e2e
- keep assertions behavioral, not overly coupled to incidental values or queue size
