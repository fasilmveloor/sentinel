# Sentinel Architecture

Sentinel v3 is a bounded autonomous API security system.

It does not execute a single static plan and stop. Instead, it runs a loop:

```text
task -> execute -> update context -> enqueue follow-up
```

## Core Components

### Parser

The parser converts an OpenAPI document into `Endpoint` objects.

### TaskQueue

`TaskQueue` is a deduplicated FIFO queue of `ScanTask` objects. It is the execution frontier for the autonomous loop.

### ScanContext

`ScanContext` stores shared state discovered during the scan:

- IDs
- tokens
- findings
- executed task signatures

This is what allows later tasks to depend on earlier results without putting AI inside the attack modules.

### SentinelOrchestrator

`SentinelOrchestrator` is the loop controller. It:

1. pops the next task
2. executes the matching deterministic attacker
3. updates `ScanContext`
4. applies simple chaining rules
5. stops when loop limits are reached

### Attack Modules

Attack modules remain deterministic. They send requests, inspect responses, and return `AttackResult` objects. They do not perform planning or chaining.

## Example Flow

```text
SQLi task
  -> response contains userId
  -> ScanContext records discovered ID
  -> Orchestrator enqueues IDOR follow-up
  -> IDOR task executes against matching endpoint
```

## Current Scope

The current v3 loop is intentionally small:

- bounded task execution
- shared context
- simple deterministic chaining

That gives Sentinel autonomous behavior without redesigning the execution layer.
