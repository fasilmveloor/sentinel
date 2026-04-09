# Autonomous Mode

In Sentinel, “autonomous” means the scanner can continue working from intermediate results instead of stopping after a single plan/execute step.

Current loop:

```text
seed task -> execute -> learn from result -> enqueue follow-up
```

## What It Does

- executes bounded scan tasks
- records artifacts in `ScanContext`
- schedules simple follow-up work through `TaskQueue`
- keeps execution deterministic

## Current Tier 1 Limitations

- only basic chaining is implemented
- current follow-up behavior is intentionally simple
- no advanced reasoning or deep multi-step strategy engine yet
- no AI in the execution layer

## Example

If Sentinel sees an ID in a response, it can queue an IDOR task for an endpoint that looks ID-based.
