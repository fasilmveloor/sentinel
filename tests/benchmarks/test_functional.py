"""
Functional benchmark tests for the current Sentinel runtime.
"""

from sentinel import (
    PassiveScanner,
    SentinelOrchestrator,
    ScanContext,
    ScanTask,
    TaskQueue,
    create_passive_scanner,
)
from sentinel.models import AttackType, Endpoint, HttpMethod, Parameter


def create_test_endpoints():
    return [
        Endpoint(
            path="/api/users",
            method=HttpMethod.GET,
            parameters=[Parameter(name="userId", location="query", required=True)],
            security=[{"bearer": []}],
        ),
        Endpoint(
            path="/api/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="id", location="path", required=True)],
            security=[{"bearer": []}],
        ),
    ]


def test_orchestrator_runtime_exists():
    assert hasattr(SentinelOrchestrator, "__init__")
    assert hasattr(SentinelOrchestrator, "run")


def test_task_queue_exists():
    queue = TaskQueue()
    endpoint = create_test_endpoints()[0]
    task = ScanTask(endpoint=endpoint, attack_type=AttackType.SQL_INJECTION, reason="seed")

    assert queue.push(task) is True
    assert queue.pop() == task


def test_scan_context_exists():
    context = ScanContext()

    assert context.discovered_ids == set()
    assert context.tokens == set()
    assert context.findings == []


def test_orchestrator_chaining_supports_idor_followups():
    endpoints = create_test_endpoints()
    orchestrator = SentinelOrchestrator("http://example.com", endpoints=endpoints)
    orchestrator.context.discovered_ids.add("42")

    orchestrator._enqueue_idor_followups()

    followup = orchestrator.queue.pop()
    assert followup is not None
    assert followup.attack_type == AttackType.IDOR
    assert followup.artifacts == {"candidate_id": "42"}


def test_passive_scanner_exports_work():
    scanner = create_passive_scanner()

    assert isinstance(scanner, PassiveScanner)
