import json
from unittest.mock import Mock

import pytest

from sentinel.models import AttackResult, AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.scan_context import ScanContext
from sentinel.tasks import TaskQueue


@pytest.fixture
def basic_endpoint():
    return Endpoint(
        path="/api/users/{id}",
        method=HttpMethod.GET,
        parameters=[Parameter(name="id", location="path", required=True, param_type="integer")],
        security=[{"bearerAuth": []}],
    )


@pytest.fixture
def list_endpoint():
    return Endpoint(
        path="/api/users",
        method=HttpMethod.GET,
        parameters=[Parameter(name="userId", location="query", required=False, param_type="integer")],
    )


class TestScanTask:
    def test_signature_ignores_reason(self, basic_endpoint):
        task_one = ScanTask(
            endpoint=basic_endpoint,
            attack_type=AttackType.IDOR,
            parameters=["id"],
            artifacts={"candidate_id": "42"},
            reason="first reason",
        )
        task_two = ScanTask(
            endpoint=basic_endpoint,
            attack_type=AttackType.IDOR,
            parameters=["id"],
            artifacts={"candidate_id": "42"},
            reason="second reason",
        )

        assert task_one.signature == task_two.signature

    def test_signature_serializes_artifacts_deterministically(self, basic_endpoint):
        task_one = ScanTask(
            endpoint=basic_endpoint,
            attack_type=AttackType.IDOR,
            artifacts={"b": 2, "a": 1},
            reason="seed",
        )
        task_two = ScanTask(
            endpoint=basic_endpoint,
            attack_type=AttackType.IDOR,
            artifacts={"a": 1, "b": 2},
            reason="seed",
        )

        expected_artifacts = json.dumps({"a": 1, "b": 2}, sort_keys=True, default=str)

        assert task_one.signature == task_two.signature
        assert task_one.signature.endswith(expected_artifacts)


class TestTaskQueue:
    def test_deduplicates_same_task(self, basic_endpoint):
        queue = TaskQueue()
        task = ScanTask(endpoint=basic_endpoint, attack_type=AttackType.IDOR, reason="seed")

        assert queue.push(task) is True
        assert queue.push(task) is False
        assert len(queue) == 1

    def test_fifo_behavior(self, basic_endpoint, list_endpoint):
        queue = TaskQueue()
        first = ScanTask(endpoint=list_endpoint, attack_type=AttackType.SQL_INJECTION, reason="first")
        second = ScanTask(endpoint=basic_endpoint, attack_type=AttackType.IDOR, reason="second")

        queue.push(first)
        queue.push(second)

        assert queue.pop() == first
        assert queue.pop() == second
        assert queue.pop() is None


class TestScanContext:
    def test_extracts_ids_from_extra_data(self, basic_endpoint):
        context = ScanContext()
        result = AttackResult(
            endpoint=basic_endpoint,
            attack_type=AttackType.SQL_INJECTION,
            success=True,
            extra_data={"userId": "42", "nested": {"account_id": "acct-7"}},
        )

        context.update_from_result(result)

        assert "42" in context.discovered_ids
        assert "acct-7" in context.discovered_ids
        assert result in context.findings

    def test_extracts_ids_and_tokens_from_response_body(self, basic_endpoint):
        context = ScanContext()
        result = AttackResult(
            endpoint=basic_endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            success=False,
            response_body=json.dumps({"userId": 123, "access_token": "token-abc"}),
        )

        context.update_from_result(result)

        assert "123" in context.discovered_ids
        assert "token-abc" in context.tokens

    def test_partial_key_matching_and_large_values(self, basic_endpoint):
        context = ScanContext()
        result = AttackResult(
            endpoint=basic_endpoint,
            attack_type=AttackType.AUTH_BYPASS,
            success=False,
            extra_data={
                "userId": "55",
                "sessionTokenValue": "tok-55",
                "recordRef": "66",
                "hugeToken": "x" * 201,
            },
        )

        context.update_from_result(result)

        assert "55" in context.discovered_ids
        assert "tok-55" in context.tokens
        assert "66" not in context.discovered_ids
        assert "x" * 201 not in context.tokens


class TestSentinelOrchestrator:
    def test_execution_guard_prevents_duplicate_execution(self, basic_endpoint, monkeypatch):
        orchestrator = SentinelOrchestrator("http://example.com", endpoints=[basic_endpoint])
        task = ScanTask(endpoint=basic_endpoint, attack_type=AttackType.IDOR, reason="seed")
        orchestrator.context.mark_executed(task.signature)
        orchestrator.queue.pop = Mock(side_effect=[task, None])
        execute_mock = Mock(return_value=[])
        monkeypatch.setattr(orchestrator, "_execute_task", execute_mock)

        results = orchestrator.run()

        assert results == []
        assert orchestrator.tasks_executed == 0
        execute_mock.assert_not_called()

    def test_loop_stops_at_max_iterations(self, basic_endpoint, monkeypatch):
        orchestrator = SentinelOrchestrator("http://example.com", max_iterations=2, max_tasks=10, endpoints=[basic_endpoint])
        for idx in range(3):
            orchestrator.push_task(
                ScanTask(
                    endpoint=basic_endpoint,
                    attack_type=AttackType.IDOR,
                    artifacts={"candidate_id": str(idx)},
                    reason=f"seed-{idx}",
                )
            )

        monkeypatch.setattr(
            orchestrator,
            "_execute_task",
            Mock(
                return_value=[
                    AttackResult(endpoint=basic_endpoint, attack_type=AttackType.IDOR, success=False)
                ]
            ),
        )
        enqueue_mock = Mock()
        monkeypatch.setattr(orchestrator, "_enqueue_idor_followups", enqueue_mock)

        orchestrator.run()

        assert orchestrator.tasks_executed == 2
        assert enqueue_mock.call_count == 2

    def test_loop_stops_at_max_tasks_and_increments_counter(self, basic_endpoint, monkeypatch):
        orchestrator = SentinelOrchestrator("http://example.com", max_iterations=10, max_tasks=1, endpoints=[basic_endpoint])
        orchestrator.push_task(ScanTask(endpoint=basic_endpoint, attack_type=AttackType.IDOR, reason="first"))
        orchestrator.push_task(
            ScanTask(
                endpoint=basic_endpoint,
                attack_type=AttackType.IDOR,
                artifacts={"candidate_id": "2"},
                reason="second",
            )
        )

        monkeypatch.setattr(
            orchestrator,
            "_execute_task",
            Mock(
                return_value=[
                    AttackResult(endpoint=basic_endpoint, attack_type=AttackType.IDOR, success=False)
                ]
            ),
        )
        monkeypatch.setattr(orchestrator, "_enqueue_idor_followups", Mock())

        orchestrator.run()

        assert orchestrator.tasks_executed == 1
