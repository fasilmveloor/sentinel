from datetime import datetime, timezone

import pytest

from sentinel.benchmarks.framework import BenchmarkResult, BenchmarkRunner, BenchmarkTarget
from sentinel.models import AttackType, Endpoint, HttpMethod, Vulnerability, Severity


def test_benchmark_result_metrics_are_safe_for_zero_counts():
    result = BenchmarkResult(target=BenchmarkTarget.CRAPI, start_time=datetime.now(timezone.utc))

    assert result.detection_rate == 0.0
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1_score == 0.0


@pytest.mark.asyncio
async def test_benchmark_runner_uses_orchestrator_scan(monkeypatch):
    runner = BenchmarkRunner()
    endpoint = Endpoint(path="/api/users", method=HttpMethod.GET, parameters=[])
    vulnerability = Vulnerability(
        endpoint=endpoint,
        attack_type=AttackType.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQL Injection in GET /api/users",
        description="Detected",
        payload="injection: ' OR 1=1 --",
        proof_of_concept="Request: GET /api/users",
        recommendation="Use parameterized queries",
    )

    async def fake_get_endpoints(target, base_url, spec_path):
        return [endpoint]

    async def fake_run_scan(endpoints, base_url, attack_types, auth_token, timeout, verbose):
        return [vulnerability]

    monkeypatch.setattr(runner, "_get_endpoints", fake_get_endpoints)
    monkeypatch.setattr(runner, "_run_scan", fake_run_scan)

    result = await runner.run_benchmark(
        target=BenchmarkTarget.CRAPI,
        base_url="http://example.com",
        attack_types=[AttackType.SQL_INJECTION],
    )

    assert result.endpoints_tested == 1
    assert result.detected_vulnerabilities == 1
    assert result.attack_types_used == [AttackType.SQL_INJECTION]
