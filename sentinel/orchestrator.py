"""
Minimal autonomous orchestrator loop for Sentinel v3.
"""

from typing import Any

from .attacks import (
    AuthBypassAttacker,
    BFLAAttacker,
    BOLAAttacker,
    BrokenAuthAttacker,
    CommandInjectionAttacker,
    ExcessiveDataExposureAttacker,
    IDORAttacker,
    JWTAttacker,
    MassAssignmentAttacker,
    NoSQLInjectionAttacker,
    RateLimitAttacker,
    SQLInjectionAttacker,
    SSRFAttacker,
    XSSAttacker,
)
from .models import AttackResult, AttackType, Endpoint, ScanTask, Severity, Vulnerability
from .scan_context import ScanContext
from .tasks import TaskQueue


class SentinelOrchestrator:
    """Minimal task-driven orchestrator for autonomous scans."""

    AUTH_TOKEN_ATTACKS = {
        AttackType.AUTH_BYPASS,
        AttackType.JWT,
        AttackType.BOLA,
        AttackType.BFLA,
        AttackType.BROKEN_AUTH,
    }

    def __init__(
        self,
        target_url: str,
        timeout: int = 5,
        max_iterations: int = 5,
        max_tasks: int = 50,
        endpoints: list[Endpoint] | None = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.max_iterations = max_iterations
        self.max_tasks = max_tasks
        self.tasks_executed = 0
        self.context = ScanContext()
        self.queue = TaskQueue()
        self._attackers: dict[AttackType, Any] = {}
        self.endpoints: list[Endpoint] = endpoints or []
        self.vulnerabilities: list[Any] = []

    def push_task(self, task: ScanTask) -> bool:
        """Queue a task for execution."""
        return self.queue.push(task)

    def add_endpoints(self, endpoints: list[Endpoint]) -> None:
        """Register endpoints available for follow-up chaining."""
        self.endpoints.extend(endpoints)

    def run(self) -> list[AttackResult]:
        """Execute queued tasks up to the configured iteration limit."""
        results: list[AttackResult] = []
        iterations = 0

        while iterations < self.max_iterations and self.tasks_executed < self.max_tasks:
            task = self.queue.pop()
            if task is None:
                break

            if self.context.has_seen(task.signature):
                continue

            execution = self._execute_task(task)
            if isinstance(execution, tuple):
                attack_results, attacker = execution
            else:
                attack_results, attacker = execution, None
            self.context.mark_executed(task.signature)
            for result in attack_results:
                self.context.update_from_result(result)
                if (
                    result.success
                    and result.request_url is not None
                    and result.response_status is not None
                    and result.evidence_excerpt is not None
                ):
                    if attacker is not None and hasattr(attacker, "create_vulnerability"):
                        vulnerability = attacker.create_vulnerability(result, task.endpoint)
                    else:
                        vulnerability = self._create_generic_vulnerability(result, task.endpoint)
                    self.vulnerabilities.append(vulnerability)
            results.extend(attack_results)
            self.tasks_executed += 1

            self._enqueue_idor_followups()

            iterations += 1

        return results

    def _execute_task(self, task: ScanTask) -> tuple[list[AttackResult], Any]:
        """Execute a single task using the appropriate deterministic attacker."""
        attacker = self._get_attacker(task.attack_type)
        if attacker is None:
            return [], None

        if task.attack_type == AttackType.IDOR:
            return self._execute_idor_task(attacker, task)

        if task.attack_type in self.AUTH_TOKEN_ATTACKS:
            auth_token = self._extract_auth_token(task)
            return attacker.attack(task.endpoint, auth_token), attacker

        parameters = task.parameters or None
        return attacker.attack(task.endpoint, parameters), attacker

    def _execute_idor_task(self, attacker: IDORAttacker, task: ScanTask) -> tuple[list[AttackResult], IDORAttacker]:
        """Execute an IDOR task using a discovered ID value when available."""
        candidate_id = task.artifacts.get("candidate_id")
        parameters = task.parameters or None
        auth_token = self._extract_auth_token(task)

        if not candidate_id:
            return attacker.attack(task.endpoint, auth_token=auth_token, parameters_to_test=parameters), attacker

        temp_attacker = IDORAttacker(self.target_url, self.timeout)
        if hasattr(attacker, "session") and hasattr(temp_attacker, "session"):
            temp_attacker.session.headers.update(attacker.session.headers)
        temp_attacker.ID_PATTERNS = self._build_candidate_patterns(candidate_id)
        return temp_attacker.attack(task.endpoint, auth_token=auth_token, parameters_to_test=parameters), temp_attacker

    def _build_candidate_patterns(self, candidate_id: Any) -> list[str]:
        """Build a minimal set of alternate IDs from a discovered ID."""
        candidate_text = str(candidate_id)
        if candidate_text.isdigit():
            candidate_int = int(candidate_text)
            return [
                str(max(candidate_int - 1, 0)),
                str(candidate_int + 1),
            ]
        return [candidate_text]

    def _extract_auth_token(self, task: ScanTask) -> str | None:
        """Extract an auth token from the task artifacts if present."""
        for key in (
            "auth_token",
            "token",
            "access_token",
            "bearer_token",
            "jwt",
        ):
            value = task.artifacts.get(key)
            if value:
                return str(value)
        return None

    def _enqueue_idor_followups(self) -> None:
        """Queue IDOR tasks for endpoints that look ID-based when IDs are known."""
        if not self.context.discovered_ids:
            return

        for discovered_id in sorted(self.context.discovered_ids):
            for endpoint in self.endpoints:
                parameters = self._get_id_parameters(endpoint)
                if not parameters and "{id}" not in endpoint.path.lower():
                    continue
                artifacts = {
                    "candidate_id": discovered_id,
                    "auth_token": next(iter(self.context.tokens), None),
                }
                artifacts = {key: value for key, value in artifacts.items() if value is not None}
                task = ScanTask(
                    endpoint=endpoint,
                    attack_type=AttackType.IDOR,
                    parameters=parameters,
                    artifacts=artifacts,
                    reason="discovered IDs available",
                )
                self.queue.push(task)

    def _get_id_parameters(self, endpoint: Endpoint) -> list[str]:
        """Return ID-like parameter names for an endpoint."""
        return [
            parameter.name
            for parameter in endpoint.parameters
            if "id" in parameter.name.lower()
        ]

    def _get_attacker(self, attack_type: AttackType):
        """Get or create the deterministic attacker for the task type."""
        if attack_type not in self._attackers:
            attacker_map = {
                AttackType.SQL_INJECTION: SQLInjectionAttacker,
                AttackType.AUTH_BYPASS: AuthBypassAttacker,
                AttackType.IDOR: IDORAttacker,
                AttackType.XSS: XSSAttacker,
                AttackType.SSRF: SSRFAttacker,
                AttackType.JWT: JWTAttacker,
                AttackType.CMD_INJECTION: CommandInjectionAttacker,
                AttackType.RATE_LIMIT: RateLimitAttacker,
                AttackType.BOLA: BOLAAttacker,
                AttackType.EXCESSIVE_DATA: ExcessiveDataExposureAttacker,
                AttackType.MASS_ASSIGNMENT: MassAssignmentAttacker,
                AttackType.BFLA: BFLAAttacker,
                AttackType.NOSQL_INJECTION: NoSQLInjectionAttacker,
                AttackType.BROKEN_AUTH: BrokenAuthAttacker,
            }
            attacker_class = attacker_map.get(attack_type)
            if attacker_class is None:
                return None
            self._attackers[attack_type] = attacker_class(self.target_url, self.timeout)

        return self._attackers[attack_type]

    def _create_generic_vulnerability(self, result: AttackResult, endpoint: Endpoint) -> Vulnerability:
        """Create a fallback vulnerability when no attacker object is available."""
        return Vulnerability(
            endpoint=endpoint,
            attack_type=result.attack_type,
            severity=Severity.HIGH,
            title=f"{result.attack_type.value} detected in {endpoint.full_path}",
            description=(
                "A proof-bearing attack result was produced, but no attacker-specific "
                "vulnerability builder was available."
            ),
            payload=result.payload or "",
            proof_of_concept=(
                f"Request: {result.request_method} {result.request_url}\n"
                f"Payload: {result.payload}\n"
                f"Response Status: {result.response_status}\n"
                f"Evidence: {result.evidence_excerpt}"
            ),
            recommendation="Review the affected endpoint and add explicit authorization and input validation controls.",
            response_evidence=result.evidence_excerpt or result.response_body,
        )
