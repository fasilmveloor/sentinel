"""
Minimal autonomous orchestrator loop for Sentinel v3.
"""

from typing import Any, Optional

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
from .models import AttackResult, AttackType, Endpoint, ScanTask
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
        endpoints: Optional[list[Endpoint]] = None,
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

            attack_results = self._execute_task(task)
            self.context.mark_executed(task.signature)
            for result in attack_results:
                self.context.update_from_result(result)
            results.extend(attack_results)
            self.tasks_executed += 1

            self._enqueue_idor_followups()

            iterations += 1

        return results

    def _execute_task(self, task: ScanTask) -> list[AttackResult]:
        """Execute a single task using the appropriate deterministic attacker."""
        attacker = self._get_attacker(task.attack_type)
        if attacker is None:
            return []

        if task.attack_type == AttackType.IDOR:
            return self._execute_idor_task(attacker, task)

        if task.attack_type in self.AUTH_TOKEN_ATTACKS:
            auth_token = self._extract_auth_token(task)
            return attacker.attack(task.endpoint, auth_token)

        parameters = task.parameters or None
        return attacker.attack(task.endpoint, parameters)

    def _execute_idor_task(self, attacker: IDORAttacker, task: ScanTask) -> list[AttackResult]:
        """Execute an IDOR task using a discovered ID value when available."""
        candidate_id = task.artifacts.get("candidate_id")
        parameters = task.parameters or None

        if not candidate_id:
            return attacker.attack(task.endpoint, parameters_to_test=parameters)

        temp_attacker = IDORAttacker(self.target_url, self.timeout)
        temp_attacker.session.headers.update(attacker.session.headers)
        temp_attacker.ID_PATTERNS = [str(candidate_id)]
        return temp_attacker.attack(task.endpoint, parameters_to_test=parameters)

    def _extract_auth_token(self, task: ScanTask) -> Optional[str]:
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
                task = ScanTask(
                    endpoint=endpoint,
                    attack_type=AttackType.IDOR,
                    parameters=parameters,
                    artifacts={"candidate_id": discovered_id},
                    reason="discovered IDs available",
                )
                if not self.context.has_seen(task.signature):
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
