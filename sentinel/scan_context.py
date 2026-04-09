"""
Minimal shared scan context for autonomous scanning.
"""

import json
from typing import Any

from .models import AttackResult


class ScanContext:
    """Tracks minimal state discovered during an autonomous scan."""

    TOKEN_KEYS = {
        "token",
        "auth_token",
        "access_token",
        "refresh_token",
        "jwt",
        "session",
        "session_token",
        "bearer_token",
    }

    ID_KEYS = {
        "id",
        "user_id",
        "account_id",
        "object_id",
        "resource_id",
        "record_id",
    }

    def __init__(self):
        self.discovered_ids: set[str] = set()
        self.tokens: set[str] = set()
        self.findings: list[AttackResult] = []
        self.executed_task_signatures: set[str] = set()

    def update_from_result(self, result: AttackResult) -> None:
        """Update the context with findings and obvious reusable artifacts."""
        if result.success:
            self.findings.append(result)

        extra_data = result.extra_data or {}
        self._collect_values(extra_data)
        if result.response_body:
            self._collect_response_body(result.response_body)

    def mark_executed(self, signature: str) -> None:
        """Mark a task signature as executed."""
        self.executed_task_signatures.add(signature)

    def has_seen(self, signature: str) -> bool:
        """Check whether a task signature has already been executed."""
        return signature in self.executed_task_signatures

    def _collect_response_body(self, response_body: str) -> None:
        """Collect values from JSON response bodies when available."""
        if len(response_body) > 10000:
            return

        try:
            parsed = json.loads(response_body)
        except (TypeError, ValueError):
            return

        self._collect_values(parsed)

    def _collect_values(self, value: Any, key_hint: str | None = None) -> None:
        """Recursively collect obvious token and ID values from nested structures."""
        if isinstance(value, dict):
            for key, nested_value in value.items():
                self._collect_values(nested_value, key)
            return

        if isinstance(value, list):
            for item in value:
                self._collect_values(item, key_hint)
            return

        if value is None:
            return

        text = str(value).strip()
        if not text:
            return
        if len(text) > 200:
            return

        normalized_key = (key_hint or "").lower()
        if "token" in normalized_key or normalized_key in self.TOKEN_KEYS:
            self.tokens.add(text)
        elif "id" in normalized_key or normalized_key in self.ID_KEYS:
            self.discovered_ids.add(text)
