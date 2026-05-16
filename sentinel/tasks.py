"""
Minimal task queue support for autonomous scanning.
"""

from collections import deque

from .models import ScanTask


class TaskQueue:
    """A simple FIFO queue with signature-based deduplication."""

    def __init__(self):
        self._queue: deque[ScanTask] = deque()
        self._signatures: set[str] = set()

    def push(self, task: ScanTask) -> bool:
        """Add a task if it has not already been queued."""
        signature = task.signature
        if signature in self._signatures:
            return False

        self._queue.append(task)
        self._signatures.add(signature)
        return True

    def pop(self) -> ScanTask | None:
        """Pop the next task, or None when empty."""
        if not self._queue:
            return None
        return self._queue.popleft()

    def __len__(self) -> int:
        return len(self._queue)

