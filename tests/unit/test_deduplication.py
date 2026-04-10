from sentinel.models import AttackType, Endpoint, HttpMethod, Parameter, ScanTask
from sentinel.tasks import TaskQueue


def make_endpoint():
    return Endpoint(
        path="/api/users/{id}",
        method=HttpMethod.GET,
        parameters=[Parameter(name="id", location="path", required=True, param_type="integer")],
    )


def test_task_deduplication_same_signature():
    endpoint = make_endpoint()
    task_one = ScanTask(
        endpoint=endpoint,
        attack_type=AttackType.IDOR,
        parameters=["id"],
        artifacts={"candidate_id": "42"},
        reason="first",
    )
    task_two = ScanTask(
        endpoint=endpoint,
        attack_type=AttackType.IDOR,
        parameters=["id"],
        artifacts={"candidate_id": "42"},
        reason="second",
    )

    assert task_one.signature == task_two.signature


def test_task_queue_rejects_duplicate_task():
    endpoint = make_endpoint()
    queue = TaskQueue()
    task = ScanTask(endpoint=endpoint, attack_type=AttackType.IDOR, reason="seed")

    assert queue.push(task) is True
    assert queue.push(task) is False


def test_task_signature_changes_with_different_artifacts():
    endpoint = make_endpoint()
    task_one = ScanTask(
        endpoint=endpoint,
        attack_type=AttackType.IDOR,
        artifacts={"candidate_id": "41"},
        reason="seed",
    )
    task_two = ScanTask(
        endpoint=endpoint,
        attack_type=AttackType.IDOR,
        artifacts={"candidate_id": "42"},
        reason="seed",
    )

    assert task_one.signature != task_two.signature
