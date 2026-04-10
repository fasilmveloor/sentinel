from unittest.mock import MagicMock, patch

from sentinel.attacks.bfla import BFLAAttacker
from sentinel.models import Endpoint, HttpMethod


def test_single_token_returns_no_results_when_baseline_not_denied():
    endpoint = Endpoint(path="/api/admin/users", method=HttpMethod.GET, parameters=[])

    with patch("sentinel.attacks.bfla.requests.Session") as mock_session_class:
        session = MagicMock()
        baseline_response = MagicMock()
        baseline_response.status_code = 200
        baseline_response.text = '{"user":{"email":"admin@example.com"}}'
        session.request.return_value = baseline_response
        mock_session_class.return_value = session

        attacker = BFLAAttacker("https://api.example.com")
        results = attacker._test_single_token(endpoint, "user-token")

    assert results == []
