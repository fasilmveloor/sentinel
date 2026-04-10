from unittest.mock import MagicMock, patch

import requests

from sentinel.attacks.injection import SQLInjectionAttacker
from sentinel.models import Endpoint, HttpMethod, Parameter


def make_endpoint():
    return Endpoint(
        path="/api/search",
        method=HttpMethod.GET,
        parameters=[Parameter(name="q", location="query", required=True)],
    )


def test_attack_returns_result_on_timeout():
    with patch("sentinel.attacks.injection.requests.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        attacker = SQLInjectionAttacker("https://api.example.com")
        attacker.session = mock_session
        attacker.session.get.side_effect = requests.exceptions.Timeout("boom")

        results = attacker.attack(make_endpoint())

    assert results
    assert results[0].success is False
    assert results[0].payload == "error_case"
    assert results[0].extra_data["exception"] is True


def test_attack_returns_result_on_connection_error():
    with patch("sentinel.attacks.injection.requests.Session") as mock_session_class:
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        attacker = SQLInjectionAttacker("https://api.example.com")
        attacker.session = mock_session
        attacker.session.get.side_effect = requests.exceptions.ConnectionError("down")

        results = attacker.attack(make_endpoint())

    assert results
    assert results[0].success is False
    assert "down" in results[0].error_message
