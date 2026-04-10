from types import SimpleNamespace

from sentinel.chat import ChatIntent, SentinelChat
from sentinel.models import LLMProvider


class DummyProvider:
    def generate(self, *args, **kwargs):
        return '{"intent": "unknown", "confidence": 0.2}'


class DummyAgent:
    def __init__(self):
        self.active_provider = DummyProvider()


def test_chat_classifies_help_without_ai(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    response = chat.chat("help me get started")

    assert response.intent == ChatIntent.HELP
    assert "Sentinel" in response.message


def test_chat_status_reports_loaded_endpoints(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)
    chat.load_endpoints([SimpleNamespace(), SimpleNamespace()])

    response = chat.chat("status")

    assert response.intent == ChatIntent.STATUS
    assert response.data["endpoints_loaded"] == 2
