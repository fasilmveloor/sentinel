from types import SimpleNamespace

from sentinel.chat import ChatIntent, SentinelChat, create_chat_interface, run_interactive_session
from sentinel.models import AttackType, Endpoint, HttpMethod, LLMProvider


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


def test_load_endpoints_updates_context(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    endpoints = [
        Endpoint(path="/api/users", method=HttpMethod.GET, parameters=[]),
        Endpoint(path="/api/posts", method=HttpMethod.POST, parameters=[]),
    ]

    chat.load_endpoints(endpoints)

    assert len(chat.endpoints) == 2


def test_chat_with_scan_intent(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    response = chat.chat("scan the API")

    assert response.intent == ChatIntent.SCAN_API


def test_chat_report_intent(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    response = chat.chat("generate a report")

    assert response.intent == ChatIntent.REPORT


def test_chat_conversation_history(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    chat.chat("help")
    chat.chat("status")

    assert len(chat.conversation_history) == 2
    assert chat.conversation_history[0]["role"] == "user"


def test_create_chat_interface(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = create_chat_interface(LLMProvider.OPENAI)

    assert isinstance(chat, SentinelChat)


def test_chat_response_default_values(monkeypatch):
    monkeypatch.setattr("sentinel.chat.create_agent", lambda provider, api_key: DummyAgent())
    chat = SentinelChat(ai_provider=LLMProvider.GEMINI)

    response = chat.chat("unknown intent xyz")

    assert isinstance(response.follow_up_suggestions, list)
    assert response.action_taken is False
