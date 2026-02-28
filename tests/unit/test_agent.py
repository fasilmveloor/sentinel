"""
Unit tests for AI Agent module.

Tests cover:
- LLM provider initialization
- SentinelAgent functionality
- Fallback decision logic
- JSON extraction
- Prompt building
- Batch analysis
"""

import json
import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Optional

from sentinel.agent import (
    BaseLLMProvider, GeminiProvider, OpenAIProvider, ClaudeProvider,
    LocalLLMProvider, SentinelAgent, AIAgentError, create_agent
)
from sentinel.models import Endpoint, HttpMethod, AttackType, LLMProvider, Parameter


# ============================================================================
# MOCK LLM PROVIDER
# ============================================================================

class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider for testing."""

    def __init__(self, response: str = None, available: bool = True):
        self.response = response or '{"recommended_attacks": ["sql_injection"], "priority": 1, "reasoning": "Test"}'
        self.available = available

    def generate(self, prompt: str, system_prompt: str) -> str:
        return self.response

    def is_available(self) -> bool:
        return self.available


# ============================================================================
# BASE LLM PROVIDER TESTS
# ============================================================================

class TestBaseLLMProvider:
    """Tests for BaseLLMProvider abstract class."""

    def test_abstract_methods_required(self):
        """Test that abstract methods must be implemented."""
        with pytest.raises(TypeError):
            # Cannot instantiate abstract class
            BaseLLMProvider()


# ============================================================================
# GEMINI PROVIDER TESTS
# ============================================================================

class TestGeminiProvider:
    """Tests for GeminiProvider."""

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        provider = GeminiProvider(api_key="test-key")
        assert provider.api_key == "test-key"

    def test_init_without_api_key(self, clean_env):
        """Test initialization without API key."""
        provider = GeminiProvider()
        assert provider.api_key is None

    def test_is_available_with_key(self):
        """Test is_available returns True with API key."""
        provider = GeminiProvider(api_key="test-key")
        assert provider.is_available() is True

    def test_is_available_without_key(self, clean_env):
        """Test is_available returns False without API key."""
        provider = GeminiProvider()
        assert provider.is_available() is False

    def test_generate_initializes_model(self):
        """Test generate initializes the model."""
        provider = GeminiProvider(api_key="test-key")
        
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = "Test response"
        
        # Patch the model directly on the provider
        provider.model = mock_model
        
        response = provider.generate("test prompt", "system prompt")
        
        assert response == "Test response"
        mock_model.generate_content.assert_called_once()


# ============================================================================
# OPENAI PROVIDER TESTS
# ============================================================================

class TestOpenAIProvider:
    """Tests for OpenAIProvider."""

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        provider = OpenAIProvider(api_key="test-key")
        assert provider.api_key == "test-key"

    def test_is_available_with_key(self):
        """Test is_available returns True with API key."""
        provider = OpenAIProvider(api_key="test-key")
        assert provider.is_available() is True

    def test_is_available_without_key(self, clean_env):
        """Test is_available returns False without API key."""
        provider = OpenAIProvider()
        assert provider.is_available() is False

    def test_generate_calls_openai(self):
        """Test generate calls OpenAI API."""
        provider = OpenAIProvider(api_key="test-key")
        
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value.choices = [
            MagicMock(message=MagicMock(content="Test response"))
        ]
        
        mock_openai = MagicMock(return_value=mock_client)
        
        with patch.dict('sys.modules', {'openai': MagicMock(OpenAI=mock_openai)}):
            response = provider.generate("test prompt", "system prompt")
            
            assert response == "Test response"


# ============================================================================
# CLAUDE PROVIDER TESTS
# ============================================================================

class TestClaudeProvider:
    """Tests for ClaudeProvider."""

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        provider = ClaudeProvider(api_key="test-key")
        assert provider.api_key == "test-key"

    def test_is_available_with_key(self):
        """Test is_available returns True with API key."""
        provider = ClaudeProvider(api_key="test-key")
        assert provider.is_available() is True

    def test_is_available_without_key(self, clean_env):
        """Test is_available returns False without API key."""
        provider = ClaudeProvider()
        assert provider.is_available() is False

    def test_generate_calls_claude(self):
        """Test generate calls Claude API."""
        provider = ClaudeProvider(api_key="test-key")
        
        mock_client = MagicMock()
        mock_client.messages.create.return_value.content = [
            MagicMock(text="Test response")
        ]
        
        mock_anthropic = MagicMock(return_value=mock_client)
        
        with patch.dict('sys.modules', {'anthropic': MagicMock(Anthropic=mock_anthropic)}):
            response = provider.generate("test prompt", "system prompt")
            
            assert response == "Test response"


# ============================================================================
# LOCAL LLM PROVIDER TESTS
# ============================================================================

class TestLocalLLMProvider:
    """Tests for LocalLLMProvider."""

    def test_init_default_url(self):
        """Test initialization with default URL."""
        provider = LocalLLMProvider()
        assert provider.base_url == "http://localhost:11434"
        assert provider.model == "llama2"

    def test_init_custom_url(self):
        """Test initialization with custom URL."""
        provider = LocalLLMProvider(base_url="http://custom:8080")
        assert provider.base_url == "http://custom:8080"

    def test_is_available_true(self):
        """Test is_available returns True when server responds."""
        provider = LocalLLMProvider()
        
        with patch('requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            assert provider.is_available() is True

    def test_is_available_false(self):
        """Test is_available returns False when server unavailable."""
        provider = LocalLLMProvider()
        
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Connection refused")
            assert provider.is_available() is False

    def test_generate_calls_ollama(self):
        """Test generate calls Ollama API."""
        provider = LocalLLMProvider()
        
        with patch('requests.post') as mock_post:
            mock_post.return_value.json.return_value = {"response": "Test response"}
            
            response = provider.generate("test prompt", "system prompt")
            
            assert response == "Test response"


# ============================================================================
# SENTINEL AGENT INITIALIZATION TESTS
# ============================================================================

class TestSentinelAgentInit:
    """Tests for SentinelAgent initialization."""

    def test_init_with_provider(self, mock_env_api_keys):
        """Test initialization with specific provider."""
        with patch.object(SentinelAgent, '_init_providers'):
            with patch.object(SentinelAgent, '_get_active_provider', return_value=MockLLMProvider()):
                agent = SentinelAgent(provider=LLMProvider.GEMINI, api_key="test-key")
                assert agent.provider_name == LLMProvider.GEMINI

    def test_init_raises_without_provider(self, clean_env):
        """Test initialization raises error without available provider."""
        with patch.object(SentinelAgent, '_init_providers'):
            with patch.object(SentinelAgent, '_get_active_provider', return_value=None):
                with pytest.raises(AIAgentError) as exc_info:
                    SentinelAgent(provider=LLMProvider.GEMINI)
                
                assert "No LLM provider available" in str(exc_info.value)

    def test_init_providers_registers_all(self):
        """Test _init_providers registers all available providers."""
        with patch.object(GeminiProvider, 'is_available', return_value=True):
            with patch.object(OpenAIProvider, 'is_available', return_value=True):
                with patch.object(ClaudeProvider, 'is_available', return_value=False):
                    with patch.object(LocalLLMProvider, 'is_available', return_value=False):
                        agent = object.__new__(SentinelAgent)
                        agent.provider_name = LLMProvider.GEMINI
                        agent.providers = {}
                        agent._init_providers("test-key")
                        
                        assert LLMProvider.GEMINI in agent.providers
                        assert LLMProvider.OPENAI in agent.providers
                        assert LLMProvider.CLAUDE not in agent.providers

    def test_get_active_provider_returns_preferred(self):
        """Test _get_active_provider returns preferred provider."""
        agent = object.__new__(SentinelAgent)
        agent.providers = {
            LLMProvider.GEMINI: MockLLMProvider(),
            LLMProvider.OPENAI: MockLLMProvider(),
        }
        
        provider = agent._get_active_provider(LLMProvider.OPENAI)
        assert provider is not None

    def test_get_active_provider_fallback(self):
        """Test _get_active_provider falls back to available provider."""
        agent = object.__new__(SentinelAgent)
        agent.providers = {
            LLMProvider.CLAUDE: MockLLMProvider(),
        }
        
        provider = agent._get_active_provider(LLMProvider.GEMINI)
        assert provider is not None
        assert agent.provider_name == LLMProvider.CLAUDE


# ============================================================================
# SENTINEL AGENT ANALYSIS TESTS
# ============================================================================

class TestSentinelAgentAnalysis:
    """Tests for SentinelAgent analysis methods."""

    @pytest.fixture
    def agent_with_mock(self):
        """Create agent with mocked provider."""
        mock_provider = MockLLMProvider(
            response=json.dumps({
                "recommended_attacks": ["sql_injection", "xss"],
                "parameters_to_test": ["id", "name"],
                "priority": 1,
                "reasoning": "Test reasoning"
            })
        )
        
        agent = object.__new__(SentinelAgent)
        agent.provider_name = LLMProvider.GEMINI
        agent.active_provider = mock_provider
        agent.providers = {LLMProvider.GEMINI: mock_provider}
        
        return agent

    def test_analyze_endpoint_returns_decision(self, agent_with_mock, sample_endpoint):
        """Test analyze_endpoint returns AIAttackDecision."""
        decision = agent_with_mock.analyze_endpoint(sample_endpoint)
        
        assert decision is not None
        assert decision.endpoint == sample_endpoint
        assert AttackType.SQL_INJECTION in decision.recommended_attacks
        assert decision.reasoning == "Test reasoning"

    def test_analyze_endpoint_handles_error(self, sample_endpoint):
        """Test analyze_endpoint falls back on error."""
        mock_provider = MockLLMProvider()
        mock_provider.generate = MagicMock(side_effect=Exception("API error"))
        
        agent = object.__new__(SentinelAgent)
        agent.active_provider = mock_provider
        agent.providers = {}
        
        decision = agent.analyze_endpoint(sample_endpoint)
        
        # Should return fallback decision
        assert decision is not None
        assert "Fallback" in decision.reasoning

    def test_build_prompt_includes_endpoint_info(self, sample_endpoint):
        """Test _build_prompt includes all endpoint information."""
        agent = object.__new__(SentinelAgent)
        
        prompt = agent._build_prompt(sample_endpoint)
        
        assert sample_endpoint.path in prompt
        assert sample_endpoint.method.value in prompt
        assert json.dumps(sample_endpoint.parameters[0].name) in prompt or sample_endpoint.parameters[0].name in prompt

    def test_build_prompt_handles_no_parameters(self):
        """Test _build_prompt handles endpoint without parameters."""
        endpoint = Endpoint(path="/health", method=HttpMethod.GET)
        
        agent = object.__new__(SentinelAgent)
        prompt = agent._build_prompt(endpoint)
        
        assert "parameters" in prompt.lower()

    def test_build_prompt_includes_security(self):
        """Test _build_prompt includes security info."""
        endpoint = Endpoint(
            path="/protected",
            method=HttpMethod.GET,
            security=[{"bearerAuth": []}]
        )
        
        agent = object.__new__(SentinelAgent)
        prompt = agent._build_prompt(endpoint)
        
        assert "requires_auth" in prompt


# ============================================================================
# LLM CALL WITH RETRY TESTS
# ============================================================================

class TestCallLLMWithRetry:
    """Tests for _call_llm_with_retry method."""

    def test_successful_call(self):
        """Test successful LLM call."""
        mock_provider = MockLLMProvider(response="Test response")
        
        agent = object.__new__(SentinelAgent)
        agent.active_provider = mock_provider
        agent.SYSTEM_PROMPT = "System prompt"
        
        response = agent._call_llm_with_retry("test prompt", max_retries=1)
        
        assert response == "Test response"

    def test_retry_on_failure(self):
        """Test retry on transient failure."""
        mock_provider = MockLLMProvider()
        call_count = [0]
        
        def mock_generate(*args):
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Transient error")
            return "Success"
        
        mock_provider.generate = mock_generate
        
        agent = object.__new__(SentinelAgent)
        agent.active_provider = mock_provider
        agent.SYSTEM_PROMPT = "System prompt"
        
        with patch('time.sleep'):  # Speed up test
            response = agent._call_llm_with_retry("test prompt", max_retries=3)
        
        assert response == "Success"
        assert call_count[0] == 3

    def test_raises_after_max_retries(self):
        """Test raises error after max retries."""
        mock_provider = MockLLMProvider()
        mock_provider.generate = MagicMock(side_effect=Exception("Persistent error"))
        
        agent = object.__new__(SentinelAgent)
        agent.active_provider = mock_provider
        agent.SYSTEM_PROMPT = "System prompt"
        
        with patch('time.sleep'):
            with pytest.raises(AIAgentError) as exc_info:
                agent._call_llm_with_retry("test prompt", max_retries=2)
            
            assert "failed after" in str(exc_info.value)


# ============================================================================
# JSON EXTRACTION TESTS
# ============================================================================

class TestJsonExtraction:
    """Tests for _extract_json method."""

    @pytest.fixture
    def agent(self):
        agent = object.__new__(SentinelAgent)
        return agent

    def test_extract_json_from_code_block(self, agent):
        """Test extracting JSON from code block."""
        text = '''
        Here is the response:
        ```json
        {"key": "value"}
        ```
        '''
        
        result = agent._extract_json(text)
        assert json.loads(result) == {"key": "value"}

    def test_extract_json_from_plain_block(self, agent):
        """Test extracting JSON from plain code block."""
        text = '''
        ```
        {"key": "value"}
        ```
        '''
        
        result = agent._extract_json(text)
        assert json.loads(result) == {"key": "value"}

    def test_extract_raw_json(self, agent):
        """Test extracting raw JSON object."""
        text = 'Here is JSON: {"key": "value"} end'
        
        result = agent._extract_json(text)
        assert json.loads(result) == {"key": "value"}

    def test_extract_nested_json(self, agent):
        """Test extracting nested JSON."""
        text = '{"outer": {"inner": ["a", "b"]}}'
        
        result = agent._extract_json(text)
        parsed = json.loads(result)
        assert parsed["outer"]["inner"] == ["a", "b"]

    def test_return_original_if_no_json(self, agent):
        """Test returns original text if no JSON found."""
        text = "This is just plain text"
        
        result = agent._extract_json(text)
        assert result == text


# ============================================================================
# RESPONSE PARSING TESTS
# ============================================================================

class TestResponseParsing:
    """Tests for _parse_response method."""

    @pytest.fixture
    def agent(self):
        agent = object.__new__(SentinelAgent)
        return agent

    def test_parse_valid_response(self, agent, sample_endpoint):
        """Test parsing valid JSON response."""
        response = json.dumps({
            "recommended_attacks": ["sql_injection", "xss"],
            "parameters_to_test": ["id"],
            "priority": 1,
            "reasoning": "Test reasoning"
        })
        
        decision = agent._parse_response(response, sample_endpoint)
        
        assert len(decision.recommended_attacks) == 2
        assert AttackType.SQL_INJECTION in decision.recommended_attacks
        assert decision.priority == 1

    def test_parse_response_in_code_block(self, agent, sample_endpoint):
        """Test parsing response in code block."""
        response = '''
        ```json
        {
            "recommended_attacks": ["idor"],
            "priority": 2,
            "reasoning": "ID in path"
        }
        ```
        '''
        
        decision = agent._parse_response(response, sample_endpoint)
        
        assert AttackType.IDOR in decision.recommended_attacks

    def test_parse_invalid_attack_type_ignored(self, agent, sample_endpoint):
        """Test invalid attack types are ignored."""
        response = json.dumps({
            "recommended_attacks": ["sql_injection", "invalid_attack", "xss"],
            "priority": 1,
            "reasoning": "Test"
        })
        
        decision = agent._parse_response(response, sample_endpoint)
        
        # Only valid attacks should be included
        valid_attacks = [a for a in decision.recommended_attacks]
        assert AttackType.SQL_INJECTION in valid_attacks
        assert AttackType.XSS in valid_attacks

    def test_parse_defaults_to_all_attacks_if_empty(self, agent, sample_endpoint):
        """Test defaults to all attacks if none specified."""
        response = json.dumps({
            "recommended_attacks": [],
            "priority": 3,
            "reasoning": "Test"
        })
        
        decision = agent._parse_response(response, sample_endpoint)
        
        # Should default to all attack types
        assert len(decision.recommended_attacks) == len(AttackType)

    def test_parse_invalid_json_falls_back(self, agent, sample_endpoint):
        """Test invalid JSON triggers fallback."""
        response = "This is not JSON"
        
        decision = agent._parse_response(response, sample_endpoint)
        
        # Should return fallback decision
        assert "Fallback" in decision.reasoning


# ============================================================================
# FALLBACK DECISION TESTS
# ============================================================================

class TestFallbackDecision:
    """Tests for _fallback_decision method."""

    @pytest.fixture
    def agent(self):
        agent = object.__new__(SentinelAgent)
        return agent

    def test_fallback_for_parameter_endpoint(self, agent, sample_endpoint):
        """Test fallback decision for endpoint with parameters."""
        decision = agent._fallback_decision(sample_endpoint, "Test error")
        
        assert AttackType.SQL_INJECTION in decision.recommended_attacks
        assert AttackType.XSS in decision.recommended_attacks
        assert "Fallback" in decision.reasoning

    def test_fallback_for_protected_endpoint(self, agent):
        """Test fallback decision for protected endpoint."""
        endpoint = Endpoint(
            path="/admin/users",
            method=HttpMethod.DELETE,
            security=[{"bearerAuth": []}]
        )
        
        decision = agent._fallback_decision(endpoint, "Test error")
        
        assert AttackType.AUTH_BYPASS in decision.recommended_attacks
        assert AttackType.JWT in decision.recommended_attacks
        assert decision.priority == 1  # Highest priority for DELETE with auth

    def test_fallback_for_idor_endpoint(self, agent):
        """Test fallback includes IDOR for ID parameters."""
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="user_id", location="path", required=True)]
        )
        
        decision = agent._fallback_decision(endpoint, "Test error")
        
        assert AttackType.IDOR in decision.recommended_attacks

    def test_fallback_for_ssrf_endpoint(self, agent):
        """Test fallback includes SSRF for URL parameters."""
        endpoint = Endpoint(
            path="/webhook",
            method=HttpMethod.POST,
            parameters=[Parameter(name="callback_url", location="body", required=True)]
        )
        
        decision = agent._fallback_decision(endpoint, "Test error")
        
        assert AttackType.SSRF in decision.recommended_attacks

    def test_fallback_includes_rate_limit(self, agent, sample_endpoint):
        """Test fallback always includes rate_limit."""
        decision = agent._fallback_decision(sample_endpoint, "Test error")
        
        assert AttackType.RATE_LIMIT in decision.recommended_attacks

    def test_fallback_priority_levels(self, agent):
        """Test fallback priority assignment."""
        # High priority: DELETE with auth
        endpoint1 = Endpoint(
            path="/admin/delete",
            method=HttpMethod.DELETE,
            security=[{"bearerAuth": []}]
        )
        decision1 = agent._fallback_decision(endpoint1, "Test")
        assert decision1.priority == 1
        
        # Medium priority: GET with auth
        endpoint2 = Endpoint(
            path="/protected",
            method=HttpMethod.GET,
            security=[{"bearerAuth": []}]
        )
        decision2 = agent._fallback_decision(endpoint2, "Test")
        assert decision2.priority == 2
        
        # Lower priority: Public endpoint
        endpoint3 = Endpoint(path="/public", method=HttpMethod.GET)
        decision3 = agent._fallback_decision(endpoint3, "Test")
        assert decision3.priority == 3

    def test_fallback_no_duplicate_attacks(self, agent):
        """Test fallback removes duplicate attacks."""
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.GET,
            parameters=[
                Parameter(name="id", location="path", required=True),
                Parameter(name="user_id", location="query", required=False)
            ],
            security=[{"bearerAuth": []}]
        )
        
        decision = agent._fallback_decision(endpoint, "Test")
        
        # Count occurrences of each attack type
        attack_counts = {}
        for attack in decision.recommended_attacks:
            attack_counts[attack] = attack_counts.get(attack, 0) + 1
        
        # All should be exactly 1
        for count in attack_counts.values():
            assert count == 1


# ============================================================================
# BATCH ANALYSIS TESTS
# ============================================================================

class TestBatchAnalysis:
    """Tests for analyze_batch method."""

    def test_analyze_batch_processes_all(self, sample_endpoints):
        """Test analyze_batch processes all endpoints."""
        mock_provider = MockLLMProvider(
            response=json.dumps({
                "recommended_attacks": ["sql_injection"],
                "priority": 1,
                "reasoning": "Test"
            })
        )
        
        agent = object.__new__(SentinelAgent)
        agent.active_provider = mock_provider
        agent.providers = {}
        
        with patch('time.sleep'):  # Speed up test
            decisions = agent.analyze_batch(sample_endpoints)
        
        assert len(decisions) == len(sample_endpoints)
        for decision in decisions:
            assert decision is not None

    def test_analyze_batch_empty_list(self):
        """Test analyze_batch with empty list."""
        agent = object.__new__(SentinelAgent)
        agent.active_provider = MockLLMProvider()
        
        decisions = agent.analyze_batch([])
        
        assert decisions == []


# ============================================================================
# CREATE AGENT CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestCreateAgent:
    """Tests for create_agent convenience function."""

    def test_create_agent_default_provider(self, mock_env_api_keys):
        """Test create_agent with default provider."""
        with patch.object(SentinelAgent, '_init_providers'):
            with patch.object(SentinelAgent, '_get_active_provider', return_value=MockLLMProvider()):
                agent = create_agent()
                assert agent is not None

    def test_create_agent_with_provider(self, mock_env_api_keys):
        """Test create_agent with specific provider."""
        with patch.object(SentinelAgent, '_init_providers'):
            with patch.object(SentinelAgent, '_get_active_provider', return_value=MockLLMProvider()):
                agent = create_agent(provider=LLMProvider.OPENAI)
                assert agent is not None

    def test_create_agent_with_api_key(self, mock_env_api_keys):
        """Test create_agent with API key."""
        with patch.object(SentinelAgent, '_init_providers'):
            with patch.object(SentinelAgent, '_get_active_provider', return_value=MockLLMProvider()):
                agent = create_agent(api_key="test-key")
                assert agent is not None


# ============================================================================
# SYSTEM PROMPT TESTS
# ============================================================================

class TestSystemPrompt:
    """Tests for system prompt."""

    def test_system_prompt_exists(self):
        """Test system prompt is defined."""
        assert SentinelAgent.SYSTEM_PROMPT is not None

    def test_system_prompt_contains_attack_types(self):
        """Test system prompt mentions attack types."""
        prompt = SentinelAgent.SYSTEM_PROMPT
        
        assert "sql_injection" in prompt
        assert "xss" in prompt
        assert "auth_bypass" in prompt
        assert "idor" in prompt
        assert "ssrf" in prompt

    def test_system_prompt_specifies_json_format(self):
        """Test system prompt specifies JSON format."""
        prompt = SentinelAgent.SYSTEM_PROMPT
        
        assert "JSON" in prompt
        assert "recommended_attacks" in prompt
        assert "priority" in prompt
