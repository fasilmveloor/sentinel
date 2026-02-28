"""
AI Agent module with multi-LLM support.

This module uses AI to analyze API endpoints and determine optimal attack strategies.
Supports multiple LLM providers: Gemini, OpenAI, Claude, and local LLMs.

v2.0 Updates:
- Multi-LLM support (OpenAI, Claude)
- Pluggable architecture
- Improved fallback logic
"""

import os
import json
import time
from typing import Any, Optional
from abc import ABC, abstractmethod
from dotenv import load_dotenv

from .models import (
    Endpoint,
    AttackType,
    AIAttackDecision,
    HttpMethod,
    LLMProvider
)

# Load environment variables
load_dotenv()


class AIAgentError(Exception):
    """Raised when AI agent encounters an error."""
    pass


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str) -> str:
        """Generate a response from the LLM."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is available and configured."""
        pass


class GeminiProvider(BaseLLMProvider):
    """Google Gemini LLM provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        self.model = None
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def _initialize(self):
        if self.model is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-pro')
            except ImportError:
                raise AIAgentError("google-generativeai not installed. Run: pip install google-generativeai")
    
    def generate(self, prompt: str, system_prompt: str) -> str:
        self._initialize()
        
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        response = self.model.generate_content(
            full_prompt,
            generation_config={
                'temperature': 0.3,
                'max_output_tokens': 500,
            }
        )
        
        return response.text


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT LLM provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def _initialize(self):
        if self.client is None:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                raise AIAgentError("openai not installed. Run: pip install openai")
    
    def generate(self, prompt: str, system_prompt: str) -> str:
        self._initialize()
        
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        return response.choices[0].message.content


class ClaudeProvider(BaseLLMProvider):
    """Anthropic Claude LLM provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.client = None
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def _initialize(self):
        if self.client is None:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
            except ImportError:
                raise AIAgentError("anthropic not installed. Run: pip install anthropic")
    
    def generate(self, prompt: str, system_prompt: str) -> str:
        self._initialize()
        
        response = self.client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=500,
            system=system_prompt,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return response.content[0].text


class LocalLLMProvider(BaseLLMProvider):
    """Local LLM provider (Ollama, etc.)."""
    
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or os.getenv('LOCAL_LLM_URL', 'http://localhost:11434')
        self.model = os.getenv('LOCAL_LLM_MODEL', 'llama2')
    
    def is_available(self) -> bool:
        import requests
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def generate(self, prompt: str, system_prompt: str) -> str:
        import requests
        
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": f"{system_prompt}\n\n{prompt}",
                "stream": False
            },
            timeout=60
        )
        
        return response.json().get('response', '')


class SentinelAgent:
    """AI-powered security analysis agent with multi-LLM support."""
    
    SYSTEM_PROMPT = """You are Sentinel, an AI security testing assistant. Your role is to analyze API endpoints and recommend the most effective security tests.

You will receive information about an API endpoint including:
- HTTP method and path
- Parameters (query, path, body)
- Authentication requirements
- Request/response structure

For each endpoint, you must decide:
1. Which attack types are relevant (sql_injection, xss, auth_bypass, idor, ssrf, jwt, cmd_injection, rate_limit)
2. Which parameters should be tested
3. Priority level (1=highest, 5=lowest)
4. Brief reasoning for your decisions

Attack types explained:
- sql_injection: Test for SQL/NoSQL injection in parameters
- xss: Test for Cross-Site Scripting
- auth_bypass: Test if authentication can be bypassed
- idor: Test for Insecure Direct Object Reference
- ssrf: Test for Server-Side Request Forgery
- jwt: Test JWT vulnerabilities
- cmd_injection: Test for OS command injection
- rate_limit: Test for rate limiting issues

Respond in JSON format:
{
    "recommended_attacks": ["sql_injection", "xss"],
    "parameters_to_test": ["id", "name"],
    "priority": 1,
    "reasoning": "Brief explanation"
}

Be efficient - only recommend relevant attacks. Not all endpoints need all tests."""

    def __init__(
        self, 
        provider: LLMProvider = LLMProvider.GEMINI,
        api_key: Optional[str] = None
    ):
        """Initialize the AI agent.
        
        Args:
            provider: The LLM provider to use
            api_key: API key (optional, uses env vars if not provided)
        """
        self.provider_name = provider
        self.providers: dict[LLMProvider, BaseLLMProvider] = {}
        
        # Initialize all available providers
        self._init_providers(api_key)
        
        # Set active provider
        self.active_provider = self._get_active_provider(provider)
        
        if not self.active_provider:
            raise AIAgentError(
                f"No LLM provider available. Set API key for {provider.value} "
                f"or another provider."
            )
    
    def _init_providers(self, api_key: Optional[str]):
        """Initialize all LLM providers."""
        # Gemini
        gemini = GeminiProvider(api_key if self.provider_name == LLMProvider.GEMINI else None)
        if gemini.is_available():
            self.providers[LLMProvider.GEMINI] = gemini
        
        # OpenAI
        openai = OpenAIProvider(api_key if self.provider_name == LLMProvider.OPENAI else None)
        if openai.is_available():
            self.providers[LLMProvider.OPENAI] = openai
        
        # Claude
        claude = ClaudeProvider(api_key if self.provider_name == LLMProvider.CLAUDE else None)
        if claude.is_available():
            self.providers[LLMProvider.CLAUDE] = claude
        
        # Local
        local = LocalLLMProvider()
        if local.is_available():
            self.providers[LLMProvider.LOCAL] = local
    
    def _get_active_provider(self, preferred: LLMProvider) -> Optional[BaseLLMProvider]:
        """Get the active provider, falling back to available ones."""
        if preferred in self.providers:
            return self.providers[preferred]
        
        # Fallback order
        fallback_order = [
            LLMProvider.GEMINI,
            LLMProvider.OPENAI,
            LLMProvider.CLAUDE,
            LLMProvider.LOCAL
        ]
        
        for provider in fallback_order:
            if provider in self.providers:
                self.provider_name = provider
                return self.providers[provider]
        
        return None
    
    def analyze_endpoint(self, endpoint: Endpoint) -> AIAttackDecision:
        """Analyze an endpoint and determine attack strategy.
        
        Args:
            endpoint: The endpoint to analyze
            
        Returns:
            AIAttackDecision with recommended attacks
        """
        prompt = self._build_prompt(endpoint)
        
        try:
            # Call LLM with retry logic
            response = self._call_llm_with_retry(prompt)
            
            # Parse the response
            decision = self._parse_response(response, endpoint)
            
            return decision
            
        except Exception as e:
            # Fallback to rule-based decision if AI fails
            return self._fallback_decision(endpoint, str(e))
    
    def _build_prompt(self, endpoint: Endpoint) -> str:
        """Build the analysis prompt for an endpoint."""
        endpoint_info = {
            'method': endpoint.method.value,
            'path': endpoint.path,
            'summary': endpoint.summary,
            'parameters': [
                {
                    'name': p.name,
                    'location': p.location,
                    'required': p.required,
                    'type': p.param_type
                }
                for p in endpoint.parameters
            ],
            'requires_auth': endpoint.requires_auth,
            'has_request_body': endpoint.request_body is not None,
            'security': endpoint.security
        }
        
        return f"""Analyze this API endpoint and recommend security tests:

{json.dumps(endpoint_info, indent=2)}

Remember to respond in JSON format with recommended_attacks, parameters_to_test, priority, and reasoning."""
    
    def _call_llm_with_retry(self, prompt: str, max_retries: int = 3) -> str:
        """Call LLM API with exponential backoff retry."""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                return self.active_provider.generate(prompt, self.SYSTEM_PROMPT)
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 1
                    time.sleep(wait_time)
        
        raise AIAgentError(f"LLM call failed after {max_retries} retries: {last_error}")
    
    def _parse_response(self, response: str, endpoint: Endpoint) -> AIAttackDecision:
        """Parse the AI response into a decision object."""
        try:
            # Extract JSON from response
            json_str = self._extract_json(response)
            data = json.loads(json_str)
            
            # Validate and convert attack types
            attack_types = []
            for attack in data.get('recommended_attacks', []):
                try:
                    attack_types.append(AttackType(attack))
                except ValueError:
                    pass
            
            # Default to all attacks if none specified
            if not attack_types:
                attack_types = list(AttackType)
            
            return AIAttackDecision(
                endpoint=endpoint,
                recommended_attacks=attack_types,
                reasoning=data.get('reasoning', 'AI analysis'),
                priority=data.get('priority', 3),
                parameters_to_test=data.get('parameters_to_test', [])
            )
            
        except json.JSONDecodeError:
            return self._fallback_decision(endpoint, "Failed to parse AI response")
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from response text."""
        import re
        
        # Look for ```json ... ``` blocks
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if json_match:
            return json_match.group(1)
        
        # Look for raw JSON object
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            return json_match.group(0)
        
        return text
    
    def _fallback_decision(self, endpoint: Endpoint, error: str) -> AIAttackDecision:
        """Generate a rule-based decision when AI is unavailable."""
        attacks = []
        params_to_test = [p.name for p in endpoint.parameters]
        reasoning = f"Fallback decision (AI unavailable: {error})"
        
        # SQL injection for endpoints with parameters
        if endpoint.parameters:
            attacks.append(AttackType.SQL_INJECTION)
            attacks.append(AttackType.XSS)
        
        # Auth bypass for protected endpoints
        if endpoint.requires_auth:
            attacks.append(AttackType.AUTH_BYPASS)
            attacks.append(AttackType.JWT)
        
        # IDOR for endpoints with ID-like parameters
        id_params = [p.name for p in endpoint.parameters 
                     if 'id' in p.name.lower()]
        if id_params or '{id}' in endpoint.path:
            attacks.append(AttackType.IDOR)
        
        # SSRF for endpoints with URL-like parameters
        url_params = [p.name for p in endpoint.parameters 
                      if any(k in p.name.lower() for k in ['url', 'link', 'callback'])]
        if url_params:
            attacks.append(AttackType.SSRF)
        
        # Rate limit for all endpoints
        attacks.append(AttackType.RATE_LIMIT)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_attacks = []
        for a in attacks:
            if a not in seen:
                seen.add(a)
                unique_attacks.append(a)
        
        # Determine priority
        if endpoint.requires_auth and endpoint.method in [HttpMethod.DELETE, HttpMethod.PUT]:
            priority = 1
        elif endpoint.requires_auth:
            priority = 2
        else:
            priority = 3
        
        return AIAttackDecision(
            endpoint=endpoint,
            recommended_attacks=unique_attacks,
            reasoning=reasoning,
            priority=priority,
            parameters_to_test=params_to_test
        )
    
    def analyze_batch(self, endpoints: list[Endpoint]) -> list[AIAttackDecision]:
        """Analyze multiple endpoints efficiently.
        
        Args:
            endpoints: List of endpoints to analyze
            
        Returns:
            List of attack decisions
        """
        decisions = []
        
        for endpoint in endpoints:
            decision = self.analyze_endpoint(endpoint)
            decisions.append(decision)
            
            # Small delay to avoid rate limiting
            time.sleep(0.1)
        
        return decisions


def create_agent(
    provider: LLMProvider = LLMProvider.GEMINI,
    api_key: Optional[str] = None
) -> SentinelAgent:
    """Convenience function to create an AI agent.
    
    Args:
        provider: The LLM provider to use
        api_key: Optional API key
        
    Returns:
        Initialized SentinelAgent
    """
    return SentinelAgent(provider=provider, api_key=api_key)
