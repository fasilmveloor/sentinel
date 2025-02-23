"""
AI Agent module using Google Gemini.

This module uses AI to analyze API endpoints and determine optimal attack strategies.
The agent considers endpoint characteristics to prioritize and select attacks.
"""

import os
import json
import time
from typing import Any, Optional
from dotenv import load_dotenv

from .models import (
    Endpoint,
    AttackType,
    AIAttackDecision,
    HttpMethod
)

# Load environment variables
load_dotenv()


class AIAgentError(Exception):
    """Raised when AI agent encounters an error."""
    pass


class SentinelAgent:
    """AI-powered security analysis agent using Google Gemini."""
    
    SYSTEM_PROMPT = """You are Sentinel, an AI security testing assistant. Your role is to analyze API endpoints and recommend the most effective security tests.

You will receive information about an API endpoint including:
- HTTP method and path
- Parameters (query, path, body)
- Authentication requirements
- Request/response structure

For each endpoint, you must decide:
1. Which attack types are relevant (sql_injection, auth_bypass, idor)
2. Which parameters should be tested
3. Priority level (1=highest, 5=lowest)
4. Brief reasoning for your decisions

Attack types explained:
- sql_injection: Test for SQL/NoSQL injection in parameters
- auth_bypass: Test if authentication can be bypassed
- idor: Test for Insecure Direct Object Reference

Respond in JSON format:
{
    "recommended_attacks": ["sql_injection", "auth_bypass"],
    "parameters_to_test": ["id", "user_id"],
    "priority": 1,
    "reasoning": "Brief explanation"
}

Be efficient - only recommend relevant attacks. Not all endpoints need all tests."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI agent.
        
        Args:
            api_key: Google Gemini API key (defaults to GEMINI_API_KEY env var)
        """
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise AIAgentError(
                "Gemini API key not found. Set GEMINI_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        self.model = None
        self._initialize_gemini()
    
    def _initialize_gemini(self) -> None:
        """Initialize the Gemini model."""
        try:
            import google.generativeai as genai
            
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            
        except ImportError:
            raise AIAgentError(
                "google-generativeai package not installed. "
                "Run: pip install google-generativeai"
            )
        except Exception as e:
            raise AIAgentError(f"Failed to initialize Gemini: {e}")
    
    def analyze_endpoint(self, endpoint: Endpoint) -> AIAttackDecision:
        """Analyze an endpoint and determine attack strategy.
        
        Args:
            endpoint: The endpoint to analyze
            
        Returns:
            AIAttackDecision with recommended attacks
        """
        # Build the prompt with endpoint information
        prompt = self._build_prompt(endpoint)
        
        try:
            # Call Gemini API with retry logic
            response = self._call_gemini_with_retry(prompt)
            
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
    
    def _call_gemini_with_retry(self, prompt: str, max_retries: int = 3) -> str:
        """Call Gemini API with exponential backoff retry."""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config={
                        'temperature': 0.3,  # Lower temperature for more consistent output
                        'max_output_tokens': 500,
                    }
                )
                
                return response.text
                
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 1  # Exponential backoff
                    time.sleep(wait_time)
        
        raise AIAgentError(f"Gemini API call failed after {max_retries} retries: {last_error}")
    
    def _parse_response(self, response: str, endpoint: Endpoint) -> AIAttackDecision:
        """Parse the AI response into a decision object."""
        try:
            # Extract JSON from response (might be wrapped in markdown)
            json_str = self._extract_json(response)
            data = json.loads(json_str)
            
            # Validate and convert attack types
            attack_types = []
            for attack in data.get('recommended_attacks', []):
                try:
                    attack_types.append(AttackType(attack))
                except ValueError:
                    pass  # Skip invalid attack types
            
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
        # Try to find JSON in markdown code blocks
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
        
        # Auth bypass for protected endpoints
        if endpoint.requires_auth or endpoint.method in [HttpMethod.GET, HttpMethod.POST]:
            attacks.append(AttackType.AUTH_BYPASS)
        
        # IDOR for endpoints with ID-like parameters
        id_params = [p.name for p in endpoint.parameters 
                     if 'id' in p.name.lower()]
        if id_params or '{id}' in endpoint.path:
            attacks.append(AttackType.IDOR)
        
        # Default to all if nothing matched
        if not attacks:
            attacks = list(AttackType)
        
        # Determine priority
        if endpoint.requires_auth and endpoint.method in [HttpMethod.DELETE, HttpMethod.PUT]:
            priority = 1
        elif endpoint.requires_auth:
            priority = 2
        else:
            priority = 3
        
        return AIAttackDecision(
            endpoint=endpoint,
            recommended_attacks=attacks,
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


def create_agent(api_key: Optional[str] = None) -> SentinelAgent:
    """Convenience function to create an AI agent.
    
    Args:
        api_key: Optional Gemini API key
        
    Returns:
        Initialized SentinelAgent
    """
    return SentinelAgent(api_key=api_key)
