"""
Autonomous Scanning Agent for Sentinel.

This module implements a multi-agent system for autonomous API security testing:
- Planner Agent: Strategic decision making
- Executor Agent: Attack execution
- Analyzer Agent: Result interpretation
- Attack Chain Discovery: Multi-step vulnerability finding

v2.5 Feature: Agentic OWASP ZAP
"""

import asyncio
import time
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from .models import (
    Endpoint,
    AttackResult,
    AttackType,
    HttpMethod,
    Severity
)
from .agent import SentinelAgent, create_agent, LLMProvider
from .attacks import (
    SQLInjectionAttacker,
    AuthBypassAttacker,
    IDORAttacker,
    XSSAttacker,
    SSRFAttacker,
    JWTAttacker,
    CommandInjectionAttacker,
    RateLimitAttacker
)


class AgentState(Enum):
    """State of the autonomous agent."""
    IDLE = "idle"
    PLANNING = "planning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    CHAIN_DISCOVERY = "chain_discovery"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class ScanPlan:
    """AI-generated scan plan."""
    target_endpoints: list[Endpoint]
    attack_sequence: list[dict]
    estimated_time: int  # seconds
    risk_score: float
    reasoning: str
    priority_map: dict[AttackType, int] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a discovered attack chain."""
    name: str
    steps: list[AttackResult]
    severity: Severity
    description: str
    exploit_path: str
    confidence: float


@dataclass
class AutonomousScanResult:
    """Result of an autonomous scan."""
    start_time: datetime
    end_time: Optional[datetime] = None
    state: AgentState = AgentState.IDLE
    plan: Optional[ScanPlan] = None
    findings: list[AttackResult] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    endpoints_scanned: int = 0
    total_requests: int = 0
    ai_decisions: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class PlannerAgent:
    """
    Strategic planner agent that decides what to test and in what order.
    
    Uses AI to analyze API structure and create optimal testing strategies.
    """
    
    PLANNING_PROMPT = """You are a security expert planning an API penetration test.

Analyze the following API endpoints and create an optimal testing strategy:

{endpoints_info}

For each endpoint, consider:
1. HTTP method (GET safer, DELETE/PUT higher risk)
2. Authentication requirements
3. Parameters that could be injected
4. Potential attack surface

Create a testing plan in JSON format:
{{
    "attack_sequence": [
        {{
            "endpoint_index": 0,
            "attack_types": ["sql_injection", "auth_bypass"],
            "priority": 1,
            "reasoning": "Why this endpoint and attacks first"
        }}
    ],
    "estimated_time_seconds": 120,
    "risk_score": 8.5,
    "reasoning": "Overall strategy explanation",
    "priority_attacks": {{
        "sql_injection": 1,
        "auth_bypass": 2,
        "idor": 3
    }}
}}

Prioritize:
1. Authentication endpoints (auth bypass, JWT)
2. User data access (IDOR, injection)
3. Admin functionality (privilege escalation)
4. Search/query parameters (injection)
5. File/upload endpoints (command injection, SSRF)

Be efficient - focus on high-impact tests first."""

    def __init__(self, ai_agent: SentinelAgent):
        self.ai_agent = ai_agent
    
    async def create_plan(self, endpoints: list[Endpoint]) -> ScanPlan:
        """Create an intelligent scan plan based on endpoint analysis."""
        
        # Build endpoints info for AI
        endpoints_info = self._build_endpoints_info(endpoints)
        
        # Get AI planning decision
        try:
            response = await asyncio.to_thread(
                self.ai_agent.active_provider.generate,
                self.PLANNING_PROMPT.format(endpoints_info=endpoints_info),
                self.ai_agent.SYSTEM_PROMPT
            )
            
            plan_data = self._parse_plan_response(response, endpoints)
            
        except Exception as e:
            # Fallback to rule-based planning
            plan_data = self._fallback_plan(endpoints)
        
        return ScanPlan(
            target_endpoints=endpoints,
            attack_sequence=plan_data.get('attack_sequence', []),
            estimated_time=plan_data.get('estimated_time_seconds', 300),
            risk_score=plan_data.get('risk_score', 5.0),
            reasoning=plan_data.get('reasoning', 'Rule-based fallback plan'),
            priority_map=plan_data.get('priority_attacks', {})
        )
    
    def _build_endpoints_info(self, endpoints: list[Endpoint]) -> str:
        """Build formatted endpoint information for AI."""
        info_lines = []
        for i, ep in enumerate(endpoints):
            params = [f"{p.name}({p.location})" for p in ep.parameters]
            info_lines.append(
                f"[{i}] {ep.method.value} {ep.path}\n"
                f"    Auth: {ep.requires_auth}, Params: {', '.join(params) or 'none'}\n"
                f"    Summary: {ep.summary or 'N/A'}"
            )
        return "\n".join(info_lines)
    
    def _parse_plan_response(self, response: str, endpoints: list[Endpoint]) -> dict:
        """Parse AI response into plan data."""
        import json
        import re
        
        # Extract JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        return self._fallback_plan(endpoints)
    
    def _fallback_plan(self, endpoints: list[Endpoint]) -> dict:
        """Create a rule-based fallback plan."""
        attack_sequence = []
        priority_attacks = {}
        
        # Score and sort endpoints
        scored_endpoints = []
        for i, ep in enumerate(endpoints):
            score = self._score_endpoint(ep)
            scored_endpoints.append((i, ep, score))
        
        scored_endpoints.sort(key=lambda x: x[2], reverse=True)
        
        # Build attack sequence
        for i, ep, score in scored_endpoints:
            attacks = self._determine_attacks(ep)
            if attacks:
                attack_sequence.append({
                    'endpoint_index': i,
                    'attack_types': [a.value for a in attacks],
                    'priority': 5 - min(score, 4),
                    'reasoning': f'Risk score: {score}'
                })
        
        return {
            'attack_sequence': attack_sequence,
            'estimated_time_seconds': len(endpoints) * 30,
            'risk_score': sum(s for _, _, s in scored_endpoints) / len(scored_endpoints) if scored_endpoints else 5.0,
            'reasoning': 'Rule-based prioritization',
            'priority_attacks': priority_attacks
        }
    
    def _score_endpoint(self, endpoint: Endpoint) -> float:
        """Score endpoint risk (0-10)."""
        score = 0.0
        
        # Method risk
        method_risk = {
            HttpMethod.GET: 1,
            HttpMethod.POST: 2,
            HttpMethod.PUT: 3,
            HttpMethod.PATCH: 3,
            HttpMethod.DELETE: 4
        }
        score += method_risk.get(endpoint.method, 1)
        
        # Auth required
        if endpoint.requires_auth:
            score += 2
        
        # Has parameters
        if endpoint.parameters:
            score += min(len(endpoint.parameters), 3)
        
        # ID-like parameters
        id_params = [p for p in endpoint.parameters if 'id' in p.name.lower()]
        score += len(id_params) * 1.5
        
        # Sensitive paths
        sensitive_keywords = ['admin', 'user', 'auth', 'password', 'token', 'payment', 'account']
        if any(kw in endpoint.path.lower() for kw in sensitive_keywords):
            score += 2
        
        return min(score, 10)
    
    def _determine_attacks(self, endpoint: Endpoint) -> list[AttackType]:
        """Determine relevant attack types for an endpoint."""
        attacks = []
        
        # Injection for parameters
        if endpoint.parameters:
            attacks.append(AttackType.SQL_INJECTION)
            attacks.append(AttackType.XSS)
        
        # Auth testing
        if endpoint.requires_auth:
            attacks.append(AttackType.AUTH_BYPASS)
            attacks.append(AttackType.JWT)
        
        # IDOR for ID parameters
        if any('id' in p.name.lower() for p in endpoint.parameters):
            attacks.append(AttackType.IDOR)
        
        # SSRF for URL parameters
        if any(kw in endpoint.path.lower() for kw in ['callback', 'url', 'webhook', 'fetch']):
            attacks.append(AttackType.SSRF)
        
        # Rate limiting for all
        attacks.append(AttackType.RATE_LIMIT)
        
        return list(set(attacks))


class ExecutorAgent:
    """
    Executes attacks based on the scan plan.
    
    Handles concurrent execution, rate limiting, and error recovery.
    """
    
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.attackers = {
            AttackType.SQL_INJECTION: SQLInjectionAttacker(),
            AttackType.AUTH_BYPASS: AuthBypassAttacker(),
            AttackType.IDOR: IDORAttacker(),
            AttackType.XSS: XSSAttacker(),
            AttackType.SSRF: SSRFAttacker(),
            AttackType.JWT: JWTAttacker(),
            AttackType.CMD_INJECTION: CommandInjectionAttacker(),
            AttackType.RATE_LIMIT: RateLimitAttacker(),
        }
        self.total_requests = 0
    
    async def execute_plan(
        self,
        plan: ScanPlan,
        base_url: str,
        headers: Optional[dict] = None,
        progress_callback: Optional[callable] = None
    ) -> list[AttackResult]:
        """Execute the scan plan asynchronously."""
        
        results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def execute_attack(attack_info: dict) -> list[AttackResult]:
            async with semaphore:
                endpoint_idx = attack_info['endpoint_index']
                attack_types = attack_info['attack_types']
                
                if endpoint_idx >= len(plan.target_endpoints):
                    return []
                
                endpoint = plan.target_endpoints[endpoint_idx]
                attack_results = []
                
                for attack_type_str in attack_types:
                    try:
                        attack_type = AttackType(attack_type_str)
                        attacker = self.attackers.get(attack_type)
                        
                        if attacker:
                            # Run attack in thread pool
                            attack_result = await asyncio.to_thread(
                                attacker.attack,
                                base_url,
                                endpoint,
                                headers or {}
                            )
                            
                            if isinstance(attack_result, list):
                                attack_results.extend(attack_result)
                                self.total_requests += len(attack_result)
                            elif attack_result:
                                attack_results.append(attack_result)
                                self.total_requests += 1
                            
                            if progress_callback:
                                await progress_callback(endpoint, attack_type, attack_result)
                                
                    except Exception as e:
                        # Log error but continue
                        print(f"Attack error: {e}")
                
                return attack_results
        
        # Execute attacks with priority ordering
        tasks = []
        for attack_info in sorted(plan.attack_sequence, key=lambda x: x.get('priority', 5)):
            tasks.append(execute_attack(attack_info))
        
        # Gather results
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in all_results:
            if isinstance(result, list):
                results.extend(result)
            elif isinstance(result, Exception):
                print(f"Task failed: {result}")
        
        return results


class AnalyzerAgent:
    """
    Analyzes scan results and identifies vulnerabilities.
    
    Uses AI to interpret results, reduce false positives, and discover attack chains.
    """
    
    ANALYSIS_PROMPT = """Analyze these security scan results and identify vulnerabilities:

Results:
{results_info}

For each finding:
1. Verify if it's a true positive or false positive
2. Assess actual severity
3. Identify if multiple findings form an attack chain

Respond in JSON format:
{{
    "verified_vulnerabilities": [
        {{
            "finding_index": 0,
            "is_true_positive": true,
            "actual_severity": "high",
            "confidence": 0.95,
            "explanation": "Why this is/isn't a real vulnerability"
        }}
    ],
    "attack_chains": [
        {{
            "name": "Account Takeover Chain",
            "step_indices": [0, 2, 5],
            "severity": "critical",
            "description": "IDOR + password reset token leak = full account takeover",
            "exploit_path": "Step 1: Use IDOR to access admin profile. Step 2: Extract password reset token. Step 3: Reset admin password."
        }}
    ],
    "summary": {{
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 1,
        "false_positives": 2
    }}
}}"""

    def __init__(self, ai_agent: SentinelAgent):
        self.ai_agent = ai_agent
    
    async def analyze_results(self, results: list[AttackResult]) -> dict:
        """Analyze scan results with AI."""
        
        if not results:
            return {'verified_vulnerabilities': [], 'attack_chains': [], 'summary': {}}
        
        # Build results info
        results_info = self._build_results_info(results)
        
        try:
            response = await asyncio.to_thread(
                self.ai_agent.active_provider.generate,
                self.ANALYSIS_PROMPT.format(results_info=results_info),
                "You are a security analyst. Analyze findings and identify attack patterns."
            )
            
            analysis = self._parse_analysis(response)
            
        except Exception as e:
            # Fallback to rule-based analysis
            analysis = self._fallback_analysis(results)
        
        return analysis
    
    def _build_results_info(self, results: list[AttackResult]) -> str:
        """Build formatted results information."""
        lines = []
        for i, r in enumerate(results):
            lines.append(
                f"[{i}] {r.attack_type.value} on {r.endpoint.path}\n"
                f"    Severity: {r.severity.value}, Success: {r.success}\n"
                f"    Evidence: {r.evidence[:100] if r.evidence else 'N/A'}..."
            )
        return "\n".join(lines)
    
    def _parse_analysis(self, response: str) -> dict:
        """Parse AI analysis response."""
        import json
        import re
        
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        return {'verified_vulnerabilities': [], 'attack_chains': [], 'summary': {}}
    
    def _fallback_analysis(self, results: list[AttackResult]) -> dict:
        """Rule-based fallback analysis."""
        verified = []
        chains = []
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'false_positives': 0}
        
        for i, r in enumerate(results):
            if r.success:
                severity = r.severity.value
                if severity in summary:
                    summary[severity] += 1
                
                verified.append({
                    'finding_index': i,
                    'is_true_positive': True,
                    'actual_severity': severity,
                    'confidence': 0.8,
                    'explanation': 'Automated detection'
                })
        
        return {
            'verified_vulnerabilities': verified,
            'attack_chains': chains,
            'summary': summary
        }
    
    async def discover_attack_chains(
        self,
        results: list[AttackResult]
    ) -> list[AttackChain]:
        """Discover multi-step attack chains from individual findings."""
        
        if len(results) < 2:
            return []
        
        analysis = await self.analyze_results(results)
        chains = []
        
        for chain_data in analysis.get('attack_chains', []):
            step_indices = chain_data.get('step_indices', [])
            steps = [results[i] for i in step_indices if i < len(results)]
            
            if steps:
                try:
                    severity = Severity(chain_data.get('severity', 'medium'))
                except ValueError:
                    severity = Severity.MEDIUM
                
                chains.append(AttackChain(
                    name=chain_data.get('name', 'Unknown Chain'),
                    steps=steps,
                    severity=severity,
                    description=chain_data.get('description', ''),
                    exploit_path=chain_data.get('exploit_path', ''),
                    confidence=0.85
                ))
        
        return chains


class AutonomousScanner:
    """
    Main orchestrator for autonomous API security scanning.
    
    Coordinates Planner, Executor, and Analyzer agents for fully autonomous testing.
    """
    
    def __init__(
        self,
        ai_provider: LLMProvider = LLMProvider.GEMINI,
        api_key: Optional[str] = None,
        max_concurrent: int = 5
    ):
        # Initialize AI agent
        self.ai_agent = create_agent(ai_provider, api_key)
        
        # Initialize sub-agents
        self.planner = PlannerAgent(self.ai_agent)
        self.executor = ExecutorAgent(max_concurrent)
        self.analyzer = AnalyzerAgent(self.ai_agent)
        
        # State
        self.current_scan: Optional[AutonomousScanResult] = None
    
    async def scan(
        self,
        endpoints: list[Endpoint],
        base_url: str,
        headers: Optional[dict] = None,
        progress_callback: Optional[callable] = None
    ) -> AutonomousScanResult:
        """
        Run an autonomous scan on the provided endpoints.
        
        Args:
            endpoints: List of API endpoints to test
            base_url: Base URL of the API
            headers: Optional headers for authentication
            progress_callback: Optional callback for progress updates
            
        Returns:
            AutonomousScanResult with all findings
        """
        
        # Initialize scan result
        result = AutonomousScanResult(
            start_time=datetime.now(),
            state=AgentState.PLANNING
        )
        self.current_scan = result
        
        try:
            # Phase 1: Planning
            print("🧠 Planning attack strategy...")
            result.plan = await self.planner.create_plan(endpoints)
            result.ai_decisions.append({
                'phase': 'planning',
                'reasoning': result.plan.reasoning,
                'risk_score': result.plan.risk_score
            })
            
            # Phase 2: Execution
            print(f"🎯 Executing {len(result.plan.attack_sequence)} attack sequences...")
            result.state = AgentState.SCANNING
            
            findings = await self.executor.execute_plan(
                result.plan,
                base_url,
                headers,
                progress_callback
            )
            result.findings = findings
            result.endpoints_scanned = len(endpoints)
            result.total_requests = self.executor.total_requests
            
            # Phase 3: Analysis
            print("🔍 Analyzing results and discovering attack chains...")
            result.state = AgentState.ANALYZING
            
            analysis = await self.analyzer.analyze_results(findings)
            result.summary = analysis.get('summary', {})
            
            # Phase 4: Attack Chain Discovery
            result.state = AgentState.CHAIN_DISCOVERY
            attack_chains = await self.analyzer.discover_attack_chains(findings)
            result.attack_chains = attack_chains
            
            # Complete
            result.state = AgentState.COMPLETED
            result.end_time = datetime.now()
            
        except Exception as e:
            result.state = AgentState.ERROR
            result.end_time = datetime.now()
            raise e
        
        return result
    
    def get_progress(self) -> dict:
        """Get current scan progress."""
        if not self.current_scan:
            return {'state': 'idle'}
        
        return {
            'state': self.current_scan.state.value,
            'endpoints_scanned': self.current_scan.endpoints_scanned,
            'findings_count': len(self.current_scan.findings),
            'chains_count': len(self.current_scan.attack_chains),
            'requests_made': self.current_scan.total_requests
        }


async def run_autonomous_scan(
    endpoints: list[Endpoint],
    base_url: str,
    headers: Optional[dict] = None,
    ai_provider: LLMProvider = LLMProvider.GEMINI,
    api_key: Optional[str] = None
) -> AutonomousScanResult:
    """
    Convenience function to run an autonomous scan.
    
    Args:
        endpoints: List of endpoints to test
        base_url: Target API base URL
        headers: Optional authentication headers
        ai_provider: LLM provider to use
        api_key: API key for the LLM
        
    Returns:
        AutonomousScanResult
    """
    scanner = AutonomousScanner(ai_provider=ai_provider, api_key=api_key)
    return await scanner.scan(endpoints, base_url, headers)
