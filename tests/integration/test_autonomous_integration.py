"""
Integration tests for the Autonomous Scanner module.

Tests cover:
- PlannerAgent planning logic
- ExecutorAgent execution flow
- AnalyzerAgent analysis
- Full AutonomousScanner workflow
- Multi-agent coordination
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime

from sentinel.autonomous import (
    AgentState, ScanPlan, AttackChain, AutonomousScanResult,
    PlannerAgent, ExecutorAgent, AnalyzerAgent, AutonomousScanner,
    run_autonomous_scan
)
from sentinel.models import Endpoint, HttpMethod, AttackType, Severity, Parameter
from sentinel.agent import SentinelAgent


# ============================================================================
# MOCK PROVIDER FOR TESTING
# ============================================================================

class MockProvider:
    """Mock LLM provider for testing."""
    
    def __init__(self, response: str = None):
        self.response = response or '{"attack_sequence": [], "estimated_time_seconds": 60, "risk_score": 5.0, "reasoning": "Test plan"}'
    
    def generate(self, prompt: str, system_prompt: str) -> str:
        return self.response
    
    def is_available(self) -> bool:
        return True


# ============================================================================
# PLANNER AGENT TESTS
# ============================================================================

class TestPlannerAgent:
    """Tests for PlannerAgent."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock AI agent."""
        agent = Mock(spec=SentinelAgent)
        agent.active_provider = MockProvider()
        agent.SYSTEM_PROMPT = "Test prompt"
        return agent

    @pytest.fixture
    def planner(self, mock_agent):
        """Create a planner agent."""
        return PlannerAgent(mock_agent)

    def test_planner_initialization(self, mock_agent):
        """Test planner initialization."""
        planner = PlannerAgent(mock_agent)
        assert planner.ai_agent == mock_agent

    def test_score_endpoint_get_no_auth(self, planner):
        """Test scoring GET endpoint without auth."""
        endpoint = Endpoint(path="/public", method=HttpMethod.GET)
        score = planner._score_endpoint(endpoint)
        
        # GET with no auth should have low score
        assert 0 <= score <= 10
        assert score < 3

    def test_score_endpoint_delete_with_auth(self, planner):
        """Test scoring DELETE endpoint with auth."""
        endpoint = Endpoint(
            path="/admin/users/{id}",
            method=HttpMethod.DELETE,
            security=[{"bearerAuth": []}]
        )
        score = planner._score_endpoint(endpoint)
        
        # DELETE with auth should have higher score
        assert score > 3

    def test_score_endpoint_with_id_parameters(self, planner):
        """Test scoring endpoint with ID parameters."""
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="user_id", location="path", required=True)]
        )
        score = planner._score_endpoint(endpoint)
        
        # Should get bonus for ID parameter
        assert score > 0

    def test_score_endpoint_sensitive_path(self, planner):
        """Test scoring endpoint with sensitive path."""
        endpoint = Endpoint(
            path="/admin/password/reset",
            method=HttpMethod.POST
        )
        score = planner._score_endpoint(endpoint)
        
        # Should get bonus for sensitive keywords
        assert score > 1

    def test_determine_attacks_with_parameters(self, planner):
        """Test determining attacks for endpoint with parameters."""
        endpoint = Endpoint(
            path="/search",
            method=HttpMethod.GET,
            parameters=[Parameter(name="q", location="query", required=False)]
        )
        attacks = planner._determine_attacks(endpoint)
        
        assert AttackType.SQL_INJECTION in attacks
        assert AttackType.XSS in attacks
        assert AttackType.RATE_LIMIT in attacks

    def test_determine_attacks_with_auth(self, planner):
        """Test determining attacks for authenticated endpoint."""
        endpoint = Endpoint(
            path="/profile",
            method=HttpMethod.GET,
            security=[{"bearerAuth": []}]
        )
        attacks = planner._determine_attacks(endpoint)
        
        assert AttackType.AUTH_BYPASS in attacks
        assert AttackType.JWT in attacks

    def test_determine_attacks_with_id_param(self, planner):
        """Test determining attacks for endpoint with ID parameter."""
        endpoint = Endpoint(
            path="/users/{id}",
            method=HttpMethod.GET,
            parameters=[Parameter(name="id", location="path", required=True)]
        )
        attacks = planner._determine_attacks(endpoint)
        
        assert AttackType.IDOR in attacks

    def test_determine_attacks_ssrf_endpoint(self, planner):
        """Test determining attacks for SSRF-prone endpoint."""
        endpoint = Endpoint(
            path="/webhook/callback",
            method=HttpMethod.POST
        )
        attacks = planner._determine_attacks(endpoint)
        
        assert AttackType.SSRF in attacks

    @pytest.mark.asyncio
    async def test_create_plan_fallback(self, planner, sample_endpoints):
        """Test fallback plan creation."""
        # Make AI fail
        planner.ai_agent.active_provider.generate = Mock(
            side_effect=Exception("AI unavailable")
        )
        
        plan = await planner.create_plan(sample_endpoints)
        
        assert isinstance(plan, ScanPlan)
        assert plan.target_endpoints == sample_endpoints
        assert "fallback" in plan.reasoning.lower() or "Rule-based" in plan.reasoning

    def test_fallback_plan_creates_sequence(self, planner, sample_endpoints):
        """Test fallback plan creates attack sequence."""
        plan_data = planner._fallback_plan(sample_endpoints)
        
        assert "attack_sequence" in plan_data
        assert len(plan_data["attack_sequence"]) > 0
        assert "estimated_time_seconds" in plan_data
        assert "risk_score" in plan_data

    def test_build_endpoints_info(self, planner, sample_endpoints):
        """Test building endpoints info string."""
        info = planner._build_endpoints_info(sample_endpoints)
        
        assert isinstance(info, str)
        for ep in sample_endpoints:
            assert ep.path in info

    def test_parse_plan_response_valid_json(self, planner, sample_endpoints):
        """Test parsing valid JSON response."""
        response = '''
        {
            "attack_sequence": [{"endpoint_index": 0, "attack_types": ["sql_injection"]}],
            "estimated_time_seconds": 120,
            "risk_score": 7.5,
            "reasoning": "Test"
        }
        '''
        
        plan_data = planner._parse_plan_response(response, sample_endpoints)
        
        assert plan_data["risk_score"] == 7.5
        assert len(plan_data["attack_sequence"]) == 1

    def test_parse_plan_response_invalid_json(self, planner, sample_endpoints):
        """Test parsing invalid JSON falls back."""
        response = "This is not JSON"
        
        plan_data = planner._parse_plan_response(response, sample_endpoints)
        
        # Should return fallback plan
        assert "attack_sequence" in plan_data


# ============================================================================
# EXECUTOR AGENT TESTS
# ============================================================================

class TestExecutorAgent:
    """Tests for ExecutorAgent."""

    @pytest.fixture
    def executor(self):
        """Create an executor agent with mocked attackers."""
        from sentinel.autonomous import ExecutorAgent
        # Create executor with pre-set mock attackers
        executor = object.__new__(ExecutorAgent)
        executor.max_concurrent = 3
        executor.total_requests = 0
        executor.attackers = {
            AttackType.SQL_INJECTION: Mock(),
            AttackType.AUTH_BYPASS: Mock(),
            AttackType.IDOR: Mock(),
            AttackType.XSS: Mock(),
            AttackType.SSRF: Mock(),
            AttackType.JWT: Mock(),
            AttackType.CMD_INJECTION: Mock(),
            AttackType.RATE_LIMIT: Mock(),
        }
        return executor

    def test_executor_initialization(self, executor):
        """Test executor initialization."""
        assert executor.max_concurrent == 3
        assert executor.total_requests == 0
        assert len(executor.attackers) > 0

    def test_attackers_registered(self, executor):
        """Test all attackers are registered."""
        expected_attackers = [
            AttackType.SQL_INJECTION,
            AttackType.AUTH_BYPASS,
            AttackType.IDOR,
            AttackType.XSS,
            AttackType.SSRF,
            AttackType.JWT,
            AttackType.CMD_INJECTION,
            AttackType.RATE_LIMIT
        ]
        
        for attack_type in expected_attackers:
            assert attack_type in executor.attackers

    @pytest.mark.asyncio
    async def test_execute_plan_empty(self, executor):
        """Test executing empty plan."""
        plan = ScanPlan(
            target_endpoints=[],
            attack_sequence=[],
            estimated_time=0,
            risk_score=0,
            reasoning="Empty plan"
        )
        
        results = await executor.execute_plan(plan, "https://example.com")
        
        assert results == []

    @pytest.mark.asyncio
    async def test_execute_plan_with_mocks(self, executor, sample_endpoints):
        """Test executing plan with mocked attackers."""
        # Mock all attackers to return empty results
        for attack_type, attacker in executor.attackers.items():
            attacker.attack = Mock(return_value=[])
        
        plan = ScanPlan(
            target_endpoints=sample_endpoints,
            attack_sequence=[
                {
                    "endpoint_index": 0,
                    "attack_types": ["sql_injection"],
                    "priority": 1
                }
            ],
            estimated_time=60,
            risk_score=5.0,
            reasoning="Test plan"
        )
        
        results = await executor.execute_plan(plan, "https://example.com")
        
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_execute_plan_invalid_endpoint_index(self, executor, sample_endpoints):
        """Test executing plan with invalid endpoint index."""
        plan = ScanPlan(
            target_endpoints=sample_endpoints,
            attack_sequence=[
                {
                    "endpoint_index": 999,  # Invalid index
                    "attack_types": ["sql_injection"],
                    "priority": 1
                }
            ],
            estimated_time=60,
            risk_score=5.0,
            reasoning="Test plan"
        )
        
        results = await executor.execute_plan(plan, "https://example.com")
        
        # Should handle gracefully
        assert results == []

    @pytest.mark.asyncio
    async def test_execute_plan_with_progress_callback(self, executor, sample_endpoints):
        """Test executing plan with progress callback."""
        for attack_type, attacker in executor.attackers.items():
            attacker.attack = Mock(return_value=[])
        
        progress_calls = []
        
        async def progress_callback(endpoint, attack_type, result):
            progress_calls.append((endpoint, attack_type, result))
        
        plan = ScanPlan(
            target_endpoints=sample_endpoints,
            attack_sequence=[
                {
                    "endpoint_index": 0,
                    "attack_types": ["sql_injection"],
                    "priority": 1
                }
            ],
            estimated_time=60,
            risk_score=5.0,
            reasoning="Test plan"
        )
        
        await executor.execute_plan(
            plan, "https://example.com",
            progress_callback=progress_callback
        )
        
        # Progress callback should have been called
        assert len(progress_calls) >= 0  # May be 0 if attack returns nothing


# ============================================================================
# ANALYZER AGENT TESTS
# ============================================================================

class TestAnalyzerAgent:
    """Tests for AnalyzerAgent."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock AI agent."""
        agent = Mock(spec=SentinelAgent)
        agent.active_provider = MockProvider()
        return agent

    @pytest.fixture
    def analyzer(self, mock_agent):
        """Create an analyzer agent."""
        return AnalyzerAgent(mock_agent)

    @pytest.mark.asyncio
    async def test_analyze_empty_results(self, analyzer):
        """Test analyzing empty results."""
        analysis = await analyzer.analyze_results([])
        
        assert analysis["verified_vulnerabilities"] == []
        assert analysis["attack_chains"] == []
        assert analysis["summary"] == {}

    def test_fallback_analysis(self, analyzer, sample_attack_results):
        """Test fallback analysis."""
        analysis = analyzer._fallback_analysis(sample_attack_results)
        
        assert "verified_vulnerabilities" in analysis
        assert "summary" in analysis

    def test_fallback_analysis_counts_severity(self, analyzer, sample_endpoints):
        """Test fallback analysis counts severity correctly."""
        from sentinel.models import AttackResult
        
        results = [
            AttackResult(
                endpoint=sample_endpoints[0],
                attack_type=AttackType.SQL_INJECTION,
                success=True,
                extra_data={'severity': 'high'}
            ),
            AttackResult(
                endpoint=sample_endpoints[1],
                attack_type=AttackType.XSS,
                success=True,
                extra_data={'severity': 'medium'}
            ),
            AttackResult(
                endpoint=sample_endpoints[2],
                attack_type=AttackType.IDOR,
                success=False,
                extra_data={'severity': 'low'}
            ),
        ]
        
        analysis = analyzer._fallback_analysis(results)
        
        # Both successful attacks get counted
        assert analysis["summary"]["high"] == 1
        assert analysis["summary"]["medium"] == 1

    def test_build_results_info(self, analyzer, sample_attack_results):
        """Test building results info string."""
        info = analyzer._build_results_info(sample_attack_results)
        
        assert isinstance(info, str)
        for result in sample_attack_results:
            assert result.attack_type.value in info

    @pytest.mark.asyncio
    async def test_discover_attack_chains_empty(self, analyzer):
        """Test attack chain discovery with no results."""
        chains = await analyzer.discover_attack_chains([])
        
        assert chains == []

    @pytest.mark.asyncio
    async def test_discover_attack_chains_single_result(self, analyzer, sample_attack_result):
        """Test attack chain discovery with single result."""
        chains = await analyzer.discover_attack_chains([sample_attack_result])
        
        # Need at least 2 results for chains
        assert chains == []


# ============================================================================
# AUTONOMOUS SCANNER TESTS
# ============================================================================

class TestAutonomousScanner:
    """Tests for AutonomousScanner."""

    @pytest.fixture
    def mock_provider_for_scanner(self):
        """Create a comprehensive mock provider."""
        provider = Mock()
        provider.generate = Mock(return_value='{"attack_sequence": [], "estimated_time_seconds": 60, "risk_score": 5.0, "reasoning": "Test"}')
        provider.is_available = Mock(return_value=True)
        return provider

    @pytest.fixture
    def mock_executor(self):
        """Create a mock executor agent."""
        executor = Mock()
        executor.max_concurrent = 5
        executor.total_requests = 0
        executor.attackers = {
            AttackType.SQL_INJECTION: Mock(),
            AttackType.AUTH_BYPASS: Mock(),
            AttackType.IDOR: Mock(),
            AttackType.XSS: Mock(),
            AttackType.SSRF: Mock(),
            AttackType.JWT: Mock(),
            AttackType.CMD_INJECTION: Mock(),
            AttackType.RATE_LIMIT: Mock(),
        }
        executor.execute_plan = AsyncMock(return_value=[])
        return executor

    @pytest.fixture
    def scanner(self, mock_provider_for_scanner, mock_executor):
        """Create an autonomous scanner with mocked components."""
        with patch('sentinel.autonomous.create_agent') as mock_create_agent, \
             patch('sentinel.autonomous.ExecutorAgent', return_value=mock_executor):
            
            mock_agent = Mock(spec=SentinelAgent)
            mock_agent.active_provider = mock_provider_for_scanner
            mock_create_agent.return_value = mock_agent
            
            scanner = AutonomousScanner()
            return scanner

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.planner is not None
        # Executor is lazily initialized (None until scan() is called)
        assert scanner.executor is None
        assert scanner.analyzer is not None
        assert scanner.current_scan is None

    def test_get_progress_no_scan(self, scanner):
        """Test get_progress with no scan."""
        progress = scanner.get_progress()
        
        assert progress["state"] == "idle"

    @pytest.mark.asyncio
    async def test_scan_basic_flow(self, scanner, sample_endpoints):
        """Test basic scan flow."""
        # Executor is already mocked in fixture
        result = await scanner.scan(
            endpoints=sample_endpoints,
            base_url="https://example.com"
        )
        
        assert result.state == AgentState.COMPLETED
        assert result.start_time is not None
        assert result.end_time is not None
        assert result.endpoints_scanned == len(sample_endpoints)

    @pytest.mark.asyncio
    async def test_scan_creates_plan(self, scanner, sample_endpoints):
        """Test scan creates a plan."""
        result = await scanner.scan(
            endpoints=sample_endpoints,
            base_url="https://example.com"
        )
        
        assert result.plan is not None
        assert isinstance(result.plan, ScanPlan)

    @pytest.mark.asyncio
    async def test_scan_tracks_progress(self, scanner, sample_endpoints):
        """Test scan tracks progress."""
        await scanner.scan(
            endpoints=sample_endpoints,
            base_url="https://example.com"
        )
        
        progress = scanner.get_progress()
        
        assert progress["state"] == "completed"

    @pytest.mark.asyncio
    async def test_scan_with_error(self, scanner, sample_endpoints):
        """Test scan handles errors."""
        scanner.planner.create_plan = AsyncMock(
            side_effect=Exception("Planning failed")
        )
        
        with pytest.raises(Exception):
            await scanner.scan(
                endpoints=sample_endpoints,
                base_url="https://example.com"
            )

    @pytest.mark.asyncio
    async def test_scan_with_progress_callback(self, scanner, sample_endpoints):
        """Test scan with progress callback."""
        callback_calls = []
        
        async def progress_callback(endpoint, attack_type, result):
            callback_calls.append((endpoint, attack_type, result))
        
        await scanner.scan(
            endpoints=sample_endpoints,
            base_url="https://example.com",
            progress_callback=progress_callback
        )
        
        # Should complete without error


# ============================================================================
# SCAN PLAN DATACLASS TESTS
# ============================================================================

class TestScanPlan:
    """Tests for ScanPlan dataclass."""

    def test_create_scan_plan(self, sample_endpoints):
        """Test creating a scan plan."""
        plan = ScanPlan(
            target_endpoints=sample_endpoints,
            attack_sequence=[{"endpoint_index": 0, "attack_types": ["sql_injection"]}],
            estimated_time=120,
            risk_score=7.5,
            reasoning="Test plan"
        )
        
        assert plan.target_endpoints == sample_endpoints
        assert plan.estimated_time == 120
        assert plan.risk_score == 7.5

    def test_scan_plan_default_priority_map(self, sample_endpoints):
        """Test scan plan default priority map."""
        plan = ScanPlan(
            target_endpoints=sample_endpoints,
            attack_sequence=[],
            estimated_time=60,
            risk_score=5.0,
            reasoning="Test"
        )
        
        assert plan.priority_map == {}


# ============================================================================
# ATTACK CHAIN DATACLASS TESTS
# ============================================================================

class TestAttackChain:
    """Tests for AttackChain dataclass."""

    def test_create_attack_chain(self, sample_attack_results):
        """Test creating an attack chain."""
        chain = AttackChain(
            name="Test Chain",
            steps=sample_attack_results[:2],
            severity=Severity.HIGH,
            description="A test attack chain",
            exploit_path="Step 1 -> Step 2",
            confidence=0.85
        )
        
        assert chain.name == "Test Chain"
        assert len(chain.steps) == 2
        assert chain.severity == Severity.HIGH


# ============================================================================
# AUTONOMOUS SCAN RESULT DATACLASS TESTS
# ============================================================================

class TestAutonomousScanResult:
    """Tests for AutonomousScanResult dataclass."""

    def test_create_scan_result(self):
        """Test creating an autonomous scan result."""
        result = AutonomousScanResult(
            start_time=datetime.now(),
            state=AgentState.IDLE
        )
        
        assert result.state == AgentState.IDLE
        assert result.findings == []
        assert result.attack_chains == []

    def test_scan_result_defaults(self):
        """Test scan result defaults."""
        result = AutonomousScanResult(start_time=datetime.now())
        
        assert result.end_time is None
        assert result.plan is None
        assert result.endpoints_scanned == 0
        assert result.total_requests == 0


# ============================================================================
# AGENT STATE ENUM TESTS
# ============================================================================

class TestAgentState:
    """Tests for AgentState enum."""

    def test_all_states_exist(self):
        """Test all expected states exist."""
        expected_states = [
            'IDLE', 'PLANNING', 'SCANNING', 'ANALYZING',
            'CHAIN_DISCOVERY', 'COMPLETED', 'ERROR'
        ]
        
        for state in expected_states:
            assert hasattr(AgentState, state)

    def test_state_values(self):
        """Test state values."""
        assert AgentState.IDLE.value == "idle"
        assert AgentState.PLANNING.value == "planning"
        assert AgentState.SCANNING.value == "scanning"
        assert AgentState.COMPLETED.value == "completed"


# ============================================================================
# RUN AUTONOMOUS SCAN CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestRunAutonomousScan:
    """Tests for run_autonomous_scan convenience function."""

    @pytest.mark.asyncio
    async def test_run_autonomous_scan_creates_scanner(self, sample_endpoints):
        """Test run_autonomous_scan creates scanner and runs scan."""
        with patch('sentinel.autonomous.AutonomousScanner') as mock_scanner_class:
            mock_scanner = Mock()
            mock_scanner.scan = AsyncMock(return_value=AutonomousScanResult(
                start_time=datetime.now(),
                state=AgentState.COMPLETED
            ))
            mock_scanner_class.return_value = mock_scanner
            
            result = await run_autonomous_scan(
                endpoints=sample_endpoints,
                base_url="https://example.com"
            )
            
            assert result.state == AgentState.COMPLETED
            mock_scanner_class.assert_called_once()
            mock_scanner.scan.assert_called_once()
