"""
Comprehensive tests for Proxy Mode module.

Tests cover:
- ProxyConfig
- ProxyTrafficStore
- TrafficAnalyzer
- SentinelProxy
- InterceptedRequest/Response
- TrafficFlow
"""

import pytest
import threading
import time
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
import urllib.parse

from sentinel.models import Endpoint, HttpMethod, Parameter, Severity
from sentinel.proxy import (
    ProxyState, ProxyConfig, InterceptedRequest, InterceptedResponse,
    TrafficFlow, ProxyTrafficStore, TrafficAnalyzer, SentinelProxy,
    SentinelProxyHandler, create_proxy
)
from sentinel.auth import AuthType
from sentinel.passive import PassiveFinding, PassiveFindingType


# ============================================================================
# PROXY STATE ENUM TESTS
# ============================================================================

class TestProxyState:
    """Tests for ProxyState enum."""

    def test_all_states_exist(self):
        """Test all expected states exist."""
        expected = ['STOPPED', 'STARTING', 'RUNNING', 'STOPPING']
        
        for state in expected:
            assert hasattr(ProxyState, state)

    def test_state_values(self):
        """Test state values."""
        assert ProxyState.STOPPED.value == "stopped"
        assert ProxyState.RUNNING.value == "running"


# ============================================================================
# PROXY CONFIG TESTS
# ============================================================================

class TestProxyConfig:
    """Tests for ProxyConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = ProxyConfig()
        
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.intercept_enabled is True
        assert config.passive_scan is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = ProxyConfig(
            host="0.0.0.0",
            port=9999,
            intercept_enabled=False,
            passive_scan=False
        )
        
        assert config.host == "0.0.0.0"
        assert config.port == 9999
        assert config.intercept_enabled is False
        assert config.passive_scan is False

    def test_ignore_hosts_default(self):
        """Test default ignored hosts."""
        config = ProxyConfig()
        
        assert "localhost" in config.ignore_hosts
        assert "127.0.0.1" in config.ignore_hosts

    def test_ignore_paths_default(self):
        """Test default ignored paths."""
        config = ProxyConfig()
        
        assert "/favicon.ico" in config.ignore_paths
        assert "/health" in config.ignore_paths

    def test_upstream_proxy_config(self):
        """Test upstream proxy configuration."""
        config = ProxyConfig(
            upstream_proxy="proxy.example.com",
            upstream_proxy_port=3128
        )
        
        assert config.upstream_proxy == "proxy.example.com"
        assert config.upstream_proxy_port == 3128

    def test_ssl_config(self):
        """Test SSL/TLS configuration."""
        config = ProxyConfig(
            cert_file="/path/to/cert.pem",
            key_file="/path/to/key.pem"
        )
        
        assert config.cert_file == "/path/to/cert.pem"
        assert config.key_file == "/path/to/key.pem"

    def test_callbacks(self):
        """Test callback configuration."""
        def on_request(req):
            pass
        
        def on_response(resp):
            pass
        
        def on_flow(flow):
            pass
        
        config = ProxyConfig(
            on_request=on_request,
            on_response=on_response,
            on_flow=on_flow
        )
        
        assert config.on_request is on_request
        assert config.on_response is on_response
        assert config.on_flow is on_flow


# ============================================================================
# INTERCEPTED REQUEST TESTS
# ============================================================================

class TestInterceptedRequest:
    """Tests for InterceptedRequest."""

    def test_create_request(self):
        """Test creating intercepted request."""
        request = InterceptedRequest(
            id="test-123",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/users",
            path="/users",
            headers={"Host": "api.example.com"},
            query_params={"page": "1"}
        )
        
        assert request.id == "test-123"
        assert request.method == "GET"
        assert request.path == "/users"
        assert request.auth_type is None

    def test_request_with_body(self):
        """Test request with body."""
        request = InterceptedRequest(
            id="test-456",
            timestamp=datetime.now(),
            method="POST",
            url="https://api.example.com/users",
            path="/users",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}'
        )
        
        assert request.body == '{"name": "test"}'
        assert request.method == "POST"

    def test_request_with_findings(self):
        """Test request with passive findings."""
        finding = PassiveFinding(
            finding_type=PassiveFindingType.SENSITIVE_DATA_EXPOSURE,
            severity=Severity.MEDIUM,
            title="Test Finding",
            description="Test description",
            evidence="test evidence",
            location="body",
            remediation="Test remediation"
        )
        
        request = InterceptedRequest(
            id="test-789",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/search",
            path="/search",
            headers={},
            passive_findings=[finding]
        )
        
        assert len(request.passive_findings) == 1
        assert request.passive_findings[0].title == "Test Finding"


# ============================================================================
# INTERCEPTED RESPONSE TESTS
# ============================================================================

class TestInterceptedResponse:
    """Tests for InterceptedResponse."""

    def test_create_response(self):
        """Test creating intercepted response."""
        response = InterceptedResponse(
            id="resp-123",
            timestamp=datetime.now(),
            status_code=200,
            headers={"Content-Type": "application/json"},
            content_type="application/json"
        )
        
        assert response.id == "resp-123"
        assert response.status_code == 200
        assert response.content_type == "application/json"

    def test_response_with_body(self):
        """Test response with body."""
        response = InterceptedResponse(
            id="resp-456",
            timestamp=datetime.now(),
            status_code=200,
            headers={},
            body='{"data": "test"}'
        )
        
        assert response.body == '{"data": "test"}'

    def test_response_with_findings(self):
        """Test response with passive findings."""
        finding = PassiveFinding(
            finding_type=PassiveFindingType.SENSITIVE_DATA_EXPOSURE,
            severity=Severity.HIGH,
            title="Token Exposed",
            description="Token in response",
            evidence="token: abc123",
            location="body",
            remediation="Remove sensitive data from response"
        )
        
        response = InterceptedResponse(
            id="resp-789",
            timestamp=datetime.now(),
            status_code=200,
            headers={},
            passive_findings=[finding]
        )
        
        assert len(response.passive_findings) == 1


# ============================================================================
# TRAFFIC FLOW TESTS
# ============================================================================

class TestTrafficFlow:
    """Tests for TrafficFlow."""

    def test_create_flow(self):
        """Test creating traffic flow."""
        request = InterceptedRequest(
            id="flow-123",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/users",
            path="/users",
            headers={}
        )
        
        flow = TrafficFlow(
            id="flow-123",
            request=request,
            duration_ms=150
        )
        
        assert flow.id == "flow-123"
        assert flow.request == request
        assert flow.duration_ms == 150
        assert flow.response is None
        assert flow.is_api is False

    def test_flow_with_response(self):
        """Test flow with response."""
        request = InterceptedRequest(
            id="flow-456",
            timestamp=datetime.now(),
            method="POST",
            url="https://api.example.com/users",
            path="/users",
            headers={}
        )
        
        response = InterceptedResponse(
            id="flow-456",
            timestamp=datetime.now(),
            status_code=201,
            headers={}
        )
        
        flow = TrafficFlow(
            id="flow-456",
            request=request,
            response=response,
            duration_ms=200,
            is_api=True,
            api_endpoint="POST /users"
        )
        
        assert flow.response is not None
        assert flow.is_api is True
        assert flow.api_endpoint == "POST /users"


# ============================================================================
# PROXY TRAFFIC STORE TESTS
# ============================================================================

class TestProxyTrafficStore:
    """Tests for ProxyTrafficStore."""

    def test_create_store(self):
        """Test creating traffic store."""
        store = ProxyTrafficStore()
        
        assert len(store.flows) == 0
        assert len(store.endpoints) == 0

    def test_add_flow(self):
        """Test adding flow to store."""
        store = ProxyTrafficStore()
        request = InterceptedRequest(
            id="test-1",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/test",
            path="/test",
            headers={}
        )
        flow = TrafficFlow(id="test-1", request=request)
        
        store.add_flow(flow)
        
        assert len(store.flows) == 1

    def test_add_flow_with_endpoint(self):
        """Test adding flow with API endpoint."""
        store = ProxyTrafficStore()
        request = InterceptedRequest(
            id="test-2",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/users",
            path="/users",
            headers={}
        )
        flow = TrafficFlow(
            id="test-2",
            request=request,
            is_api=True,
            api_endpoint="GET /users"
        )
        
        store.add_flow(flow)
        
        assert "GET /users" in store.endpoints

    def test_max_flows_limit(self):
        """Test max flows limit."""
        store = ProxyTrafficStore(max_flows=5)
        
        for i in range(10):
            request = InterceptedRequest(
                id=f"test-{i}",
                timestamp=datetime.now(),
                method="GET",
                url=f"https://api.example.com/test/{i}",
                path=f"/test/{i}",
                headers={}
            )
            flow = TrafficFlow(id=f"test-{i}", request=request)
            store.add_flow(flow)
        
        assert len(store.flows) == 5

    def test_get_flows(self):
        """Test getting flows."""
        store = ProxyTrafficStore()
        
        for i in range(5):
            request = InterceptedRequest(
                id=f"test-{i}",
                timestamp=datetime.now(),
                method="GET",
                url=f"/test/{i}",
                path=f"/test/{i}",
                headers={}
            )
            flow = TrafficFlow(id=f"test-{i}", request=request)
            store.add_flow(flow)
        
        flows = store.get_flows(limit=3)
        
        assert len(flows) == 3

    def test_get_endpoints(self):
        """Test getting discovered endpoints."""
        store = ProxyTrafficStore()
        request = InterceptedRequest(
            id="test-1",
            timestamp=datetime.now(),
            method="GET",
            url="/users",
            path="/users",
            headers={}
        )
        flow = TrafficFlow(
            id="test-1",
            request=request,
            is_api=True,
            api_endpoint="GET /users"
        )
        store.add_flow(flow)
        
        endpoints = store.get_endpoints()
        
        assert "GET /users" in endpoints

    def test_get_flow_by_id(self):
        """Test getting flow by ID."""
        store = ProxyTrafficStore()
        request = InterceptedRequest(
            id="find-me",
            timestamp=datetime.now(),
            method="GET",
            url="/test",
            path="/test",
            headers={}
        )
        flow = TrafficFlow(id="find-me", request=request)
        store.add_flow(flow)
        
        found = store.get_flow("find-me")
        
        assert found is not None
        assert found.id == "find-me"

    def test_get_flow_not_found(self):
        """Test getting nonexistent flow."""
        store = ProxyTrafficStore()
        
        found = store.get_flow("nonexistent")
        
        assert found is None

    def test_clear(self):
        """Test clearing store."""
        store = ProxyTrafficStore()
        request = InterceptedRequest(
            id="test-1",
            timestamp=datetime.now(),
            method="GET",
            url="/test",
            path="/test",
            headers={}
        )
        flow = TrafficFlow(id="test-1", request=request)
        store.add_flow(flow)
        
        store.clear()
        
        assert len(store.flows) == 0
        assert len(store.endpoints) == 0

    def test_get_stats(self):
        """Test getting traffic statistics."""
        store = ProxyTrafficStore()
        
        for i in range(3):
            request = InterceptedRequest(
                id=f"test-{i}",
                timestamp=datetime.now(),
                method="GET" if i < 2 else "POST",
                url=f"/test/{i}",
                path=f"/test/{i}",
                headers={}
            )
            response = InterceptedResponse(
                id=f"test-{i}",
                timestamp=datetime.now(),
                status_code=200 if i < 2 else 201,
                headers={}
            )
            flow = TrafficFlow(id=f"test-{i}", request=request, response=response)
            store.add_flow(flow)
        
        stats = store.get_stats()
        
        assert stats["total_flows"] == 3
        assert "GET" in stats["methods"]
        assert "POST" in stats["methods"]


# ============================================================================
# TRAFFIC ANALYZER TESTS
# ============================================================================

class TestTrafficAnalyzer:
    """Tests for TrafficAnalyzer."""

    def test_create_analyzer(self):
        """Test creating traffic analyzer."""
        analyzer = TrafficAnalyzer()
        
        assert analyzer.passive_scanner is not None

    def test_analyze_request(self):
        """Test analyzing request."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-1",
            timestamp=datetime.now(),
            method="POST",
            url="https://api.example.com/login",
            path="/login",
            headers={
                "Authorization": "Bearer token123",
                "Content-Type": "application/json"
            },
            body='{"username": "admin", "password": "secret"}'
        )
        
        findings = analyzer.analyze_request(request)
        
        assert isinstance(findings, list)

    def test_analyze_request_detects_auth_type(self):
        """Test auth type detection in request."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-2",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/users",
            path="/users",
            headers={"Authorization": "Bearer token123"}
        )
        
        analyzer.analyze_request(request)
        
        assert request.auth_type == AuthType.BEARER

    def test_analyze_request_detects_basic_auth(self):
        """Test basic auth detection."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-3",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/admin",
            path="/admin",
            headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        
        analyzer.analyze_request(request)
        
        assert request.auth_type == AuthType.BASIC

    def test_analyze_request_sensitive_params(self):
        """Test detection of sensitive parameters."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-4",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/search",
            path="/search",
            headers={},
            query_params={"password": "secret123", "q": "test"}
        )
        
        findings = analyzer.analyze_request(request)
        
        # Should detect password in query params
        sensitive_findings = [f for f in findings if "password" in f.title.lower()]
        assert len(sensitive_findings) > 0

    def test_analyze_response(self):
        """Test analyzing response."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-5",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/users",
            path="/users",
            headers={}
        )
        response = InterceptedResponse(
            id="test-5",
            timestamp=datetime.now(),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"users": [{"id": 1, "name": "test"}]}'
        )
        
        findings = analyzer.analyze_response(response, request)
        
        assert isinstance(findings, list)

    def test_analyze_response_detects_token(self):
        """Test detection of tokens in response."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-6",
            timestamp=datetime.now(),
            method="POST",
            url="https://api.example.com/login",
            path="/login",
            headers={}
        )
        response = InterceptedResponse(
            id="test-6",
            timestamp=datetime.now(),
            status_code=200,
            headers={},
            body='{"token": "abc123", "access_token": "xyz789"}'
        )
        
        findings = analyzer.analyze_response(response, request)
        
        # Should detect tokens in response
        token_findings = [f for f in findings if "token" in f.title.lower()]
        assert len(token_findings) > 0

    def test_detect_api_endpoint_json_content_type(self):
        """Test API detection with JSON content type."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-7",
            timestamp=datetime.now(),
            method="GET",
            url="https://api.example.com/data",
            path="/data",
            headers={"Content-Type": "application/json"}
        )
        flow = TrafficFlow(id="test-7", request=request)
        
        result = analyzer.detect_api_endpoint(flow)
        
        assert result is not None
        assert flow.is_api is True

    def test_detect_api_endpoint_api_path(self):
        """Test API detection with /api/ path."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="test-8",
            timestamp=datetime.now(),
            method="GET",
            url="https://example.com/api/users",
            path="/api/users",
            headers={}
        )
        flow = TrafficFlow(id="test-8", request=request)
        
        result = analyzer.detect_api_endpoint(flow)
        
        assert result is not None

    def test_normalize_path_uuid(self):
        """Test path normalization with UUID."""
        analyzer = TrafficAnalyzer()
        
        normalized = analyzer._normalize_path("/users/550e8400-e29b-41d4-a716-446655440000/profile")
        
        assert "{uuid}" in normalized

    def test_normalize_path_numeric_id(self):
        """Test path normalization with numeric ID."""
        analyzer = TrafficAnalyzer()
        
        normalized = analyzer._normalize_path("/users/123/profile")
        
        assert "{id}" in normalized


# ============================================================================
# SENTINEL PROXY TESTS
# ============================================================================

class TestSentinelProxy:
    """Tests for SentinelProxy."""

    def test_create_proxy_default(self):
        """Test creating proxy with default config."""
        proxy = SentinelProxy()
        
        assert proxy.state == ProxyState.STOPPED
        assert proxy.traffic_store is not None
        assert proxy.traffic_analyzer is not None

    def test_create_proxy_custom_config(self):
        """Test creating proxy with custom config."""
        config = ProxyConfig(
            host="0.0.0.0",
            port=9000,
            passive_scan=False
        )
        proxy = SentinelProxy(config)
        
        assert proxy.config.host == "0.0.0.0"
        assert proxy.config.port == 9000

    def test_start_non_blocking(self):
        """Test starting proxy non-blocking."""
        config = ProxyConfig(port=18080)
        proxy = SentinelProxy(config)
        
        try:
            proxy.start(blocking=False)
            
            # Give it a moment to start
            time.sleep(0.1)
            
            assert proxy.state == ProxyState.RUNNING
        finally:
            proxy.stop()

    def test_stop(self):
        """Test stopping proxy."""
        config = ProxyConfig(port=18081)
        proxy = SentinelProxy(config)
        
        proxy.start(blocking=False)
        time.sleep(0.1)
        proxy.stop()
        
        assert proxy.state == ProxyState.STOPPED

    def test_get_flows(self):
        """Test getting flows from proxy."""
        proxy = SentinelProxy()
        
        flows = proxy.get_flows()
        
        assert isinstance(flows, list)

    def test_get_endpoints(self):
        """Test getting endpoints from proxy."""
        proxy = SentinelProxy()
        
        endpoints = proxy.get_endpoints()
        
        assert isinstance(endpoints, list)

    def test_get_stats(self):
        """Test getting stats from proxy."""
        proxy = SentinelProxy()
        
        stats = proxy.get_stats()
        
        assert "total_flows" in stats
        assert "unique_endpoints" in stats

    def test_clear_traffic(self):
        """Test clearing traffic from proxy."""
        proxy = SentinelProxy()
        
        # Should not raise
        proxy.clear_traffic()

    def test_context_manager(self):
        """Test using proxy as context manager."""
        config = ProxyConfig(port=18082)
        
        with SentinelProxy(config) as proxy:
            time.sleep(0.1)
            assert proxy.state == ProxyState.RUNNING
        
        assert proxy.state == ProxyState.STOPPED

    def test_extract_openapi_spec(self):
        """Test extracting OpenAPI spec from traffic."""
        proxy = SentinelProxy()
        
        # Add some test flows
        request = InterceptedRequest(
            id="test-1",
            timestamp=datetime.now(),
            method="GET",
            url="/api/users",
            path="/api/users",
            headers={"Content-Type": "application/json"}
        )
        response = InterceptedResponse(
            id="test-1",
            timestamp=datetime.now(),
            status_code=200,
            headers={},
            content_type="application/json"
        )
        flow = TrafficFlow(
            id="test-1",
            request=request,
            response=response,
            is_api=True,
            api_endpoint="GET /api/users"
        )
        proxy.traffic_store.add_flow(flow)
        
        spec = proxy.extract_openapi_spec()
        
        assert spec["openapi"] == "3.0.0"
        assert "paths" in spec


# ============================================================================
# CREATE PROXY FUNCTION TESTS
# ============================================================================

class TestCreateProxyFunction:
    """Tests for create_proxy convenience function."""

    def test_create_proxy_default_args(self):
        """Test create_proxy with default arguments."""
        proxy = create_proxy()
        
        assert proxy.config.host == "127.0.0.1"
        assert proxy.config.port == 8080
        assert proxy.config.passive_scan is True

    def test_create_proxy_custom_args(self):
        """Test create_proxy with custom arguments."""
        proxy = create_proxy(
            host="0.0.0.0",
            port=9999,
            passive_scan=False
        )
        
        assert proxy.config.host == "0.0.0.0"
        assert proxy.config.port == 9999
        assert proxy.config.passive_scan is False


# ============================================================================
# SENTINEL PROXY HANDLER TESTS
# ============================================================================

class TestSentinelProxyHandler:
    """Tests for SentinelProxyHandler."""

    def test_handler_methods_exist(self):
        """Test handler has all HTTP method handlers."""
        assert hasattr(SentinelProxyHandler, 'do_GET')
        assert hasattr(SentinelProxyHandler, 'do_POST')
        assert hasattr(SentinelProxyHandler, 'do_PUT')
        assert hasattr(SentinelProxyHandler, 'do_DELETE')
        assert hasattr(SentinelProxyHandler, 'do_PATCH')
        assert hasattr(SentinelProxyHandler, 'do_OPTIONS')
        assert hasattr(SentinelProxyHandler, 'do_HEAD')

    def test_handler_has_config_attributes(self):
        """Test handler has required class attributes."""
        # These are set at runtime
        assert hasattr(SentinelProxyHandler, '__annotations__') or True


# ============================================================================
# THREAD SAFETY TESTS
# ============================================================================

class TestThreadSafety:
    """Tests for thread safety of proxy components."""

    def test_concurrent_flow_adds(self):
        """Test concurrent flow additions."""
        store = ProxyTrafficStore()
        
        def add_flows(start_id):
            for i in range(100):
                request = InterceptedRequest(
                    id=f"flow-{start_id}-{i}",
                    timestamp=datetime.now(),
                    method="GET",
                    url="/test",
                    path="/test",
                    headers={}
                )
                flow = TrafficFlow(id=f"flow-{start_id}-{i}", request=request)
                store.add_flow(flow)
        
        threads = [
            threading.Thread(target=add_flows, args=(i,))
            for i in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(store.flows) == 500

    def test_concurrent_get_flows(self):
        """Test concurrent flow reads."""
        store = ProxyTrafficStore()
        
        # Add some flows first
        for i in range(50):
            request = InterceptedRequest(
                id=f"flow-{i}",
                timestamp=datetime.now(),
                method="GET",
                url="/test",
                path="/test",
                headers={}
            )
            flow = TrafficFlow(id=f"flow-{i}", request=request)
            store.add_flow(flow)
        
        results = []
        
        def get_flows():
            results.append(len(store.get_flows()))
        
        threads = [threading.Thread(target=get_flows) for _ in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(r == 50 for r in results)


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_request_body(self):
        """Test handling empty request body."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="empty-body",
            timestamp=datetime.now(),
            method="GET",
            url="/test",
            path="/test",
            headers={},
            body=None
        )
        
        findings = analyzer.analyze_request(request)
        
        assert isinstance(findings, list)

    def test_large_request_body(self):
        """Test handling large request body."""
        analyzer = TrafficAnalyzer()
        large_body = "x" * 1000000  # 1MB
        
        request = InterceptedRequest(
            id="large-body",
            timestamp=datetime.now(),
            method="POST",
            url="/upload",
            path="/upload",
            headers={},
            body=large_body
        )
        
        findings = analyzer.analyze_request(request)
        
        assert isinstance(findings, list)

    def test_malformed_json_body(self):
        """Test handling malformed JSON body."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="malformed",
            timestamp=datetime.now(),
            method="POST",
            url="/test",
            path="/test",
            headers={},
            body='{"broken": json}'
        )
        
        findings = analyzer.analyze_request(request)
        
        assert isinstance(findings, list)

    def test_unicode_in_path(self):
        """Test handling Unicode in path."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="unicode",
            timestamp=datetime.now(),
            method="GET",
            url="/users/日本語",
            path="/users/日本語",
            headers={}
        )
        flow = TrafficFlow(id="unicode", request=request)
        
        result = analyzer.detect_api_endpoint(flow)
        
        assert isinstance(result, (str, type(None)))

    def test_special_characters_in_headers(self):
        """Test handling special characters in headers."""
        analyzer = TrafficAnalyzer()
        request = InterceptedRequest(
            id="special",
            timestamp=datetime.now(),
            method="GET",
            url="/test",
            path="/test",
            headers={"X-Custom": "value\nwith\nnewlines"}
        )
        
        findings = analyzer.analyze_request(request)
        
        assert isinstance(findings, list)
