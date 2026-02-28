"""
Proxy Mode for Sentinel.

Intercepts and analyzes HTTP traffic for security testing.
Based on mitmproxy-like functionality for API security analysis.

v3.0 Feature: Traffic Interception & Analysis
"""

import asyncio
import json
import re
import threading
import time
from typing import Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse
from enum import Enum

from .models import Endpoint, HttpMethod, Severity
from .passive import PassiveScanner, PassiveFinding, PassiveFindingType, create_passive_scanner
from .auth import AuthType, detect_auth_type


class ProxyState(Enum):
    """Proxy server state."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"


@dataclass
class InterceptedRequest:
    """Represents an intercepted HTTP request."""
    id: str
    timestamp: datetime
    method: str
    url: str
    path: str
    headers: dict
    body: Optional[str] = None
    query_params: dict = field(default_factory=dict)
    
    # Analysis results
    auth_type: Optional[AuthType] = None
    passive_findings: list[PassiveFinding] = field(default_factory=list)


@dataclass
class InterceptedResponse:
    """Represents an intercepted HTTP response."""
    id: str
    timestamp: datetime
    status_code: int
    headers: dict
    body: Optional[str] = None
    content_type: Optional[str] = None
    
    # Analysis results
    passive_findings: list[PassiveFinding] = field(default_factory=list)


@dataclass
class TrafficFlow:
    """Represents a complete request/response flow."""
    id: str
    request: InterceptedRequest
    response: Optional[InterceptedResponse] = None
    duration_ms: int = 0
    
    # API detection
    is_api: bool = False
    api_endpoint: Optional[str] = None


@dataclass
class ProxyConfig:
    """Configuration for the proxy server."""
    host: str = "127.0.0.1"
    port: int = 8080
    
    # Traffic handling
    intercept_enabled: bool = True
    modify_requests: bool = False
    modify_responses: bool = False
    
    # Analysis
    passive_scan: bool = True
    detect_api: bool = True
    extract_endpoints: bool = True
    
    # Filtering
    ignore_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    ignore_paths: list[str] = field(default_factory=lambda: ["/favicon.ico", "/health"])
    only_json: bool = False
    
    # Upstream proxy
    upstream_proxy: Optional[str] = None
    upstream_proxy_port: Optional[int] = None
    
    # SSL/TLS
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    
    # Callbacks
    on_request: Optional[Callable] = None
    on_response: Optional[Callable] = None
    on_flow: Optional[Callable] = None


class ProxyTrafficStore:
    """Stores intercepted traffic for analysis."""
    
    def __init__(self, max_flows: int = 1000):
        self.flows: list[TrafficFlow] = []
        self.max_flows = max_flows
        self.endpoints: dict[str, list[TrafficFlow]] = {}
        self._lock = threading.Lock()
    
    def add_flow(self, flow: TrafficFlow):
        """Add a traffic flow to storage."""
        with self._lock:
            self.flows.append(flow)
            
            # Index by endpoint
            if flow.api_endpoint:
                if flow.api_endpoint not in self.endpoints:
                    self.endpoints[flow.api_endpoint] = []
                self.endpoints[flow.api_endpoint].append(flow)
            
            # Trim if exceeded max
            if len(self.flows) > self.max_flows:
                removed = self.flows.pop(0)
                if removed.api_endpoint in self.endpoints:
                    self.endpoints[removed.api_endpoint] = [
                        f for f in self.endpoints[removed.api_endpoint] if f.id != removed.id
                    ]
    
    def get_flows(self, limit: int = 100) -> list[TrafficFlow]:
        """Get recent flows."""
        with self._lock:
            return self.flows[-limit:]
    
    def get_endpoints(self) -> list[str]:
        """Get discovered API endpoints."""
        with self._lock:
            return list(self.endpoints.keys())
    
    def get_flow(self, flow_id: str) -> Optional[TrafficFlow]:
        """Get a specific flow by ID."""
        with self._lock:
            for flow in self.flows:
                if flow.id == flow_id:
                    return flow
        return None
    
    def clear(self):
        """Clear all stored traffic."""
        with self._lock:
            self.flows.clear()
            self.endpoints.clear()
    
    def get_stats(self) -> dict:
        """Get traffic statistics."""
        with self._lock:
            methods = {}
            status_codes = {}
            
            for flow in self.flows:
                methods[flow.request.method] = methods.get(flow.request.method, 0) + 1
                if flow.response:
                    status_codes[flow.response.status_code] = status_codes.get(flow.response.status_code, 0) + 1
            
            return {
                "total_flows": len(self.flows),
                "unique_endpoints": len(self.endpoints),
                "methods": methods,
                "status_codes": status_codes
            }


class TrafficAnalyzer:
    """Analyzes intercepted traffic for security issues."""
    
    def __init__(self):
        self.passive_scanner = create_passive_scanner()
    
    def analyze_request(self, request: InterceptedRequest) -> list[PassiveFinding]:
        """Analyze an HTTP request for security issues."""
        findings = []
        
        # Detect authentication type
        request.auth_type = detect_auth_type(request.headers)
        
        # Run passive scanner on request
        if request.body:
            findings.extend(
                self.passive_scanner.analyze_request(
                    url=request.url,
                    method=request.method,
                    headers=request.headers,
                    body=request.body
                )
            )
        
        # Check for sensitive data in URL
        sensitive_params = ['password', 'token', 'secret', 'key', 'auth']
        for param in request.query_params:
            if any(s in param.lower() for s in sensitive_params):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.SENSITIVE_DATA_EXPOSURE,
                    severity=Severity.MEDIUM,
                    title=f"Sensitive Parameter in URL: {param}",
                    description=f"Parameter '{param}' may contain sensitive data exposed in URL",
                    evidence=f"Query param: {param}",
                    location="url",
                    remediation="Send sensitive data in request body or headers instead"
                ))
        
        return findings
    
    def analyze_response(self, response: InterceptedResponse, request: InterceptedRequest) -> list[PassiveFinding]:
        """Analyze an HTTP response for security issues."""
        findings = []
        
        # Run passive scanner
        findings.extend(
            self.passive_scanner.analyze_response(
                url=request.url,
                method=request.method,
                request_headers=request.headers,
                response_headers=response.headers,
                response_body=response.body or "",
                status_code=response.status_code
            )
        )
        
        # Check for authentication data in response
        if response.body:
            self._check_auth_data(response.body, findings)
        
        return findings
    
    def _check_auth_data(self, body: str, findings: list):
        """Check for authentication data in response body."""
        patterns = [
            (r'"token"\s*:\s*"[^"]+"', "Token in response body"),
            (r'"access_token"\s*:\s*"[^"]+"', "Access token in response body"),
            (r'"password"\s*:\s*"[^"]+"', "Password in response body"),
            (r'"secret"\s*:\s*"[^"]+"', "Secret in response body"),
        ]
        
        for pattern, title in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.SENSITIVE_DATA_EXPOSURE,
                    severity=Severity.HIGH,
                    title=title,
                    description=f"Sensitive authentication data found in response body",
                    evidence=pattern,
                    location="body",
                    remediation="Remove sensitive data from response or encrypt it"
                ))
    
    def detect_api_endpoint(self, flow: TrafficFlow) -> Optional[str]:
        """Detect if this is an API endpoint and return normalized path."""
        request = flow.request
        
        # Check content type
        content_type = request.headers.get("Content-Type", "")
        accept = request.headers.get("Accept", "")
        
        is_api = (
            "application/json" in content_type or
            "application/json" in accept or
            "application/xml" in content_type or
            "/api/" in request.path.lower() or
            request.path.endswith((".json", ".xml"))
        )
        
        if is_api:
            # Normalize path (replace IDs with placeholders)
            normalized = self._normalize_path(request.path)
            flow.is_api = True
            flow.api_endpoint = f"{request.method} {normalized}"
            return flow.api_endpoint
        
        return None
    
    def _normalize_path(self, path: str) -> str:
        """Normalize API path by replacing variable segments."""
        # Replace UUIDs
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{uuid}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace numeric IDs
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
        
        # Replace common ID patterns
        path = re.sub(r'/[a-f0-9]{24}(?=/|$)', '/{id}', path)  # MongoDB ObjectID
        path = re.sub(r'/[a-zA-Z0-9_-]{10,}(?=/|$)', '/{token}', path)  # Tokens
        
        return path


class SentinelProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the proxy server."""
    
    proxy_config: 'ProxyConfig' = None
    traffic_store: ProxyTrafficStore = None
    traffic_analyzer: TrafficAnalyzer = None
    
    def log_message(self, format, *args):
        """Override to suppress default logging."""
        pass
    
    def do_GET(self):
        self._handle_request("GET")
    
    def do_POST(self):
        self._handle_request("POST")
    
    def do_PUT(self):
        self._handle_request("PUT")
    
    def do_DELETE(self):
        self._handle_request("DELETE")
    
    def do_PATCH(self):
        self._handle_request("PATCH")
    
    def do_OPTIONS(self):
        self._handle_request("OPTIONS")
    
    def do_HEAD(self):
        self._handle_request("HEAD")
    
    def _handle_request(self, method: str):
        """Handle an HTTP request."""
        import uuid
        import requests
        
        flow_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        
        # Parse URL
        parsed_url = urllib.parse.urlparse(self.path)
        
        # Read request body
        body = None
        if 'Content-Length' in self.headers:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        # Parse query params
        query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
        
        # Create intercepted request
        request = InterceptedRequest(
            id=flow_id,
            timestamp=datetime.now(),
            method=method,
            url=self.path,
            path=parsed_url.path,
            headers=dict(self.headers),
            body=body,
            query_params=query_params
        )
        
        # Analyze request
        if self.proxy_config.passive_scan:
            request.passive_findings = self.traffic_analyzer.analyze_request(request)
        
        # Forward request to target
        try:
            # Determine target URL
            target_url = self._get_target_url(parsed_url)
            
            # Prepare headers
            forward_headers = dict(self.headers)
            forward_headers.pop('Host', None)
            
            # Forward the request
            response = requests.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                data=body,
                allow_redirects=False,
                timeout=30
            )
            
            # Create intercepted response
            intercepted_response = InterceptedResponse(
                id=flow_id,
                timestamp=datetime.now(),
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:100000] if response.text else None,  # Limit body size
                content_type=response.headers.get('Content-Type', '')
            )
            
            # Analyze response
            if self.proxy_config.passive_scan:
                intercepted_response.passive_findings = self.traffic_analyzer.analyze_response(
                    intercepted_response, request
                )
            
            # Send response back to client
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ['content-encoding', 'transfer-encoding']:
                    self.send_header(header, value)
            self.end_headers()
            
            if response.content:
                self.wfile.write(response.content)
            
            # Create flow
            flow = TrafficFlow(
                id=flow_id,
                request=request,
                response=intercepted_response,
                duration_ms=int((time.time() - start_time) * 1000)
            )
            
            # Detect API endpoint
            if self.proxy_config.detect_api:
                self.traffic_analyzer.detect_api_endpoint(flow)
            
            # Store traffic
            self.traffic_store.add_flow(flow)
            
            # Callback
            if self.proxy_config.on_flow:
                try:
                    self.proxy_config.on_flow(flow)
                except Exception:
                    pass
            
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Proxy Error: {str(e)}".encode())
            
            # Store failed flow
            flow = TrafficFlow(
                id=flow_id,
                request=request,
                duration_ms=int((time.time() - start_time) * 1000)
            )
            self.traffic_store.add_flow(flow)
    
    def _get_target_url(self, parsed_url) -> str:
        """Get the target URL for forwarding."""
        # If path is full URL, use it directly
        if parsed_url.scheme:
            return self.path
        
        # Otherwise, use Host header
        host = self.headers.get('Host', 'localhost')
        scheme = 'https' if self.proxy_config.cert_file else 'http'
        return f"{scheme}://{host}{self.path}"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for handling multiple connections."""
    daemon_threads = True


class SentinelProxy:
    """
    Main proxy server for traffic interception and analysis.
    
    Features:
    - Traffic interception and forwarding
    - Passive security analysis
    - API endpoint detection
    - Authentication detection
    """
    
    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig()
        self.traffic_store = ProxyTrafficStore()
        self.traffic_analyzer = TrafficAnalyzer()
        self.server: Optional[ThreadedHTTPServer] = None
        self.state = ProxyState.STOPPED
        self._server_thread: Optional[threading.Thread] = None
    
    def start(self, blocking: bool = True):
        """
        Start the proxy server.
        
        Args:
            blocking: If True, blocks the current thread
        """
        if self.state == ProxyState.RUNNING:
            return
        
        self.state = ProxyState.STARTING
        
        # Configure handler
        SentinelProxyHandler.proxy_config = self.config
        SentinelProxyHandler.traffic_store = self.traffic_store
        SentinelProxyHandler.traffic_analyzer = self.traffic_analyzer
        
        try:
            self.server = ThreadedHTTPServer(
                (self.config.host, self.config.port),
                SentinelProxyHandler
            )
            
            self.state = ProxyState.RUNNING
            
            if blocking:
                print(f"🚀 Sentinel Proxy running on {self.config.host}:{self.config.port}")
                self.server.serve_forever()
            else:
                self._server_thread = threading.Thread(
                    target=self.server.serve_forever,
                    daemon=True
                )
                self._server_thread.start()
                print(f"🚀 Sentinel Proxy started on {self.config.host}:{self.config.port}")
                
        except Exception as e:
            self.state = ProxyState.STOPPED
            raise RuntimeError(f"Failed to start proxy: {e}")
    
    def stop(self):
        """Stop the proxy server."""
        if self.state != ProxyState.RUNNING:
            return
        
        self.state = ProxyState.STOPPING
        
        if self.server:
            self.server.shutdown()
            self.server = None
        
        self.state = ProxyState.STOPPED
        print("🛑 Sentinel Proxy stopped")
    
    def get_flows(self, limit: int = 100) -> list[TrafficFlow]:
        """Get intercepted traffic flows."""
        return self.traffic_store.get_flows(limit)
    
    def get_endpoints(self) -> list[str]:
        """Get discovered API endpoints."""
        return self.traffic_store.get_endpoints()
    
    def get_stats(self) -> dict:
        """Get traffic statistics."""
        return self.traffic_store.get_stats()
    
    def clear_traffic(self):
        """Clear all stored traffic."""
        self.traffic_store.clear()
    
    def extract_openapi_spec(self) -> dict:
        """
        Extract OpenAPI specification from intercepted traffic.
        
        Returns:
            OpenAPI 3.0 specification dict
        """
        endpoints = {}
        
        for flow in self.traffic_store.get_flows(limit=10000):
            if not flow.is_api:
                continue
            
            endpoint_key = flow.api_endpoint
            if not endpoint_key:
                continue
            
            if endpoint_key not in endpoints:
                method, path = endpoint_key.split(" ", 1)
                endpoints[endpoint_key] = {
                    "method": method.lower(),
                    "path": path,
                    "requests": []
                }
            
            endpoints[endpoint_key]["requests"].append({
                "request": flow.request,
                "response": flow.response
            })
        
        # Build OpenAPI spec
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Extracted API",
                "version": "1.0.0",
                "description": "Auto-generated from intercepted traffic"
            },
            "paths": {}
        }
        
        for endpoint_key, data in endpoints.items():
            path = data["path"]
            method = data["method"]
            
            if path not in spec["paths"]:
                spec["paths"][path] = {}
            
            # Build operation
            operation = {
                "summary": f"Auto-detected {method.upper()} operation",
                "responses": {}
            }
            
            # Add parameters from query params
            params = set()
            for req_data in data["requests"]:
                req = req_data["request"]
                for param_name in req.query_params.keys():
                    params.add(param_name)
            
            if params:
                operation["parameters"] = [
                    {"name": p, "in": "query", "schema": {"type": "string"}}
                    for p in params
                ]
            
            # Add responses
            status_codes = set()
            for req_data in data["requests"]:
                resp = req_data["response"]
                if resp and resp.status_code not in status_codes:
                    status_codes.add(resp.status_code)
                    operation["responses"][resp.status_code] = {
                        "description": f"Status {resp.status_code}",
                        "content": {
                            resp.content_type or "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    }
            
            spec["paths"][path][method] = operation
        
        return spec
    
    def __enter__(self):
        """Context manager entry."""
        self.start(blocking=False)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def create_proxy(
    host: str = "127.0.0.1",
    port: int = 8080,
    passive_scan: bool = True
) -> SentinelProxy:
    """Create a proxy server instance."""
    config = ProxyConfig(
        host=host,
        port=port,
        passive_scan=passive_scan
    )
    return SentinelProxy(config)
