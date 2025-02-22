"""
Core data structures for Sentinel using Pydantic.

This module defines all the data models used throughout the application:
- Endpoint: Represents an API endpoint from OpenAPI spec
- AttackResult: Results from security testing
- Vulnerability: Details of found vulnerabilities
- ScanConfig: Configuration for a scan run
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class HttpMethod(str, Enum):
    """HTTP methods supported by Sentinel."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class AttackType(str, Enum):
    """Types of security attacks Sentinel can perform."""
    SQL_INJECTION = "sql_injection"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Parameter(BaseModel):
    """Represents an API parameter."""
    name: str
    location: str  # query, path, header, body
    required: bool = False
    param_type: str = "string"
    description: Optional[str] = None
    example: Optional[Any] = None


class Endpoint(BaseModel):
    """Represents an API endpoint from OpenAPI specification."""
    path: str
    method: HttpMethod
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: Optional[dict] = None
    responses: dict[str, Any] = Field(default_factory=dict)
    security: Optional[list[dict]] = None
    tags: list[str] = Field(default_factory=list)
    
    @property
    def requires_auth(self) -> bool:
        """Check if endpoint requires authentication."""
        return self.security is not None and len(self.security) > 0
    
    @property
    def full_path(self) -> str:
        """Get the full path with method."""
        return f"{self.method.value} {self.path}"


class AttackResult(BaseModel):
    """Result of a single attack attempt."""
    endpoint: Endpoint
    attack_type: AttackType
    success: bool  # True if vulnerability found
    payload: Optional[str] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: Optional[str] = None
    duration_ms: Optional[float] = None


class Vulnerability(BaseModel):
    """Details of a discovered vulnerability."""
    endpoint: Endpoint
    attack_type: AttackType
    severity: Severity
    title: str
    description: str
    payload: str
    proof_of_concept: str
    recommendation: str
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    owasp_category: Optional[str] = None
    response_evidence: Optional[str] = None


class ScanConfig(BaseModel):
    """Configuration for a security scan."""
    target_url: str
    swagger_path: str
    output_path: str = "sentinel_report.md"
    attack_types: list[AttackType] = Field(default_factory=lambda: list(AttackType))
    timeout: int = 5  # seconds per request
    verbose: bool = False
    max_endpoints: int = 50  # Maximum endpoints to test
    rate_limit_delay: float = 0.5  # Delay between requests in seconds


class ScanResult(BaseModel):
    """Complete result of a security scan."""
    config: ScanConfig
    endpoints_tested: list[Endpoint] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    attack_results: list[AttackResult] = Field(default_factory=list)
    total_requests: int = 0
    duration_seconds: float = 0.0
    ai_decisions: list[dict] = Field(default_factory=list)
    
    @property
    def vulnerability_count(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Number of critical vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Number of high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Number of medium severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Number of low severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)


class AIAttackDecision(BaseModel):
    """AI's decision on which attacks to run for an endpoint."""
    endpoint: Endpoint
    recommended_attacks: list[AttackType]
    reasoning: str
    priority: int = 1  # 1 = highest, 5 = lowest
    parameters_to_test: list[str] = Field(default_factory=list)
