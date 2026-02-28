"""
Core data structures for Sentinel using Pydantic.

This module defines all the data models used throughout the application:
- Endpoint: Represents an API endpoint from OpenAPI spec
- AttackResult: Results from security testing
- Vulnerability: Details of found vulnerabilities
- ScanConfig: Configuration for a scan run

v2.0 Updates:
- Added XSS, SSRF, JWT, CMD_INJECTION, RATE_LIMIT attack types
- Added LLMProvider enum for multi-LLM support
- Added ReportFormat enum for multiple output formats
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class HttpMethod(str, Enum):
    """HTTP methods supported by Sentinel."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class AttackType(str, Enum):
    """Types of security attacks Sentinel can perform."""
    # v1.0 Attacks
    SQL_INJECTION = "sql_injection"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    # v2.0 Attacks
    XSS = "xss"
    SSRF = "ssrf"
    JWT = "jwt"
    CMD_INJECTION = "cmd_injection"
    RATE_LIMIT = "rate_limit"
    # Future Attacks
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LLMProvider(str, Enum):
    """Supported LLM providers for AI-powered analysis."""
    GEMINI = "gemini"
    OPENAI = "openai"
    CLAUDE = "claude"
    LOCAL = "local"  # For local LLMs like Ollama


class ReportFormat(str, Enum):
    """Supported report output formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    JUNIT = "junit"


class Parameter(BaseModel):
    """Represents an API parameter."""
    name: str
    location: str  # query, path, header, body, cookie
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
    extra_data: Optional[dict] = None  # Additional attack-specific data


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
    cvss_score: Optional[float] = None  # CVSS severity score
    references: list[str] = Field(default_factory=list)  # Reference URLs


class ScanConfig(BaseModel):
    """Configuration for a security scan."""
    target_url: str
    swagger_path: str
    output_path: str = "sentinel_report.md"
    output_format: ReportFormat = ReportFormat.MARKDOWN
    attack_types: list[AttackType] = Field(default_factory=lambda: list(AttackType))
    timeout: int = 5  # seconds per request
    verbose: bool = False
    max_endpoints: int = 50  # Maximum endpoints to test
    rate_limit_delay: float = 0.5  # Delay between requests in seconds
    llm_provider: LLMProvider = LLMProvider.GEMINI
    llm_api_key: Optional[str] = None
    follow_redirects: bool = True
    verify_ssl: bool = True
    custom_headers: dict[str, str] = Field(default_factory=dict)
    auth_token: Optional[str] = None  # Pre-authenticated token for testing


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
    
    @property
    def info_count(self) -> int:
        """Number of info severity findings."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.INFO)


class AIAttackDecision(BaseModel):
    """AI's decision on which attacks to run for an endpoint."""
    endpoint: Endpoint
    recommended_attacks: list[AttackType]
    reasoning: str
    priority: int = 1  # 1 = highest, 5 = lowest
    parameters_to_test: list[str] = Field(default_factory=list)
    confidence: float = 1.0  # AI confidence in the decision


# Attack-specific data models

class SQLInjectionResult(BaseModel):
    """SQL injection specific result data."""
    injection_type: str  # error-based, time-based, union-based, blind
    database_type: Optional[str] = None  # mysql, postgresql, mssql, etc.
    extractable_data: Optional[str] = None


class XSSResult(BaseModel):
    """XSS specific result data."""
    xss_type: str  # reflected, stored, dom-based
    context: str  # html, attribute, script, url
    bypass_technique: Optional[str] = None


class SSRFResult(BaseModel):
    """SSRF specific result data."""
    ssrf_type: str  # basic, blind, time-based
    reachable_host: Optional[str] = None
    protocol: Optional[str] = None  # http, file, gopher, etc.


class JWTResult(BaseModel):
    """JWT vulnerability specific result data."""
    vulnerability_type: str  # none-alg, weak-secret, alg-confusion, etc.
    token_header: Optional[dict] = None
    token_payload: Optional[dict] = None


class RateLimitResult(BaseModel):
    """Rate limit detection result data."""
    requests_made: int = 0
    time_window_seconds: float = 0.0
    blocked_after: Optional[int] = None
    bypass_found: bool = False


# OpenAPI 3.1.0 Support Models

class OpenAPIVersion(str, Enum):
    """Supported OpenAPI/Swagger versions."""
    SWAGGER_2_0 = "2.0"
    OPENAPI_3_0 = "3.0"
    OPENAPI_3_1 = "3.1"


class Webhook(BaseModel):
    """
    Represents an OpenAPI 3.1.0 Webhook.
    
    Webhooks define incoming API calls that the API consumer can receive.
    New in OpenAPI 3.1.0.
    """
    name: str
    endpoints: list["Endpoint"] = Field(default_factory=list)
    description: Optional[str] = None


class OpenAPISpecInfo(BaseModel):
    """Metadata about an OpenAPI specification."""
    title: str = "API"
    version: str = "1.0.0"
    description: Optional[str] = None
    terms_of_service: Optional[str] = None
    contact: Optional[dict] = None
    license: Optional[dict] = None
    summary: Optional[str] = None  # OpenAPI 3.1.0


class JSONSchema(BaseModel):
    """
    JSON Schema representation for OpenAPI 3.1.0.
    
    OpenAPI 3.1.0 uses full JSON Schema 2020-12 draft.
    """
    schema_ref: Optional[str] = Field(None, alias="$schema")
    id: Optional[str] = Field(None, alias="$id")
    type: Optional[str | list[str]] = None
    title: Optional[str] = None
    description: Optional[str] = None
    default: Optional[Any] = None
    examples: Optional[list[Any]] = None
    enum: Optional[list[Any]] = None
    const: Optional[Any] = None
    
    # Number constraints
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    exclusive_minimum: Optional[float | bool] = None
    exclusive_maximum: Optional[float | bool] = None
    multiple_of: Optional[float] = None
    
    # String constraints
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    format: Optional[str] = None
    
    # Array constraints
    items: Optional["JSONSchema"] = None
    min_items: Optional[int] = None
    max_items: Optional[int] = None
    unique_items: Optional[bool] = None
    
    # Object constraints
    properties: Optional[dict[str, "JSONSchema"]] = None
    required: Optional[list[str]] = None
    additional_properties: Optional["JSONSchema | bool"] = None
    min_properties: Optional[int] = None
    max_properties: Optional[int] = None
    
    # Composition
    all_of: Optional[list["JSONSchema"]] = Field(None, alias="allOf")
    any_of: Optional[list["JSONSchema"]] = Field(None, alias="anyOf")
    one_of: Optional[list["JSONSchema"]] = Field(None, alias="oneOf")
    not_schema: Optional["JSONSchema"] = Field(None, alias="not")
    
    # Reference
    ref: Optional[str] = Field(None, alias="$ref")
    
    model_config = ConfigDict(populate_by_name=True)


class ParsedSpec(BaseModel):
    """
    Complete parsed OpenAPI specification.
    
    Contains all endpoints, webhooks, security schemes, and metadata.
    """
    openapi_version: Optional[str] = None
    swagger_version: Optional[str] = None
    info: OpenAPISpecInfo = Field(default_factory=OpenAPISpecInfo)
    servers: list[dict] = Field(default_factory=list)
    endpoints: list["Endpoint"] = Field(default_factory=list)
    webhooks: list["Webhook"] = Field(default_factory=list)
    security_schemes: dict[str, Any] = Field(default_factory=dict)
    components: dict[str, Any] = Field(default_factory=dict)
    tags: list[dict] = Field(default_factory=list)
    external_docs: Optional[dict] = None
    json_schema_dialect: Optional[str] = None  # OpenAPI 3.1.0
    
    @property
    def version(self) -> OpenAPIVersion:
        """Get the detected OpenAPI version."""
        if self.openapi_version:
            if self.openapi_version.startswith("3.1"):
                return OpenAPIVersion.OPENAPI_3_1
            elif self.openapi_version.startswith("3.0"):
                return OpenAPIVersion.OPENAPI_3_0
        if self.swagger_version:
            return OpenAPIVersion.SWAGGER_2_0
        return OpenAPIVersion.OPENAPI_3_0  # Default assumption
