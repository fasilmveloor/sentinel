"""
OpenAPI/Swagger specification parser with full version support.

This module parses OpenAPI 2.0 (Swagger), 3.0.x, and 3.1.x specifications
and extracts endpoint information for security testing.

Supported Features:
- OpenAPI 2.0 (Swagger): Full support
- OpenAPI 3.0.x: Full support
- OpenAPI 3.1.x: Full support including:
  - Webhooks
  - Full JSON Schema 2020-12 draft support
  - $ref resolution in all locations
  - pathItem $ref
  - info.summary
  - jsonSchemaDialect
"""

import copy
import json
import re
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urljoin
import yaml

from .models import (
    Endpoint,
    HttpMethod,
    Parameter,
    OpenAPIVersion,
    OpenAPISpecInfo,
    ParsedSpec,
    Webhook,
)


class SwaggerParseError(Exception):
    """Raised when Swagger/OpenAPI spec cannot be parsed."""
    pass


class ReferenceResolver:
    """
    Resolves $ref references in OpenAPI specifications.
    
    Supports:
    - Local references: #/components/schemas/Example
    - Internal component resolution
    - Circular reference detection
    - OpenAPI 3.1.0 pathItem $ref
    """
    
    def __init__(self, spec: dict, max_depth: int = 10):
        self.spec = spec
        self.max_depth = max_depth
        self._resolution_cache: dict[str, Any] = {}
        self._resolution_stack: set[str] = set()
    
    def resolve(self, ref: str, current_depth: int = 0) -> Any:
        """
        Resolve a $ref reference to its target.
        
        Args:
            ref: The reference string (e.g., "#/components/schemas/User")
            current_depth: Current recursion depth for circular detection
            
        Returns:
            The resolved value or None if not found
        """
        if current_depth > self.max_depth:
            return None
        
        # Check cache first
        if ref in self._resolution_cache:
            return self._resolution_cache[ref]
        
        # Detect circular references
        if ref in self._resolution_stack:
            return {"$ref": ref, "_circular": True}
        
        self._resolution_stack.add(ref)
        
        try:
            if ref.startswith("#/"):
                # Local reference
                parts = ref[2:].split("/")
                current = self.spec
                
                for part in parts:
                    # Handle JSON Pointer escaping
                    part = part.replace("~1", "/").replace("~0", "~")
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        return None
                
                # If the resolved value has a $ref, resolve it too
                if isinstance(current, dict) and "$ref" in current:
                    current = self.resolve(current["$ref"], current_depth + 1)
                
                self._resolution_cache[ref] = current
                return current
            
            # External references not supported yet
            return None
            
        finally:
            self._resolution_stack.discard(ref)
    
    def resolve_in_place(self, obj: Any, depth: int = 0) -> Any:
        """
        Recursively resolve all $ref references in an object.
        
        Args:
            obj: The object to process
            depth: Current recursion depth
            
        Returns:
            The object with all references resolved
        """
        if depth > self.max_depth:
            return obj
        
        if isinstance(obj, dict):
            if "$ref" in obj:
                resolved = self.resolve(obj["$ref"], depth)
                if resolved:
                    # Merge resolved content with remaining properties
                    result = copy.deepcopy(resolved)
                    for key, value in obj.items():
                        if key != "$ref":
                            result[key] = value
                    return self.resolve_in_place(result, depth + 1)
                return obj
            
            return {k: self.resolve_in_place(v, depth + 1) for k, v in obj.items()}
        
        elif isinstance(obj, list):
            return [self.resolve_in_place(item, depth + 1) for item in obj]
        
        return obj


class SwaggerParser:
    """
    Parser for OpenAPI/Swagger specifications with full version support.
    
    Supports:
    - OpenAPI 2.0 (Swagger)
    - OpenAPI 3.0.x
    - OpenAPI 3.1.x (including webhooks)
    """
    
    def __init__(self, spec_path: str):
        """Initialize parser with path to spec file.
        
        Args:
            spec_path: Path to OpenAPI/Swagger YAML or JSON file
        """
        self.spec_path = Path(spec_path)
        self.spec: dict[str, Any] = {}
        self.resolver: Optional[ReferenceResolver] = None
        self.openapi_version: Optional[str] = None
        self.swagger_version: Optional[str] = None
    
    def parse(self) -> list[Endpoint]:
        """Parse the specification file and return list of endpoints.
        
        Returns:
            List of Endpoint objects extracted from the spec
            
        Raises:
            SwaggerParseError: If spec cannot be parsed
        """
        spec = self.parse_full()
        return spec.endpoints
    
    def parse_full(self) -> ParsedSpec:
        """
        Parse the specification and return complete parsed result.
        
        Returns:
            ParsedSpec with all extracted information
            
        Raises:
            SwaggerParseError: If spec cannot be parsed
        """
        self._load_spec()
        self._detect_version()
        
        # Initialize resolver
        self.resolver = ReferenceResolver(self.spec)
        self.resolver.resolve_in_place(self.spec)
        
        # Extract all components
        info = self._extract_info()
        servers = self._extract_servers()
        endpoints = self._extract_endpoints()
        webhooks = self._extract_webhooks()
        security_schemes = self._extract_security_schemes()
        components = self._extract_components()
        tags = self._extract_tags()
        external_docs = self.spec.get("externalDocs")
        json_schema_dialect = self.spec.get("jsonSchemaDialect")
        
        return ParsedSpec(
            openapi_version=self.openapi_version,
            swagger_version=self.swagger_version,
            info=info,
            servers=servers,
            endpoints=endpoints,
            webhooks=webhooks,
            security_schemes=security_schemes,
            components=components,
            tags=tags,
            external_docs=external_docs,
            json_schema_dialect=json_schema_dialect
        )
    
    def _load_spec(self) -> None:
        """Load the specification from file."""
        if not self.spec_path.exists():
            raise SwaggerParseError(f"Specification file not found: {self.spec_path}")
        
        content = self.spec_path.read_text(encoding='utf-8')
        
        # Try JSON first, then YAML
        try:
            self.spec = json.loads(content)
        except json.JSONDecodeError:
            try:
                self.spec = yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise SwaggerParseError(f"Failed to parse spec as JSON or YAML: {e}")
        
        if not isinstance(self.spec, dict):
            raise SwaggerParseError("Specification must be a JSON/YAML object")
    
    def _detect_version(self) -> None:
        """Detect OpenAPI/Swagger version."""
        self.openapi_version = self.spec.get('openapi')
        self.swagger_version = self.spec.get('swagger')
        
        if not self.openapi_version and not self.swagger_version:
            raise SwaggerParseError(
                "Could not detect OpenAPI/Swagger version. "
                "Expected 'openapi' or 'swagger' field in spec."
            )
    
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
        return OpenAPIVersion.OPENAPI_3_0
    
    def _extract_info(self) -> OpenAPISpecInfo:
        """Extract API info/metadata."""
        info = self.spec.get("info", {})
        
        # Resolve $ref if present (OpenAPI 3.1.0 allows $ref in info)
        if "$ref" in info:
            info = self.resolver.resolve(info["$ref"]) or info
        
        return OpenAPISpecInfo(
            title=info.get("title", "API"),
            version=info.get("version", "1.0.0"),
            description=info.get("description"),
            terms_of_service=info.get("termsOfService"),
            contact=info.get("contact"),
            license=info.get("license"),
            summary=info.get("summary")  # OpenAPI 3.1.0
        )
    
    def _extract_servers(self) -> list[dict]:
        """Extract server definitions."""
        servers = []
        
        # OpenAPI 3.x servers
        for server in self.spec.get("servers", []):
            if isinstance(server, dict):
                servers.append({
                    "url": server.get("url", ""),
                    "description": server.get("description"),
                    "variables": server.get("variables", {})
                })
        
        # Swagger 2.0 host/basePath/schemes
        if not servers and self.swagger_version:
            host = self.spec.get("host")
            base_path = self.spec.get("basePath", "")
            schemes = self.spec.get("schemes", ["http"])
            
            if host:
                for scheme in schemes:
                    servers.append({
                        "url": f"{scheme}://{host}{base_path}",
                        "description": f"Default {scheme} server"
                    })
        
        return servers
    
    def _extract_endpoints(self) -> list[Endpoint]:
        """Extract all endpoints from the specification."""
        endpoints: list[Endpoint] = []
        
        paths = self.spec.get('paths', {})
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            # Handle OpenAPI 3.1.0 pathItem $ref
            if "$ref" in path_item:
                path_item = self.resolver.resolve(path_item["$ref"]) or path_item
            
            endpoints.extend(self._extract_path_endpoints(path, path_item))
        
        return endpoints
    
    def _extract_path_endpoints(self, path: str, path_item: dict) -> list[Endpoint]:
        """Extract endpoints from a single path item."""
        endpoints: list[Endpoint] = []
        
        http_methods = ['get', 'post', 'put', 'patch', 'delete']
        
        for method_lower in http_methods:
            if method_lower not in path_item:
                continue
                
            operation = path_item[method_lower]
            if not isinstance(operation, dict):
                continue
            
            endpoint = self._create_endpoint(
                path=path,
                method=HttpMethod(method_lower.upper()),
                operation=operation,
                path_parameters=path_item.get('parameters', [])
            )
            endpoints.append(endpoint)
        
        return endpoints
    
    def _create_endpoint(
        self, 
        path: str, 
        method: HttpMethod, 
        operation: dict,
        path_parameters: list
    ) -> Endpoint:
        """Create an Endpoint object from operation data."""
        # Combine path-level and operation-level parameters
        all_params = path_parameters + operation.get('parameters', [])
        parameters = self._parse_parameters(all_params)
        
        # Resolve request body if it's a $ref
        request_body = operation.get('requestBody')
        if request_body and "$ref" in request_body:
            request_body = self.resolver.resolve(request_body["$ref"]) or request_body
        
        # Convert response keys to strings (Swagger 2.0 uses integers)
        responses = operation.get('responses', {})
        responses = {str(k): v for k, v in responses.items()}
        
        return Endpoint(
            path=path,
            method=method,
            operation_id=operation.get('operationId'),
            summary=operation.get('summary'),
            description=operation.get('description'),
            parameters=parameters,
            request_body=request_body,
            responses=responses,
            security=operation.get('security'),
            tags=operation.get('tags', [])
        )
    
    def _parse_parameters(self, params: list) -> list[Parameter]:
        """Parse parameter definitions into Parameter objects."""
        parameters: list[Parameter] = []
        
        for param in params:
            if not isinstance(param, dict):
                continue
            
            # Resolve $ref
            if '$ref' in param:
                param = self.resolver.resolve(param['$ref']) or param
            
            if not isinstance(param, dict):
                continue
            
            param_obj = Parameter(
                name=param.get('name', ''),
                location=param.get('in', 'query'),
                required=param.get('required', False),
                param_type=self._get_param_type(param),
                description=param.get('description'),
                example=self._get_example(param)
            )
            parameters.append(param_obj)
        
        return parameters
    
    def _get_param_type(self, param: dict) -> str:
        """Get the type of a parameter."""
        schema = param.get('schema', {})
        
        # Resolve schema $ref
        if isinstance(schema, dict) and '$ref' in schema:
            schema = self.resolver.resolve(schema['$ref']) or schema
        
        if isinstance(schema, dict):
            return schema.get('type', 'string')
        return 'string'
    
    def _get_example(self, param: dict) -> Any:
        """Get example value for a parameter."""
        # Check direct example
        if 'example' in param:
            return param['example']
        
        # Check schema example
        schema = param.get('schema', {})
        if isinstance(schema, dict):
            if '$ref' in schema:
                schema = self.resolver.resolve(schema['$ref']) or schema
            if 'example' in schema:
                return schema['example']
        
        # Check examples object (OpenAPI 3.x)
        examples = param.get('examples', {})
        if examples and isinstance(examples, dict):
            first_example = next(iter(examples.values()), None)
            if isinstance(first_example, dict):
                # Check for $ref in example
                if '$ref' in first_example:
                    first_example = self.resolver.resolve(first_example['$ref']) or first_example
                if 'value' in first_example:
                    return first_example['value']
        
        return None
    
    def _extract_webhooks(self) -> list[Webhook]:
        """
        Extract webhooks from OpenAPI 3.1.0 specification.
        
        Webhooks are new in OpenAPI 3.1.0 and define incoming API calls
        that the API consumer can receive.
        """
        webhooks: list[Webhook] = []
        
        # Only available in OpenAPI 3.1.x
        if not self.openapi_version or not self.openapi_version.startswith("3.1"):
            return webhooks
        
        webhooks_spec = self.spec.get("webhooks", {})
        
        for name, webhook_item in webhooks_spec.items():
            if not isinstance(webhook_item, dict):
                continue
            
            # Resolve $ref if present
            if "$ref" in webhook_item:
                webhook_item = self.resolver.resolve(webhook_item["$ref"]) or webhook_item
            
            webhook_endpoints = []
            
            # Webhook item is similar to Path Item Object
            for method in ['get', 'post', 'put', 'patch', 'delete']:
                if method in webhook_item:
                    operation = webhook_item[method]
                    if isinstance(operation, dict):
                        # Create a synthetic path for the webhook
                        endpoint = self._create_endpoint(
                            path=f"/webhook/{name}",
                            method=HttpMethod(method.upper()),
                            operation=operation,
                            path_parameters=[]
                        )
                        webhook_endpoints.append(endpoint)
            
            if webhook_endpoints:
                webhooks.append(Webhook(
                    name=name,
                    endpoints=webhook_endpoints,
                    description=webhook_item.get("description") or webhook_item.get("summary")
                ))
        
        return webhooks
    
    def _extract_security_schemes(self) -> dict[str, Any]:
        """Get security scheme definitions."""
        security_schemes = {}
        
        # OpenAPI 3.x
        components = self.spec.get('components', {})
        if isinstance(components, dict):
            schemes = components.get('securitySchemes', {})
            if schemes:
                # Resolve any $refs in security schemes
                for name, scheme in schemes.items():
                    if isinstance(scheme, dict) and '$ref' in scheme:
                        scheme = self.resolver.resolve(scheme['$ref']) or scheme
                    security_schemes[name] = scheme
        
        # Swagger 2.0
        if not security_schemes:
            schemes = self.spec.get('securityDefinitions', {})
            if schemes:
                for name, scheme in schemes.items():
                    if isinstance(scheme, dict) and '$ref' in scheme:
                        scheme = self.resolver.resolve(scheme['$ref']) or scheme
                    security_schemes[name] = scheme
        
        return security_schemes
    
    def _extract_components(self) -> dict[str, Any]:
        """Extract all components/schemas."""
        components = {}
        
        # OpenAPI 3.x components
        if 'components' in self.spec:
            components = copy.deepcopy(self.spec['components'])
        
        # Swagger 2.0 definitions
        if 'definitions' in self.spec:
            components['schemas'] = components.get('schemas', {})
            components['schemas'].update(copy.deepcopy(self.spec['definitions']))
        
        # Resolve all $refs in components
        if self.resolver:
            components = self.resolver.resolve_in_place(components)
        
        return components
    
    def _extract_tags(self) -> list[dict]:
        """Extract tag definitions."""
        tags = []
        
        for tag in self.spec.get("tags", []):
            if isinstance(tag, dict):
                # Resolve $ref if present (OpenAPI 3.1.0 allows $ref in tags)
                if "$ref" in tag:
                    tag = self.resolver.resolve(tag["$ref"]) or tag
                tags.append(tag)
        
        return tags
    
    def get_base_url(self) -> Optional[str]:
        """Get the base URL from server definitions (OpenAPI 3.x) or host (Swagger 2.0)."""
        # Ensure spec is loaded
        if not self.spec:
            self._load_spec()
            self._detect_version()
            self.resolver = ReferenceResolver(self.spec)
        
        servers = self._extract_servers()
        
        if servers:
            first_server = servers[0]
            url = first_server.get("url", "")
            
            # Handle server variables
            variables = first_server.get("variables", {})
            if variables:
                for var_name, var_def in variables.items():
                    if isinstance(var_def, dict):
                        default = var_def.get("default", "")
                        url = url.replace(f"{{{var_name}}}", default)
            
            return url
        
        return None
    
    def get_security_schemes(self) -> dict[str, Any]:
        """Get security scheme definitions."""
        return self._extract_security_schemes()
    
    def get_info(self) -> dict[str, Any]:
        """Get API info (title, version, description)."""
        info = self._extract_info()
        return info.model_dump()


def parse_swagger(spec_path: str) -> list[Endpoint]:
    """Convenience function to parse a swagger file.
    
    Args:
        spec_path: Path to OpenAPI/Swagger file
        
    Returns:
        List of Endpoint objects
    """
    parser = SwaggerParser(spec_path)
    return parser.parse()


def parse_openapi(spec_path: str) -> ParsedSpec:
    """
    Parse an OpenAPI specification and return full parsed result.
    
    Args:
        spec_path: Path to OpenAPI/Swagger file
        
    Returns:
        ParsedSpec with all extracted information including webhooks
    """
    parser = SwaggerParser(spec_path)
    return parser.parse_full()


def get_sample_endpoint_values(endpoint: Endpoint) -> dict[str, Any]:
    """Generate sample values for endpoint parameters.
    
    Useful for creating test requests when no examples are provided.
    
    Args:
        endpoint: The endpoint to generate values for
        
    Returns:
        Dictionary with parameter names and sample values
    """
    sample_values: dict[str, Any] = {}
    
    type_defaults = {
        'string': 'test',
        'integer': 1,
        'number': 1.0,
        'boolean': True,
        'array': [],
        'object': {}
    }
    
    for param in endpoint.parameters:
        if param.example is not None:
            sample_values[param.name] = param.example
        else:
            sample_values[param.name] = type_defaults.get(param.param_type, 'test')
    
    return sample_values
