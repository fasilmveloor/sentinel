"""
OpenAPI/Swagger specification parser.

This module parses OpenAPI 3.0 and Swagger 2.0 specifications and extracts
endpoint information for security testing.
"""

import json
from pathlib import Path
from typing import Any, Optional
import yaml

from .models import Endpoint, HttpMethod, Parameter


class SwaggerParseError(Exception):
    """Raised when Swagger/OpenAPI spec cannot be parsed."""
    pass


class SwaggerParser:
    """Parser for OpenAPI/Swagger specifications."""
    
    def __init__(self, spec_path: str):
        """Initialize parser with path to spec file.
        
        Args:
            spec_path: Path to OpenAPI/Swagger YAML or JSON file
        """
        self.spec_path = Path(spec_path)
        self.spec: dict[str, Any] = {}
        self.openapi_version: Optional[str] = None
        self.swagger_version: Optional[str] = None
        
    def parse(self) -> list[Endpoint]:
        """Parse the specification file and return list of endpoints.
        
        Returns:
            List of Endpoint objects extracted from the spec
            
        Raises:
            SwaggerParseError: If spec cannot be parsed
        """
        self._load_spec()
        self._detect_version()
        return self._extract_endpoints()
    
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
    
    def _extract_endpoints(self) -> list[Endpoint]:
        """Extract all endpoints from the specification."""
        endpoints: list[Endpoint] = []
        
        paths = self.spec.get('paths', {})
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
                
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
        
        return Endpoint(
            path=path,
            method=method,
            operation_id=operation.get('operationId'),
            summary=operation.get('summary'),
            description=operation.get('description'),
            parameters=parameters,
            request_body=operation.get('requestBody'),
            responses=operation.get('responses', {}),
            security=operation.get('security'),
            tags=operation.get('tags', [])
        )
    
    def _parse_parameters(self, params: list) -> list[Parameter]:
        """Parse parameter definitions into Parameter objects."""
        parameters: list[Parameter] = []
        
        for param in params:
            if not isinstance(param, dict):
                continue
                
            # Handle OpenAPI 3.0 references (skip for now)
            if '$ref' in param:
                continue
            
            param_obj = Parameter(
                name=param.get('name', ''),
                location=param.get('in', 'query'),  # query, path, header, cookie
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
        if isinstance(schema, dict) and 'example' in schema:
            return schema['example']
        
        # Check examples object (OpenAPI 3.0)
        examples = param.get('examples', {})
        if examples and isinstance(examples, dict):
            first_example = next(iter(examples.values()), None)
            if isinstance(first_example, dict) and 'value' in first_example:
                return first_example['value']
        
        return None
    
    def get_base_url(self) -> Optional[str]:
        """Get the base URL from server definitions (OpenAPI 3.0) or host (Swagger 2.0)."""
        # OpenAPI 3.0
        servers = self.spec.get('servers', [])
        if servers and isinstance(servers, list):
            first_server = servers[0]
            if isinstance(first_server, dict):
                return first_server.get('url')
        
        # Swagger 2.0
        host = self.spec.get('host')
        base_path = self.spec.get('basePath', '')
        schemes = self.spec.get('schemes', ['http'])
        
        if host:
            scheme = schemes[0] if schemes else 'http'
            return f"{scheme}://{host}{base_path}"
        
        return None
    
    def get_security_schemes(self) -> dict[str, Any]:
        """Get security scheme definitions."""
        # OpenAPI 3.0
        components = self.spec.get('components', {})
        if isinstance(components, dict):
            return components.get('securitySchemes', {})
        
        # Swagger 2.0
        return self.spec.get('securityDefinitions', {})
    
    def get_info(self) -> dict[str, Any]:
        """Get API info (title, version, description)."""
        return self.spec.get('info', {})


def parse_swagger(spec_path: str) -> list[Endpoint]:
    """Convenience function to parse a swagger file.
    
    Args:
        spec_path: Path to OpenAPI/Swagger file
        
    Returns:
        List of Endpoint objects
    """
    parser = SwaggerParser(spec_path)
    return parser.parse()


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
