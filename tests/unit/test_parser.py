"""
Unit tests for OpenAPI/Swagger specification parser.

Tests cover:
- OpenAPI 3.0 parsing
- Swagger 2.0 parsing
- JSON and YAML format support
- Parameter extraction
- Error handling
- Edge cases
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from sentinel.parser import (
    SwaggerParser, SwaggerParseError,
    parse_swagger, get_sample_endpoint_values,
    ReferenceResolver
)
from sentinel.models import Endpoint, HttpMethod


# ============================================================================
# SWAGGER PARSER INITIALIZATION TESTS
# ============================================================================

class TestSwaggerParserInit:
    """Tests for SwaggerParser initialization."""

    def test_init_with_string_path(self, temp_dir):
        """Test initialization with string path."""
        spec_file = temp_dir / "test.json"
        spec_file.write_text('{"openapi": "3.0.0", "paths": {}}')
        
        parser = SwaggerParser(str(spec_file))
        assert parser.spec_path == spec_file
        assert parser.spec == {}

    def test_init_with_path_object(self, temp_dir):
        """Test initialization with Path object."""
        spec_file = temp_dir / "test.json"
        spec_file.write_text('{"openapi": "3.0.0", "paths": {}}')
        
        parser = SwaggerParser(str(spec_file))
        assert parser.spec_path.exists()


# ============================================================================
# SPEC LOADING TESTS
# ============================================================================

class TestSpecLoading:
    """Tests for specification loading."""

    def test_load_json_spec(self, temp_openapi_file):
        """Test loading JSON specification."""
        parser = SwaggerParser(str(temp_openapi_file))
        parser._load_spec()
        
        assert parser.spec is not None
        assert "openapi" in parser.spec
        assert parser.spec["openapi"] == "3.0.0"

    def test_load_yaml_spec(self, temp_yaml_spec_file):
        """Test loading YAML specification."""
        parser = SwaggerParser(str(temp_yaml_spec_file))
        parser._load_spec()
        
        assert parser.spec is not None
        assert parser.spec["openapi"] == "3.0.0"

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        parser = SwaggerParser("/nonexistent/spec.json")
        
        with pytest.raises(SwaggerParseError) as exc_info:
            parser._load_spec()
        
        assert "not found" in str(exc_info.value)

    def test_load_invalid_json(self, temp_dir):
        """Test loading invalid JSON (without valid version) raises error."""
        invalid_file = temp_dir / "invalid.json"
        # YAML can parse this as {'invalid json': None}, but it lacks openapi/swagger version
        invalid_file.write_text("{ invalid json }")
        
        parser = SwaggerParser(str(invalid_file))
        
        # _load_spec succeeds (YAML parses it), but _detect_version fails
        with pytest.raises(SwaggerParseError):
            parser.parse()  # This calls _load_spec + _detect_version

    def test_load_invalid_yaml(self, temp_dir):
        """Test loading invalid YAML raises error."""
        invalid_file = temp_dir / "invalid.yaml"
        invalid_file.write_text(":\n  - invalid yaml: [")
        
        parser = SwaggerParser(str(invalid_file))
        
        with pytest.raises(SwaggerParseError):
            parser._load_spec()

    def test_load_non_dict_spec(self, temp_dir):
        """Test loading non-dict spec raises error."""
        list_file = temp_dir / "list.json"
        list_file.write_text('[1, 2, 3]')
        
        parser = SwaggerParser(str(list_file))
        
        with pytest.raises(SwaggerParseError) as exc_info:
            parser._load_spec()
        
        assert "must be a JSON/YAML object" in str(exc_info.value)


# ============================================================================
# VERSION DETECTION TESTS
# ============================================================================

class TestVersionDetection:
    """Tests for OpenAPI/Swagger version detection."""

    def test_detect_openapi_3_0(self, temp_openapi_file):
        """Test detecting OpenAPI 3.0 version."""
        parser = SwaggerParser(str(temp_openapi_file))
        parser._load_spec()
        parser._detect_version()
        
        assert parser.openapi_version == "3.0.0"
        assert parser.swagger_version is None

    def test_detect_swagger_2_0(self, temp_swagger_file):
        """Test detecting Swagger 2.0 version."""
        parser = SwaggerParser(str(temp_swagger_file))
        parser._load_spec()
        parser._detect_version()
        
        assert parser.swagger_version == "2.0"
        assert parser.openapi_version is None

    def test_detect_no_version(self, temp_dir):
        """Test spec without version raises error."""
        no_version_file = temp_dir / "no_version.json"
        no_version_file.write_text('{"info": {"title": "Test"}}')
        
        parser = SwaggerParser(str(no_version_file))
        parser._load_spec()
        
        with pytest.raises(SwaggerParseError) as exc_info:
            parser._detect_version()
        
        assert "Could not detect" in str(exc_info.value)


# ============================================================================
# ENDPOINT EXTRACTION TESTS
# ============================================================================

class TestEndpointExtraction:
    """Tests for endpoint extraction."""

    def test_extract_single_endpoint(self, temp_dir):
        """Test extracting a single endpoint."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "operationId": "listUsers"
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints) == 1
        assert endpoints[0].path == "/users"
        assert endpoints[0].method == HttpMethod.GET
        assert endpoints[0].summary == "List users"

    def test_extract_multiple_methods(self, temp_dir):
        """Test extracting multiple methods for same path."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"},
                    "put": {"summary": "Update user"},
                    "delete": {"summary": "Delete user"}
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints) == 4
        methods = {e.method for e in endpoints}
        assert methods == {HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE}

    def test_extract_multiple_paths(self, temp_openapi_file):
        """Test extracting multiple paths."""
        parser = SwaggerParser(str(temp_openapi_file))
        endpoints = parser.parse()
        
        # From sample_openapi_spec fixture
        assert len(endpoints) >= 2
        paths = {e.path for e in endpoints}
        assert "/users" in paths
        assert "/users/{id}" in paths

    def test_extract_empty_paths(self, temp_dir):
        """Test spec with no paths returns empty list."""
        spec = {"openapi": "3.0.0", "paths": {}}
        spec_file = temp_dir / "empty.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert endpoints == []

    def test_extract_no_paths_key(self, temp_dir):
        """Test spec without paths key returns empty list."""
        spec = {"openapi": "3.0.0"}
        spec_file = temp_dir / "no_paths.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert endpoints == []

    def test_skip_non_dict_path_item(self, temp_dir):
        """Test non-dict path items are skipped."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": "not a dict",
                "/posts": {
                    "get": {"summary": "List posts"}
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints) == 1
        assert endpoints[0].path == "/posts"

    def test_skip_non_dict_operation(self, temp_dir):
        """Test non-dict operations are skipped."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": "not a dict",
                    "post": {"summary": "Create user"}
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints) == 1
        assert endpoints[0].method == HttpMethod.POST


# ============================================================================
# PARAMETER PARSING TESTS
# ============================================================================

class TestParameterParsing:
    """Tests for parameter parsing."""

    def test_parse_query_parameter(self, temp_dir):
        """Test parsing query parameter."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "integer"}
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints[0].parameters) == 1
        param = endpoints[0].parameters[0]
        assert param.name == "limit"
        assert param.location == "query"
        assert param.required is False
        assert param.param_type == "integer"

    def test_parse_path_parameter(self, temp_dir):
        """Test parsing path parameter."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        param = endpoints[0].parameters[0]
        assert param.location == "path"
        assert param.required is True

    def test_parse_header_parameter(self, temp_dir):
        """Test parsing header parameter."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "X-API-Key",
                                "in": "header",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        param = endpoints[0].parameters[0]
        assert param.location == "header"
        assert param.name == "X-API-Key"

    def test_parse_multiple_parameters(self, temp_dir):
        """Test parsing multiple parameters."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert len(endpoints[0].parameters) == 3

    def test_parse_parameter_with_description(self, temp_dir):
        """Test parsing parameter with description."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "query",
                                "description": "User identifier",
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert endpoints[0].parameters[0].description == "User identifier"

    def test_parse_parameter_with_example(self, temp_dir):
        """Test parsing parameter with example."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "status",
                                "in": "query",
                                "example": "active",
                                "schema": {"type": "string"}
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert endpoints[0].parameters[0].example == "active"

    def test_parse_parameter_with_schema_example(self, temp_dir):
        """Test parsing parameter with example in schema."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {
                                "name": "count",
                                "in": "query",
                                "schema": {
                                    "type": "integer",
                                    "example": 10
                                }
                            }
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        assert endpoints[0].parameters[0].example == 10

    def test_skip_reference_parameters(self, temp_dir):
        """Test $ref parameters are skipped."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/CommonParam"},
                            {"name": "id", "in": "query", "schema": {"type": "string"}}
                        ]
                    }
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        # Now that we resolve $refs, we get both parameters
        # The $ref parameter is resolved and has an empty name (from the ref structure)
        assert len(endpoints[0].parameters) == 2
        # One of them should be the 'id' parameter
        param_names = [p.name for p in endpoints[0].parameters]
        assert "id" in param_names

    def test_path_level_parameters(self, temp_dir):
        """Test path-level parameters are inherited."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "get": {"summary": "Get user"},
                    "put": {"summary": "Update user"}
                }
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        # Both endpoints should have the path parameter
        assert len(endpoints) == 2
        for endpoint in endpoints:
            assert len(endpoint.parameters) == 1
            assert endpoint.parameters[0].name == "id"


# ============================================================================
# BASE URL EXTRACTION TESTS
# ============================================================================

class TestBaseUrlExtraction:
    """Tests for base URL extraction."""

    def test_get_base_url_openapi_3(self, temp_openapi_file):
        """Test getting base URL from OpenAPI 3.0 spec."""
        parser = SwaggerParser(str(temp_openapi_file))
        parser._load_spec()
        
        base_url = parser.get_base_url()
        assert base_url == "https://api.example.com"

    def test_get_base_url_swagger_2(self, temp_swagger_file):
        """Test getting base URL from Swagger 2.0 spec."""
        parser = SwaggerParser(str(temp_swagger_file))
        parser._load_spec()
        parser._detect_version()
        
        base_url = parser.get_base_url()
        assert base_url == "https://api.example.com/v2"

    def test_get_base_url_swagger_2_http(self, temp_dir):
        """Test Swagger 2.0 with http scheme."""
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "schemes": ["http"]
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        parser._detect_version()
        
        base_url = parser.get_base_url()
        assert base_url == "http://api.example.com"

    def test_get_base_url_swagger_2_no_base_path(self, temp_dir):
        """Test Swagger 2.0 without basePath."""
        spec = {
            "swagger": "2.0",
            "host": "api.example.com"
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        parser._detect_version()
        
        base_url = parser.get_base_url()
        assert base_url == "http://api.example.com"

    def test_get_base_url_no_servers(self, temp_dir):
        """Test spec without servers/host returns None."""
        spec = {"openapi": "3.0.0"}
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        
        base_url = parser.get_base_url()
        assert base_url is None


# ============================================================================
# SECURITY SCHEMES TESTS
# ============================================================================

class TestSecuritySchemes:
    """Tests for security scheme extraction."""

    def test_get_security_schemes_openapi_3(self, temp_openapi_file):
        """Test getting security schemes from OpenAPI 3.0 spec."""
        parser = SwaggerParser(str(temp_openapi_file))
        parser._load_spec()
        
        schemes = parser.get_security_schemes()
        assert "bearerAuth" in schemes

    def test_get_security_schemes_swagger_2(self, temp_dir):
        """Test getting security schemes from Swagger 2.0 spec."""
        spec = {
            "swagger": "2.0",
            "securityDefinitions": {
                "api_key": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
            }
        }
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        
        schemes = parser.get_security_schemes()
        assert "api_key" in schemes

    def test_get_security_schemes_empty(self, temp_dir):
        """Test spec without security schemes returns empty dict."""
        spec = {"openapi": "3.0.0"}
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        
        schemes = parser.get_security_schemes()
        assert schemes == {}


# ============================================================================
# API INFO TESTS
# ============================================================================

class TestApiInfo:
    """Tests for API info extraction."""

    def test_get_info(self, temp_openapi_file):
        """Test getting API info."""
        parser = SwaggerParser(str(temp_openapi_file))
        parser._load_spec()
        
        info = parser.get_info()
        assert info["title"] == "Test API"
        assert info["version"] == "1.0.0"

    def test_get_info_empty(self, temp_dir):
        """Test spec without info returns default info."""
        spec = {"openapi": "3.0.0"}
        spec_file = temp_dir / "spec.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        parser._load_spec()
        parser._detect_version()
        parser.resolver = ReferenceResolver(parser.spec)
        
        info = parser.get_info()
        # Now returns a model dump with default values
        assert info["title"] == "API"
        assert info["version"] == "1.0.0"


# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_parse_swagger_function(self, temp_openapi_file):
        """Test parse_swagger convenience function."""
        endpoints = parse_swagger(str(temp_openapi_file))
        
        assert isinstance(endpoints, list)
        assert len(endpoints) >= 2

    def test_get_sample_endpoint_values(self, sample_endpoint):
        """Test get_sample_endpoint_values function."""
        values = get_sample_endpoint_values(sample_endpoint)
        
        assert isinstance(values, dict)
        # Should have values for parameters
        for param in sample_endpoint.parameters:
            if param.name in values:
                assert values[param.name] is not None

    def test_get_sample_values_with_examples(self):
        """Test sample values use examples when available."""
        from sentinel.models import Parameter
        
        endpoint = Endpoint(
            path="/test",
            method=HttpMethod.GET,
            parameters=[
                Parameter(name="status", location="query", example="active"),
                Parameter(name="count", location="query", param_type="integer")
            ]
        )
        
        values = get_sample_endpoint_values(endpoint)
        
        assert values["status"] == "active"  # Uses example
        assert values["count"] == 1  # Uses default for integer


# ============================================================================
# FULL PARSE FLOW TESTS
# ============================================================================

class TestFullParseFlow:
    """Tests for complete parsing workflow."""

    def test_full_parse_openapi_3(self, temp_openapi_file):
        """Test full parse of OpenAPI 3.0 spec."""
        parser = SwaggerParser(str(temp_openapi_file))
        endpoints = parser.parse()
        
        # Verify all expected endpoints are present
        assert len(endpoints) > 0
        
        # Verify endpoint properties
        for endpoint in endpoints:
            assert isinstance(endpoint, Endpoint)
            assert endpoint.path.startswith("/")
            assert isinstance(endpoint.method, HttpMethod)

    def test_full_parse_swagger_2(self, temp_swagger_file):
        """Test full parse of Swagger 2.0 spec."""
        parser = SwaggerParser(str(temp_swagger_file))
        endpoints = parser.parse()
        
        assert len(endpoints) > 0
        for endpoint in endpoints:
            assert isinstance(endpoint, Endpoint)

    def test_parse_complex_spec(self, temp_dir):
        """Test parsing complex spec with all features."""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Complex API",
                "version": "1.0.0"
            },
            "servers": [
                {"url": "https://api.example.com/v1"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List all users",
                        "description": "Returns a list of users",
                        "tags": ["users"],
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "operationId": "createUser",
                        "summary": "Create a user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "security": [{"bearerAuth": []}],
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "get": {
                        "operationId": "getUser",
                        "summary": "Get user by ID",
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "delete": {
                        "operationId": "deleteUser",
                        "summary": "Delete user",
                        "security": [{"bearerAuth": []}],
                        "responses": {"204": {"description": "No content"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        }
        spec_file = temp_dir / "complex.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        endpoints = parser.parse()
        
        # Should have 4 endpoints
        assert len(endpoints) == 4
        
        # Verify operations
        operations = {(e.path, e.method) for e in endpoints}
        assert ("/users", HttpMethod.GET) in operations
        assert ("/users", HttpMethod.POST) in operations
        assert ("/users/{id}", HttpMethod.GET) in operations
        assert ("/users/{id}", HttpMethod.DELETE) in operations
        
        # Verify security
        for endpoint in endpoints:
            if endpoint.method == HttpMethod.GET and endpoint.path == "/users":
                assert not endpoint.requires_auth
            else:
                assert endpoint.requires_auth


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_parse_before_load_raises(self):
        """Test parsing before loading raises appropriate error."""
        parser = SwaggerParser("/nonexistent.json")
        
        with pytest.raises(SwaggerParseError):
            parser.parse()

    def test_graceful_handling_of_malformed_spec(self, temp_dir):
        """Test graceful handling of malformed spec."""
        # Spec with invalid structure but valid JSON
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": None  # Invalid operation
                }
            }
        }
        spec_file = temp_dir / "malformed.json"
        spec_file.write_text(json.dumps(spec))
        
        parser = SwaggerParser(str(spec_file))
        # Should not crash, just skip invalid operations
        endpoints = parser.parse()
        assert len(endpoints) == 0
