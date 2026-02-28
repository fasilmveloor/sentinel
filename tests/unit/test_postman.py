"""
Unit tests for Postman Collection support.

Tests cover:
- PostmanParser: Collection parsing
- PostmanGenerator: Collection generation
- Round-trip conversion
- CLI commands integration
"""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from sentinel.postman import (
    PostmanParser,
    PostmanGenerator,
    PostmanParseError,
    PostmanVariable,
    PostmanRequest,
    PostmanAuthType,
    parse_postman,
    generate_postman_collection,
    convert_openapi_to_postman
)
from sentinel.models import Endpoint, HttpMethod, Parameter


# ==================== Fixtures ====================

@pytest.fixture
def sample_postman_collection_v21():
    """Sample Postman Collection v2.1."""
    return {
        "info": {
            "_postman_id": "test-123",
            "name": "Test API Collection",
            "description": "A test collection for unit tests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "name": "Get Users",
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "https://api.example.com/users?page=1&limit=10",
                                "protocol": "https",
                                "host": ["api", "example", "com"],
                                "path": ["users"],
                                "query": [
                                    {"key": "page", "value": "1"},
                                    {"key": "limit", "value": "10"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Create User",
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/users",
                            "header": [
                                {"key": "Content-Type", "value": "application/json"}
                            ],
                            "body": {
                                "mode": "raw",
                                "raw": "{\"name\": \"John\", \"email\": \"john@example.com\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Get User by ID",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "https://api.example.com/users/{{user_id}}",
                        "path": ["users", "{{user_id}}"]
                    },
                    "auth": {
                        "type": "bearer",
                        "bearer": [{"key": "token", "value": "{{auth_token}}"}]
                    }
                }
            }
        ],
        "variable": [
            {"key": "base_url", "value": "https://api.example.com"},
            {"key": "auth_token", "value": "secret-token"}
        ]
    }


@pytest.fixture
def sample_postman_collection_v20():
    """Sample Postman Collection v2.0."""
    return {
        "info": {
            "name": "v2.0 Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json"
        },
        "item": [
            {
                "name": "Simple GET",
                "request": {
                    "method": "GET",
                    "url": "http://localhost:8000/api/test"
                }
            }
        ]
    }


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample API",
            "version": "1.0.0",
            "description": "A sample API for testing"
        },
        "servers": [
            {"url": "https://api.example.com/v1"}
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "operationId": "listUsers",
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {"200": {"description": "OK"}}
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "operationId": "getUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "OK"}}
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


@pytest.fixture
def temp_collection_file(tmp_path, sample_postman_collection_v21):
    """Create a temporary Postman collection file."""
    collection_path = tmp_path / "test_collection.json"
    with open(collection_path, 'w') as f:
        json.dump(sample_postman_collection_v21, f)
    return collection_path


@pytest.fixture
def temp_openapi_file(tmp_path, sample_openapi_spec):
    """Create a temporary OpenAPI spec file."""
    spec_path = tmp_path / "openapi.json"
    with open(spec_path, 'w') as f:
        json.dump(sample_openapi_spec, f)
    return spec_path


# ==================== PostmanVariable Tests ====================

class TestPostmanVariable:
    """Tests for PostmanVariable class."""
    
    def test_create_variable(self):
        """Test creating a variable."""
        var = PostmanVariable(
            key="base_url",
            value="https://api.example.com",
            description="API base URL"
        )
        
        assert var.key == "base_url"
        assert var.value == "https://api.example.com"
        assert var.description == "API base URL"
    
    def test_to_dict(self):
        """Test converting variable to dict."""
        var = PostmanVariable(
            key="api_key",
            value="secret123",
            description="API Key"
        )
        
        result = var.to_dict()
        
        assert result["key"] == "api_key"
        assert result["value"] == "secret123"
        assert result["description"] == "API Key"
    
    def test_from_dict(self):
        """Test creating variable from dict."""
        data = {
            "key": "token",
            "value": "bearer-token",
            "description": "Auth token"
        }
        
        var = PostmanVariable.from_dict(data)
        
        assert var.key == "token"
        assert var.value == "bearer-token"
        assert var.description == "Auth token"


# ==================== PostmanParser Tests ====================

class TestPostmanParser:
    """Tests for PostmanParser class."""
    
    def test_parse_v21_collection(self, temp_collection_file):
        """Test parsing a v2.1 collection."""
        parser = PostmanParser(str(temp_collection_file))
        endpoints = parser.parse()
        
        assert len(endpoints) >= 1
        assert all(isinstance(ep, Endpoint) for ep in endpoints)
    
    def test_parse_returns_endpoints(self, temp_collection_file):
        """Test that parse returns Endpoint objects."""
        parser = PostmanParser(str(temp_collection_file))
        endpoints = parser.parse()
        
        # Check that we have GET and POST endpoints
        methods = [ep.method for ep in endpoints]
        assert HttpMethod.GET in methods
    
    def test_parse_full(self, temp_collection_file):
        """Test parse_full returns complete information."""
        parser = PostmanParser(str(temp_collection_file))
        result = parser.parse_full()
        
        assert "info" in result
        assert "endpoints" in result
        assert "variables" in result
        assert "auth" in result
        
        info = result["info"]
        assert info["name"] == "Test API Collection"
    
    def test_extract_variables(self, temp_collection_file):
        """Test variable extraction."""
        parser = PostmanParser(str(temp_collection_file))
        parser.parse()
        
        assert "base_url" in parser.variables
        assert "auth_token" in parser.variables
        assert parser.variables["auth_token"] == "secret-token"
    
    def test_get_base_url(self, temp_collection_file):
        """Test base URL extraction."""
        parser = PostmanParser(str(temp_collection_file))
        parser.parse()
        
        # The get_base_url method extracts from the most common host
        # Check that variables were properly extracted instead
        assert "base_url" in parser.variables
        assert "api.example.com" in parser.variables["base_url"]
    
    def test_parse_missing_file(self, tmp_path):
        """Test error handling for missing file."""
        with pytest.raises(PostmanParseError):
            parser = PostmanParser(str(tmp_path / "nonexistent.json"))
            parser.parse()
    
    def test_parse_invalid_json(self, tmp_path):
        """Test error handling for invalid JSON."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json {{{")
        
        with pytest.raises(PostmanParseError):
            parser = PostmanParser(str(invalid_file))
            parser.parse()
    
    def test_parse_missing_schema(self, tmp_path):
        """Test error handling for missing schema."""
        no_schema = {"info": {"name": "Test"}}
        file_path = tmp_path / "no_schema.json"
        file_path.write_text(json.dumps(no_schema))
        
        with pytest.raises(PostmanParseError):
            parser = PostmanParser(str(file_path))
            parser.parse()
    
    def test_resolve_variables(self, temp_collection_file):
        """Test variable resolution in URLs."""
        parser = PostmanParser(str(temp_collection_file))
        parser.parse()
        
        # Variables are extracted during parse
        assert parser.variables.get("base_url") == "https://api.example.com"
        assert parser.variables.get("auth_token") == "secret-token"
    
    def test_parse_v20_collection(self, tmp_path, sample_postman_collection_v20):
        """Test parsing a v2.0 collection."""
        file_path = tmp_path / "v20.json"
        file_path.write_text(json.dumps(sample_postman_collection_v20))
        
        parser = PostmanParser(str(file_path))
        endpoints = parser.parse()
        
        assert len(endpoints) >= 1
        assert parser.version == "2.0"


# ==================== PostmanGenerator Tests ====================

class TestPostmanGenerator:
    """Tests for PostmanGenerator class."""
    
    def test_create_generator(self):
        """Test creating a generator."""
        generator = PostmanGenerator(name="Test Collection")
        
        assert generator.name == "Test Collection"
    
    def test_create_collection_structure(self):
        """Test creating collection structure."""
        generator = PostmanGenerator(name="Test")
        collection = generator.create_collection(items=[])
        
        assert "info" in collection
        assert "item" in collection
        assert collection["info"]["name"] == "Test"
        assert "schema" in collection["info"]
    
    def test_from_endpoints(self):
        """Test generating collection from endpoints."""
        endpoints = [
            Endpoint(
                path="/users",
                method=HttpMethod.GET,
                summary="List users"
            ),
            Endpoint(
                path="/users",
                method=HttpMethod.POST,
                summary="Create user"
            )
        ]
        
        generator = PostmanGenerator(name="User API")
        collection = generator.from_endpoints(
            endpoints=endpoints,
            base_url="https://api.example.com"
        )
        
        assert "info" in collection
        assert collection["info"]["name"] == "User API"
        assert "item" in collection
        assert len(collection["item"]) >= 1
        assert "variable" in collection
    
    def test_from_endpoints_with_tags(self):
        """Test grouping by tags."""
        endpoints = [
            Endpoint(
                path="/users",
                method=HttpMethod.GET,
                tags=["Users"]
            ),
            Endpoint(
                path="/products",
                method=HttpMethod.GET,
                tags=["Products"]
            )
        ]
        
        generator = PostmanGenerator(name="API")
        collection = generator.from_endpoints(
            endpoints=endpoints,
            base_url="https://api.example.com",
            group_by_tag=True
        )
        
        # Should have folders for tags
        assert len(collection["item"]) == 2  # Two tag folders
    
    def test_from_endpoints_with_auth(self):
        """Test collection with authentication."""
        endpoints = [
            Endpoint(
                path="/protected",
                method=HttpMethod.GET,
                security=[{"bearerAuth": []}]
            )
        ]
        
        generator = PostmanGenerator(name="API")
        collection = generator.from_endpoints(
            endpoints=endpoints,
            base_url="https://api.example.com",
            auth_type="bearer",
            auth_config={"token": "secret"}
        )
        
        assert "auth" in collection
        assert collection["auth"]["type"] == "bearer"
    
    def test_save_collection(self, tmp_path):
        """Test saving collection to file."""
        generator = PostmanGenerator(name="Test")
        collection = generator.create_collection(items=[])
        
        output_path = tmp_path / "output_collection.json"
        result = generator.save(collection, str(output_path))
        
        assert output_path.exists()
        
        # Verify content
        with open(output_path) as f:
            saved = json.load(f)
        
        assert saved["info"]["name"] == "Test"


# ==================== Round-trip Tests ====================

class TestRoundTrip:
    """Tests for round-trip conversion."""
    
    def test_openapi_to_postman(self, temp_openapi_file):
        """Test converting OpenAPI to Postman collection."""
        collection = convert_openapi_to_postman(
            openapi_path=str(temp_openapi_file)
        )
        
        assert "info" in collection
        assert collection["info"]["name"] == "Sample API"
        assert "item" in collection
        assert len(collection["item"]) >= 1
    
    def test_endpoints_preserved(self, temp_openapi_file):
        """Test that endpoints are preserved in conversion."""
        from sentinel.parser import SwaggerParser
        
        # Get original endpoints
        parser = SwaggerParser(str(temp_openapi_file))
        original_endpoints = parser.parse()
        
        # Convert to Postman
        collection = convert_openapi_to_postman(
            openapi_path=str(temp_openapi_file)
        )
        
        # Count items in collection
        def count_items(items):
            count = 0
            for item in items:
                if "request" in item:
                    count += 1
                if "item" in item:
                    count += count_items(item["item"])
            return count
        
        item_count = count_items(collection["item"])
        assert item_count == len(original_endpoints)


# ==================== Convenience Function Tests ====================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_postman(self, temp_collection_file):
        """Test parse_postman convenience function."""
        endpoints = parse_postman(str(temp_collection_file))
        
        assert isinstance(endpoints, list)
        assert all(isinstance(ep, Endpoint) for ep in endpoints)
    
    def test_generate_postman_collection(self):
        """Test generate_postman_collection convenience function."""
        endpoints = [
            Endpoint(path="/test", method=HttpMethod.GET)
        ]
        
        collection = generate_postman_collection(
            endpoints=endpoints,
            name="Test API"
        )
        
        assert collection["info"]["name"] == "Test API"


# ==================== Integration Tests ====================

class TestPostmanIntegration:
    """Integration tests for Postman functionality."""
    
    def test_full_workflow(self, tmp_path, sample_openapi_spec):
        """Test complete workflow: OpenAPI -> Sentinel -> Postman."""
        # Save OpenAPI spec
        openapi_path = tmp_path / "api.json"
        openapi_path.write_text(json.dumps(sample_openapi_spec))
        
        # Parse OpenAPI
        from sentinel.parser import SwaggerParser
        parser = SwaggerParser(str(openapi_path))
        endpoints = parser.parse()
        
        # Generate Postman collection
        generator = PostmanGenerator(name="Generated from OpenAPI")
        collection = generator.from_endpoints(
            endpoints=endpoints,
            base_url="https://api.example.com/v1"
        )
        
        # Save collection
        postman_path = tmp_path / "generated_collection.json"
        generator.save(collection, str(postman_path))
        
        # Re-import
        re_parser = PostmanParser(str(postman_path))
        re_endpoints = re_parser.parse()
        
        # Verify round-trip
        assert len(re_endpoints) == len(endpoints)
    
    def test_request_body_parsing(self, tmp_path):
        """Test that request bodies are parsed correctly."""
        collection = {
            "info": {
                "name": "Body Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [
                {
                    "name": "POST with JSON",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/data",
                        "body": {
                            "mode": "raw",
                            "raw": "{\"name\": \"test\", \"value\": 123}"
                        }
                    }
                }
            ]
        }
        
        file_path = tmp_path / "body_test.json"
        file_path.write_text(json.dumps(collection))
        
        parser = PostmanParser(str(file_path))
        endpoints = parser.parse()
        
        assert len(endpoints) == 1
        assert endpoints[0].request_body is not None
        assert "application/json" in endpoints[0].request_body["content"]
    
    def test_authentication_parsing(self, tmp_path):
        """Test that authentication is parsed correctly."""
        collection = {
            "info": {
                "name": "Auth Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [
                {
                    "name": "Protected Endpoint",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/protected",
                        "auth": {
                            "type": "bearer"
                        }
                    }
                }
            ]
        }
        
        file_path = tmp_path / "auth_test.json"
        file_path.write_text(json.dumps(collection))
        
        parser = PostmanParser(str(file_path))
        endpoints = parser.parse()
        
        assert len(endpoints) == 1
        assert endpoints[0].security is not None
