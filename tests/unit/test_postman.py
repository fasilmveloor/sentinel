"""
Comprehensive Unit tests for Sentinel Postman Collection Support.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from sentinel.postman import (
    PostmanParser,
    PostmanGenerator,
    PostmanParseError,
    PostmanRequest,
    PostmanVariable,
    PostmanAuthType,
    parse_postman,
    generate_postman_collection,
    convert_openapi_to_postman,
)
from sentinel.models import Endpoint, HttpMethod, ScanResult, ScanConfig, AttackResult, Vulnerability, Severity, Parameter


# ==================== Fixtures ====================

@pytest.fixture
def valid_collection():
    """Valid Postman collection v2.1."""
    return {
        "info": {
            "name": "Test API",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "https://api.example.com/users",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    },
                    "header": [{"key": "Authorization", "value": "Bearer token"}]
                }
            }
        ],
        "variable": [{"key": "token", "value": "test-token"}]
    }


@pytest.fixture
def collection_file(valid_collection):
    """Create a temporary collection file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(valid_collection, f)
        return Path(f.name)


# ==================== PostmanVariable Tests ====================

class TestPostmanVariable:
    """Tests for PostmanVariable class."""
    
    def test_create_variable(self):
        """Test creating a variable."""
        var = PostmanVariable(key="token", value="abc123")
        
        assert var.key == "token"
        assert var.value == "abc123"
    
    def test_to_dict_basic(self):
        """Test converting to dict."""
        var = PostmanVariable(key="token", value="abc123")
        result = var.to_dict()
        
        assert result["key"] == "token"
        assert result["value"] == "abc123"
    
    def test_to_dict_with_description(self):
        """Test to_dict with description."""
        var = PostmanVariable(key="token", value="abc", description="API token")
        result = var.to_dict()
        
        assert result["description"] == "API token"
    
    def test_to_dict_with_type(self):
        """Test to_dict with non-string type."""
        var = PostmanVariable(key="count", value=10, type="integer")
        result = var.to_dict()
        
        assert result["type"] == "integer"
    
    def test_to_dict_disabled(self):
        """Test to_dict with disabled flag."""
        var = PostmanVariable(key="old", value="deprecated", disabled=True)
        result = var.to_dict()
        
        assert result["disabled"] is True
    
    def test_from_dict(self):
        """Test creating from dict."""
        data = {"key": "token", "value": "abc123"}
        var = PostmanVariable.from_dict(data)
        
        assert var.key == "token"
        assert var.value == "abc123"
    
    def test_from_dict_with_all_fields(self):
        """Test from_dict with all fields."""
        data = {
            "key": "token",
            "value": "abc",
            "description": "API token",
            "type": "string",
            "disabled": True
        }
        var = PostmanVariable.from_dict(data)
        
        assert var.key == "token"
        assert var.description == "API token"
        assert var.disabled is True


# ==================== PostmanRequest Tests ====================

class TestPostmanRequest:
    """Tests for PostmanRequest class."""
    
    def test_create_request(self):
        """Test creating a request."""
        req = PostmanRequest(
            name="Get Users",
            method=HttpMethod.GET,
            url="https://api.example.com/users"
        )
        
        assert req.name == "Get Users"
        assert req.method == HttpMethod.GET
    
    def test_to_endpoint(self):
        """Test converting to endpoint."""
        req = PostmanRequest(
            name="Get Users",
            method=HttpMethod.GET,
            url="https://api.example.com/users?page=1",
            headers={"Authorization": "Bearer token"}
        )
        
        endpoint = req.to_endpoint()
        
        assert endpoint.path == "/users"
        assert endpoint.method == HttpMethod.GET
        assert len(endpoint.parameters) > 0
    
    def test_to_endpoint_with_body(self):
        """Test to_endpoint with request body."""
        req = PostmanRequest(
            name="Create User",
            method=HttpMethod.POST,
            url="https://api.example.com/users",
            body={"name": "test"}
        )
        
        endpoint = req.to_endpoint()
        
        assert endpoint.request_body is not None
    
    def test_to_endpoint_with_bearer_auth(self):
        """Test to_endpoint with bearer auth."""
        req = PostmanRequest(
            name="Protected",
            method=HttpMethod.GET,
            url="https://api.example.com/protected",
            auth={"type": "bearer"}
        )
        
        endpoint = req.to_endpoint()
        
        assert endpoint.security is not None
    
    def test_to_endpoint_with_basic_auth(self):
        """Test to_endpoint with basic auth."""
        req = PostmanRequest(
            name="Protected",
            method=HttpMethod.GET,
            url="https://api.example.com/protected",
            auth={"type": "basic"}
        )
        
        endpoint = req.to_endpoint()
        
        assert endpoint.security is not None


# ==================== PostmanParser Tests ====================

class TestPostmanParser:
    """Tests for Postman collection parser."""
    
    def test_parse_returns_endpoints(self, collection_file):
        """Test parsing returns endpoints."""
        parser = PostmanParser(collection_file)
        result = parser.parse()
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    def test_parse_full(self, collection_file):
        """Test parse_full returns complete info."""
        parser = PostmanParser(collection_file)
        result = parser.parse_full()
        
        assert "info" in result
        assert "endpoints" in result
        assert "variables" in result
    
    def test_get_base_url(self, collection_file):
        """Test extracting base URL."""
        parser = PostmanParser(collection_file)
        parser.parse()
        
        base_url = parser.get_base_url()
        
        assert base_url is not None
    
    def test_version_detection_v21(self, collection_file):
        """Test v2.1 detection."""
        parser = PostmanParser(collection_file)
        parser.parse()
        
        assert parser.version == "2.1"
    
    def test_v20_collection(self):
        """Test v2.0 collection parsing."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json"
            },
            "item": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            parser.parse()
            
            assert parser.version == "2.0"
        finally:
            temp_path.unlink()
    
    def test_unsupported_schema_raises_error(self):
        """Test unsupported schema raises error."""
        collection = {
            "info": {"name": "Test", "schema": "https://unknown.schema.com/v1"},
            "item": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            with pytest.raises(PostmanParseError):
                parser.parse()
        finally:
            temp_path.unlink()


# ==================== PostmanGenerator Tests ====================

class TestPostmanGenerator:
    """Tests for Postman collection generator."""
    
    def test_create_collection(self):
        """Test creating collection."""
        generator = PostmanGenerator()
        items = [{"name": "Test", "request": {"method": "GET", "url": "https://api.example.com"}}]
        
        collection = generator.create_collection(items)
        
        assert "info" in collection
        assert "item" in collection
        assert collection["item"] == items
    
    def test_create_collection_with_variables(self):
        """Test creating collection with variables."""
        generator = PostmanGenerator()
        items = []
        variables = [{"key": "token", "value": "abc"}]
        
        collection = generator.create_collection(items, variables=variables)
        
        assert collection["variable"] == variables
    
    def test_create_collection_with_auth(self):
        """Test creating collection with auth."""
        generator = PostmanGenerator()
        items = []
        auth = {"type": "bearer", "bearer": [{"key": "token", "value": "abc"}]}
        
        collection = generator.create_collection(items, auth=auth)
        
        assert collection["auth"] == auth
    
    def test_from_endpoints_with_tags(self):
        """Test from_endpoints groups by tags."""
        generator = PostmanGenerator()
        
        endpoints = [
            Endpoint(path="/users", method=HttpMethod.GET, tags=["Users"]),
            Endpoint(path="/posts", method=HttpMethod.GET, tags=["Posts"]),
        ]
        
        collection = generator.from_endpoints(endpoints, base_url="https://api.example.com")
        
        # Should have folder items for tags
        assert "item" in collection
    
    def test_from_endpoints_without_tags(self):
        """Test from_endpoints without grouping."""
        generator = PostmanGenerator()
        
        endpoints = [
            Endpoint(path="/users", method=HttpMethod.GET, tags=[]),
        ]
        
        collection = generator.from_endpoints(
            endpoints, 
            base_url="https://api.example.com",
            group_by_tag=False
        )
        
        assert "item" in collection
    
    def test_from_endpoints_with_bearer_auth(self):
        """Test from_endpoints with bearer auth."""
        generator = PostmanGenerator()
        
        endpoints = [Endpoint(path="/users", method=HttpMethod.GET)]
        
        collection = generator.from_endpoints(
            endpoints,
            base_url="https://api.example.com",
            auth_type="bearer",
            auth_config={"token": "abc123"}
        )
        
        assert collection["auth"] is not None
    
    def test_from_endpoints_with_basic_auth(self):
        """Test from_endpoints with basic auth."""
        generator = PostmanGenerator()
        
        endpoints = [Endpoint(path="/users", method=HttpMethod.GET)]
        
        collection = generator.from_endpoints(
            endpoints,
            base_url="https://api.example.com",
            auth_type="basic",
            auth_config={"username": "user", "password": "pass"}
        )
        
        assert collection["auth"]["type"] == "basic"
    
    def test_from_endpoints_with_apikey_auth(self):
        """Test from_endpoints with API key auth."""
        generator = PostmanGenerator()
        
        endpoints = [Endpoint(path="/users", method=HttpMethod.GET)]
        
        collection = generator.from_endpoints(
            endpoints,
            base_url="https://api.example.com",
            auth_type="apikey",
            auth_config={"key": "X-API-Key", "value": "abc"}
        )
        
        assert collection["auth"]["type"] == "apikey"
    
    def test_from_endpoints_with_oauth2_auth(self):
        """Test from_endpoints with OAuth2 auth."""
        generator = PostmanGenerator()
        
        endpoints = [Endpoint(path="/users", method=HttpMethod.GET)]
        
        collection = generator.from_endpoints(
            endpoints,
            base_url="https://api.example.com",
            auth_type="oauth2",
            auth_config={"access_token": "abc"}
        )
        
        assert collection["auth"]["type"] == "oauth2"
    
    def test_from_scan_result_with_vulnerabilities(self):
        """Test from_scan_result with vulnerabilities."""
        generator = PostmanGenerator()
        
        config = ScanConfig(target_url="https://api.example.com", swagger_path="test.yaml")
        result = ScanResult(config=config)
        result.vulnerabilities.append(Vulnerability(
            endpoint=Endpoint(path="/users", method=HttpMethod.GET),
            attack_type="sql_injection",
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Test",
            payload="' OR 1=1--",
            proof_of_concept="",
            recommendation="Fix it"
        ))
        
        collection = generator.from_scan_result(result)
        
        assert "item" in collection
        # Should have vulnerabilities folder
        vuln_folder = [i for i in collection["item"] if i.get("name") == "Vulnerabilities Found"]
        assert len(vuln_folder) == 1
    
    def test_from_attack_results(self):
        """Test from_attack_results."""
        generator = PostmanGenerator()
        
        results = [
            AttackResult(
                endpoint=Endpoint(path="/users", method=HttpMethod.GET),
                attack_type="sql_injection",
                payload="' OR 1=1--",
                success=True,
                response_status=200
            )
        ]
        
        collection = generator.from_attack_results(results, base_url="https://api.example.com")
        
        assert "item" in collection
        assert len(collection["item"]) > 0
    
    def test_save_creates_file(self):
        """Test save creates file."""
        generator = PostmanGenerator()
        
        collection = generator.create_collection([])
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        result = generator.save(collection, output_path)
        
        assert Path(output_path).exists()
        Path(output_path).unlink()


# ==================== Convenience Functions Tests ====================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_postman(self, collection_file):
        """Test parse_postman function."""
        result = parse_postman(str(collection_file))
        
        assert isinstance(result, list)
    
    def test_generate_postman_collection(self):
        """Test generate_postman_collection function."""
        endpoints = [Endpoint(path="/test", method=HttpMethod.GET)]
        
        result = generate_postman_collection(endpoints)
        
        assert "info" in result
        assert "item" in result
    
    def test_generate_with_output(self):
        """Test generate_postman_collection with output."""
        endpoints = [Endpoint(path="/test", method=HttpMethod.GET)]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        result = generate_postman_collection(endpoints, output_path=output_path)
        
        assert Path(output_path).exists()
        Path(output_path).unlink()


# ==================== Request Body Tests ====================

class TestRequestBodyParsing:
    """Tests for request body parsing."""
    
    def test_urlencoded_body(self):
        """Test parsing urlencoded body."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Login",
                "request": {
                    "method": "POST",
                    "url": {"raw": "https://api.example.com/login"},
                    "body": {
                        "mode": "urlencoded",
                        "urlencoded": [
                            {"key": "username", "value": "test"},
                            {"key": "password", "value": "secret"}
                        ]
                    }
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
            assert result[0].request_body is not None
        finally:
            temp_path.unlink()
    
    def test_formdata_body(self):
        """Test parsing formdata body."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Upload",
                "request": {
                    "method": "POST",
                    "url": {"raw": "https://api.example.com/upload"},
                    "body": {
                        "mode": "formdata",
                        "formdata": [
                            {"key": "file", "value": "test.txt"},
                            {"key": "name", "value": "test"}
                        ]
                    }
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
            assert result[0].request_body is not None
        finally:
            temp_path.unlink()
    
    def test_raw_json_body(self):
        """Test parsing raw JSON body."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Create",
                "request": {
                    "method": "POST",
                    "url": {"raw": "https://api.example.com/users"},
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps({"name": "test", "email": "test@example.com"})
                    }
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
            assert result[0].request_body is not None
        finally:
            temp_path.unlink()


# ==================== Variable Resolution Tests ====================

class TestVariableResolution:
    """Tests for variable resolution."""
    
    def test_resolve_variables(self):
        """Test resolving collection variables."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Test",
                "request": {
                    "method": "GET",
                    "url": {"raw": "https://{{host}}/users"},
                    "header": [{"key": "Authorization", "value": "Bearer {{token}}"}]
                }
            }],
            "variable": [
                {"key": "host", "value": "api.example.com"},
                {"key": "token", "value": "abc123"}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
        finally:
            temp_path.unlink()


# ==================== Auth Tests ====================

class TestAuthParsing:
    """Tests for authentication parsing."""
    
    def test_bearer_auth(self):
        """Test parsing bearer auth."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Protected",
                "request": {
                    "method": "GET",
                    "url": {"raw": "https://api.example.com/protected"},
                    "auth": {"type": "bearer"}
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
            assert result[0].security is not None
        finally:
            temp_path.unlink()
    
    def test_oauth2_auth(self):
        """Test parsing OAuth2 auth."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Protected",
                "request": {
                    "method": "GET",
                    "url": {"raw": "https://api.example.com/protected"},
                    "auth": {"type": "oauth2"}
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
        finally:
            temp_path.unlink()


# ==================== Edge Cases ====================

class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_request_with_string_url(self):
        """Test request with string URL instead of object."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Simple",
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/simple"
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
        finally:
            temp_path.unlink()
    
    def test_request_without_method(self):
        """Test request without method defaults to GET."""
        collection = {
            "info": {
                "name": "Test",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [{
                "name": "Default",
                "request": {
                    "url": {"raw": "https://api.example.com/test"}
                }
            }]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collection, f)
            temp_path = Path(f.name)
        
        try:
            parser = PostmanParser(temp_path)
            result = parser.parse()
            
            assert len(result) == 1
            assert result[0].method == HttpMethod.GET
        finally:
            temp_path.unlink()
    
    def test_endpoint_with_request_body(self):
        """Test generator handles endpoint with request body."""
        generator = PostmanGenerator()
        
        endpoint = Endpoint(
            path="/users",
            method=HttpMethod.POST,
            request_body={
                "content": {
                    "application/json": {
                        "example": {"name": "test"}
                    }
                }
            }
        )
        
        collection = generator.from_endpoints([endpoint], base_url="https://api.example.com")
        
        assert "item" in collection
    
    def test_endpoint_with_security(self):
        """Test generator handles endpoint with security."""
        generator = PostmanGenerator()
        
        endpoint = Endpoint(
            path="/protected",
            method=HttpMethod.GET,
            security=[{"bearerAuth": []}]
        )
        
        collection = generator.from_endpoints([endpoint], base_url="https://api.example.com")
        
        assert "item" in collection
    
    def test_vulnerability_with_json_payload(self):
        """Test vulnerability item with JSON payload."""
        generator = PostmanGenerator()
        
        config = ScanConfig(target_url="https://api.example.com", swagger_path="test.yaml")
        result = ScanResult(config=config)
        result.vulnerabilities.append(Vulnerability(
            endpoint=Endpoint(path="/users", method=HttpMethod.POST),
            attack_type="sql_injection",
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Test",
            payload=json.dumps({"username": "admin'--"}),
            proof_of_concept="",
            recommendation="Fix it"
        ))
        
        collection = generator.from_scan_result(result)
        
        assert "item" in collection
    
    def test_attack_result_with_payload(self):
        """Test attack result with payload."""
        generator = PostmanGenerator()
        
        result = AttackResult(
            endpoint=Endpoint(path="/users", method=HttpMethod.GET),
            attack_type="sql_injection",
            payload=json.dumps({"id": "1 OR 1=1"}),
            success=True,
            response_status=200,
            response_body="[]"
        )
        
        collection = generator.from_attack_results([result], base_url="https://api.example.com")
        
        assert "item" in collection
        