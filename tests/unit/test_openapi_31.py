"""
Comprehensive tests for OpenAPI 3.1.0 support.

Tests cover:
- Version detection for 3.1.0
- Webhook parsing
- $ref resolution in all locations
- JSON Schema 2020-12 support
- pathItem $ref
- info.summary
- jsonSchemaDialect
"""

import json
import tempfile
from pathlib import Path

import pytest

from sentinel.parser import (
    SwaggerParser,
    SwaggerParseError,
    ReferenceResolver,
    parse_openapi,
    parse_swagger,
    get_sample_endpoint_values
)
from sentinel.models import (
    Endpoint,
    HttpMethod,
    OpenAPIVersion,
    Webhook,
    ParsedSpec,
)


# =============================================================================
# Test Fixtures - OpenAPI 3.1.0 Specifications
# =============================================================================

OPENAPI_31_MINIMAL = """
openapi: "3.1.0"
info:
  title: Minimal API
  version: "1.0.0"
  summary: A minimal API for testing
paths:
  /test:
    get:
      operationId: testGet
      responses:
        '200':
          description: Success
"""

OPENAPI_31_WITH_WEBHOOKS = """
openapi: "3.1.0"
info:
  title: Webhook API
  version: "1.0.0"
  summary: API with webhooks
webhooks:
  newUser:
    post:
      operationId: newUserWebhook
      summary: New user created
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                userId:
                  type: string
                email:
                  type: string
      responses:
        '200':
          description: Webhook received
  orderCompleted:
    post:
      operationId: orderCompletedWebhook
      summary: Order completed notification
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Order'
      responses:
        '200':
          description: Acknowledged
paths:
  /users:
    get:
      operationId: getUsers
      responses:
        '200':
          description: List of users
components:
  schemas:
    Order:
      type: object
      properties:
        orderId:
          type: string
        amount:
          type: number
"""

OPENAPI_31_WITH_REFS = """
openapi: "3.1.0"
info:
  title: API with References
  version: "1.0.0"
jsonSchemaDialect: "https://json-schema.org/draft/2020-12/schema"
paths:
  /users/{userId}:
    get:
      operationId: getUser
      parameters:
        - $ref: '#/components/parameters/userIdParam'
      responses:
        '200':
          description: User found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
  /orders:
    $ref: '#/components/pathItems/ordersPath'
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
  parameters:
    userIdParam:
      name: userId
      in: path
      required: true
      schema:
        type: string
  pathItems:
    ordersPath:
      get:
        operationId: getOrders
        responses:
          '200':
            description: List of orders
      post:
        operationId: createOrder
        requestBody:
          $ref: '#/components/requestBodies/orderBody'
        responses:
          '201':
            description: Order created
  requestBodies:
    orderBody:
      required: true
      content:
        application/json:
          schema:
            type: object
"""

OPENAPI_31_JSON_SCHEMA = """
openapi: "3.1.0"
info:
  title: JSON Schema Test API
  version: "1.0.0"
paths:
  /data:
    post:
      operationId: postData
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  minLength: 1
                  maxLength: 100
                age:
                  type: integer
                  minimum: 0
                  maximum: 150
                tags:
                  type: array
                  items:
                    type: string
                  minItems: 1
                  uniqueItems: true
                metadata:
                  type: object
                  additionalProperties: true
                status:
                  type: ["string", "null"]
                  enum: ["active", "inactive", null]
              required:
                - name
      responses:
        '200':
          description: Success
"""

OPENAPI_31_CIRCULAR_REF = """
openapi: "3.1.0"
info:
  title: Circular Reference API
  version: "1.0.0"
paths:
  /nodes:
    get:
      operationId: getNodes
      responses:
        '200':
          description: List of nodes
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Node'
components:
  schemas:
    Node:
      type: object
      properties:
        id:
          type: string
        children:
          type: array
          items:
            $ref: '#/components/schemas/Node'
"""

OPENAPI_30_SPEC = """
openapi: "3.0.3"
info:
  title: OpenAPI 3.0 API
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: getItems
      responses:
        '200':
          description: List of items
"""

SWAGGER_2_SPEC = """
swagger: "2.0"
info:
  title: Swagger 2.0 API
  version: "1.0.0"
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /items:
    get:
      operationId: getItems
      responses:
        200:
          description: List of items
"""


# =============================================================================
# Test Version Detection
# =============================================================================

class TestVersionDetection:
    """Tests for OpenAPI version detection."""

    def test_detect_openapi_31(self):
        """Test detection of OpenAPI 3.1.0."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_MINIMAL)
            f.flush()
            
            parser = SwaggerParser(f.name)
            parser._load_spec()
            parser._detect_version()
            
            assert parser.openapi_version == "3.1.0"
            assert parser.swagger_version is None
            assert parser.version == OpenAPIVersion.OPENAPI_3_1

    def test_detect_openapi_30(self):
        """Test detection of OpenAPI 3.0.x."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_30_SPEC)
            f.flush()
            
            parser = SwaggerParser(f.name)
            parser._load_spec()
            parser._detect_version()
            
            assert parser.openapi_version == "3.0.3"
            assert parser.version == OpenAPIVersion.OPENAPI_3_0

    def test_detect_swagger_2(self):
        """Test detection of Swagger 2.0."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(SWAGGER_2_SPEC)
            f.flush()
            
            parser = SwaggerParser(f.name)
            parser._load_spec()
            parser._detect_version()
            
            assert parser.openapi_version is None
            assert parser.swagger_version == "2.0"
            assert parser.version == OpenAPIVersion.SWAGGER_2_0


# =============================================================================
# Test Webhooks
# =============================================================================

class TestWebhooks:
    """Tests for OpenAPI 3.1.0 webhook parsing."""

    def test_extract_webhooks_31(self):
        """Test extracting webhooks from OpenAPI 3.1.0."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_WEBHOOKS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert len(spec.webhooks) == 2
            
            # Check first webhook
            new_user = next((w for w in spec.webhooks if w.name == "newUser"), None)
            assert new_user is not None
            assert len(new_user.endpoints) == 1
            assert new_user.endpoints[0].method == HttpMethod.POST
            assert new_user.endpoints[0].operation_id == "newUserWebhook"

    def test_webhooks_not_extracted_in_30(self):
        """Test that webhooks are not extracted from OpenAPI 3.0."""
        spec_with_webhooks = OPENAPI_30_SPEC + "\nwebhooks:\n  test:\n    post:\n      responses:\n        '200':\n          description: test"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(spec_with_webhooks)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            # Webhooks should be empty for 3.0.x
            assert len(spec.webhooks) == 0

    def test_webhook_endpoint_path(self):
        """Test that webhook endpoints have correct synthetic path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_WEBHOOKS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            for webhook in spec.webhooks:
                for endpoint in webhook.endpoints:
                    assert endpoint.path.startswith("/webhook/")

    def test_webhook_with_ref_in_schema(self):
        """Test webhook with $ref in request body schema."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_WEBHOOKS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            order_webhook = next((w for w in spec.webhooks if w.name == "orderCompleted"), None)
            assert order_webhook is not None
            # The request body should be resolved
            endpoint = order_webhook.endpoints[0]
            assert endpoint.request_body is not None


# =============================================================================
# Test Reference Resolution
# =============================================================================

class TestReferenceResolution:
    """Tests for $ref resolution."""

    def test_resolve_parameter_ref(self):
        """Test resolving $ref in parameters."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_REFS)
            f.flush()
            
            endpoints = parse_swagger(f.name)
            
            user_endpoint = next((e for e in endpoints if e.operation_id == "getUser"), None)
            assert user_endpoint is not None
            assert len(user_endpoint.parameters) == 1
            assert user_endpoint.parameters[0].name == "userId"
            assert user_endpoint.parameters[0].location == "path"

    def test_resolve_pathitem_ref(self):
        """Test resolving $ref in pathItems (OpenAPI 3.1.0 feature)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_REFS)
            f.flush()
            
            endpoints = parse_swagger(f.name)
            
            # Should have endpoints from the referenced pathItem
            orders_get = next((e for e in endpoints if e.operation_id == "getOrders"), None)
            orders_post = next((e for e in endpoints if e.operation_id == "createOrder"), None)
            
            assert orders_get is not None
            assert orders_post is not None
            assert orders_get.path == "/orders"

    def test_resolve_schema_ref(self):
        """Test resolving $ref in schemas."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_REFS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert "User" in spec.components.get("schemas", {})

    def test_circular_reference_handling(self):
        """Test handling of circular references."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_CIRCULAR_REF)
            f.flush()
            
            # Should not raise
            spec = parse_openapi(f.name)
            
            assert len(spec.endpoints) == 1
            assert spec.endpoints[0].operation_id == "getNodes"


# =============================================================================
# Test JSON Schema 2020-12 Support
# =============================================================================

class TestJSONSchemaSupport:
    """Tests for JSON Schema 2020-12 features."""

    def test_json_schema_dialect(self):
        """Test jsonSchemaDialect extraction."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_REFS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert spec.json_schema_dialect == "https://json-schema.org/draft/2020-12/schema"

    def test_type_array(self):
        """Test type as array (allows null)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_JSON_SCHEMA)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            # Should parse without errors
            assert len(spec.endpoints) == 1

    def test_info_summary(self):
        """Test info.summary field (new in 3.1.0)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_MINIMAL)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert spec.info.summary == "A minimal API for testing"


# =============================================================================
# Test ParsedSpec Model
# =============================================================================

class TestParsedSpec:
    """Tests for the ParsedSpec model."""

    def test_parsed_spec_contains_all_data(self):
        """Test that ParsedSpec contains all expected data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_WITH_WEBHOOKS)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert spec.openapi_version == "3.1.0"
            assert spec.info.title == "Webhook API"
            assert len(spec.servers) >= 0  # May be empty
            assert len(spec.endpoints) > 0
            assert len(spec.webhooks) > 0
            assert len(spec.security_schemes) >= 0
            assert len(spec.components) > 0
            assert len(spec.tags) >= 0

    def test_parsed_spec_version_property(self):
        """Test the version property of ParsedSpec."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_31_MINIMAL)
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert spec.version == OpenAPIVersion.OPENAPI_3_1


# =============================================================================
# Test ReferenceResolver
# =============================================================================

class TestReferenceResolver:
    """Tests for the ReferenceResolver class."""

    def test_resolve_local_ref(self):
        """Test resolving local references."""
        spec = {
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        resolver = ReferenceResolver(spec)
        result = resolver.resolve("#/components/schemas/User")
        
        assert result is not None
        assert result.get("type") == "object"

    def test_resolve_nested_ref(self):
        """Test resolving nested references."""
        spec = {
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "address": {"$ref": "#/components/schemas/Address"}
                        }
                    },
                    "Address": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        resolver = ReferenceResolver(spec)
        result = resolver.resolve_in_place(spec)
        
        # The User schema should have address resolved
        user = result["components"]["schemas"]["User"]
        assert user["properties"]["address"]["type"] == "object"
        # But the nested properties should also be resolved
        assert "city" in user["properties"]["address"]["properties"]

    def test_resolve_nonexistent_ref(self):
        """Test resolving a non-existent reference."""
        spec = {"components": {"schemas": {}}}
        
        resolver = ReferenceResolver(spec)
        result = resolver.resolve("#/components/schemas/NonExistent")
        
        assert result is None

    def test_resolve_with_escaped_characters(self):
        """Test resolving references with escaped characters."""
        spec = {
            "components": {
                "schemas": {
                    "User/Data": {
                        "type": "object"
                    }
                }
            }
        }
        
        resolver = ReferenceResolver(spec)
        # ~1 is escaped /
        result = resolver.resolve("#/components/schemas/User~1Data")
        
        assert result is not None


# =============================================================================
# Test Backward Compatibility
# =============================================================================

class TestBackwardCompatibility:
    """Tests for backward compatibility with OpenAPI 3.0 and Swagger 2.0."""

    def test_openapi_30_still_works(self):
        """Test that OpenAPI 3.0 specs still parse correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(OPENAPI_30_SPEC)
            f.flush()
            
            endpoints = parse_swagger(f.name)
            
            assert len(endpoints) == 1
            assert endpoints[0].operation_id == "getItems"

    def test_swagger_2_still_works(self):
        """Test that Swagger 2.0 specs still parse correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(SWAGGER_2_SPEC)
            f.flush()
            
            endpoints = parse_swagger(f.name)  # Use parse_swagger which returns just endpoints
            
            assert len(endpoints) == 1
            assert endpoints[0].operation_id == "getItems"

    def test_swagger_2_base_url(self):
        """Test base URL extraction from Swagger 2.0."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(SWAGGER_2_SPEC)
            f.flush()
            
            parser = SwaggerParser(f.name)
            parser._load_spec()  # Explicitly load spec
            parser._detect_version()
            base_url = parser.get_base_url()
            
            assert base_url == "https://api.example.com/v1"


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_spec(self):
        """Test handling of empty specification."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("openapi: '3.1.0'\ninfo:\n  title: Empty\n  version: '1.0'\npaths: {}")
            f.flush()
            
            spec = parse_openapi(f.name)
            
            assert len(spec.endpoints) == 0
            assert len(spec.webhooks) == 0

    def test_invalid_yaml(self):
        """Test handling of invalid YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("openapi: '3.1.0'\n  invalid: indentation\n    wrong: here")
            f.flush()
            
            with pytest.raises(SwaggerParseError):
                parse_swagger(f.name)

    def test_missing_version(self):
        """Test handling of missing version field."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("info:\n  title: Test\n  version: '1.0'\npaths: {}")
            f.flush()
            
            with pytest.raises(SwaggerParseError):
                parse_swagger(f.name)

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        with pytest.raises(SwaggerParseError):
            parse_swagger("/nonexistent/path/to/spec.yaml")


# =============================================================================
# Test JSON Format
# =============================================================================

class TestJSONFormat:
    """Tests for JSON format support."""

    def test_json_spec(self):
        """Test parsing JSON format specification."""
        spec = {
            "openapi": "3.1.0",
            "info": {
                "title": "JSON API",
                "version": "1.0.0",
                "summary": "A JSON format API spec"
            },
            "paths": {
                "/test": {
                    "get": {
                        "operationId": "testGet",
                        "responses": {
                            "200": {"description": "Success"}
                        }
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(spec, f)
            f.flush()
            
            parsed = parse_openapi(f.name)
            
            assert parsed.openapi_version == "3.1.0"
            assert parsed.info.summary == "A JSON format API spec"
            assert len(parsed.endpoints) == 1


# =============================================================================
# Test Servers
# =============================================================================

class TestServers:
    """Tests for server extraction."""

    def test_servers_31(self):
        """Test server extraction from OpenAPI 3.1.0."""
        spec = """
openapi: "3.1.0"
info:
  title: Test
  version: "1.0.0"
servers:
  - url: https://api.example.com/v1
    description: Production server
  - url: https://staging.example.com/v1
    description: Staging server
paths:
  /test:
    get:
      responses:
        '200':
          description: Success
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(spec)
            f.flush()
            
            parsed = parse_openapi(f.name)
            
            assert len(parsed.servers) == 2
            assert parsed.servers[0]["url"] == "https://api.example.com/v1"

    def test_server_variables(self):
        """Test server with variables."""
        spec = '''
openapi: "3.1.0"
info:
  title: Test
  version: "1.0.0"
servers:
  - url: https://{environment}.example.com/{version}
    variables:
      environment:
        default: api
        enum: [api, staging, dev]
      version:
        default: v1
paths:
  /test:
    get:
      responses:
        '200':
          description: Success
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(spec)
            f.flush()
            
            parser = SwaggerParser(f.name)
            parser._load_spec()  # Explicitly load spec
            parser._detect_version()
            base_url = parser.get_base_url()
            
            # Variables should be replaced with defaults
            assert base_url == "https://api.example.com/v1"
