"""
Postman Collection support for Sentinel.

This module provides comprehensive Postman Collection v2.0/v2.1 support:
- Parse Postman collections to Sentinel Endpoint objects
- Generate Postman collections from Sentinel scan configurations
- Export scan results as Postman collections for further testing
- Import Postman environments and variables

Supported Features:
- Postman Collection v2.0 and v2.1
- Request methods, headers, body, auth
- Folder structure preservation
- Variables (collection and environment)
- Pre-request scripts (metadata only)
- Tests (metadata only)
- Authentication types (Bearer, Basic, API Key, OAuth2, etc.)

Example usage:
    # Import a Postman collection
    parser = PostmanParser('collection.json')
    endpoints = parser.parse()

    # Export to Postman collection
    generator = PostmanGenerator(name="My API")
    collection = generator.from_endpoints(endpoints)
    generator.save(collection, 'my_api_collection.json')

    # Convert OpenAPI to Postman collection
    from sentinel.parser import SwaggerParser
    swagger = SwaggerParser('api.yaml')
    endpoints = swagger.parse()
    generator = PostmanGenerator(name="My API")
    collection = generator.from_endpoints(endpoints, base_url="https://api.example.com")
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlparse, parse_qs, unquote

from .models import (
    Endpoint,
    HttpMethod,
    Parameter,
    AttackResult,
    Vulnerability,
    ScanConfig,
    ScanResult,
    Severity,
)


class PostmanParseError(Exception):
    """Raised when Postman collection cannot be parsed."""
    pass


class PostmanAuthType(str):
    """Postman authentication types."""
    NOAUTH = "noauth"
    BEARER = "bearer"
    BASIC = "basic"
    APIKEY = "apikey"
    OAUTH1 = "oauth1"
    OAUTH2 = "oauth2"
    DIGEST = "digest"
    HAWK = "hawk"
    AWS = "awsv4"
    NTLM = "ntlm"


class PostmanVariable:
    """
    Represents a Postman variable.

    Variables can be defined at collection, folder, or request level.
    They use {{variable_name}} syntax in URLs, headers, and body.
    """

    def __init__(
        self,
        key: str,
        value: Any = "",
        description: Optional[str] = None,
        type: str = "string",
        disabled: bool = False
    ):
        self.key = key
        self.value = value
        self.description = description
        self.type = type
        self.disabled = disabled

    def to_dict(self) -> dict:
        """Convert to Postman variable format."""
        result = {
            "key": self.key,
            "value": self.value
        }
        if self.description:
            result["description"] = self.description
        if self.type != "string":
            result["type"] = self.type
        if self.disabled:
            result["disabled"] = True
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "PostmanVariable":
        """Create from Postman variable dict."""
        return cls(
            key=data.get("key", ""),
            value=data.get("value", ""),
            description=data.get("description"),
            type=data.get("type", "string"),
            disabled=data.get("disabled", False)
        )


class PostmanRequest:
    """
    Represents a Postman request item.

    A request contains all the information needed to make an HTTP request
    including method, URL, headers, body, and authentication.
    """

    def __init__(
        self,
        name: str,
        method: HttpMethod,
        url: str,
        description: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        body: Optional[Any] = None,
        auth: Optional[dict] = None,
        tests: Optional[str] = None,
        pre_request_script: Optional[str] = None
    ):
        self.name = name
        self.method = method
        self.url = url
        self.description = description
        self.headers = headers or {}
        self.body = body
        self.auth = auth
        self.tests = tests
        self.pre_request_script = pre_request_script

    def to_endpoint(self) -> Endpoint:
        """Convert to Sentinel Endpoint object."""
        # Parse URL to extract path and parameters
        parsed = urlparse(self.url)
        path = parsed.path or "/"

        # Parse query parameters
        parameters: list[Parameter] = []
        if parsed.query:
            qs = parse_qs(parsed.query)
            for name, values in qs.items():
                parameters.append(Parameter(
                    name=name,
                    location="query",
                    required=False,
                    param_type="string",
                    example=values[0] if values else None
                ))

        # Add headers as parameters
        for name, value in self.headers.items():
            if name.lower() not in ["content-type", "accept", "user-agent", "host"]:
                parameters.append(Parameter(
                    name=name,
                    location="header",
                    required=False,
                    param_type="string",
                    example=value
                ))

        # Build request body schema
        request_body = None
        if self.body:
            if isinstance(self.body, dict):
                request_body = {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"},
                            "example": self.body
                        }
                    }
                }
            elif isinstance(self.body, str):
                request_body = {
                    "content": {
                        "text/plain": {
                            "schema": {"type": "string"},
                            "example": self.body
                        }
                    }
                }

        # Build security from auth
        security = None
        if self.auth:
            auth_type = self.auth.get("type", "")
            if auth_type == PostmanAuthType.BEARER:
                security = [{"bearerAuth": []}]
            elif auth_type == PostmanAuthType.BASIC:
                security = [{"basicAuth": []}]
            elif auth_type == PostmanAuthType.APIKEY:
                security = [{"apiKeyAuth": []}]

        return Endpoint(
            path=path,
            method=self.method,
            operation_id=self.name.lower().replace(" ", "_"),
            summary=self.name,
            description=self.description,
            parameters=parameters,
            request_body=request_body,
            security=security
        )


class PostmanParser:
    """
    Parser for Postman Collection v2.0 and v2.1 formats.

    Parses Postman collections and extracts endpoints for security testing.
    Supports nested folders, variables, and authentication.

    Example:
        parser = PostmanParser('my_collection.json')
        endpoints = parser.parse()
        for endpoint in endpoints:
            print(f"{endpoint.method.value} {endpoint.path}")
    """

    def __init__(self, collection_path: str):
        """
        Initialize parser with path to Postman collection file.

        Args:
            collection_path: Path to Postman collection JSON file
        """
        self.collection_path = Path(collection_path)
        self.collection: dict[str, Any] = {}
        self.variables: dict[str, Any] = {}

    def parse(self) -> list[Endpoint]:
        """
        Parse the Postman collection and return list of endpoints.

        Returns:
            List of Endpoint objects extracted from the collection

        Raises:
            PostmanParseError: If collection cannot be parsed
        """
        self._load_collection()
        self._extract_variables()
        return self._extract_endpoints()

    def parse_full(self) -> dict:
        """
        Parse the collection and return full information.

        Returns:
            Dictionary with endpoints, variables, auth, and metadata
        """
        self._load_collection()
        self._extract_variables()

        return {
            "info": self._extract_info(),
            "endpoints": self._extract_endpoints(),
            "variables": self.variables,
            "auth": self._extract_auth(),
            "folders": self._extract_folder_structure()
        }

    def _load_collection(self) -> None:
        """Load the collection from file."""
        if not self.collection_path.exists():
            raise PostmanParseError(f"Collection file not found: {self.collection_path}")

        try:
            content = self.collection_path.read_text(encoding='utf-8')
            self.collection = json.loads(content)
        except json.JSONDecodeError as e:
            raise PostmanParseError(f"Failed to parse collection as JSON: {e}")

        if not isinstance(self.collection, dict):
            raise PostmanParseError("Collection must be a JSON object")

        # Validate collection format
        info = self.collection.get("info", {})
        schema = info.get("schema", "")

        if not schema:
            raise PostmanParseError(
                "Invalid Postman collection: missing schema in info. "
                "Expected Postman Collection v2.0 or v2.1 format."
            )

        # Detect version
        if "v2.1" in schema:
            self.version = "2.1"
        elif "v2.0" in schema:
            self.version = "2.0"
        else:
            raise PostmanParseError(f"Unsupported collection schema: {schema}")

    def _extract_info(self) -> dict:
        """Extract collection info/metadata."""
        info = self.collection.get("info", {})
        return {
            "name": info.get("name", "Imported Collection"),
            "description": info.get("description"),
            "version": info.get("version"),
            "schema": info.get("schema")
        }

    def _extract_variables(self) -> None:
        """Extract collection-level variables."""
        self.variables = {}
        for var in self.collection.get("variable", []):
            if isinstance(var, dict):
                key = var.get("key", "")
                value = var.get("value", "")
                if key:
                    self.variables[key] = value

    def _extract_auth(self) -> Optional[dict]:
        """Extract collection-level authentication."""
        return self.collection.get("auth")

    def _extract_folder_structure(self) -> list[dict]:
        """Extract folder structure from the collection."""
        folders = []

        def process_items(items: list, parent_path: str = "") -> None:
            for item in items:
                if not isinstance(item, dict):
                    continue

                name = item.get("name", "")

                # Check if it's a folder (has items but no request)
                if "item" in item and "request" not in item:
                    folder_path = f"{parent_path}/{name}" if parent_path else name
                    folders.append({
                        "name": name,
                        "path": folder_path,
                        "description": item.get("description")
                    })
                    process_items(item["item"], folder_path)

        process_items(self.collection.get("item", []))
        return folders

    def _extract_endpoints(self) -> list[Endpoint]:
        """Extract all endpoints from the collection."""
        endpoints: list[Endpoint] = []
        collection_auth = self._extract_auth()

        def process_items(items: list, parent_auth: Optional[dict] = None) -> None:
            for item in items:
                if not isinstance(item, dict):
                    continue

                # Check if it's a folder
                if "item" in item:
                    # Merge auth if specified at folder level
                    folder_auth = item.get("auth", parent_auth)
                    process_items(item["item"], folder_auth)
                    continue

                # It's a request
                if "request" not in item:
                    continue

                request = item["request"]
                if not isinstance(request, dict):
                    continue

                endpoint = self._parse_request(item, parent_auth or collection_auth)
                if endpoint:
                    endpoints.append(endpoint)

        process_items(self.collection.get("item", []))
        return endpoints

    def _parse_request(
        self,
        item: dict,
        collection_auth: Optional[dict] = None
    ) -> Optional[Endpoint]:
        """Parse a single request item to an Endpoint."""
        request = item.get("request", {})
        if not isinstance(request, dict):
            return None

        # Extract method
        method_str = request.get("method", "GET").upper()
        try:
            method = HttpMethod(method_str)
        except ValueError:
            method = HttpMethod.GET

        # Extract URL
        url_data = request.get("url", {})
        if isinstance(url_data, dict):
            raw_url = url_data.get("raw", "")
            # Build URL from components if raw not available
            if not raw_url:
                host = url_data.get("host", [])
                if isinstance(host, list):
                    host = ".".join(host)
                path = url_data.get("path", [])
                if isinstance(path, list):
                    path = "/" + "/".join(path)
                protocol = url_data.get("protocol", "https")
                port = url_data.get("port", "")
                raw_url = f"{protocol}://{host}"
                if port:
                    raw_url += f":{port}"
                raw_url += path
        else:
            raw_url = str(url_data)

        # Resolve variables in URL
        raw_url = self._resolve_variables(raw_url)

        # Parse URL
        parsed = urlparse(raw_url)
        path = parsed.path or "/"

        # Extract parameters
        parameters: list[Parameter] = []

        # Query parameters
        query_params = request.get("url", {}).get("query", []) if isinstance(request.get("url"), dict) else []
        for param in query_params:
            if isinstance(param, dict) and not param.get("disabled", False):
                parameters.append(Parameter(
                    name=param.get("key", ""),
                    location="query",
                    required=False,
                    param_type="string",
                    description=param.get("description"),
                    example=self._resolve_variables(param.get("value", ""))
                ))

        # URL path variables
        path_vars = request.get("url", {}).get("variable", []) if isinstance(request.get("url"), dict) else []
        for var in path_vars:
            if isinstance(var, dict) and not var.get("disabled", False):
                parameters.append(Parameter(
                    name=var.get("key", ""),
                    location="path",
                    required=True,
                    param_type="string",
                    description=var.get("description"),
                    example=self._resolve_variables(var.get("value", ""))
                ))

        # Headers
        headers = request.get("header", [])
        for header in headers:
            if isinstance(header, dict) and not header.get("disabled", False):
                key = header.get("key", "")
                # Skip common headers that don't affect security testing
                if key.lower() not in ["content-type", "accept", "user-agent", "host", "content-length"]:
                    parameters.append(Parameter(
                        name=key,
                        location="header",
                        required=False,
                        param_type="string",
                        description=header.get("description"),
                        example=self._resolve_variables(header.get("value", ""))
                    ))

        # Build request body
        request_body = None
        body = request.get("body", {})
        if isinstance(body, dict):
            mode = body.get("mode", "")
            if mode == "raw":
                raw_body = body.get("raw", "")
                raw_body = self._resolve_variables(raw_body)
                try:
                    # Try to parse as JSON
                    parsed_body = json.loads(raw_body)
                    request_body = {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                                "example": parsed_body
                            }
                        }
                    }
                except json.JSONDecodeError:
                    # Treat as text
                    request_body = {
                        "content": {
                            "text/plain": {
                                "schema": {"type": "string"},
                                "example": raw_body
                            }
                        }
                    }
            elif mode == "urlencoded":
                urlencoded = body.get("urlencoded", [])
                form_data = {}
                for field in urlencoded:
                    if isinstance(field, dict) and not field.get("disabled", False):
                        form_data[field.get("key", "")] = self._resolve_variables(field.get("value", ""))
                request_body = {
                    "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": {"type": "object"},
                            "example": form_data
                        }
                    }
                }
            elif mode == "formdata":
                formdata = body.get("formdata", [])
                form_data = {}
                for field in formdata:
                    if isinstance(field, dict) and not field.get("disabled", False):
                        form_data[field.get("key", "")] = self._resolve_variables(field.get("value", ""))
                request_body = {
                    "content": {
                        "multipart/form-data": {
                            "schema": {"type": "object"},
                            "example": form_data
                        }
                    }
                }

        # Build security from auth
        security = None
        auth = request.get("auth", collection_auth)
        if auth:
            auth_type = auth.get("type", "")
            if auth_type == PostmanAuthType.BEARER:
                security = [{"bearerAuth": []}]
            elif auth_type == PostmanAuthType.BASIC:
                security = [{"basicAuth": []}]
            elif auth_type == PostmanAuthType.APIKEY:
                security = [{"apiKeyAuth": []}]
            elif auth_type == PostmanAuthType.OAUTH2:
                security = [{"oauth2": []}]

        return Endpoint(
            path=path,
            method=method,
            operation_id=item.get("name", "").lower().replace(" ", "_"),
            summary=item.get("name"),
            description=item.get("description") or request.get("description"),
            parameters=parameters,
            request_body=request_body,
            security=security,
            tags=[]  # Could use folder names as tags
        )

    def _resolve_variables(self, value: str) -> str:
        """Resolve {{variable}} syntax using collection variables."""
        if not isinstance(value, str):
            return value

        import re
        pattern = r'\{\{([^}]+)\}\}'

        def replace_var(match):
            var_name = match.group(1)
            return str(self.variables.get(var_name, match.group(0)))

        return re.sub(pattern, replace_var, value)

    def get_base_url(self) -> Optional[str]:
        """
        Extract the base URL from the collection.

        Returns the most common host across all requests.
        """
        hosts: dict[str, int] = {}

        def count_hosts(items: list) -> None:
            for item in items:
                if not isinstance(item, dict):
                    continue

                if "item" in item:
                    count_hosts(item["item"])
                    continue

                request = item.get("request", {})
                if not isinstance(request, dict):
                    continue

                url_data = request.get("url", {})
                if isinstance(url_data, dict):
                    host = url_data.get("host", [])
                    if isinstance(host, list):
                        host = ".".join(host)
                    protocol = url_data.get("protocol", "https")
                    full_host = f"{protocol}://{host}"
                    hosts[full_host] = hosts.get(full_host, 0) + 1

        count_hosts(self.collection.get("item", []))

        if hosts:
            # Return the most common host
            return max(hosts, key=hosts.get)
        return None


class PostmanGenerator:
    """
    Generator for Postman Collection v2.1 format.

    Creates Postman collections from Sentinel endpoints, scan configurations,
    or scan results. Useful for exporting test cases for further manual testing.

    Example:
        # From endpoints
        generator = PostmanGenerator(name="My API Security Tests")
        collection = generator.from_endpoints(endpoints, base_url="https://api.example.com")
        generator.save(collection, "security_tests.json")

        # From scan results
        collection = generator.from_scan_result(result)
        generator.save(collection, "vulnerability_tests.json")
    """

    def __init__(
        self,
        name: str = "Sentinel Export",
        description: Optional[str] = None
    ):
        """
        Initialize the generator.

        Args:
            name: Collection name
            description: Collection description
        """
        self.name = name
        self.description = description

    def create_collection(
        self,
        items: list[dict],
        variables: Optional[list[dict]] = None,
        auth: Optional[dict] = None
    ) -> dict:
        """
        Create a Postman collection structure.

        Args:
            items: List of request items or folders
            variables: Collection variables
            auth: Collection-level authentication

        Returns:
            Complete Postman collection dictionary
        """
        collection = {
            "info": {
                "_postman_id": str(uuid.uuid4()),
                "name": self.name,
                "description": self.description or f"Generated by Sentinel API Security Scanner on {datetime.now(timezone.utc).isoformat()}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": items
        }

        if variables:
            collection["variable"] = variables

        if auth:
            collection["auth"] = auth

        return collection

    def from_endpoints(
        self,
        endpoints: list[Endpoint],
        base_url: str = "{{base_url}}",
        auth_type: Optional[str] = None,
        auth_config: Optional[dict] = None,
        group_by_tag: bool = True
    ) -> dict:
        """
        Generate a Postman collection from Sentinel endpoints.

        Args:
            endpoints: List of Endpoint objects
            base_url: Base URL for the API (can use variable)
            auth_type: Authentication type to use
            auth_config: Authentication configuration
            group_by_tag: Group requests by their tags

        Returns:
            Postman collection dictionary
        """
        items = []
        tag_folders: dict[str, list[dict]] = {}

        for endpoint in endpoints:
            request_item = self._create_request_item(endpoint, base_url)

            if group_by_tag and endpoint.tags:
                # Group by first tag
                tag = endpoint.tags[0]
                if tag not in tag_folders:
                    tag_folders[tag] = []
                tag_folders[tag].append(request_item)
            else:
                items.append(request_item)

        # Add tag folders to items
        for tag, folder_items in tag_folders.items():
            items.append({
                "name": tag,
                "item": folder_items,
                "description": f"Endpoints tagged with '{tag}'"
            })

        # Create variables
        variables = [
            {
                "key": "base_url",
                "value": base_url if base_url != "{{base_url}}" else "https://api.example.com",
                "description": "Base URL for the API"
            }
        ]

        # Create auth config
        auth = None
        if auth_type:
            auth = self._create_auth(auth_type, auth_config or {})

        return self.create_collection(items, variables, auth)

    def from_scan_config(self, config: ScanConfig) -> dict:
        """
        Generate a Postman collection from a scan configuration.

        Args:
            config: Sentinel ScanConfig object

        Returns:
            Postman collection dictionary
        """
        # Parse the swagger to get endpoints
        from .parser import SwaggerParser
        parser = SwaggerParser(config.swagger_path)
        endpoints = parser.parse()

        # Determine auth type from config
        auth_type = None
        auth_config = {}
        if config.auth_token:
            auth_type = "bearer"
            auth_config = {"token": config.auth_token}

        return self.from_endpoints(
            endpoints=endpoints,
            base_url=config.target_url,
            auth_type=auth_type,
            auth_config=auth_config
        )

    def from_scan_result(self, result: ScanResult) -> dict:
        """
        Generate a Postman collection from scan results.

        Creates a collection with:
        - Original endpoints tested
        - Vulnerability reproduction requests

        Args:
            result: Sentinel ScanResult object

        Returns:
            Postman collection dictionary
        """
        items = []

        # Create folders for organization
        tested_folder = {
            "name": "Tested Endpoints",
            "description": "All endpoints that were tested",
            "item": []
        }

        vuln_folder = {
            "name": "Vulnerabilities Found",
            "description": f"Reproduction requests for {len(result.vulnerabilities)} vulnerabilities",
            "item": []
        }

        # Add tested endpoints
        for endpoint in result.endpoints_tested:
            tested_folder["item"].append(
                self._create_request_item(endpoint, result.config.target_url)
            )

        # Add vulnerability reproduction requests
        for vuln in result.vulnerabilities:
            vuln_folder["item"].append(
                self._create_vulnerability_item(vuln, result.config.target_url)
            )

        items.append(tested_folder)
        if vuln_folder["item"]:
            items.append(vuln_folder)

        # Create collection variables
        variables = [
            {
                "key": "base_url",
                "value": result.config.target_url,
                "description": "Target API base URL"
            },
            {
                "key": "auth_token",
                "value": result.config.auth_token or "",
                "description": "Authentication token",
                "type": "secret"
            }
        ]

        return self.create_collection(
            items,
            variables,
            auth={"type": "bearer", "bearer": [{"key": "token", "value": "{{auth_token}}"}]}
            if result.config.auth_token else None
        )

    def from_attack_results(
        self,
        results: list[AttackResult],
        base_url: str
    ) -> dict:
        """
        Generate a Postman collection from attack results.

        Useful for reproducing successful attacks.

        Args:
            results: List of AttackResult objects
            base_url: Base URL for the API

        Returns:
            Postman collection dictionary
        """
        items = []

        # Group by attack type
        attack_folders: dict[str, list[dict]] = {}

        for result in results:
            attack_type = result.attack_type.value
            if attack_type not in attack_folders:
                attack_folders[attack_type] = []

            attack_folders[attack_type].append(
                self._create_attack_result_item(result, base_url)
            )

        # Create folders for each attack type
        for attack_type, folder_items in attack_folders.items():
            items.append({
                "name": f"{attack_type.upper()} Tests",
                "item": folder_items,
                "description": f"Attack payloads for {attack_type}"
            })

        return self.create_collection(items)

    def _create_request_item(self, endpoint: Endpoint, base_url: str) -> dict:
        """Create a Postman request item from an Endpoint."""
        # Build URL
        url = f"{base_url.rstrip('/')}{endpoint.path}"

        # Build query params
        query_params = []
        for param in endpoint.parameters:
            if param.location == "query":
                query_params.append({
                    "key": param.name,
                    "value": param.example or f"{{{param.name}}}",
                    "disabled": False,
                    "description": param.description
                })

        # Build headers
        headers = []
        for param in endpoint.parameters:
            if param.location == "header":
                headers.append({
                    "key": param.name,
                    "value": param.example or f"{{{param.name}}}",
                    "disabled": False,
                    "description": param.description
                })

        # Build body
        body = None
        if endpoint.request_body:
            content = endpoint.request_body.get("content", {})
            if "application/json" in content:
                example = content["application/json"].get("example", {})
                body = {
                    "mode": "raw",
                    "raw": json.dumps(example, indent=2) if example else "{}",
                    "options": {"raw": {"language": "json"}}
                }
            elif "application/x-www-form-urlencoded" in content:
                example = content["application/x-www-form-urlencoded"].get("example", {})
                body = {
                    "mode": "urlencoded",
                    "urlencoded": [
                        {"key": k, "value": str(v)} for k, v in example.items()
                    ]
                }

        # Parse URL for Postman format
        parsed = urlparse(url)

        request_item = {
            "name": endpoint.summary or endpoint.full_path,
            "request": {
                "method": endpoint.method.value,
                "header": headers,
                "url": {
                    "raw": url,
                    "protocol": parsed.scheme,
                    "host": parsed.netloc.split(":")[0].split("."),
                    "path": [p for p in parsed.path.split("/") if p],
                    "query": query_params
                },
                "description": endpoint.description
            }
        }

        if body:
            request_item["request"]["body"] = body

        # Add auth if endpoint requires it
        if endpoint.security:
            request_item["request"]["auth"] = self._create_auth_from_security(endpoint.security)

        return request_item

    def _create_vulnerability_item(
        self,
        vuln: Vulnerability,
        base_url: str
    ) -> dict:
        """Create a Postman request item for a vulnerability."""
        url = f"{base_url.rstrip('/')}{vuln.endpoint.path}"

        # Parse the payload to determine body/query params
        body = None
        headers = []
        query_params = []

        if vuln.payload:
            # Try to parse as JSON
            try:
                payload_data = json.loads(vuln.payload)
                body = {
                    "mode": "raw",
                    "raw": json.dumps(payload_data, indent=2),
                    "options": {"raw": {"language": "json"}}
                }
            except json.JSONDecodeError:
                # Treat as form data or query string
                if "=" in vuln.payload:
                    # Could be query string or form data
                    pairs = vuln.payload.split("&")
                    form_data = []
                    for pair in pairs:
                        if "=" in pair:
                            key, val = pair.split("=", 1)
                            form_data.append({"key": unquote(key), "value": unquote(val)})
                    if form_data:
                        body = {
                            "mode": "urlencoded",
                            "urlencoded": form_data
                        }

        request_item = {
            "name": f"[{vuln.severity.value.upper()}] {vuln.title}",
            "request": {
                "method": vuln.endpoint.method.value,
                "header": headers,
                "url": {
                    "raw": url,
                    "host": urlparse(url).netloc.split("."),
                    "path": [p for p in urlparse(url).path.split("/") if p],
                    "query": query_params
                },
                "description": f"{vuln.description}\n\n**Recommendation**: {vuln.recommendation}\n\n**CWE**: {vuln.cwe_id or 'N/A'}"
            }
        }

        if body:
            request_item["request"]["body"] = body

        return request_item

    def _create_attack_result_item(
        self,
        result: AttackResult,
        base_url: str
    ) -> dict:
        """Create a Postman request item from an attack result."""
        url = f"{base_url.rstrip('/')}{result.endpoint.path}"

        body = None
        if result.payload:
            try:
                payload_data = json.loads(result.payload)
                body = {
                    "mode": "raw",
                    "raw": json.dumps(payload_data, indent=2),
                    "options": {"raw": {"language": "json"}}
                }
            except json.JSONDecodeError:
                body = {
                    "mode": "raw",
                    "raw": result.payload
                }

        status = "SUCCESS" if result.success else "FAILED"

        request_item = {
            "name": f"[{status}] {result.endpoint.full_path}",
            "request": {
                "method": result.endpoint.method.value,
                "url": url,
                "description": f"Attack Type: {result.attack_type.value}\nSuccess: {result.success}"
            }
        }

        if body:
            request_item["request"]["body"] = body

        # Add response info as a test
        if result.response_status:
            request_item["response"] = [{
                "name": f"Response ({result.response_status})",
                "status": result.response_status,
                "body": result.response_body or ""
            }]

        return request_item

    def _create_auth(self, auth_type: str, config: dict) -> dict:
        """Create Postman auth configuration."""
        if auth_type == "bearer":
            return {
                "type": "bearer",
                "bearer": [
                    {"key": "token", "value": config.get("token", "{{auth_token}}")}
                ]
            }
        elif auth_type == "basic":
            return {
                "type": "basic",
                "basic": [
                    {"key": "username", "value": config.get("username", "")},
                    {"key": "password", "value": config.get("password", "")}
                ]
            }
        elif auth_type == "apikey":
            return {
                "type": "apikey",
                "apikey": [
                    {"key": "key", "value": config.get("key", "X-API-Key")},
                    {"key": "value", "value": config.get("value", "{{api_key}}")},
                    {"key": "in", "value": config.get("in", "header")}
                ]
            }
        elif auth_type == "oauth2":
            return {
                "type": "oauth2",
                "oauth2": [
                    {"key": "access_token", "value": config.get("access_token", "{{access_token}}")},
                    {"key": "token_type", "value": config.get("token_type", "Bearer")}
                ]
            }

        return {"type": "noauth"}

    def _create_auth_from_security(self, security: list[dict]) -> dict:
        """Create Postman auth from OpenAPI security object."""
        if not security:
            return {"type": "noauth"}

        # Get first security requirement
        sec = security[0]
        if "bearerAuth" in sec or "bearer" in sec:
            return {"type": "bearer", "bearer": [{"key": "token", "value": "{{auth_token}}"}]}
        elif "basicAuth" in sec or "basic" in sec:
            return {"type": "basic", "basic": [{"key": "username", "value": ""}, {"key": "password", "value": ""}]}
        elif "apiKeyAuth" in sec or "apiKey" in sec:
            return {"type": "apikey", "apikey": [{"key": "key", "value": "X-API-Key"}, {"key": "value", "value": "{{api_key}}"}]}

        return {"type": "noauth"}

    def save(self, collection: dict, output_path: str) -> str:
        """
        Save the collection to a JSON file.

        Args:
            collection: Collection dictionary
            output_path: Path to save the file

        Returns:
            Path to the saved file
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open(output, 'w', encoding='utf-8') as f:
            json.dump(collection, f, indent=2)

        return str(output)


# Convenience functions

def parse_postman(collection_path: str) -> list[Endpoint]:
    """
    Parse a Postman collection and return endpoints.

    Args:
        collection_path: Path to Postman collection JSON file

    Returns:
        List of Endpoint objects
    """
    parser = PostmanParser(collection_path)
    return parser.parse()


def generate_postman_collection(
    endpoints: list[Endpoint],
    name: str = "Sentinel Export",
    base_url: str = "{{base_url}}",
    output_path: Optional[str] = None
) -> dict:
    """
    Generate a Postman collection from endpoints.

    Args:
        endpoints: List of Endpoint objects
        name: Collection name
        base_url: Base URL for the API
        output_path: Optional path to save the collection

    Returns:
        Postman collection dictionary
    """
    generator = PostmanGenerator(name=name)
    collection = generator.from_endpoints(endpoints, base_url=base_url)

    if output_path:
        generator.save(collection, output_path)

    return collection


def convert_openapi_to_postman(
    openapi_path: str,
    output_path: Optional[str] = None,
    name: Optional[str] = None,
    base_url: Optional[str] = None
) -> dict:
    """
    Convert an OpenAPI specification to a Postman collection.

    Args:
        openapi_path: Path to OpenAPI/Swagger file
        output_path: Optional path to save the collection
        name: Collection name (defaults to API title)
        base_url: Base URL for the API (defaults to server from spec)

    Returns:
        Postman collection dictionary
    """
    from .parser import SwaggerParser

    parser = SwaggerParser(openapi_path)
    endpoints = parser.parse()
    info = parser.get_info()

    # Use API title if name not provided
    collection_name = name or info.get("title", "API Collection")

    # Use server from spec if base_url not provided
    if not base_url:
        base_url = parser.get_base_url() or "{{base_url}}"

    generator = PostmanGenerator(name=collection_name, description=info.get("description"))
    collection = generator.from_endpoints(endpoints, base_url=base_url)

    if output_path:
        generator.save(collection, output_path)

    return collection
