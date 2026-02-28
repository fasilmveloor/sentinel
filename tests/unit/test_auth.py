"""
Comprehensive tests for Authentication Handler module.

Tests cover:
- API Key authentication
- Bearer token authentication
- Basic authentication
- OAuth2 flows
- Session authentication
- JWT authentication
- AWS Signature
- HMAC authentication
- Custom authentication
- AuthManager
"""

import pytest
import base64
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta

from sentinel.auth import (
    AuthType, AuthConfig, AuthHandler, AuthManager, AuthenticationError,
    create_api_key_auth, create_bearer_auth, create_basic_auth,
    create_oauth2_client_credentials, create_session_auth, detect_auth_type
)


# ============================================================================
# AUTH TYPE ENUM TESTS
# ============================================================================

class TestAuthType:
    """Tests for AuthType enum."""

    def test_all_auth_types_exist(self):
        """Test all expected auth types exist."""
        expected = [
            'NONE', 'API_KEY', 'BEARER', 'BASIC',
            'OAUTH2_CLIENT_CREDENTIALS', 'OAUTH2_PASSWORD',
            'OAUTH2_AUTHORIZATION_CODE', 'JWT', 'SESSION',
            'CUSTOM', 'DIGEST', 'AWS_SIGNATURE', 'HMAC'
        ]
        
        for auth_type in expected:
            assert hasattr(AuthType, auth_type)

    def test_auth_type_values(self):
        """Test auth type values."""
        assert AuthType.NONE.value == "none"
        assert AuthType.API_KEY.value == "api_key"
        assert AuthType.BEARER.value == "bearer"
        assert AuthType.BASIC.value == "basic"


# ============================================================================
# AUTH CONFIG TESTS
# ============================================================================

class TestAuthConfig:
    """Tests for AuthConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = AuthConfig()
        
        assert config.auth_type == AuthType.NONE
        assert config.api_key is None
        assert config.bearer_token is None

    def test_api_key_config(self):
        """Test API key configuration."""
        config = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key="test-key-123",
            api_key_name="X-API-Key",
            api_key_location="header"
        )
        
        assert config.api_key == "test-key-123"
        assert config.api_key_name == "X-API-Key"
        assert config.api_key_location == "header"

    def test_bearer_config(self):
        """Test bearer token configuration."""
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="token-abc-xyz"
        )
        
        assert config.bearer_token == "token-abc-xyz"

    def test_basic_auth_config(self):
        """Test basic auth configuration."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="admin",
            password="secret"
        )
        
        assert config.username == "admin"
        assert config.password == "secret"

    def test_oauth2_config(self):
        """Test OAuth2 configuration."""
        config = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            oauth_token_url="https://auth.example.com/token",
            oauth_client_id="client-123",
            oauth_client_secret="secret-456",
            oauth_scope="read write"
        )
        
        assert config.oauth_token_url == "https://auth.example.com/token"
        assert config.oauth_client_id == "client-123"
        assert config.oauth_scope == "read write"

    def test_jwt_config(self):
        """Test JWT configuration."""
        config = AuthConfig(
            auth_type=AuthType.JWT,
            jwt_secret="super-secret-key",
            jwt_algorithm="HS256",
            jwt_payload={"sub": "user123", "role": "admin"}
        )
        
        assert config.jwt_secret == "super-secret-key"
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_payload["role"] == "admin"

    def test_aws_signature_config(self):
        """Test AWS signature configuration."""
        config = AuthConfig(
            auth_type=AuthType.AWS_SIGNATURE,
            aws_access_key="AKIAIOSFODNN7EXAMPLE",
            aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_region="us-east-1",
            aws_service="execute-api"
        )
        
        assert config.aws_access_key == "AKIAIOSFODNN7EXAMPLE"
        assert config.aws_region == "us-east-1"

    def test_hmac_config(self):
        """Test HMAC configuration."""
        config = AuthConfig(
            auth_type=AuthType.HMAC,
            hmac_key="hmac-secret-key",
            hmac_algorithm="sha256",
            hmac_header_name="X-Signature"
        )
        
        assert config.hmac_key == "hmac-secret-key"
        assert config.hmac_algorithm == "sha256"


# ============================================================================
# AUTH HANDLER - NONE TYPE TESTS
# ============================================================================

class TestAuthHandlerNone:
    """Tests for AuthHandler with no authentication."""

    def test_none_auth_returns_empty_headers(self):
        """Test NONE auth returns empty headers."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers == {}


# ============================================================================
# AUTH HANDLER - API KEY TESTS
# ============================================================================

class TestAuthHandlerApiKey:
    """Tests for API Key authentication."""

    def test_api_key_in_header(self):
        """Test API key in header."""
        config = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key="test-key",
            api_key_name="X-API-Key",
            api_key_location="header"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["X-API-Key"] == "test-key"

    def test_api_key_custom_header_name(self):
        """Test API key with custom header name."""
        config = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key="test-key",
            api_key_name="X-Custom-Auth",
            api_key_location="header"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["X-Custom-Auth"] == "test-key"

    def test_api_key_in_query(self):
        """Test API key in query parameters."""
        config = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key="test-key",
            api_key_name="api_key",
            api_key_location="query"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        # Query params handled separately
        assert headers == {}
        
        params = handler.get_auth_params()
        assert params["api_key"] == "test-key"

    def test_api_key_in_cookie(self):
        """Test API key in cookie."""
        config = AuthConfig(
            auth_type=AuthType.API_KEY,
            api_key="test-key",
            api_key_name="session_id",
            api_key_location="cookie"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "Cookie" in headers
        assert "session_id=test-key" in headers["Cookie"]

    def test_api_key_missing_raises_error(self):
        """Test missing API key raises error."""
        config = AuthConfig(auth_type=AuthType.API_KEY)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - BEARER TOKEN TESTS
# ============================================================================

class TestAuthHandlerBearer:
    """Tests for Bearer token authentication."""

    def test_bearer_token(self):
        """Test bearer token authentication."""
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

    def test_bearer_token_missing_raises_error(self):
        """Test missing bearer token raises error."""
        config = AuthConfig(auth_type=AuthType.BEARER)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - BASIC AUTH TESTS
# ============================================================================

class TestAuthHandlerBasic:
    """Tests for Basic authentication."""

    def test_basic_auth(self):
        """Test basic authentication."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="admin",
            password="secret"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        
        # Verify the encoded credentials
        encoded = headers["Authorization"].replace("Basic ", "")
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "admin:secret"

    def test_basic_auth_missing_credentials_raises_error(self):
        """Test missing credentials raises error."""
        config = AuthConfig(auth_type=AuthType.BASIC)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()

    def test_basic_auth_missing_password_raises_error(self):
        """Test missing password raises error."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="admin"
        )
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - OAUTH2 TESTS
# ============================================================================

class TestAuthHandlerOAuth2:
    """Tests for OAuth2 authentication."""

    @patch('sentinel.auth.requests.Session')
    def test_oauth2_client_credentials(self, mock_session_class):
        """Test OAuth2 client credentials flow."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock token response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access-token-123",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        
        config = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            oauth_token_url="https://auth.example.com/token",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            oauth_scope="read"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "Authorization" in headers
        assert "Bearer access-token-123" in headers["Authorization"]

    def test_oauth2_missing_config_raises_error(self):
        """Test OAuth2 with missing config raises error."""
        config = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            oauth_token_url="https://auth.example.com/token"
            # Missing client_id and client_secret
        )
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - SESSION AUTH TESTS
# ============================================================================

class TestAuthHandlerSession:
    """Tests for session-based authentication."""

    @patch('sentinel.auth.requests.Session')
    def test_session_auth(self, mock_session_class):
        """Test session authentication."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        
        # Mock login response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "session-token"}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_session.cookies = {"session_id": "abc123"}
        
        config = AuthConfig(
            auth_type=AuthType.SESSION,
            session_login_url="https://example.com/login",
            username="admin",
            password="secret"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        # Should return cookie header
        assert "Cookie" in headers or "Authorization" in headers

    def test_session_missing_config_raises_error(self):
        """Test session auth with missing config raises error."""
        config = AuthConfig(auth_type=AuthType.SESSION)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - JWT TESTS
# ============================================================================

class TestAuthHandlerJWT:
    """Tests for JWT authentication."""

    def test_jwt_with_bearer_token(self):
        """Test JWT with provided bearer token."""
        config = AuthConfig(
            auth_type=AuthType.JWT,
            bearer_token="existing-jwt-token"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["Authorization"] == "Bearer existing-jwt-token"

    @patch('jwt.encode')
    def test_jwt_generation(self, mock_encode):
        """Test JWT generation."""
        mock_encode.return_value = "generated-jwt-token"
        
        config = AuthConfig(
            auth_type=AuthType.JWT,
            jwt_secret="super-secret",
            jwt_algorithm="HS256",
            jwt_payload={"sub": "user123"}
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "Authorization" in headers
        assert "generated-jwt-token" in headers["Authorization"]

    def test_jwt_missing_config_raises_error(self):
        """Test JWT with missing config raises error."""
        config = AuthConfig(auth_type=AuthType.JWT)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - AWS SIGNATURE TESTS
# ============================================================================

class TestAuthHandlerAWSSignature:
    """Tests for AWS Signature authentication."""

    def test_aws_signature(self):
        """Test AWS signature authentication."""
        config = AuthConfig(
            auth_type=AuthType.AWS_SIGNATURE,
            aws_access_key="AKIAIOSFODNN7EXAMPLE",
            aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_region="us-east-1",
            aws_service="execute-api"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "X-Amz-Date" in headers
        assert "Authorization" in headers

    def test_aws_missing_credentials_raises_error(self):
        """Test AWS with missing credentials raises error."""
        config = AuthConfig(auth_type=AuthType.AWS_SIGNATURE)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - HMAC TESTS
# ============================================================================

class TestAuthHandlerHMAC:
    """Tests for HMAC authentication."""

    def test_hmac_auth(self):
        """Test HMAC authentication."""
        config = AuthConfig(
            auth_type=AuthType.HMAC,
            hmac_key="hmac-secret-key",
            hmac_algorithm="sha256",
            hmac_header_name="X-Signature"
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert "X-Signature" in headers
        assert "X-Timestamp" in headers

    def test_hmac_missing_key_raises_error(self):
        """Test HMAC with missing key raises error."""
        config = AuthConfig(auth_type=AuthType.HMAC)
        handler = AuthHandler(config)
        
        with pytest.raises(AuthenticationError):
            handler.authenticate()


# ============================================================================
# AUTH HANDLER - CUSTOM AUTH TESTS
# ============================================================================

class TestAuthHandlerCustom:
    """Tests for custom authentication."""

    def test_custom_auth_with_headers(self):
        """Test custom auth with predefined headers."""
        config = AuthConfig(
            auth_type=AuthType.CUSTOM,
            custom_headers={"X-Custom-Auth": "custom-value"}
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["X-Custom-Auth"] == "custom-value"

    def test_custom_auth_with_callback(self):
        """Test custom auth with callback function."""
        def custom_callback():
            return {"X-Token": "generated-token"}
        
        config = AuthConfig(
            auth_type=AuthType.CUSTOM,
            custom_callback=custom_callback
        )
        handler = AuthHandler(config)
        
        headers = handler.authenticate()
        
        assert headers["X-Token"] == "generated-token"


# ============================================================================
# AUTH HANDLER - TOKEN MANAGEMENT TESTS
# ============================================================================

class TestAuthHandlerTokenManagement:
    """Tests for token management."""

    def test_is_token_valid_no_token(self):
        """Test token validity check with no token."""
        config = AuthConfig(auth_type=AuthType.BEARER)
        handler = AuthHandler(config)
        
        assert handler._is_token_valid() is False

    def test_is_token_valid_with_token(self):
        """Test token validity check with token."""
        config = AuthConfig(auth_type=AuthType.BEARER)
        handler = AuthHandler(config)
        handler.config._access_token = "test-token"
        
        assert handler._is_token_valid() is True

    def test_is_token_valid_with_expiry(self):
        """Test token validity check with expiry."""
        config = AuthConfig(auth_type=AuthType.BEARER)
        handler = AuthHandler(config)
        handler.config._access_token = "test-token"
        handler.config._token_expires_at = datetime.now() + timedelta(hours=1)
        
        assert handler._is_token_valid() is True

    def test_is_token_valid_expired(self):
        """Test token validity check when expired."""
        config = AuthConfig(auth_type=AuthType.BEARER)
        handler = AuthHandler(config)
        handler.config._access_token = "test-token"
        handler.config._token_expires_at = datetime.now() - timedelta(hours=1)
        
        assert handler._is_token_valid() is False

    def test_refresh(self):
        """Test token refresh."""
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="test-token"
        )
        handler = AuthHandler(config)
        handler.config._access_token = "old-token"
        
        handler.refresh()
        
        assert handler.config._access_token is None

    def test_get_session(self):
        """Test getting session object."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        
        session = handler.get_session()
        
        assert session is not None


# ============================================================================
# AUTH HANDLER - HELPER METHOD TESTS
# ============================================================================

class TestAuthHandlerHelpers:
    """Tests for helper methods."""

    def test_format_cookies(self):
        """Test cookie formatting."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        handler.config._session_cookies = {"session_id": "abc123", "user": "admin"}
        
        formatted = handler._format_cookies()
        
        assert "session_id=abc123" in formatted
        assert "user=admin" in formatted

    def test_format_cookies_empty(self):
        """Test cookie formatting when empty."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        
        formatted = handler._format_cookies()
        
        assert formatted == ""

    def test_extract_json_path(self):
        """Test JSON path extraction."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        
        data = {"user": {"profile": {"name": "John"}}}
        
        result = handler._extract_json_path(data, "user.profile.name")
        
        assert result == "John"

    def test_extract_json_path_not_found(self):
        """Test JSON path extraction when path not found."""
        config = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(config)
        
        data = {"user": {"name": "John"}}
        
        result = handler._extract_json_path(data, "user.profile.name")
        
        assert result is None


# ============================================================================
# AUTH MANAGER TESTS
# ============================================================================

class TestAuthManager:
    """Tests for AuthManager."""

    def test_add_auth(self):
        """Test adding auth configuration."""
        manager = AuthManager()
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="test-token"
        )
        
        manager.add_auth("default", config)
        
        assert "default" in manager.auth_configs
        assert "default" in manager.handlers

    def test_add_auth_as_default(self):
        """Test adding auth as default."""
        manager = AuthManager()
        config = AuthConfig(auth_type=AuthType.NONE)
        
        manager.add_auth("default", config, is_default=True)
        
        assert manager.default_auth == "default"

    def test_get_auth_headers(self):
        """Test getting auth headers."""
        manager = AuthManager()
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="test-token"
        )
        manager.add_auth("default", config)
        
        headers = manager.get_auth_headers("default")
        
        assert "Authorization" in headers

    def test_get_auth_headers_default(self):
        """Test getting auth headers for default auth."""
        manager = AuthManager()
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            bearer_token="test-token"
        )
        manager.add_auth("default", config, is_default=True)
        
        headers = manager.get_auth_headers()
        
        assert "Authorization" in headers

    def test_get_auth_headers_not_found_raises_error(self):
        """Test getting auth headers for nonexistent auth raises error."""
        manager = AuthManager()
        
        with pytest.raises(AuthenticationError):
            manager.get_auth_headers("nonexistent")

    def test_get_handler(self):
        """Test getting auth handler."""
        manager = AuthManager()
        config = AuthConfig(auth_type=AuthType.NONE)
        manager.add_auth("default", config)
        
        handler = manager.get_handler("default")
        
        assert isinstance(handler, AuthHandler)

    def test_list_auths(self):
        """Test listing auth configurations."""
        manager = AuthManager()
        manager.add_auth("auth1", AuthConfig(auth_type=AuthType.NONE))
        manager.add_auth("auth2", AuthConfig(auth_type=AuthType.NONE))
        
        auths = manager.list_auths()
        
        assert "auth1" in auths
        assert "auth2" in auths

    def test_remove_auth(self):
        """Test removing auth configuration."""
        manager = AuthManager()
        manager.add_auth("default", AuthConfig(auth_type=AuthType.NONE))
        
        manager.remove_auth("default")
        
        assert "default" not in manager.auth_configs


# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_api_key_auth(self):
        """Test creating API key auth handler."""
        handler = create_api_key_auth("test-key", "X-API-Key", "header")
        
        headers = handler.authenticate()
        
        assert headers["X-API-Key"] == "test-key"

    def test_create_bearer_auth(self):
        """Test creating bearer auth handler."""
        handler = create_bearer_auth("test-token")
        
        headers = handler.authenticate()
        
        assert headers["Authorization"] == "Bearer test-token"

    def test_create_basic_auth(self):
        """Test creating basic auth handler."""
        handler = create_basic_auth("admin", "secret")
        
        headers = handler.authenticate()
        
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_create_oauth2_client_credentials(self):
        """Test creating OAuth2 client credentials handler."""
        handler = create_oauth2_client_credentials(
            "https://auth.example.com/token",
            "client-id",
            "client-secret",
            "read"
        )
        
        assert handler.config.auth_type == AuthType.OAUTH2_CLIENT_CREDENTIALS
        assert handler.config.oauth_client_id == "client-id"

    def test_create_session_auth(self):
        """Test creating session auth handler."""
        handler = create_session_auth(
            "https://example.com/login",
            "admin",
            "secret"
        )
        
        assert handler.config.auth_type == AuthType.SESSION
        assert handler.config.username == "admin"


# ============================================================================
# DETECT AUTH TYPE TESTS
# ============================================================================

class TestDetectAuthType:
    """Tests for detect_auth_type function."""

    def test_detect_bearer(self):
        """Test detecting Bearer auth."""
        headers = {"Authorization": "Bearer token123"}
        
        auth_type = detect_auth_type(headers)
        
        assert auth_type == AuthType.BEARER

    def test_detect_basic(self):
        """Test detecting Basic auth."""
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        
        auth_type = detect_auth_type(headers)
        
        assert auth_type == AuthType.BASIC

    def test_detect_api_key(self):
        """Test detecting API key auth."""
        headers = {"X-API-Key": "test-key"}
        
        auth_type = detect_auth_type(headers)
        
        assert auth_type == AuthType.API_KEY

    def test_detect_none(self):
        """Test detecting no auth."""
        headers = {}
        
        auth_type = detect_auth_type(headers)
        
        assert auth_type == AuthType.NONE

    def test_detect_aws_signature(self):
        """Test detecting AWS signature."""
        headers = {"Authorization": "AWS4-HMAC-SHA256 Credential=..."}
        
        auth_type = detect_auth_type(headers)
        
        assert auth_type == AuthType.AWS_SIGNATURE
