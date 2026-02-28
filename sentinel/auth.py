"""
Authentication Handler for Sentinel.

Handles various authentication methods for API security testing:
- API Keys (Header, Query, Cookie)
- Bearer Tokens (JWT, OAuth2)
- Basic Authentication
- OAuth 2.0 (Authorization Code, Client Credentials, Password)
- Session-based Authentication
- Custom Authentication Schemes

v3.0 Feature: Enterprise Authentication Support
"""

import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse
from typing import Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta, timezone

import requests


class AuthType(Enum):
    """Supported authentication types."""
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    BASIC = "basic"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_PASSWORD = "oauth2_password"
    OAUTH2_AUTHORIZATION_CODE = "oauth2_authorization_code"
    JWT = "jwt"
    SESSION = "session"
    CUSTOM = "custom"
    DIGEST = "digest"
    AWS_SIGNATURE = "aws_signature"
    HMAC = "hmac"


@dataclass
class AuthConfig:
    """Configuration for authentication."""
    auth_type: AuthType = AuthType.NONE
    
    # API Key auth
    api_key: Optional[str] = None
    api_key_name: str = "X-API-Key"
    api_key_location: str = "header"  # header, query, cookie
    
    # Bearer token auth
    bearer_token: Optional[str] = None
    
    # Basic auth
    username: Optional[str] = None
    password: Optional[str] = None
    
    # OAuth2
    oauth_token_url: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_scope: Optional[str] = None
    oauth_authorization_url: Optional[str] = None
    oauth_redirect_uri: Optional[str] = None
    
    # Session auth
    session_login_url: Optional[str] = None
    session_username_field: str = "username"
    session_password_field: str = "password"
    session_token_path: Optional[str] = None  # JSON path to extract token
    
    # Custom auth
    custom_headers: dict = field(default_factory=dict)
    custom_callback: Optional[Callable] = None
    
    # JWT
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_payload: dict = field(default_factory=dict)
    
    # AWS Signature
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_region: str = "us-east-1"
    aws_service: str = "execute-api"
    
    # HMAC
    hmac_key: Optional[str] = None
    hmac_algorithm: str = "sha256"
    hmac_header_name: str = "X-Signature"
    
    # Token refresh
    auto_refresh: bool = True
    refresh_buffer_seconds: int = 300  # Refresh 5 minutes before expiry
    
    # Internal state
    _access_token: Optional[str] = None
    _refresh_token: Optional[str] = None
    _token_expires_at: Optional[datetime] = None
    _session_cookies: Optional[dict] = None


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class TokenExpiredError(AuthenticationError):
    """Raised when a token has expired."""
    pass


class AuthHandler:
    """
    Handles authentication for API requests.
    
    Supports multiple authentication methods with automatic token refresh
    and session management.
    """
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._session = requests.Session()
        self._last_auth_time: Optional[datetime] = None
    
    def authenticate(self) -> dict:
        """
        Perform authentication and return headers to use.
        
        Returns:
            Dictionary of headers to add to requests
        """
        if self.config.auth_type == AuthType.NONE:
            return {}
        
        elif self.config.auth_type == AuthType.API_KEY:
            return self._handle_api_key()
        
        elif self.config.auth_type == AuthType.BEARER:
            return self._handle_bearer()
        
        elif self.config.auth_type == AuthType.BASIC:
            return self._handle_basic()
        
        elif self.config.auth_type == AuthType.OAUTH2_CLIENT_CREDENTIALS:
            return self._handle_oauth2_client_credentials()
        
        elif self.config.auth_type == AuthType.OAUTH2_PASSWORD:
            return self._handle_oauth2_password()
        
        elif self.config.auth_type == AuthType.SESSION:
            return self._handle_session()
        
        elif self.config.auth_type == AuthType.JWT:
            return self._handle_jwt()
        
        elif self.config.auth_type == AuthType.AWS_SIGNATURE:
            return self._handle_aws_signature()
        
        elif self.config.auth_type == AuthType.HMAC:
            return self._handle_hmac()
        
        elif self.config.auth_type == AuthType.CUSTOM:
            return self._handle_custom()
        
        else:
            raise AuthenticationError(f"Unsupported auth type: {self.config.auth_type}")
    
    def _handle_api_key(self) -> dict:
        """Handle API Key authentication."""
        if not self.config.api_key:
            raise AuthenticationError("API key not configured")
        
        if self.config.api_key_location == "header":
            return {self.config.api_key_name: self.config.api_key}
        elif self.config.api_key_location == "query":
            # Query params handled separately in request
            return {}
        elif self.config.api_key_location == "cookie":
            return {"Cookie": f"{self.config.api_key_name}={self.config.api_key}"}
        
        return {self.config.api_key_name: self.config.api_key}
    
    def _handle_bearer(self) -> dict:
        """Handle Bearer token authentication."""
        if not self.config.bearer_token:
            raise AuthenticationError("Bearer token not configured")
        
        return {"Authorization": f"Bearer {self.config.bearer_token}"}
    
    def _handle_basic(self) -> dict:
        """Handle Basic authentication."""
        if not self.config.username or not self.config.password:
            raise AuthenticationError("Username/password not configured")
        
        credentials = f"{self.config.username}:{self.config.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        return {"Authorization": f"Basic {encoded}"}
    
    def _handle_oauth2_client_credentials(self) -> dict:
        """Handle OAuth2 Client Credentials flow."""
        # Check if we have a valid token
        if self._is_token_valid():
            return {"Authorization": f"Bearer {self.config._access_token}"}
        
        # Request new token
        if not all([self.config.oauth_token_url, self.config.oauth_client_id, 
                    self.config.oauth_client_secret]):
            raise AuthenticationError("OAuth2 client credentials not fully configured")
        
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.oauth_client_id,
            "client_secret": self.config.oauth_client_secret
        }
        
        if self.config.oauth_scope:
            data["scope"] = self.config.oauth_scope
        
        try:
            response = self._session.post(
                self.config.oauth_token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            self._store_token(token_data)
            
            return {"Authorization": f"Bearer {self.config._access_token}"}
            
        except requests.RequestException as e:
            raise AuthenticationError(f"OAuth2 token request failed: {e}")
    
    def _handle_oauth2_password(self) -> dict:
        """Handle OAuth2 Resource Owner Password flow."""
        # Check if we have a valid token
        if self._is_token_valid():
            return {"Authorization": f"Bearer {self.config._access_token}"}
        
        # Request new token
        if not all([self.config.oauth_token_url, self.config.username, self.config.password]):
            raise AuthenticationError("OAuth2 password credentials not fully configured")
        
        data = {
            "grant_type": "password",
            "username": self.config.username,
            "password": self.config.password
        }
        
        if self.config.oauth_client_id:
            data["client_id"] = self.config.oauth_client_id
        if self.config.oauth_client_secret:
            data["client_secret"] = self.config.oauth_client_secret
        if self.config.oauth_scope:
            data["scope"] = self.config.oauth_scope
        
        try:
            response = self._session.post(
                self.config.oauth_token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            self._store_token(token_data)
            
            return {"Authorization": f"Bearer {self.config._access_token}"}
            
        except requests.RequestException as e:
            raise AuthenticationError(f"OAuth2 password flow failed: {e}")
    
    def _handle_session(self) -> dict:
        """Handle session-based authentication."""
        # Check if we have an active session
        if self.config._session_cookies and self._is_session_valid():
            return {"Cookie": self._format_cookies()}
        
        # Login to get session
        if not all([self.config.session_login_url, self.config.username, self.config.password]):
            raise AuthenticationError("Session auth not fully configured")
        
        login_data = {
            self.config.session_username_field: self.config.username,
            self.config.session_password_field: self.config.password
        }
        
        try:
            response = self._session.post(
                self.config.session_login_url,
                json=login_data,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Extract cookies
            self.config._session_cookies = dict(self._session.cookies)
            self._last_auth_time = datetime.now()
            
            # Try to extract token from response if path specified
            if self.config.session_token_path:
                try:
                    token = self._extract_json_path(response.json(), self.config.session_token_path)
                    if token:
                        self.config._access_token = token
                        return {"Authorization": f"Bearer {token}"}
                except:
                    pass
            
            return {"Cookie": self._format_cookies()}
            
        except requests.RequestException as e:
            raise AuthenticationError(f"Session login failed: {e}")
    
    def _handle_jwt(self) -> dict:
        """Handle JWT authentication (generate or use existing)."""
        if self.config.bearer_token:
            return {"Authorization": f"Bearer {self.config.bearer_token}"}
        
        # Generate JWT if secret is provided
        if self.config.jwt_secret:
            token = self._generate_jwt()
            return {"Authorization": f"Bearer {token}"}
        
        raise AuthenticationError("JWT not configured (need bearer_token or jwt_secret)")
    
    def _generate_jwt(self) -> str:
        """Generate a JWT token."""
        try:
            import jwt
        except ImportError:
            raise AuthenticationError("PyJWT not installed. Run: pip install PyJWT")
        
        payload = {
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            **self.config.jwt_payload
        }
        
        token = jwt.encode(
            payload,
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm
        )
        
        return token
    
    def _handle_aws_signature(self) -> dict:
        """Handle AWS Signature V4 authentication."""
        if not all([self.config.aws_access_key, self.config.aws_secret_key]):
            raise AuthenticationError("AWS credentials not configured")
        
        # Note: Full AWS Sig v4 implementation would be done here
        # For now, return basic structure
        return {
            "X-Amz-Date": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "Authorization": f"AWS4-HMAC-SHA256 Credential={self.config.aws_access_key}/..."
        }
    
    def _handle_hmac(self) -> dict:
        """Handle HMAC signature authentication."""
        if not self.config.hmac_key:
            raise AuthenticationError("HMAC key not configured")
        
        # Generate timestamp
        timestamp = str(int(time.time()))
        
        # Create signature (would need request details for full implementation)
        message = timestamp.encode()
        # Get the hash function from hashlib
        hash_func = getattr(hashlib, self.config.hmac_algorithm, hashlib.sha256)
        signature = hmac.new(
            self.config.hmac_key.encode(),
            message,
            hash_func
        ).hexdigest()
        
        return {
            self.config.hmac_header_name: signature,
            "X-Timestamp": timestamp
        }
    
    def _handle_custom(self) -> dict:
        """Handle custom authentication."""
        if self.config.custom_callback:
            return self.config.custom_callback()
        
        return self.config.custom_headers
    
    def _is_token_valid(self) -> bool:
        """Check if current token is valid."""
        if not self.config._access_token:
            return False
        
        if not self.config._token_expires_at:
            return True  # No expiry set, assume valid
        
        # Check if token expires soon
        buffer = timedelta(seconds=self.config.refresh_buffer_seconds)
        return datetime.now() < (self.config._token_expires_at - buffer)
    
    def _is_session_valid(self) -> bool:
        """Check if session is still valid."""
        if not self.config._session_cookies:
            return False
        
        # Sessions typically expire after 30 minutes of inactivity
        if self._last_auth_time:
            return datetime.now() < self._last_auth_time + timedelta(minutes=25)
        
        return True
    
    def _store_token(self, token_data: dict):
        """Store token data from OAuth response."""
        self.config._access_token = token_data.get("access_token")
        self.config._refresh_token = token_data.get("refresh_token")
        
        expires_in = token_data.get("expires_in", 3600)
        self.config._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        self._last_auth_time = datetime.now()
    
    def _format_cookies(self) -> str:
        """Format cookies for header."""
        if not self.config._session_cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.config._session_cookies.items())
    
    def _extract_json_path(self, data: dict, path: str):
        """Extract value from JSON using dot-notation path."""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def get_auth_params(self) -> dict:
        """Get query parameters for authentication (for API key in query)."""
        if self.config.auth_type == AuthType.API_KEY and self.config.api_key_location == "query":
            return {self.config.api_key_name: self.config.api_key}
        return {}
    
    def refresh(self) -> dict:
        """Force refresh authentication."""
        self.config._access_token = None
        self.config._refresh_token = None
        self.config._token_expires_at = None
        return self.authenticate()
    
    def get_session(self) -> requests.Session:
        """Get the session object for authenticated requests."""
        return self._session


class AuthManager:
    """
    Manages multiple authentication configurations.
    
    Useful for testing with different user roles or permissions.
    """
    
    def __init__(self):
        self.auth_configs: dict[str, AuthConfig] = {}
        self.handlers: dict[str, AuthHandler] = {}
        self.default_auth: Optional[str] = None
    
    def add_auth(self, name: str, config: AuthConfig, is_default: bool = False):
        """Add an authentication configuration."""
        self.auth_configs[name] = config
        self.handlers[name] = AuthHandler(config)
        
        if is_default or not self.default_auth:
            self.default_auth = name
    
    def get_auth_headers(self, name: Optional[str] = None) -> dict:
        """Get authentication headers for a named config."""
        auth_name = name or self.default_auth
        
        if not auth_name:
            return {}
        
        if auth_name not in self.handlers:
            raise AuthenticationError(f"Auth config '{auth_name}' not found")
        
        return self.handlers[auth_name].authenticate()
    
    def get_handler(self, name: Optional[str] = None) -> AuthHandler:
        """Get auth handler for a named config."""
        auth_name = name or self.default_auth
        
        if not auth_name:
            raise AuthenticationError("No default auth configured")
        
        if auth_name not in self.handlers:
            raise AuthenticationError(f"Auth config '{auth_name}' not found")
        
        return self.handlers[auth_name]
    
    def list_auths(self) -> list[str]:
        """List available auth configurations."""
        return list(self.auth_configs.keys())
    
    def remove_auth(self, name: str):
        """Remove an authentication configuration."""
        self.auth_configs.pop(name, None)
        self.handlers.pop(name, None)
        
        if self.default_auth == name:
            self.default_auth = self.auth_configs.keys()[0] if self.auth_configs else None


# Convenience functions

def create_api_key_auth(api_key: str, header_name: str = "X-API-Key", 
                         location: str = "header") -> AuthHandler:
    """Create API Key authentication handler."""
    config = AuthConfig(
        auth_type=AuthType.API_KEY,
        api_key=api_key,
        api_key_name=header_name,
        api_key_location=location
    )
    return AuthHandler(config)


def create_bearer_auth(token: str) -> AuthHandler:
    """Create Bearer token authentication handler."""
    config = AuthConfig(
        auth_type=AuthType.BEARER,
        bearer_token=token
    )
    return AuthHandler(config)


def create_basic_auth(username: str, password: str) -> AuthHandler:
    """Create Basic authentication handler."""
    config = AuthConfig(
        auth_type=AuthType.BASIC,
        username=username,
        password=password
    )
    return AuthHandler(config)


def create_oauth2_client_credentials(
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: Optional[str] = None
) -> AuthHandler:
    """Create OAuth2 Client Credentials authentication handler."""
    config = AuthConfig(
        auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
        oauth_token_url=token_url,
        oauth_client_id=client_id,
        oauth_client_secret=client_secret,
        oauth_scope=scope
    )
    return AuthHandler(config)


def create_session_auth(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password"
) -> AuthHandler:
    """Create session-based authentication handler."""
    config = AuthConfig(
        auth_type=AuthType.SESSION,
        session_login_url=login_url,
        username=username,
        password=password,
        session_username_field=username_field,
        session_password_field=password_field
    )
    return AuthHandler(config)


def detect_auth_type(headers: dict) -> AuthType:
    """Detect authentication type from request headers."""
    auth_header = headers.get("Authorization", "")
    
    if auth_header.startswith("Bearer "):
        return AuthType.BEARER
    elif auth_header.startswith("Basic "):
        return AuthType.BASIC
    elif auth_header.startswith("AWS4-HMAC-SHA256"):
        return AuthType.AWS_SIGNATURE
    elif auth_header.startswith("Digest "):
        return AuthType.DIGEST
    
    # Check for API key headers
    api_key_headers = ["X-API-Key", "Api-Key", "apikey", "X-Auth-Token"]
    for header in api_key_headers:
        if header in headers:
            return AuthType.API_KEY
    
    return AuthType.NONE
