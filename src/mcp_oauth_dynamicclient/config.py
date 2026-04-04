"""Configuration module for MCP OAuth Dynamic Client"""

from typing import Optional

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Sacred Configuration following the divine laws"""

    # GitHub OAuth
    github_client_id: str
    github_client_secret: str

    # JWT Configuration
    jwt_secret: str = Field(alias="OAUTH_JWT_SECRET")
    jwt_algorithm: str = Field(alias="OAUTH_JWT_ALGORITHM")  # NO DEFAULTS!
    jwt_private_key_b64: Optional[str] = Field(None, alias="OAUTH_JWT_PRIVATE_KEY_B64")  # Base64 encoded RSA private key for RS256

    # Domain Configuration
    base_domain: str
    auth_subdomain: str = "auth"  # Subdomain prefix for auth service URLs

    # Redis Configuration
    redis_url: str
    redis_password: Optional[str]  # NO DEFAULTS!

    # Token Lifetimes - NO DEFAULTS, MUST BE IN .env!
    access_token_lifetime: int = Field(alias="OAUTH_ACCESS_TOKEN_LIFETIME")
    refresh_token_lifetime: int = Field(alias="OAUTH_REFRESH_TOKEN_LIFETIME")
    session_timeout: int = Field(alias="OAUTH_SESSION_TIMEOUT")
    client_lifetime: int = Field(alias="OAUTH_CLIENT_LIFETIME")  # 0 = never expires
    device_code_lifetime: int = Field(600, alias="OAUTH_DEVICE_CODE_LIFETIME")
    device_code_interval: int = Field(5, alias="OAUTH_DEVICE_CODE_INTERVAL")

    # Access Control
    allowed_github_users: str = Field(alias="OAUTH_ALLOWED_GITHUB_USERS")  # NO DEFAULTS! Comma-separated list

    # MCP Protocol Version
    mcp_protocol_version: str = Field(alias="OAUTH_MCP_PROTOCOL_VERSION")  # NO DEFAULTS!

    # Gateway Proxy Settings
    mcp_allowed_origins: str = Field("", alias="MCP_ALLOWED_ORIGINS")  # Comma-separated extra origin domains
    mcp_proxy_connect_timeout: int = Field(240, alias="MCP_PROXY_CONNECT_TIMEOUT")  # seconds
    mcp_proxy_read_timeout: int = Field(86400, alias="MCP_PROXY_READ_TIMEOUT")  # 24h for SSE streams

    model_config = ConfigDict(
        env_file=".env",
        extra="ignore",  # Allow extra fields from environment
        populate_by_name=True,  # Allow both field name and alias
    )
