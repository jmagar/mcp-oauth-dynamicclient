"""Async-compatible ResourceProtector for FastAPI
Since Authlib's ResourceProtector doesn't support async natively,
we create a wrapper that works with FastAPI's async handlers.
"""

from typing import Any, Optional

import redis.asyncio as redis
from fastapi import HTTPException, Request

from .config import Settings
from .keys import RSAKeyManager
from .resource_protector import JWTBearerTokenValidator


class AsyncResourceProtector:
    """Async wrapper for Authlib's ResourceProtector that works with FastAPI.
    This maintains the security benefits of ResourceProtector while supporting async operations.
    """

    def __init__(self, settings: Settings, redis_client: redis.Redis, key_manager: RSAKeyManager):
        self.settings = settings
        self.redis_client = redis_client
        self.key_manager = key_manager
        self.validator = JWTBearerTokenValidator(settings, redis_client, key_manager)

    async def validate_request(self, request: Request, resource: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Validate the request and extract token information.

        Args:
            request: FastAPI Request object
            resource: Optional resource URI for audience validation

        Returns:
            Token claims if valid, raises HTTPException if invalid

        """
        # Build WWW-Authenticate header with metadata URLs (RFC 9728)
        auth_server_url = (
            f"https://{self.settings.auth_subdomain}.{self.settings.base_domain}"
        )

        # If resource is provided, construct resource metadata URL
        if resource:
            resource_metadata_url = (
                f"{resource.rstrip('/')}/.well-known/oauth-protected-resource"
            )
        else:
            # Use request host as resource
            host = request.headers.get("host", "localhost")
            proto = request.headers.get("x-forwarded-proto", "https")
            resource = f"{proto}://{host}"
            resource_metadata_url = (
                f"{resource.rstrip('/')}/.well-known/oauth-protected-resource"
            )

        www_auth_params = [
            'Bearer',
            f'realm="MCP Server"',
            f'as_uri="{auth_server_url}/.well-known/oauth-authorization-server"',
            f'resource_metadata="{resource_metadata_url}"',
        ]
        www_authenticate = ", ".join(www_auth_params)

        # Check if request is valid
        error = self.validator.request_invalid(request)
        if error:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_request", "error_description": error},
                headers={"WWW-Authenticate": www_authenticate},
            )

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_request",
                    "error_description": "Authorization header must use Bearer scheme",
                },
                headers={"WWW-Authenticate": www_authenticate},
            )

        token_string = auth_header[7:]  # Remove "Bearer " prefix

        # Validate token asynchronously
        token_data = await self.validator.authenticate_token(token_string)

        if not token_data:
            # Add error parameter to WWW-Authenticate
            www_auth_error = www_authenticate.replace('Bearer', 'Bearer error="invalid_token"')
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired",
                },
                headers={"WWW-Authenticate": www_auth_error},
            )

        # Validate audience if resource is specified
        if resource and token_data:
            aud = token_data.get("aud", [])
            # Normalize audience to list
            if isinstance(aud, str):
                aud = [aud]

            # Normalize trailing slashes for comparison
            resource_normalized = resource.rstrip("/")
            aud_normalized = [a.rstrip("/") for a in aud]
            # Accept either the specific resource URL or the auth server's own URL
            # (tokens issued directly by this gateway are valid for all its services)
            valid_audiences = {resource_normalized, auth_server_url.rstrip("/")}
            if not any(a in valid_audiences for a in aud_normalized):
                www_auth_error = www_authenticate.replace('Bearer', 'Bearer error="invalid_audience"')
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "invalid_audience",
                        "error_description": f"Token is not valid for resource: {resource}",
                    },
                    headers={"WWW-Authenticate": www_auth_error},
                )

        return token_data


def create_async_resource_protector(
    settings: Settings,
    redis_client: redis.Redis,
    key_manager: RSAKeyManager,
) -> AsyncResourceProtector:
    """Create an async-compatible ResourceProtector instance.

    Args:
        settings: Application settings
        redis_client: Redis client for token storage
        key_manager: RSA key manager for JWT validation

    Returns:
        AsyncResourceProtector instance

    """
    return AsyncResourceProtector(settings, redis_client, key_manager)
