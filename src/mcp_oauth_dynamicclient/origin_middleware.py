"""Origin validation middleware for MCP Gateway proxy routes."""

import logging
import re
from typing import List, Pattern

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Default allowed origin patterns (matches current nginx config)
DEFAULT_ALLOWED_PATTERNS: List[str] = [
    "anthropic.com",
    "claude.ai",
]


class OriginValidationMiddleware(BaseHTTPMiddleware):
    """Validate Origin header to prevent DNS rebinding attacks.

    Applied only to proxy routes (/mcp, /session, /sessions, /health).
    OAuth endpoints are excluded since they need to be accessible from any origin.

    This middleware ports the nginx origin validation logic from the mcp-template.subdomain.conf
    to application-level middleware for proxy-agnostic deployments.
    """

    # Paths that skip origin validation (OAuth/discovery endpoints)
    SKIP_PATHS: set[str] = {
        "/register", "/authorize", "/token", "/callback",
        "/revoke", "/introspect", "/verify", "/error", "/success",
        "/jwks", "/device/code", "/activate", "/device/success",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-client-id-metadata",
    }

    def __init__(self, app, allowed_origins_str: str = "") -> None:
        """Initialize with optional comma-separated allowed origin domains.

        Args:
            app: The ASGI application
            allowed_origins_str: Comma-separated domain patterns (e.g. "example.com,myapp.io")
                These are ADDED to the default allowlist (anthropic.com, claude.ai).
                Empty string means use defaults only.
        """
        super().__init__(app)
        self._patterns = self._build_patterns(allowed_origins_str)

    def _build_patterns(self, allowed_origins_str: str) -> List[Pattern[str]]:
        """Build compiled regex patterns from domain list."""
        domains = list(DEFAULT_ALLOWED_PATTERNS)
        if allowed_origins_str:
            domains.extend(d.strip() for d in allowed_origins_str.split(",") if d.strip())

        patterns: List[Pattern[str]] = []
        for domain in domains:
            # Escape dots, allow optional wildcard subdomain
            escaped = re.escape(domain)
            patterns.append(re.compile(rf"^https://(.*\.)?{escaped}$"))

        # Always allow localhost and 127.0.0.1 with any port (HTTP or HTTPS)
        patterns.append(re.compile(r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$"))

        return patterns

    def _is_origin_allowed(self, origin: str, server_name: str) -> bool:
        """Check if origin is in the allowlist.

        Ports the nginx logic:
        - Empty origin is allowed (matches nginx behavior)
        - Exact match on server's own origin
        - Check against compiled patterns
        """
        # Empty origin is always allowed (matches nginx behavior)
        if not origin:
            return True

        # Exact match on the server's own origin
        if origin == f"https://{server_name}":
            return True

        # Check against compiled patterns
        return any(p.match(origin) for p in self._patterns)

    async def dispatch(self, request: Request, call_next):
        """Validate origin for proxy routes only."""
        path = request.url.path

        # Skip validation for OAuth/discovery endpoints
        if path in self.SKIP_PATHS or path.startswith("/register/"):
            return await call_next(request)

        # Only validate origin for proxy-targeted paths
        if path in ("/mcp", "/health") or path.startswith("/session"):
            origin = request.headers.get("origin", "")
            server_name = request.headers.get("host", "").split(":")[0]

            if not self._is_origin_allowed(origin, server_name):
                logger.warning(
                    "Origin validation failed: origin=%s host=%s path=%s",
                    origin, server_name, path
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "origin_not_allowed",
                        "message": "Origin header validation failed"
                    },
                )

        return await call_next(request)