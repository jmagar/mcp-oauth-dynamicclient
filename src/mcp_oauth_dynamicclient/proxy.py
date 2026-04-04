"""Streaming reverse proxy for MCP backend services.

Handles authentication inline and proxies requests to MCP backends
over Tailscale, eliminating the need for nginx auth_request.
"""

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from .async_resource_protector import AsyncResourceProtector
from .service_registry import ServiceEntry, ServiceRegistry

logger = logging.getLogger(__name__)

# Headers to forward from client to backend
FORWARD_HEADERS = {
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-session-id",
    "last-event-id",
}

# Headers to strip from upstream response (handled by gateway CORS middleware)
STRIP_RESPONSE_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-allow-credentials",
    "access-control-max-age",
}


async def _get_service(request: Request) -> ServiceEntry:
    """FastAPI dependency: resolve backend service from Host header."""
    registry: ServiceRegistry = request.app.state.service_registry
    host = request.headers.get("host", "")
    service = registry.resolve(host)
    if not service:
        raise HTTPException(status_code=404, detail={"error": "unknown_service", "error_description": f"No MCP service registered for host: {host}"})
    return service


async def _authenticate(request: Request, service: ServiceEntry = Depends(_get_service)) -> dict[str, Any]:
    """FastAPI dependency: validate Bearer token and return claims.

    Uses the service's public_base as the resource for audience validation.
    """
    protector: AsyncResourceProtector = request.app.state.require_oauth
    token = await protector.validate_request(request, resource=service.public_base)
    return token


def _build_upstream_headers(request: Request, token: dict[str, Any]) -> dict[str, str]:
    """Build headers to send to the upstream MCP backend."""
    headers = {}

    # Forward allowed client headers
    for name in FORWARD_HEADERS:
        value = request.headers.get(name)
        if value:
            headers[name] = value

    # Inject user identity from token claims
    headers["x-user-id"] = str(token.get("sub", ""))
    headers["x-user-name"] = str(token.get("username", ""))
    # Pass the original bearer token for backends that need it
    auth_header = request.headers.get("authorization", "")
    if auth_header:
        headers["x-auth-token"] = auth_header.removeprefix("Bearer ").strip()

    return headers


def _build_response_headers(upstream_headers: httpx.Headers) -> dict[str, str]:
    """Filter upstream response headers, stripping CORS (handled by gateway)."""
    result = {}
    for name, value in upstream_headers.items():
        if name.lower() not in STRIP_RESPONSE_HEADERS:
            # Skip hop-by-hop headers
            if name.lower() in ("transfer-encoding", "connection", "keep-alive"):
                continue
            result[name] = value
    return result


def _get_http_client(request: Request) -> httpx.AsyncClient:
    """FastAPI dependency: get the long-lived httpx client from app state."""
    return request.app.state.http_client


def create_proxy_router() -> APIRouter:
    """Create the proxy router with all MCP proxy routes."""
    router = APIRouter()

    @router.api_route("/mcp", methods=["POST", "GET", "DELETE"])
    async def proxy_mcp(
        request: Request,
        service: ServiceEntry = Depends(_get_service),
        token: dict[str, Any] = Depends(_authenticate),
        client: httpx.AsyncClient = Depends(_get_http_client),
    ):
        """Proxy MCP requests to the backend service with streaming support.

        POST /mcp — JSON-RPC requests (response may be JSON or SSE)
        GET /mcp — SSE notification stream (long-lived)
        DELETE /mcp — Session termination
        """
        backend_url = f"{service.backend_url}/mcp"
        headers = _build_upstream_headers(request, token)

        logger.info(
            "PROXY %s /mcp → %s (user=%s, service=%s)",
            request.method, backend_url, token.get("username", "?"), service.name,
        )

        try:
            upstream_req = client.build_request(
                request.method,
                backend_url,
                headers=headers,
                content=request.stream() if request.method == "POST" else None,
            )
            upstream_resp = await client.send(upstream_req, stream=True)
        except httpx.ConnectError:
            logger.error("Backend unreachable: %s", backend_url)
            raise HTTPException(status_code=502, detail={"error": "backend_unreachable", "error_description": f"MCP backend {service.name} is unreachable"})
        except httpx.TimeoutException:
            logger.error("Backend timeout: %s", backend_url)
            raise HTTPException(status_code=504, detail={"error": "backend_timeout", "error_description": f"MCP backend {service.name} timed out"})

        resp_headers = _build_response_headers(upstream_resp.headers)
        content_type = upstream_resp.headers.get("content-type", "application/json")

        return StreamingResponse(
            upstream_resp.aiter_raw(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=content_type.split(";")[0].strip(),
            background=BackgroundTask(upstream_resp.aclose),
        )

    @router.get("/health")
    async def proxy_health(
        request: Request,
        service: ServiceEntry = Depends(_get_service),
        client: httpx.AsyncClient = Depends(_get_http_client),
    ):
        """Proxy health checks to backend (no auth required)."""
        backend_url = f"{service.backend_url}/health"

        try:
            resp = await client.get(backend_url, timeout=10.0)
            return JSONResponse(
                status_code=resp.status_code,
                content=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"status": "ok"},
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            return JSONResponse(
                status_code=502,
                content={"error": "backend_unreachable", "error_description": f"MCP backend {service.name} is unreachable"},
            )

    @router.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource(
        request: Request,
        service: ServiceEntry = Depends(_get_service),
    ):
        """Dynamic RFC 9728 Protected Resource Metadata.

        Returns the authorization server metadata for the requested service.
        Previously this was a static JSON block per nginx config file.
        """
        # Get auth server URL from app settings
        settings = request.app.state.settings
        auth_server = f"https://{settings.auth_subdomain}.{settings.base_domain}"

        return JSONResponse(
            content={
                "resource": service.public_base,
                "authorization_servers": [auth_server],
                "scopes_supported": ["mcp:read", "mcp:write"],
                "bearer_methods_supported": ["header"],
            },
            headers={"Cache-Control": "public, max-age=3600"},
        )

    return router