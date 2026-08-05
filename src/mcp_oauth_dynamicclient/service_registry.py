"""Service registry for MCP backend routing."""

import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServiceEntry:
    """A registered MCP backend service."""
    name: str           # e.g. "fetch"
    public_url: str     # e.g. "https://fetch.yourdomain.com/mcp" (from MCP_*_URLS)
    public_host: str    # e.g. "fetch.yourdomain.com" (extracted from public_url)
    public_base: str    # e.g. "https://fetch.yourdomain.com" (no /mcp path)
    backend_url: str    # e.g. "http://198.51.100.1:3000" (from MCP_*_BACKEND)
    path_prefix: str = ''  # e.g. "/swag" for path-based routing, '' for host-based


class ServiceRegistry:
    """Routes incoming requests to MCP backend services based on Host header or path prefix."""

    def __init__(self) -> None:
        self._services: dict[str, ServiceEntry] = {}  # keyed by public_host or host|/prefix
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Scan os.environ for MCP_*_ENABLED services and build routing table."""
        enabled_pattern = re.compile(r'^MCP_(\w+)_ENABLED$')
        registered_count = 0

        for env_key, env_value in os.environ.items():
            match = enabled_pattern.match(env_key)
            if not match:
                continue

            service_name_upper = match.group(1)
            service_name = service_name_upper.lower()

            # Check if service is enabled (case-insensitive)
            if env_value.lower() != 'true':
                continue

            # Look for corresponding URLs and BACKEND vars
            urls_key = f"MCP_{service_name_upper}_URLS"
            backend_key = f"MCP_{service_name_upper}_BACKEND"

            public_url = os.environ.get(urls_key)
            backend_url = os.environ.get(backend_key)

            if not public_url:
                logger.warning(f"Service {service_name} enabled but missing {urls_key}")
                continue

            if not backend_url:
                logger.warning(f"Service {service_name} enabled but missing {backend_key}")
                continue

            # Parse the public URL to extract hostname and base
            try:
                parsed = urlparse(public_url)
                public_host = parsed.hostname
                if not public_host:
                    logger.warning(f"Service {service_name} has invalid public URL: {public_url}")
                    continue

                public_base = f"{parsed.scheme}://{parsed.netloc}"

                # Extract path prefix: any first path segment that is not 'mcp' is a prefix.
                # '/synapse'     -> '/synapse' (path-based, bare endpoint)
                # '/synapse/mcp' -> '/synapse' (path-based, legacy /mcp suffix)
                # '/mcp'         -> ''         (host-based, service owns the whole host)
                # '/' or ''      -> ''         (host-based)
                path_segments = [s for s in parsed.path.split('/') if s]
                path_prefix = f'/{path_segments[0]}' if path_segments and path_segments[0] != 'mcp' else ''

                service_entry = ServiceEntry(
                    name=service_name,
                    public_url=public_url,
                    public_host=public_host,
                    public_base=public_base,
                    backend_url=backend_url,
                    path_prefix=path_prefix,
                )

                if path_prefix:
                    registry_key = f'{public_host}|{path_prefix}'
                else:
                    registry_key = public_host

                self._services[registry_key] = service_entry
                registered_count += 1

            except Exception as e:
                logger.warning(f"Failed to parse public URL for service {service_name}: {e}")
                continue

        logger.info(f"Service registry loaded {registered_count} services: {list(self._services.keys())}")

    def resolve(self, host: str, path: str = '') -> ServiceEntry | None:
        """Look up a backend service by Host header value and optional request path.

        Strips port from host if present (e.g. "fetch.example.com:443" -> "fetch.example.com").
        If path is provided, tries compound key "host|/prefix" first (path-based routing),
        then falls back to plain host key (host-based routing).
        """
        # Strip port if present
        if ':' in host:
            host = host.split(':')[0]

        # Try path-based routing first when path is provided
        if path:
            parts = path.split('/')
            # parts[0] is empty string before leading slash; parts[1] is first segment
            if len(parts) > 1 and parts[1]:
                compound_key = f'{host}|/{parts[1]}'
                service = self._services.get(compound_key)
                if service is not None:
                    return service

        # Fall back to host-based routing
        return self._services.get(host)

    def all_services(self) -> list[ServiceEntry]:
        """Return all registered services."""
        return list(self._services.values())

    def __len__(self) -> int:
        return len(self._services)
