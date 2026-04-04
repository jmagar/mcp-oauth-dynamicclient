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
    backend_url: str    # e.g. "http://100.75.111.118:3000" (from MCP_*_BACKEND)


class ServiceRegistry:
    """Routes incoming requests to MCP backend services based on Host header."""

    def __init__(self) -> None:
        self._services: dict[str, ServiceEntry] = {}  # keyed by public_host
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

                service_entry = ServiceEntry(
                    name=service_name,
                    public_url=public_url,
                    public_host=public_host,
                    public_base=public_base,
                    backend_url=backend_url
                )

                self._services[public_host] = service_entry
                registered_count += 1

            except Exception as e:
                logger.warning(f"Failed to parse public URL for service {service_name}: {e}")
                continue

        logger.info(f"Service registry loaded {registered_count} services: {list(self._services.keys())}")

    def resolve(self, host: str) -> ServiceEntry | None:
        """Look up a backend service by Host header value.

        Strips port from host if present (e.g. "fetch.example.com:443" -> "fetch.example.com").
        """
        # Strip port if present
        if ':' in host:
            host = host.split(':')[0]

        return self._services.get(host)

    def all_services(self) -> list[ServiceEntry]:
        """Return all registered services."""
        return list(self._services.values())

    def __len__(self) -> int:
        return len(self._services)
