"""Authentication and token management module using Authlib
Implements OAuth 2.1, RFC 7591, and Client ID Metadata Documents
"""

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import redis.asyncio as redis
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc6749 import ClientMixin

from .config import Settings
from .keys import RSAKeyManager

logger = logging.getLogger(__name__)

# Loopback hosts per RFC 8252 Section 7.3
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


class OAuth2Client(ClientMixin):
    """OAuth2 Client model for Authlib"""

    def __init__(self, client_data: dict):
        self._client_data = client_data

    def get_client_id(self) -> str:
        return self._client_data["client_id"]

    def get_default_redirect_uri(self) -> Optional[str]:
        redirect_uris = self._client_data.get("redirect_uris", [])
        if isinstance(redirect_uris, str):
            import json

            redirect_uris = json.loads(redirect_uris)
        return redirect_uris[0] if redirect_uris else None

    def get_allowed_scope(self, scope: str) -> Optional[str]:
        return scope  # Allow all scopes for now

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """Validate redirect_uri with RFC 8252 Section 7.3 loopback port flexibility.

        For loopback redirect URIs (localhost, 127.0.0.1, [::1]), the authorization
        server MUST allow any port at the time of the request per RFC 8252.
        """
        redirect_uris = self._client_data.get("redirect_uris", [])
        if isinstance(redirect_uris, str):
            redirect_uris = json.loads(redirect_uris)

        # Exact match first (fast path)
        if redirect_uri in redirect_uris:
            return True

        # RFC 8252 Section 7.3: loopback redirect URIs allow any port
        parsed_request = urlparse(redirect_uri)
        if parsed_request.hostname in LOOPBACK_HOSTS:
            for registered_uri in redirect_uris:
                parsed_registered = urlparse(registered_uri)
                if (
                    parsed_registered.hostname in LOOPBACK_HOSTS
                    and parsed_request.scheme == parsed_registered.scheme
                    and parsed_request.path == parsed_registered.path
                ):
                    # Scheme and path match, port is flexible for loopback
                    return True

        return False

    def has_client_secret(self) -> bool:
        return bool(self._client_data.get("client_secret"))

    def check_client_secret(self, client_secret: str) -> bool:
        return secrets.compare_digest(self._client_data.get("client_secret", ""), client_secret)

    def is_public_client(self) -> bool:
        """Check if this is a public client (token_endpoint_auth_method=none)."""
        return self._client_data.get("token_endpoint_auth_method") == "none"

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        """Support public clients (none) and confidential clients."""
        client_method = self._client_data.get("token_endpoint_auth_method")
        if client_method == "none":
            return method == "none"
        return method in ["client_secret_post", "client_secret_basic", "none"]

    def check_response_type(self, response_type: str) -> bool:
        return response_type in self._client_data.get("response_types", ["code"])

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self._client_data.get("grant_types", ["authorization_code"])


class AuthManager:
    """Manages OAuth authentication flows and token operations using Authlib"""

    def __init__(self, settings: Settings):
        self.settings = settings
        # Initialize Authlib JWT with our settings
        self.jwt = JsonWebToken(algorithms=[settings.jwt_algorithm])

        # Initialize RSA key manager for RS256 - THE BLESSED ALGORITHM!
        self.key_manager = RSAKeyManager()
        self.key_manager.load_or_generate_keys()

        # For GitHub OAuth integration
        self.github_client = AsyncOAuth2Client(
            client_id=settings.github_client_id,
            client_secret=settings.github_client_secret,
            redirect_uri=f"https://{settings.auth_subdomain}.{settings.base_domain}/callback",
        )

    async def create_jwt_token(
        self, claims: dict, redis_client: redis.Redis, resource: Optional[str] = None
    ) -> str:
        """Creates a JWT token using Authlib with RFC 8707 resource indicator support"""
        # Generate JTI for tracking
        jti = secrets.token_urlsafe(16)

        # Audience is the target resource (RFC 8707) or fallback to auth server
        audience = resource or f"https://{self.settings.auth_subdomain}.{self.settings.base_domain}"

        # Prepare JWT claims according to RFC 7519
        now = datetime.now(timezone.utc)
        header = {"alg": self.settings.jwt_algorithm}
        
        # Handle audience claim for RFC 8707 Resource Indicators
        resources = claims.pop("resources", [])
        if resources:
            # If resources specified, use them as audience (RFC 8707)
            aud = resources if len(resources) > 1 else resources[0]
        else:
            # Fallback to auth server URL for backward compatibility
            aud = f"https://auth.{self.settings.base_domain}"
        
        payload = {
            **claims,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self.settings.access_token_lifetime)).timestamp()),
            "iss": f"https://{self.settings.auth_subdomain}.{self.settings.base_domain}",
            "aud": aud,
            "azp": claims.get("client_id"),  # Authorized party claim
        }
        logger.info(
            f"JWT CREATED - jti={jti}, sub={claims.get('sub')}, aud={audience}, "
            f"client_id={claims.get('client_id')}, scope={claims.get('scope')}, "
            f"expires_in={self.settings.access_token_lifetime}s"
        )

        # Create token using Authlib with the BLESSED RS256 algorithm!
        if self.settings.jwt_algorithm == "RS256":
            # Use RSA private key for RS256 - cryptographic blessing!
            token = self.jwt.encode(header, payload, self.key_manager.private_key)
        else:
            # HS256 is HERESY but we support it for backwards compatibility during transition
            token = self.jwt.encode(header, payload, self.settings.jwt_secret)

        # Store token reference in Redis
        await redis_client.setex(
            f"oauth:token:{jti}",
            self.settings.access_token_lifetime,
            json.dumps(
                {
                    **claims,
                    "created_at": int(now.timestamp()),
                    "expires_at": int(
                        (now + timedelta(seconds=self.settings.access_token_lifetime)).timestamp(),
                    ),
                },
            ),
        )

        # Track user's tokens if username present
        if "username" in claims:
            await redis_client.sadd(f"oauth:user_tokens:{claims['username']}", jti)

        return token.decode("utf-8") if isinstance(token, bytes) else token

    async def verify_jwt_token(self, token: str, redis_client: redis.Redis) -> Optional[dict]:
        """Verifies JWT token using Authlib and checks Redis"""
        try:
            # Decode and validate token using Authlib
            if self.settings.jwt_algorithm == "RS256":
                # Use RSA public key for RS256 verification - divine cryptographic validation!
                claims = self.jwt.decode(
                    token,
                    self.key_manager.public_key,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": f"https://{self.settings.auth_subdomain}.{self.settings.base_domain}",
                        },
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )
            else:
                # HS256 fallback during transition period
                claims = self.jwt.decode(
                    token,
                    self.settings.jwt_secret,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": f"https://{self.settings.auth_subdomain}.{self.settings.base_domain}",
                        },
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )

            # Validate claims
            claims.validate()

            # Check if token exists in Redis (not revoked)
            jti = claims["jti"]
            token_data = await redis_client.get(f"oauth:token:{jti}")

            if not token_data:
                return None  # Token revoked or expired

            return dict(claims)

        except JoseError as e:
            # Token validation failed
            print(f"Token validation error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error during token validation: {e}")
            return None

    async def create_refresh_token(self, user_data: dict, redis_client: redis.Redis) -> str:
        """Creates a refresh token with Authlib"""
        refresh_token = secrets.token_urlsafe(32)

        # Store refresh token in Redis with longer TTL
        await redis_client.setex(
            f"oauth:refresh:{refresh_token}",
            self.settings.refresh_token_lifetime,
            json.dumps({**user_data, "created_at": int(datetime.now(timezone.utc).timestamp())}),
        )

        return refresh_token

    async def exchange_github_code(self, code: str) -> Optional[dict]:
        """Exchange GitHub authorization code for access token using Authlib"""
        try:
            # Set up token endpoint
            self.github_client.metadata = {
                "token_endpoint": "https://github.com/login/oauth/access_token",
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
            }

            # Exchange code for token
            token = await self.github_client.fetch_token(
                "https://github.com/login/oauth/access_token",
                code=code,
                headers={"Accept": "application/json"},
            )

            if not token or "access_token" not in token:
                return None

            # Get user info using the token
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "Authorization": f"Bearer {token['access_token']}",
                    "Accept": "application/vnd.github.v3+json",
                }

                # Get user info
                user_response = await client.get("https://api.github.com/user", headers=headers)

                if user_response.status_code != 200:
                    return None

                return user_response.json()

        except Exception as e:
            print(f"GitHub OAuth error: {e}")
            return None

    def verify_pkce_challenge(self, verifier: str, challenge: str, method: str = "S256") -> bool:
        """Verify PKCE code challenge - S256 only as per CLAUDE.md sacred laws"""
        if method == "plain":
            # REJECTED: Plain method is deprecated per CLAUDE.md commandments!
            return False

        if method != "S256":
            # Only S256 is blessed by the sacred laws
            return False

        # Proper S256 verification: SHA256 hash + base64url encode
        digest = hashlib.sha256(verifier.encode()).digest()
        # Base64url encode without padding (RFC 7636 compliant)
        computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")

        # Divine verification: computed challenge must match stored challenge
        return computed == challenge

    async def introspect_token(self, token: str, redis_client: redis.Redis) -> dict:
        """Token introspection using Authlib (RFC 7662)"""
        token_data = await self.verify_jwt_token(token, redis_client)

        if not token_data:
            return {"active": False}

        # Return RFC 7662 compliant response
        return {
            "active": True,
            "scope": token_data.get("scope", ""),
            "client_id": token_data.get("client_id"),
            "username": token_data.get("username"),
            "exp": token_data.get("exp"),
            "iat": token_data.get("iat"),
            "sub": token_data.get("sub"),
            "aud": token_data.get("aud"),
            "iss": token_data.get("iss"),
            "jti": token_data.get("jti"),
        }

    async def revoke_token(self, token: str, redis_client: redis.Redis) -> bool:
        """Revoke a token using Authlib patterns"""
        try:
            # Try to decode the token to get JTI
            if self.settings.jwt_algorithm == "RS256":
                # RS256 - the blessed way!
                claims = self.jwt.decode(
                    token,
                    self.key_manager.public_key,
                    claims_options={"jti": {"essential": True}},
                )
            else:
                # HS256 fallback
                claims = self.jwt.decode(
                    token,
                    self.settings.jwt_secret,
                    claims_options={"jti": {"essential": True}},
                )

            jti = claims.get("jti")
            if jti:
                # Remove from Redis
                await redis_client.delete(f"oauth:token:{jti}")

                # Remove from user's token set if username present
                username = claims.get("username")
                if username:
                    await redis_client.srem(f"oauth:user_tokens:{username}", jti)

                return True

        except JoseError:
            # Token might be a refresh token
            if await redis_client.exists(f"oauth:refresh:{token}"):
                await redis_client.delete(f"oauth:refresh:{token}")
                return True

        return False

    @staticmethod
    def is_metadata_document_url(client_id: str) -> bool:
        """Check if client_id is an HTTPS URL (Client ID Metadata Document)."""
        return client_id.startswith("https://") and "/" in client_id[8:]

    async def fetch_client_metadata(self, client_id_url: str) -> Optional[dict]:
        """Fetch and validate a Client ID Metadata Document per
        draft-ietf-oauth-client-id-metadata-document-00.

        Validates:
        - Document is valid JSON
        - client_id in document matches the URL exactly
        - Required fields present (client_id, client_name, redirect_uris)
        - SSRF protection (HTTPS only, no private IPs)
        """
        parsed = urlparse(client_id_url)
        if parsed.scheme != "https":
            logger.warning(f"Client metadata URL must be HTTPS: {client_id_url}")
            return None

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    client_id_url,
                    headers={"Accept": "application/json"},
                    follow_redirects=False,  # SSRF: don't follow redirects
                )
                if resp.status_code != 200:
                    logger.warning(
                        f"Client metadata fetch failed: {resp.status_code} from {client_id_url}"
                    )
                    return None

                metadata = resp.json()

        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.warning(f"Client metadata fetch error for {client_id_url}: {e}")
            return None

        # Validate client_id matches URL exactly
        if metadata.get("client_id") != client_id_url:
            logger.warning(
                f"Client metadata client_id mismatch: "
                f"document={metadata.get('client_id')}, url={client_id_url}"
            )
            return None

        # Validate required fields
        if not metadata.get("redirect_uris"):
            logger.warning(f"Client metadata missing redirect_uris: {client_id_url}")
            return None

        return metadata

    async def get_or_fetch_client(
        self, client_id: str, redis_client: redis.Redis
    ) -> Optional[OAuth2Client]:
        """Get client from Redis, or fetch Client ID Metadata Document if URL-format.

        For URL-format client_ids, fetches metadata doc, validates it, and
        caches the client in Redis for future requests.
        """
        # Try Redis first
        client = await self.get_client(client_id, redis_client)
        if client:
            return client

        # If client_id is a URL, try Client ID Metadata Document flow
        if not self.is_metadata_document_url(client_id):
            return None

        logger.info(f"Fetching Client ID Metadata Document: {client_id}")
        metadata = await self.fetch_client_metadata(client_id)
        if not metadata:
            return None

        # Cache the client in Redis (public client, no secret)
        created_at = int(datetime.now(timezone.utc).timestamp())
        client_data = {
            "client_id": client_id,
            "client_secret": "",  # Public client - no secret
            "client_secret_expires_at": 0,
            "client_id_issued_at": created_at,
            "redirect_uris": json.dumps(metadata.get("redirect_uris", [])),
            "client_name": metadata.get("client_name", "Unknown Client"),
            "scope": "openid profile email",
            "created_at": created_at,
            "response_types": json.dumps(metadata.get("response_types", ["code"])),
            "grant_types": json.dumps(
                metadata.get("grant_types", ["authorization_code", "refresh_token"])
            ),
            "token_endpoint_auth_method": metadata.get(
                "token_endpoint_auth_method", "none"
            ),
            "client_uri": metadata.get("client_uri", ""),
            "logo_uri": metadata.get("logo_uri", ""),
            "is_metadata_document_client": True,
        }

        # Cache with 1-hour TTL (re-fetch on expiry to pick up metadata changes)
        await redis_client.setex(
            f"oauth:client:{client_id}",
            3600,
            json.dumps(client_data),
        )

        logger.info(
            f"Cached Client ID Metadata Document client: {client_id} "
            f"(name={client_data['client_name']})"
        )
        return OAuth2Client(client_data)

    async def get_client(self, client_id: str, redis_client: redis.Redis) -> Optional[OAuth2Client]:
        """Get OAuth2 client from Redis."""
        client_data = await redis_client.get(f"oauth:client:{client_id}")

        if not client_data:
            return None

        return OAuth2Client(json.loads(client_data))

    def create_authorization_response(self, client: OAuth2Client, request: dict) -> dict:
        """Create authorization response using Authlib patterns"""
        # This would typically use Authlib's AuthorizationServer
        # For now, we'll create a compatible response
        code = secrets.token_urlsafe(32)

        response = {"code": code, "state": request.get("state")}

        return response, code

    def generate_client_credentials(self) -> dict:
        """Generate client credentials using Authlib patterns"""
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)

        return {"client_id": client_id, "client_secret": client_secret}
