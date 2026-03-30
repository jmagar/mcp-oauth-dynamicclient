"""Pydantic models for OAuth 2.1, RFC 7591, and Client ID Metadata Document compliance"""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


# OAuth Client Registration Model (RFC 7591 + draft-ietf-oauth-client-id-metadata-document-00)
class ClientRegistration(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # RFC 7591 fields
    client_id: Optional[str] = None  # HTTPS URL for Client ID Metadata Documents
    redirect_uris: Optional[list[str]] = None
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: Optional[str] = None
    contacts: Optional[list[str]] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    jwks_uri: Optional[str] = None
    jwks: Optional[dict[str, Any]] = None
    software_id: Optional[str] = None
    software_version: Optional[str] = None
    grant_types: Optional[list[str]] = None
    response_types: Optional[list[str]] = None
    token_endpoint_auth_method: Optional[str] = None  # "none" for public clients


# Token Response Model
class TokenResponse(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


# Error Response Model (RFC 6749)
class ErrorResponse(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
