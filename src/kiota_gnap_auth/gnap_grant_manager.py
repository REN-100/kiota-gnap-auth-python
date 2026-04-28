"""
GNAP Grant Manager - RFC 9635 Grant Lifecycle (Python)

Handles the full GNAP grant lifecycle:
- Grant requests (Section 2)
- Grant responses (Section 3)
- Continuation (Section 5)
- Token management (Section 6)
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Optional

import httpx

from .types import (
    AccessRight,
    ClientKeyConfig,
    ContinuationInfo,
    GrantResponse,
    InteractionConfig,
    InteractionResponse,
    TokenAccess,
)


class GnapGrantManager:
    """
    Manages GNAP grant requests and responses per RFC 9635.

    Handles the complete lifecycle:
    1. Client sends grant request to the AS
    2. AS responds with tokens, interaction, or continuation
    3. Client handles interaction and continues the grant
    4. Client manages token rotation and revocation
    """

    def __init__(
        self,
        grant_endpoint: str,
        client_key: ClientKeyConfig,
    ) -> None:
        self._grant_endpoint = grant_endpoint
        self._client_key = client_key
        self._http_client = httpx.AsyncClient()

    async def request_grant(
        self,
        access_rights: list[AccessRight],
        interaction: Optional[InteractionConfig] = None,
    ) -> GrantResponse:
        """
        Request a new grant from the authorization server.

        Per RFC 9635 Section 2, the grant request includes:
        - access_token: requested access rights
        - client: client key information
        - interact: interaction preferences (optional)
        """
        grant_request: dict[str, Any] = {
            "access_token": {
                "access": [
                    {
                        "type": right.type,
                        "actions": right.actions,
                        **({"locations": right.locations} if right.locations else {}),
                    }
                    for right in access_rights
                ]
            },
            "client": {
                "key": {
                    "proof": self._client_key.proof.value,
                    "jwk": self._export_public_jwk(),
                }
            },
        }

        # Add interaction if configured
        if interaction is not None:
            interact_obj: dict[str, Any] = {
                "start": interaction.start,
            }
            if interaction.finish is not None:
                interact_obj["finish"] = {
                    "method": interaction.finish.method,
                    "uri": interaction.finish.uri,
                    "nonce": interaction.finish.nonce or secrets.token_urlsafe(32),
                }
            grant_request["interact"] = interact_obj

        response = await self._make_signed_request(
            url=self._grant_endpoint,
            method="POST",
            body=grant_request,
        )

        return self._parse_grant_response(response)

    async def continue_grant(
        self,
        continue_uri: str,
        continue_token: str,
        interact_ref: str,
    ) -> GrantResponse:
        """
        Continue a pending grant after resource owner interaction.

        Per RFC 9635 Section 5.1, uses the continuation access token
        from the initial grant response.
        """
        response = await self._make_signed_request(
            url=continue_uri,
            method="POST",
            body={"interact_ref": interact_ref},
            bearer_token=continue_token,
        )

        return self._parse_grant_response(response)

    async def rotate_token(
        self,
        management_uri: str,
        current_token: str,
    ) -> str:
        """
        Rotate an existing access token (RFC 9635 Section 6.1).
        """
        response = await self._make_signed_request(
            url=management_uri,
            method="POST",
            body={},
            bearer_token=current_token,
        )

        data = response.json()
        return data["access_token"]["value"]

    async def revoke_token(
        self,
        management_uri: str,
        current_token: str,
    ) -> None:
        """
        Revoke an access token (RFC 9635 Section 6.2).
        """
        await self._make_signed_request(
            url=management_uri,
            method="DELETE",
            bearer_token=current_token,
        )

    async def _make_signed_request(
        self,
        url: str,
        method: str,
        body: Optional[dict[str, Any]] = None,
        bearer_token: Optional[str] = None,
    ) -> httpx.Response:
        """Make an HTTP request signed with HTTP Message Signatures."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }

        if bearer_token:
            headers["Authorization"] = f"GNAP {bearer_token}"

        body_bytes = json.dumps(body).encode() if body else None

        # TODO: Add HTTP Message Signature headers (RFC 9421)
        # This will use the http_signature_signer module

        response = await self._http_client.request(
            method=method,
            url=url,
            headers=headers,
            content=body_bytes,
        )

        response.raise_for_status()
        return response

    def _export_public_jwk(self) -> dict[str, str]:
        """Export the client's public key as a JWK."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self._client_key.key_id,
        }

    def _parse_grant_response(self, response: httpx.Response) -> GrantResponse:
        """Parse a GNAP grant response."""
        data = response.json()

        access_token = None
        if "access_token" in data:
            at = data["access_token"]
            access_token = TokenAccess(
                value=at["value"],
                manage_uri=at.get("manage", {}).get("uri"),
                access=[
                    AccessRight(type=a["type"], actions=a.get("actions", []))
                    for a in at.get("access", [])
                ],
                expires_in=at.get("expires_in"),
            )

        interact = None
        if "interact" in data:
            i = data["interact"]
            interact = InteractionResponse(
                redirect=i.get("redirect"),
                user_code=i.get("user_code", {}).get("code") if "user_code" in i else None,
            )

        continuation = None
        if "continue" in data:
            c = data["continue"]
            continuation = ContinuationInfo(
                uri=c["uri"],
                access_token=c["access_token"]["value"],
                wait=c.get("wait"),
            )

        return GrantResponse(
            access_token=access_token,
            interact=interact,
            continuation=continuation,
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http_client.aclose()
