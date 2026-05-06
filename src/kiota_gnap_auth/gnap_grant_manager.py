"""
GNAP Grant Manager — RFC 9635 Grant Lifecycle (Python)

Handles the full GNAP grant lifecycle for the ShujaaPay Open Payments
ecosystem:

- Grant requests (§2) with Open Payments identifier/limits support
- Grant responses (§3) with structured error handling
- Continuation (§5) with wait interval support
- Token management (§6) — rotation and revocation
- Grant deletion (§5.4)
- Content-Digest header (RFC 9530) for body integrity
- HTTP Message Signatures with tag="gnap" (RFC 9421/9635)

@see https://www.rfc-editor.org/rfc/rfc9635
@see https://www.shujaapay.me
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any, Optional

import httpx

from .errors import GnapError, parse_gnap_error_response
from .http_signature_signer import compute_content_digest, export_public_jwk
from .retry import DEFAULT_RETRY_POLICY, RetryPolicy, with_retry
from .types import (
    AccessRight,
    ClientDisplay,
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

    Example::

        manager = GnapGrantManager(
            grant_endpoint="https://auth.wallet.example/",
            client_key=ClientKeyConfig(
                key_id="my-key",
                private_key=my_private_key,
            ),
            wallet_address="https://wallet.example/alice",
            client_display=ClientDisplay(name="ShujaaPay"),
        )

        grant = await manager.request_grant(access_rights)
    """

    def __init__(
        self,
        grant_endpoint: str,
        client_key: ClientKeyConfig,
        wallet_address: Optional[str] = None,
        client_display: Optional[ClientDisplay] = None,
        retry_policy: Optional[RetryPolicy] = None,
    ) -> None:
        self._grant_endpoint = grant_endpoint
        self._client_key = client_key
        self._wallet_address = wallet_address
        self._client_display = client_display
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=0, retryable_statuses=[]
        )
        self._http_client = httpx.AsyncClient()

    async def request_grant(
        self,
        access_rights: list[AccessRight],
        interaction: Optional[InteractionConfig] = None,
        flags: Optional[list[str]] = None,
    ) -> GrantResponse:
        """
        Request a new grant from the authorization server.

        Per RFC 9635 §2, the grant request includes:
        - access_token: requested access rights (with OP identifier/limits)
        - client: client key information (with wallet_address/display)
        - interact: interaction preferences (optional)

        Args:
            access_rights: Resources and actions to request
            interaction: Interaction configuration (optional)
            flags: Token flags (bearer, durable)

        Returns:
            Grant response with tokens and/or continuation info

        Raises:
            GnapError: On structured AS error responses
        """
        # Build access rights with Open Payments extensions
        access_list = []
        for right in access_rights:
            entry: dict[str, Any] = {
                "type": right.type,
                "actions": right.actions,
            }
            if right.identifier:
                entry["identifier"] = right.identifier
            if right.locations:
                entry["locations"] = right.locations
            if right.datatypes:
                entry["datatypes"] = right.datatypes
            if right.limits:
                entry["limits"] = right.limits.to_dict()
            access_list.append(entry)

        grant_request: dict[str, Any] = {
            "access_token": {
                "access": access_list,
            },
            "client": {
                "key": {
                    "proof": self._client_key.proof.value,
                    "jwk": export_public_jwk(self._client_key),
                },
            },
        }

        # Add flags
        if flags:
            grant_request["access_token"]["flags"] = flags

        # Add wallet address and display
        if self._wallet_address:
            grant_request["client"]["wallet_address"] = self._wallet_address
        if self._client_display:
            display: dict[str, str] = {}
            if self._client_display.name:
                display["name"] = self._client_display.name
            if self._client_display.uri:
                display["uri"] = self._client_display.uri
            if self._client_display.logo_uri:
                display["logo_uri"] = self._client_display.logo_uri
            if display:
                grant_request["client"]["display"] = display

        # Add interaction
        if interaction is not None:
            interact_obj: dict[str, Any] = {
                "start": interaction.start,
            }
            if interaction.finish is not None:
                finish_obj: dict[str, Any] = {
                    "method": interaction.finish.method,
                    "uri": interaction.finish.uri,
                    "nonce": interaction.finish.nonce or secrets.token_urlsafe(32),
                }
                if interaction.finish.hash_method:
                    finish_obj["hash_method"] = interaction.finish.hash_method
                interact_obj["finish"] = finish_obj
            grant_request["interact"] = interact_obj

        response = await self._make_signed_request(
            url=self._grant_endpoint,
            method="POST",
            body=grant_request,
        )

        if not _is_ok(response):
            raise await parse_gnap_error_response(response)

        return self._parse_grant_response(response)

    async def continue_grant(
        self,
        continue_uri: str,
        continue_token: str,
        interact_ref: str,
    ) -> GrantResponse:
        """
        Continue a pending grant after resource owner interaction.

        Per RFC 9635 §5.1, uses the continuation access token
        from the initial grant response.

        Args:
            continue_uri: Continuation URI from grant response
            continue_token: Continuation access token
            interact_ref: Interaction reference from the callback

        Returns:
            Updated grant response

        Raises:
            GnapError: On structured AS error responses
        """
        response = await self._make_signed_request(
            url=continue_uri,
            method="POST",
            body={"interact_ref": interact_ref},
            bearer_token=continue_token,
        )

        if not _is_ok(response):
            raise await parse_gnap_error_response(response)

        return self._parse_grant_response(response)

    async def rotate_token(
        self,
        management_uri: str,
        current_token: str,
    ) -> str:
        """
        Rotate an existing access token (RFC 9635 §6.1).

        Presents the current access token to the management URI
        to receive a new one.

        Args:
            management_uri: Token management URI
            current_token: Current access token value

        Returns:
            New access token value

        Raises:
            GnapError: On rotation failure
        """
        response = await self._make_signed_request(
            url=management_uri,
            method="POST",
            body={},
            bearer_token=current_token,
        )

        if not _is_ok(response):
            raise await parse_gnap_error_response(response)

        data = response.json()
        return data["access_token"]["value"]

    async def revoke_token(
        self,
        management_uri: str,
        current_token: str,
    ) -> None:
        """
        Revoke an access token (RFC 9635 §6.2).

        Sends DELETE to the management URI.
        """
        await self._make_signed_request(
            url=management_uri,
            method="DELETE",
            bearer_token=current_token,
        )

    async def delete_grant(
        self,
        continue_uri: str,
        continue_token: str,
    ) -> None:
        """
        Delete/cancel a pending grant (RFC 9635 §5.4).

        Sends DELETE to the continuation URI.

        Raises:
            GnapError: On deletion failure
        """
        response = await self._make_signed_request(
            url=continue_uri,
            method="DELETE",
            bearer_token=continue_token,
        )

        if not _is_ok(response):
            raise await parse_gnap_error_response(response)

    async def _make_signed_request(
        self,
        url: str,
        method: str,
        body: Optional[dict[str, Any]] = None,
        bearer_token: Optional[str] = None,
    ) -> httpx.Response:
        """
        Make an HTTP request with HTTP Message Signatures and Content-Digest.

        Includes retry logic for transient failures.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }

        if bearer_token:
            headers["Authorization"] = f"GNAP {bearer_token}"

        body_bytes = json.dumps(body).encode() if body else None

        # Add Content-Digest for POST requests with body (RFC 9530)
        if body_bytes and method in ("POST", "PUT", "PATCH"):
            headers["Content-Digest"] = compute_content_digest(body_bytes)

        # Add HTTP Message Signature headers
        import time
        import base64 as b64

        created = int(time.time())
        covered = ['"@method"', '"@target-uri"']
        if bearer_token:
            covered.append('"authorization"')
        if body_bytes and method in ("POST", "PUT", "PATCH"):
            covered.append('"content-type"')
            covered.append('"content-digest"')

        component_list = " ".join(covered)
        sig_input = (
            f'sig1=({component_list});'
            f'created={created};keyid="{self._client_key.key_id}";tag="gnap"'
        )

        # Build signature base
        sig_lines: list[str] = []
        for comp in covered:
            cn = comp.strip('"')
            if cn == "@method":
                sig_lines.append(f'"@method": {method}')
            elif cn == "@target-uri":
                sig_lines.append(f'"@target-uri": {url}')
            elif cn == "authorization":
                sig_lines.append(f'"authorization": GNAP {bearer_token}')
            elif cn == "content-type":
                sig_lines.append('"content-type": application/json')
            elif cn == "content-digest":
                sig_lines.append(
                    f'"content-digest": {headers.get("Content-Digest", "")}'
                )

        sig_params = sig_input.split("=", 1)[1]
        sig_lines.append(f'"@signature-params": {sig_params}')
        sig_base = "\n".join(sig_lines)

        from .http_signature_signer import _sign_bytes

        sig_bytes = _sign_bytes(sig_base.encode("utf-8"), self._client_key)
        sig_b64 = b64.b64encode(sig_bytes).decode("ascii")

        headers["Signature-Input"] = sig_input
        headers["Signature"] = f"sig1=:{sig_b64}:"

        async def _do_request() -> httpx.Response:
            return await self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=body_bytes,
            )

        if self._retry_policy.max_attempts > 0:
            return await with_retry(
                _do_request,
                policy=self._retry_policy,
                should_retry=lambda r: r.status_code in self._retry_policy.retryable_statuses,
            )

        return await _do_request()

    def _parse_grant_response(self, response: httpx.Response) -> GrantResponse:
        """Parse a GNAP grant response into typed dataclasses."""
        data = response.json()

        access_token = None
        if "access_token" in data:
            at = data["access_token"]
            # manage is a string in Open Payments spec
            manage = at.get("manage")
            if isinstance(manage, dict):
                manage = manage.get("uri")  # backwards compat

            access_token = TokenAccess(
                value=at["value"],
                manage=manage,
                access=[
                    AccessRight(
                        type=a["type"],
                        actions=a.get("actions", []),
                        identifier=a.get("identifier"),
                    )
                    for a in at.get("access", [])
                ],
                expires_in=at.get("expires_in"),
                flags=at.get("flags", []),
            )

        interact = None
        if "interact" in data:
            i = data["interact"]
            user_code = None
            user_code_uri = None
            if "user_code" in i:
                uc = i["user_code"]
                if isinstance(uc, dict):
                    user_code = uc.get("code")
                    user_code_uri = uc.get("url")
                else:
                    user_code = str(uc)

            interact = InteractionResponse(
                redirect=i.get("redirect"),
                user_code=user_code,
                user_code_uri=user_code_uri,
                finish=i.get("finish"),
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


def _is_ok(response: httpx.Response) -> bool:
    """Check if an HTTP response is successful."""
    return 200 <= response.status_code < 300
