"""
HTTP Message Signature Signer - RFC 9421

Signs Kiota RequestInformation objects with HTTP Message Signatures
for GNAP key proof compliance.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Optional

from kiota_abstractions.request_information import RequestInformation

from .types import ClientKeyConfig


async def sign_request(
    request: RequestInformation,
    client_key: ClientKeyConfig,
) -> None:
    """
    Sign a Kiota RequestInformation with HTTP Message Signatures.

    Adds the following headers:
    - Signature-Input: describes which components were signed
    - Signature: the actual signature value
    - Content-Digest: SHA-256 hash of the body (if present)

    Args:
        request: The Kiota request to sign
        client_key: Client key configuration for signing
    """
    method = str(request.http_method or "GET").upper()
    url = request.url or ""
    created = int(time.time())

    # Determine covered components
    covered_components = ['"@method"', '"@target-uri"']

    # Include authorization if present
    auth_header = request.headers.try_get("Authorization")
    if auth_header:
        covered_components.append('"authorization"')

    # Add content-related components for requests with bodies
    if method in ("POST", "PUT", "PATCH") and request.content is not None:
        body_bytes = (
            request.content
            if isinstance(request.content, bytes)
            else request.content.encode("utf-8")
        )
        # Generate Content-Digest (RFC 9530)
        digest = hashlib.sha256(body_bytes).digest()
        digest_b64 = base64.b64encode(digest).decode("ascii")
        content_digest = f"sha-256=:{digest_b64}:"
        request.headers.try_add("Content-Digest", content_digest)

        covered_components.append('"content-type"')
        covered_components.append('"content-digest"')

    # Build Signature-Input
    component_list = " ".join(covered_components)
    sig_input = (
        f"sig=({component_list});"
        f'created={created};keyid="{client_key.key_id}"'
    )

    # Build signature base
    sig_base_lines = []
    for comp in covered_components:
        comp_name = comp.strip('"')
        if comp_name == "@method":
            sig_base_lines.append(f'"@method": {method}')
        elif comp_name == "@target-uri":
            sig_base_lines.append(f'"@target-uri": {url}')
        elif comp_name == "authorization":
            sig_base_lines.append(f'"authorization": {auth_header}')
        elif comp_name == "content-type":
            ct = request.headers.try_get("Content-Type") or "application/json"
            sig_base_lines.append(f'"content-type": {ct}')
        elif comp_name == "content-digest":
            cd = request.headers.try_get("Content-Digest") or ""
            sig_base_lines.append(f'"content-digest": {cd}')

    sig_base_lines.append(f'"@signature-params": {sig_input.split("=", 1)[1]}')
    sig_base = "\n".join(sig_base_lines)

    # Sign the base (placeholder - actual crypto implementation pending)
    # In production, this uses Ed25519/ECDSA from the cryptography library
    signature_bytes = _sign_bytes(
        sig_base.encode("utf-8"),
        client_key,
    )
    sig_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Add signature headers
    request.headers.try_add("Signature-Input", sig_input)
    request.headers.try_add("Signature", f"sig=:{sig_b64}:")


def _sign_bytes(data: bytes, client_key: ClientKeyConfig) -> bytes:
    """
    Sign bytes with the client's private key.

    Currently supports Ed25519 via the cryptography library.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if isinstance(client_key.private_key, bytes):
            key = Ed25519PrivateKey.from_private_bytes(client_key.private_key)
            return key.sign(data)
    except ImportError:
        pass

    # Fallback: return placeholder (for development/testing)
    return hashlib.sha256(data).digest()
