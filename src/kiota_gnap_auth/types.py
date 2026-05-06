"""
Type definitions for the Kiota GNAP Authentication Provider.

Uses Python dataclasses for clean, type-safe configuration.
Covers RFC 9635 GNAP types and Open Payments extensions.

@see https://www.rfc-editor.org/rfc/rfc9635
@see https://openpayments.dev
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional, Protocol, runtime_checkable


class Algorithm(str, Enum):
    """Supported signing algorithms for GNAP key proofs."""
    ED25519 = "ed25519"
    ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
    ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
    RSA_PSS_SHA512 = "rsa-pss-sha512"


class ProofMethod(str, Enum):
    """GNAP key proof methods (RFC 9635 Section 7.3)."""
    HTTPSIG = "httpsig"
    MTLS = "mtls"
    JWSD = "jwsd"
    DPOP = "dpop"


@dataclass
class ClientKeyConfig:
    """Client key configuration for GNAP proofs."""
    key_id: str
    private_key: bytes | str
    algorithm: Algorithm = Algorithm.ED25519
    proof: ProofMethod = ProofMethod.HTTPSIG


@dataclass
class Amount:
    """
    Monetary amount representation (Open Payments).

    Uses integer-based representation with asset scale to avoid
    floating-point precision issues in financial calculations.

    Example::

        # $10.00 USD
        Amount(value="1000", asset_code="USD", asset_scale=2)
        # KES 500.00
        Amount(value="50000", asset_code="KES", asset_scale=2)
    """
    value: str
    """Unsigned 64-bit integer amount as a string."""
    asset_code: str
    """ISO 4217 currency code (e.g., 'USD', 'KES', 'EUR')."""
    asset_scale: int
    """Decimal places defining the smallest divisible unit."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "assetCode": self.asset_code,
            "assetScale": self.asset_scale,
        }


@dataclass
class PaymentLimits:
    """
    Payment limits for outgoing-payment grants (Open Payments).

    Used to constrain the total debit/receive amounts and payment
    intervals for grants that authorize outgoing payments.

    Example::

        PaymentLimits(
            receiver="https://wallet.example/bob/incoming-payments/abc",
            debit_amount=Amount(value="1000", asset_code="USD", asset_scale=2),
            interval="R12/2024-01-01T00:00:00Z/P1M",
        )
    """
    receiver: Optional[str] = None
    """URL of the incoming payment being paid."""
    debit_amount: Optional[Amount] = None
    """Maximum debit amount per interval."""
    receive_amount: Optional[Amount] = None
    """Maximum receive amount per interval."""
    interval: Optional[str] = None
    """ISO 8601 repeating interval (e.g., 'R12/2024-01-01T00:00:00Z/P1M')."""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.receiver is not None:
            d["receiver"] = self.receiver
        if self.debit_amount is not None:
            d["debitAmount"] = self.debit_amount.to_dict()
        if self.receive_amount is not None:
            d["receiveAmount"] = self.receive_amount.to_dict()
        if self.interval is not None:
            d["interval"] = self.interval
        return d


@dataclass
class AccessRight:
    """
    GNAP access right request (RFC 9635 Section 8 + Open Payments extensions).

    Open Payments standard actions:
      - incoming-payment: create, complete, read, read-all, list, list-all
      - outgoing-payment: create, read, read-all, list, list-all
      - quote: create, read, read-all
    """
    type: str
    actions: list[str]
    identifier: Optional[str] = None
    """Wallet address URL for resource scoping (Open Payments)."""
    locations: list[str] = field(default_factory=list)
    datatypes: list[str] = field(default_factory=list)
    limits: Optional[PaymentLimits] = None
    """Payment limits for outgoing-payment grants (Open Payments)."""


@dataclass
class ClientDisplay:
    """
    Client display information (RFC 9635 §2.3).
    Shown to the resource owner during interaction.
    """
    name: Optional[str] = None
    uri: Optional[str] = None
    logo_uri: Optional[str] = None


@dataclass
class InteractionFinish:
    """Interaction finish configuration."""
    method: str = "redirect"
    uri: str = ""
    nonce: Optional[str] = None
    hash_method: Optional[str] = None
    """Hash method for interaction hash verification (default: sha-256)."""


@dataclass
class InteractionConfig:
    """Interaction configuration for resource owner authorization."""
    start: list[str] = field(default_factory=lambda: ["redirect"])
    finish: Optional[InteractionFinish] = None


@dataclass
class TokenAccess:
    """Access token details from grant response."""
    value: str
    manage: Optional[str] = None
    """Token management URI (for rotation/revocation)."""
    access: list[AccessRight] = field(default_factory=list)
    expires_in: Optional[int] = None
    flags: list[str] = field(default_factory=list)
    """Token flags (bearer, durable) per RFC 9635 §2.1.1."""


@dataclass
class ContinuationInfo:
    """Grant continuation information."""
    uri: str
    access_token: str
    wait: Optional[int] = None


@dataclass
class InteractionResponse:
    """Interaction requirements from grant response."""
    redirect: Optional[str] = None
    app: Optional[str] = None
    user_code: Optional[str] = None
    user_code_uri: Optional[str] = None
    finish: Optional[str] = None


@dataclass
class GrantResponse:
    """GNAP grant response (RFC 9635 Section 3)."""
    access_token: Optional[TokenAccess] = None
    interact: Optional[InteractionResponse] = None
    continuation: Optional[ContinuationInfo] = None


@dataclass
class TokenInfo:
    """Stored token information for the token store."""
    value: str
    management_uri: Optional[str] = None
    access: list[AccessRight] = field(default_factory=list)
    expires_at: Optional[float] = None
    flags: list[str] = field(default_factory=list)
    continuation: Optional[ContinuationInfo] = None


@runtime_checkable
class TokenStore(Protocol):
    """Token storage protocol (implement for custom storage)."""

    async def get(self, scope_key: str) -> Optional[TokenInfo]: ...
    async def set(self, scope_key: str, token: TokenInfo) -> None: ...
    async def delete(self, scope_key: str) -> None: ...
    async def clear(self) -> None: ...


@dataclass
class GnapAuthOptions:
    """Configuration for the GNAP authentication provider."""
    grant_endpoint: str
    client_key: ClientKeyConfig
    access_rights: list[AccessRight]
    interaction: Optional[InteractionConfig] = None
    token_store: Optional[Any] = None
    """Custom token store (default: InMemoryTokenStore)."""
    allowed_hosts: list[str] = field(default_factory=list)
    """
    Allowed hosts for token transmission.
    Prevents credential leakage to unauthorized domains.
    """
    wallet_address: Optional[str] = None
    """
    Wallet address for client identification (Open Payments).
    If set, the AS resolves the client's JWKS from this endpoint.
    """
    client_display: Optional[ClientDisplay] = None
    """Client display information shown to the resource owner."""
