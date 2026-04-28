"""
Type definitions for the Kiota GNAP Authentication Provider.
Uses Python dataclasses for clean, type-safe configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
class AccessRight:
    """GNAP access right request (RFC 9635 Section 8)."""
    type: str
    actions: list[str]
    locations: list[str] = field(default_factory=list)
    datatypes: list[str] = field(default_factory=list)


@dataclass
class InteractionFinish:
    """Interaction finish configuration."""
    method: str = "redirect"
    uri: str = ""
    nonce: Optional[str] = None


@dataclass
class InteractionConfig:
    """Interaction configuration for resource owner authorization."""
    start: list[str] = field(default_factory=lambda: ["redirect"])
    finish: Optional[InteractionFinish] = None


@dataclass
class TokenAccess:
    """Access token details from grant response."""
    value: str
    manage_uri: Optional[str] = None
    access: list[AccessRight] = field(default_factory=list)
    expires_in: Optional[int] = None


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
    continuation: Optional[ContinuationInfo] = None


@dataclass
class GnapAuthOptions:
    """Configuration for the GNAP authentication provider."""
    grant_endpoint: str
    client_key: ClientKeyConfig
    access_rights: list[AccessRight]
    interaction: Optional[InteractionConfig] = None
