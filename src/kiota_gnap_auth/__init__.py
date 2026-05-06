"""
@shujaapay/kiota-gnap-auth-python

Kiota GNAP Authentication Provider for Python
Implements RFC 9635 (GNAP) authorization for Open Payments SDK generation.

Part of the ShujaaPay GNAP Stack.

@see https://www.rfc-editor.org/rfc/rfc9635
@see https://www.shujaapay.me
"""

# Core providers
from .gnap_auth_provider import GnapAuthenticationProvider
from .gnap_access_token_provider import GnapAccessTokenProvider
from .gnap_grant_manager import GnapGrantManager

# Token storage
from .token_store import InMemoryTokenStore

# Error handling (RFC 9635 §3.6)
from .errors import GnapError, GnapInteractionRequiredError, parse_gnap_error_response

# Interaction hash verification (RFC 9635 §4.2.3)
from .interaction_hash import verify_interaction_hash, compute_interaction_hash

# Retry policy
from .retry import with_retry, DEFAULT_RETRY_POLICY, RetryPolicy

# Event system
from .events import GnapEventEmitter

# HTTP signature utilities
from .http_signature_signer import compute_content_digest, export_public_jwk

# Type definitions
from .types import (
    GnapAuthOptions,
    ClientKeyConfig,
    ClientDisplay,
    AccessRight,
    Amount,
    PaymentLimits,
    InteractionConfig,
    InteractionFinish,
    GrantResponse,
    ContinuationInfo,
    TokenInfo,
    TokenAccess,
    TokenStore,
    Algorithm,
    ProofMethod,
)

__all__ = [
    # Providers
    "GnapAuthenticationProvider",
    "GnapAccessTokenProvider",
    "GnapGrantManager",
    # Storage
    "InMemoryTokenStore",
    # Errors
    "GnapError",
    "GnapInteractionRequiredError",
    "parse_gnap_error_response",
    # Interaction
    "verify_interaction_hash",
    "compute_interaction_hash",
    # Retry
    "with_retry",
    "DEFAULT_RETRY_POLICY",
    "RetryPolicy",
    # Events
    "GnapEventEmitter",
    # HTTP Signatures
    "compute_content_digest",
    "export_public_jwk",
    # Types
    "GnapAuthOptions",
    "ClientKeyConfig",
    "ClientDisplay",
    "AccessRight",
    "Amount",
    "PaymentLimits",
    "InteractionConfig",
    "InteractionFinish",
    "GrantResponse",
    "ContinuationInfo",
    "TokenInfo",
    "TokenAccess",
    "TokenStore",
    "Algorithm",
    "ProofMethod",
]

__version__ = "0.1.0"
