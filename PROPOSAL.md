# Proposal: Kiota GNAP Authentication Provider for Python

**Authors:** Super App Africa Limited (ShujaaPay)  
**Date:** April 2026  
**Status:** ✅ v0.2.0 Released — Workstream 3  
**Submitted to:** Interledger Foundation — SDK Grant Program

---

## 1. Executive Summary

This proposal describes a **Python authentication provider for Microsoft Kiota** that implements the GNAP (RFC 9635) authorization protocol. It is the Python counterpart to the TypeScript provider (Workstream 2), enabling Python developers to generate and use SDKs for GNAP-protected APIs — including Open Payments — with zero manual authorization code.

## 2. Motivation

Python is the dominant language for:

- **Backend services** in FinTech (Django, FastAPI, Flask)
- **Data engineering and analytics** pipelines that consume payment data
- **Machine learning systems** that need payment history for fraud detection and credit scoring
- **Automation and scripting** for financial operations

Without a Python GNAP provider, these use cases require hand-built authorization flows, creating a significant adoption barrier for the Interledger ecosystem.

## 3. Solution

### 3.1 Architecture

```python
from kiota_gnap_auth import GnapAuthenticationProvider

auth = GnapAuthenticationProvider(
    grant_endpoint="https://auth.wallet.example.com/",
    client_key={
        "proof": "httpsig",
        "jwk": public_key_jwk,
    },
    access_rights=[
        {
            "type": "incoming-payment",
            "actions": ["create", "read", "list"],
            "identifier": "https://wallet.example.com/alice",
        }
    ],
    signer=private_key,
)

# Use with Kiota-generated client
client = create_open_payments_client(auth)
payments = await client.incoming_payments.list(
    wallet_address="https://wallet.example.com/alice"
)
```

### 3.2 Key Components

| Component | Description |
|-----------|-------------|
| `GnapAuthenticationProvider` | Implements Kiota's `AuthenticationProvider` ABC. Manages grant lifecycle and automatic token refresh. |
| `HttpMessageSigner` | RFC 9421 HTTP Message Signatures in Python. Uses `cryptography` library for Ed25519 and ECDSA-P256. |
| `KeyManager` | Key generation, PEM/JWK serialization, and secure storage (keyring integration). |
| `GnapTokenCache` | Thread-safe in-memory token cache with TTL expiry. Optional Redis backend for distributed systems. |
| `InteractionHandler` | Handles redirect (launch browser) and user-code interaction modes. |

### 3.3 Package Structure

```
kiota-gnap-auth-python/
├── src/
│   └── kiota_gnap_auth/
│       ├── __init__.py
│       ├── provider.py          # GnapAuthenticationProvider
│       ├── signer.py            # HttpMessageSigner (RFC 9421)
│       ├── keys.py              # KeyManager (Ed25519, ECDSA-P256)
│       ├── cache.py             # GnapTokenCache
│       ├── interaction.py       # InteractionHandler
│       ├── models.py            # Grant request/response models
│       └── errors.py            # GNAP-specific exceptions
├── tests/
│   ├── test_provider.py
│   ├── test_signer.py
│   ├── test_keys.py
│   └── test_integration.py
├── examples/
│   ├── basic_usage.py
│   ├── open_payments.py
│   └── django_integration.py
├── pyproject.toml
├── PROPOSAL.md
└── README.md
```

## 4. Deliverables

| Deliverable | Timeline | Status |
|-------------|----------|--------|
| Core `GnapAuthenticationProvider` class | Month 2-3 | ✅ Shipped |
| HTTP Message Signatures (RFC 9421) in Python | Month 2 | ✅ Shipped |
| Token caching (memory + Redis) | Month 3 | ✅ In-memory shipped (Redis: future) |
| Interaction handler | Month 3-4 | ✅ Shipped (redirect + user_code) |
| Integration tests with Rafiki testnet | Month 4 | 🔜 Pending deployment |
| PyPI package publication | Month 4-5 | 🔜 Ready for `twine upload` |
| Documentation and examples | Month 5 | ✅ Shipped |

## 5. Dependencies

| Package | Purpose |
|---------|---------|
| `kiota-abstractions` | Kiota authentication provider interface |
| `cryptography` | Ed25519 and ECDSA key operations |
| `httpx` | Async HTTP client for grant requests |
| `pydantic` | Request/response model validation |

## 6. Python-Specific Considerations

### 6.1 Async-First Design

The provider is built for `asyncio`, matching modern Python web frameworks:

```python
# FastAPI integration
from fastapi import Depends

async def get_open_payments_client():
    auth = GnapAuthenticationProvider(...)
    return create_open_payments_client(auth)

@app.post("/send-payment")
async def send_payment(client=Depends(get_open_payments_client)):
    result = await client.outgoing_payments.create(...)
    return result
```

### 6.2 Thread Safety

Token cache uses `asyncio.Lock` for async contexts and `threading.Lock` for sync contexts, making it safe for both paradigms.

### 6.3 Type Hints

Full type annotations throughout, compatible with `mypy --strict`.

## 7. Related Workstreams

| # | Workstream | Repository |
|---|-----------|------------|
| 1 | GNAP OpenAPI Security Scheme (`x-gnap`) | `gnap-openapi-security-scheme` |
| 2 | Kiota GNAP Auth Provider (TypeScript) | `kiota-gnap-auth-ts` |
| **3** | **Kiota GNAP Auth Provider (Python)** | **`kiota-gnap-auth-python`** |
| 4 | HTTP Message Signatures (TypeScript) | `http-message-signatures-ts` |

---

**Submitted by:**  
Super App Africa Limited  
ShujaaPay — Global Payments. Local Freedom.  
Contact: rensonmumbo@gmail.com
