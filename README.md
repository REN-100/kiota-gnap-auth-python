# Kiota GNAP Authentication Provider for Python

> A Kiota-compatible authentication provider implementing GNAP (RFC 9635) for automated Open Payments SDK generation in Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![RFC 9635](https://img.shields.io/badge/RFC-9635-orange.svg)](https://www.rfc-editor.org/rfc/rfc9635)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)

## Overview

This package implements a [Kiota](https://learn.microsoft.com/en-us/openapi/kiota/) `AuthenticationProvider` that handles the complete GNAP authorization lifecycle for Open Payments APIs in Python. Designed as a direct counterpart to the [TypeScript provider](https://github.com/REN-100/kiota-gnap-auth-ts), ensuring cross-language parity.

## Features

- **Full GNAP lifecycle** - Grant requests, token acquisition, continuation, rotation, and revocation
- **Kiota-native** - Implements `AuthenticationProvider` and `AccessTokenProvider` interfaces
- **HTTP Message Signatures** - Automatic RFC 9421 request signing
- **Async-first** - Built on `asyncio` and `httpx` for modern Python
- **Token management** - In-memory token store with automatic refresh
- **Open Payments optimized** - Pre-configured for ILP resource types

## Installation

```bash
pip install shujaapay-kiota-gnap-auth
```

## Quick Start

```python
from kiota_gnap_auth import GnapAuthenticationProvider, ClientKeyConfig, AccessRight

# 1. Create the GNAP auth provider
auth_provider = GnapAuthenticationProvider(
    grant_endpoint="https://auth.wallet.example/",
    client_key=ClientKeyConfig(
        key_id="my-client-key",
        private_key=my_ed25519_private_key,
        algorithm="ed25519",
        proof="httpsig",
    ),
    access_rights=[
        AccessRight(type="incoming-payment", actions=["create", "read", "list"]),
        AccessRight(type="outgoing-payment", actions=["create", "read", "list"]),
        AccessRight(type="quote", actions=["create", "read"]),
    ],
)

# 2. Use with Kiota-generated client
from kiota_http.httpx_request_adapter import HttpxRequestAdapter

adapter = HttpxRequestAdapter(auth_provider)
client = OpenPaymentsClient(adapter)

# 3. Make authenticated API calls
payments = await client.incoming_payments.get()
```

## Architecture

```
                    Kiota SDK (Python)
                          |
                          v
          +-------------------------------+
          | GnapAuthenticationProvider     |
          |  - authenticate_request()     |
          |  - get_authorization_token()  |
          +-------------------------------+
                          |
             +------------+------------+
             |                         |
             v                         v
    +------------------+    +----------------------+
    | GnapGrantManager |    | HttpSignatureSigner  |
    |  - request_grant |    |  - sign_request      |
    |  - continue_grant|    |  - RFC 9421          |
    |  - rotate_token  |    +----------------------+
    +------------------+
             |
             v
    +------------------+
    | TokenStore       |
    |  - get/set/clear |
    |  - auto-refresh  |
    +------------------+
```

## Conformance Test Suite

This provider shares a conformance test suite with the [TypeScript provider](https://github.com/REN-100/kiota-gnap-auth-ts), ensuring behavioral parity across languages:

```bash
# Run the shared conformance tests
pytest tests/conformance/ -v
```

Test scenarios cover:
- Grant request construction and signing
- Token lifecycle (acquire, rotate, revoke)
- Interaction handling (redirect, user_code)
- Error handling (expired tokens, network failures)
- HTTP Message Signature verification

## Project Structure

```
src/kiota_gnap_auth/
  __init__.py                     # Public exports
  gnap_auth_provider.py           # Kiota AuthenticationProvider
  gnap_access_token_provider.py   # Kiota AccessTokenProvider
  gnap_grant_manager.py           # GNAP grant lifecycle
  http_signature_signer.py        # RFC 9421 signing
  token_store.py                  # Token storage
  types.py                        # Type definitions (dataclasses)
tests/
  test_gnap_auth_provider.py
  test_gnap_grant_manager.py
  conformance/                    # Shared conformance test suite
    test_grant_request.py
    test_token_lifecycle.py
```

## Relationship to ShujaaPay GNAP Stack

| Repo | Workstream | Role |
|---|---|---|
| [gnap-openapi-security-scheme](https://github.com/REN-100/gnap-openapi-security-scheme) | WS1 | x-gnap metadata definition |
| [kiota-gnap-auth-ts](https://github.com/REN-100/kiota-gnap-auth-ts) | WS2 | TypeScript equivalent |
| **This repo** | **WS3** | **Kiota Python GNAP auth provider** |
| [http-message-signatures-ts](https://github.com/REN-100/http-message-signatures-ts) | WS4 | Signing library (TS reference) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).
