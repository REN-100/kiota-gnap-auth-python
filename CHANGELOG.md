# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-06

### Added
- **Token introspection** (`introspect_token()`) — RFC 9635 §6.3 compliance, returns full `TokenAccess` dataclass
- **Wallet address resolution** (`resolve_wallet_address()`) — Auto-discover auth/resource servers from Open Payments wallet addresses
- **Full rotation response** — `rotate_token()` now returns `TokenAccess` dataclass with `value`, `manage_uri`, `expires_in`, `flags`, `access`
- **Context manager support** — `async with` for lifecycle management
- **Examples directory** — `basic_usage.py`, `open_payments.py`, `fastapi_integration.py`
- **CI enhancements** — mypy type checking step added to GitHub Actions
- **Wallet address tests** — Resolution, `$`-format, HTTPS enforcement, error paths

### Changed
- `rotate_token()` return type changed from `str` to `TokenAccess` (**BREAKING**)
- `introspect_token()` return type changed from `dict` to `TokenAccess`
- Version synchronized to `0.2.0` across pyproject.toml and code

### Fixed
- Rotation logic now persists new management URI, expiry, access, and flags from rotation response

## [0.1.0] - 2026-04-28

### Added
- Initial release
- Kiota `AuthenticationProvider` implementation
- GNAP grant lifecycle: `request_grant()`, `continue_grant()`, `rotate_token()`, `revoke_token()`, `delete_grant()`
- HTTP Message Signatures (RFC 9421) via `cryptography` library
- Content-Digest header generation (RFC 9530)
- Structured error handling (`GnapError`, `GnapInteractionRequiredError`)
- Token store with TTL-based expiration
- Proactive token refresh within grace period
- Continuation polling with backoff
- Configurable retry with exponential backoff
- Ed25519 and ECDSA-P256 key proof support
- Token flags (`bearer`, `durable`)
- Open Payments: `identifier`, `limits`, wallet address, client display
- Full type annotations with `py.typed` marker
- CI pipeline with Python 3.11/3.12/3.13 matrix
