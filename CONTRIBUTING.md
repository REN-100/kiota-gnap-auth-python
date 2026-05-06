# Contributing to kiota-gnap-auth-python

Thank you for your interest in contributing to the **ShujaaPay GNAP Stack**! This project is part of the [Open Payments](https://openpayments.dev) ecosystem, and contributions are welcome from anyone in the community.

## Getting Started

### Prerequisites

- Python 3.11+
- [pip](https://pip.pypa.io/) or [uv](https://github.com/astral-sh/uv)
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/REN-100/kiota-gnap-auth-python.git
cd kiota-gnap-auth-python

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_grant_manager.py

# Run with coverage
pytest --cov=kiota_gnap_auth
```

### Type Checking

```bash
# Install mypy
pip install mypy

# Run type checks
mypy src/
```

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) conventions
- Use type hints for all public APIs
- Write docstrings for all public classes, methods, and functions
- Use `from __future__ import annotations` for forward references
- Prefer `dataclass` over plain dicts for structured data

## Making Changes

1. **Fork** the repository and create a feature branch
2. **Write tests** for any new functionality
3. **Ensure all tests pass** before submitting
4. **Update documentation** if your changes affect the public API
5. **Submit a pull request** with a clear description of changes

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add wallet address resolution (Open Payments §1.3)
fix: rotation response now returns full TokenAccess (RFC 9635 §6.1)
test: add introspection tests for token management
docs: update API reference for context manager usage
```

## RFC Compliance

This library implements several RFCs. When making changes, please reference the relevant sections:

- **RFC 9635** — Grant Negotiation and Authorization Protocol (GNAP)
- **RFC 9421** — HTTP Message Signatures
- **RFC 9530** — Content-Digest header
- **Open Payments** — https://openpayments.dev

## AI Disclosure

Per best practices (see [Interledger Foundation SDK grant program](https://github.com/interledger/Grants/wiki/SDK-grant-program)), use of generative AI should be disclosed in pull requests. If you use AI tools, please include:

- The tool/model used
- How it was used (code generation, review, documentation, etc.)
- That you have reviewed 100% of AI-generated output

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open an [issue](https://github.com/REN-100/kiota-gnap-auth-python/issues) for bug reports or feature requests
- Join the [Interledger Slack](https://communityinviter.com/apps/interledger/interledger-working-groups-slack) `#cfp-sdk` channel

---

Part of the **ShujaaPay GNAP Stack** — open-source tooling for the [Open Payments](https://openpayments.dev) ecosystem by [ShujaaPay](https://www.shujaapay.me).
