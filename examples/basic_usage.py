"""
Basic GNAP Grant Request — kiota-gnap-auth-python

Demonstrates the simplest path: request an incoming-payment grant,
receive a token immediately, and use it with a Kiota-generated SDK.

Requirements:
    pip install shujaapay-kiota-gnap-auth

Before running:
    1. Generate an Ed25519 keypair:
       python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; \
       from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption; \
       k = Ed25519PrivateKey.generate(); print(k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())"

    2. Register the public key with your Open Payments authorization server.
"""

import asyncio

from kiota_gnap_auth import (
    AccessRight,
    Algorithm,
    ClientKeyConfig,
    GnapAuthOptions,
    GnapAuthenticationProvider,
)


async def main() -> None:
    # --- 1. Configure the provider ---
    private_key_pem = b"""-----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikUFN9eaKGJYoFEIyjrX9
    -----END PRIVATE KEY-----"""  # Replace with your real key

    auth = GnapAuthenticationProvider(
        GnapAuthOptions(
            grant_endpoint="https://auth.wallet.example/",
            client_key=ClientKeyConfig(
                key_id="my-client-key-1",
                private_key=private_key_pem,
                algorithm=Algorithm.ED25519,
            ),
            access_rights=[
                AccessRight(
                    type="incoming-payment",
                    actions=["create", "read", "list"],
                    identifier="https://wallet.example/alice",
                ),
            ],
            wallet_address="https://wallet.example/alice",
        )
    )

    # --- 2. Listen for lifecycle events ---
    auth.events.on("token:acquired", lambda e: print(f"✅ Token acquired: {e}"))
    auth.events.on(
        "token:rotation_failed", lambda e: print(f"⚠️  Rotation failed: {e}")
    )

    # --- 3. Use with Kiota-generated SDK ---
    # from kiota_http.httpx_request_adapter import HttpxRequestAdapter
    # adapter = HttpxRequestAdapter(auth)
    # client = OpenPaymentsClient(adapter)
    # payments = await client.incoming_payments.get()

    # --- 4. Manual token acquisition (for debugging) ---
    async with auth:
        token = await auth.token_provider.get_authorization_token(
            "https://wallet.example/alice"
        )
        print(f"Token: {token}")


if __name__ == "__main__":
    asyncio.run(main())
