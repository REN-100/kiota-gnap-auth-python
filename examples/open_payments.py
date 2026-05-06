"""
Open Payments Integration — kiota-gnap-auth-python

Demonstrates the full Open Payments workflow:
1. Resolve wallet address to discover the authorization server
2. Request a grant with outgoing-payment limits
3. Handle interactive redirect flow
4. Continue the grant after user approval
5. Use the token with a Kiota-generated SDK

This is the canonical use case for the ShujaaPay GNAP stack.
"""

import asyncio
import webbrowser

from kiota_gnap_auth import (
    AccessRight,
    Algorithm,
    Amount,
    ClientDisplay,
    ClientKeyConfig,
    GnapAuthOptions,
    GnapAuthenticationProvider,
    GnapInteractionRequiredError,
    PaymentLimits,
    resolve_wallet_address,
    verify_interaction_hash,
)


async def main() -> None:
    # --- 1. Resolve wallet address → discover auth server ---
    sender_wallet = "https://wallet.example/alice"
    receiver_wallet = "https://wallet.example/bob"

    sender_info = await resolve_wallet_address(sender_wallet)
    print(f"🔍 Auth server: {sender_info.auth_server}")
    print(f"💰 Asset: {sender_info.asset_code} (scale {sender_info.asset_scale})")

    # --- 2. Build provider with outgoing-payment limits ---
    private_key_pem = b"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

    auth = GnapAuthenticationProvider(
        GnapAuthOptions(
            grant_endpoint=sender_info.auth_server,
            client_key=ClientKeyConfig(
                key_id="shujaapay-prod-key",
                private_key=private_key_pem,
                algorithm=Algorithm.ED25519,
            ),
            access_rights=[
                AccessRight(
                    type="outgoing-payment",
                    actions=["create", "read", "list"],
                    identifier=sender_wallet,
                    limits=PaymentLimits(
                        receiver=f"{receiver_wallet}/incoming-payments/inv-123",
                        debit_amount=Amount(
                            value="50000",
                            asset_code=sender_info.asset_code,
                            asset_scale=sender_info.asset_scale,
                        ),
                    ),
                ),
                AccessRight(
                    type="quote",
                    actions=["create", "read"],
                    identifier=sender_wallet,
                ),
            ],
            wallet_address=sender_wallet,
            client_display=ClientDisplay(
                name="ShujaaPay",
                uri="https://www.shujaapay.me",
            ),
        )
    )

    # --- 3. Attempt to get a token (may require interaction) ---
    async with auth:
        try:
            token = await auth.token_provider.get_authorization_token()
            print(f"✅ Immediate token: {token[:20]}...")
        except GnapInteractionRequiredError as e:
            print(f"🔗 Interaction required!")

            if e.redirect_url:
                print(f"   Redirect URL: {e.redirect_url}")
                # In a web app: return redirect(e.redirect_url)
                # In a CLI: open browser
                webbrowser.open(e.redirect_url)
            elif e.user_code:
                print(f"   Enter code: {e.user_code}")
                if e.user_code_uri:
                    print(f"   At: {e.user_code_uri}")

            # --- 4. After user approves, continue the grant ---
            # The callback URL will contain interact_ref and hash
            interact_ref = input("Enter interact_ref from callback: ")
            callback_hash = input("Enter hash from callback: ")

            # Verify the interaction hash (MANDATORY per RFC 9635 §4.2.3)
            if e.continue_uri and e.continue_token:
                # In production, verify the hash before continuing
                # is_valid = verify_interaction_hash(...)

                token = await auth.token_provider.continue_grant(
                    continue_uri=e.continue_uri,
                    continue_token=e.continue_token,
                    interact_ref=interact_ref,
                )
                print(f"✅ Token after interaction: {token[:20]}...")

        # --- 5. Use with Kiota-generated SDK ---
        # from kiota_http.httpx_request_adapter import HttpxRequestAdapter
        # adapter = HttpxRequestAdapter(auth)
        # client = OpenPaymentsClient(adapter)
        #
        # quote = await client.quotes.create(sender_wallet, {
        #     "receiver": f"{receiver_wallet}/incoming-payments/inv-123",
        #     "walletAddress": sender_wallet,
        # })
        # print(f"Quote: {quote.id}, send: {quote.debitAmount}")
        #
        # payment = await client.outgoing_payments.create(sender_wallet, {
        #     "walletAddress": sender_wallet,
        #     "quoteId": quote.id,
        # })
        # print(f"Payment created: {payment.id}")


if __name__ == "__main__":
    asyncio.run(main())
