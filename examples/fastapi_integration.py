"""
FastAPI Integration — kiota-gnap-auth-python

Demonstrates integrating the GNAP auth provider with a FastAPI
application for backend-to-backend Open Payments API calls.

This pattern is used by ShujaaPay's gateway service for:
- Initiating outgoing payments on behalf of users
- Reading incoming payment status
- Creating quotes for FX conversion

Requirements:
    pip install shujaapay-kiota-gnap-auth fastapi uvicorn
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

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
)

# --- Configuration (from environment in production) ---
GRANT_ENDPOINT = "https://auth.wallet.example/"
PRIVATE_KEY_PEM = b"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
KEY_ID = "shujaapay-backend-key"
WALLET_ADDRESS = "https://wallet.example/shujaapay-merchant"

# Global auth provider (shared across requests)
_auth_provider: GnapAuthenticationProvider | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize and cleanup GNAP auth."""
    global _auth_provider

    _auth_provider = GnapAuthenticationProvider(
        GnapAuthOptions(
            grant_endpoint=GRANT_ENDPOINT,
            client_key=ClientKeyConfig(
                key_id=KEY_ID,
                private_key=PRIVATE_KEY_PEM,
                algorithm=Algorithm.ED25519,
            ),
            access_rights=[
                AccessRight(
                    type="incoming-payment",
                    actions=["create", "read", "list", "complete"],
                    identifier=WALLET_ADDRESS,
                ),
                AccessRight(
                    type="outgoing-payment",
                    actions=["create", "read", "list"],
                    identifier=WALLET_ADDRESS,
                ),
                AccessRight(
                    type="quote",
                    actions=["create", "read"],
                    identifier=WALLET_ADDRESS,
                ),
            ],
            wallet_address=WALLET_ADDRESS,
            client_display=ClientDisplay(
                name="ShujaaPay",
                uri="https://www.shujaapay.me",
            ),
        )
    )

    # Wire up lifecycle events for observability
    _auth_provider.events.on(
        "token:acquired",
        lambda e: print(f"[GNAP] Token acquired: {e}"),
    )
    _auth_provider.events.on(
        "token:rotated",
        lambda e: print(f"[GNAP] Token rotated: {e}"),
    )
    _auth_provider.events.on(
        "token:rotation_failed",
        lambda e: print(f"[GNAP] ⚠️  Rotation failed: {e}"),
    )

    yield

    await _auth_provider.close()


app = FastAPI(
    title="ShujaaPay Payments API",
    description="Open Payments gateway with GNAP authentication",
    version="1.0.0",
    lifespan=lifespan,
)


def get_auth_provider() -> GnapAuthenticationProvider:
    """Dependency: get the GNAP auth provider."""
    if _auth_provider is None:
        raise RuntimeError("Auth provider not initialized")
    return _auth_provider


# --- Request / Response Models ---


class SendPaymentRequest(BaseModel):
    receiver_wallet: str
    amount: str
    asset_code: str = "KES"
    asset_scale: int = 2


class PaymentResponse(BaseModel):
    status: str
    message: str
    token_preview: str | None = None


# --- API Endpoints ---


@app.post("/api/payments/send", response_model=PaymentResponse)
async def send_payment(
    req: SendPaymentRequest,
    auth: GnapAuthenticationProvider = Depends(get_auth_provider),
) -> PaymentResponse:
    """
    Initiate an outgoing payment via Open Payments.

    The GNAP auth provider handles:
    - Token acquisition (cache-first, rotation fallback)
    - HTTP Message Signature generation
    - Content-Digest header for request integrity
    """
    try:
        token = await auth.token_provider.get_authorization_token()

        if not token:
            raise HTTPException(status_code=401, detail="Failed to acquire GNAP token")

        # In production, use the Kiota-generated SDK:
        # adapter = HttpxRequestAdapter(auth)
        # client = OpenPaymentsClient(adapter)
        # payment = await client.outgoing_payments.create(...)

        return PaymentResponse(
            status="pending",
            message=f"Payment of {req.amount} {req.asset_code} to {req.receiver_wallet} initiated",
            token_preview=f"{token[:16]}...",
        )

    except GnapInteractionRequiredError:
        raise HTTPException(
            status_code=403,
            detail="Grant requires user interaction — redirect flow needed",
        )


@app.get("/api/wallet/info")
async def get_wallet_info(wallet_address: str) -> dict:
    """
    Resolve a wallet address to discover its capabilities.

    Uses the Open Payments wallet address resolution protocol
    to discover the authorization server, asset, and public name.
    """
    try:
        info = await resolve_wallet_address(wallet_address)
        return {
            "id": info.id,
            "publicName": info.public_name,
            "authServer": info.auth_server,
            "resourceServer": info.resource_server,
            "assetCode": info.asset_code,
            "assetScale": info.asset_scale,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
async def health_check() -> dict:
    return {"status": "healthy", "auth_ready": _auth_provider is not None}
