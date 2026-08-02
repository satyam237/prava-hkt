"""Contract tests for PravaClient against mocked httpx responses.

No network. Every fixture body is built from the shapes Prava's docs specify,
so a change in our parsing that would break against the live API breaks here
first.

The test that matters most is not a happy path: it is that
``THRESHOLD_EXCEEDED`` and ``MANDATE_MERCHANT_NOT_ALLOWED`` arrive as two
different exception types. Reconciliation has to tell "spent too much" from
"bought from the wrong merchant", and both are 403s with a JSON body.
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest

from app.services.prava_client import (
    SANDBOX_BASE_URL,
    PravaAuthRequired,
    PravaClient,
    PravaError,
    PravaMandateNotFound,
    PravaMerchantNotAllowed,
    PravaThresholdExceeded,
    PravaTimeout,
    PravaTransportError,
    PravaValidationError,
    key_fingerprint,
    redact,
)

SECRET = "sk_test_smoke_not_a_real_key"
MANDATE_ID = "mnd_abc123"
SESSION_ID = "ses_abc123"


def make_client(handler) -> PravaClient:
    """A PravaClient wired to an in-memory transport — never touches a socket."""
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url=SANDBOX_BASE_URL)
    return PravaClient(SECRET, client=http)


def json_route(status: int, body: dict, *, capture: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        return httpx.Response(status, json=body)

    return handler


# ---------------------------------------------------------------------------
# Construction and money handling
# ---------------------------------------------------------------------------


def test_secret_key_is_required():
    with pytest.raises(ValueError, match="secret_key is required"):
        PravaClient("")


def test_key_fingerprint_exposes_only_eight_characters():
    assert key_fingerprint(SECRET) == "sk_test_"
    assert SECRET[8:] not in key_fingerprint(SECRET)


async def test_charge_rejects_a_float_amount():
    """A float amount is a bug, not something to round. Fail loudly."""
    client = make_client(json_route(200, {}))
    with pytest.raises(ValueError, match="never touches float"):
        await client.charge_mandate(MANDATE_ID, 84.00)


async def test_charge_rejects_more_than_two_decimal_places():
    client = make_client(json_route(200, {}))
    with pytest.raises(ValueError, match="max 2 decimal places"):
        await client.charge_mandate(MANDATE_ID, "84.005")


async def test_decimal_and_int_amounts_normalize_to_strings():
    captured: list[httpx.Request] = []
    client = make_client(
        json_route(200, {"status": "awaiting_result"}, capture=captured)
    )

    await client.charge_mandate(MANDATE_ID, Decimal("84.00"))
    await client.charge_mandate(MANDATE_ID, 84)

    import json

    assert json.loads(captured[0].content)["amount"] == "84.00"
    assert json.loads(captured[1].content)["amount"] == "84"


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


async def test_health_returns_ok():
    client = make_client(
        json_route(200, {"status": "ok", "timestamp": "2026-08-02T00:00:00Z"})
    )
    result = await client.health()
    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# create_mandate_session
# ---------------------------------------------------------------------------


async def test_create_mandate_session_sends_the_documented_body():
    captured: list[httpx.Request] = []
    client = make_client(
        json_route(
            200,
            {
                "session_id": SESSION_ID,
                "mandate_id": MANDATE_ID,
                "iframe_url": "https://sandbox.prava.space/checkout/ses_abc123",
                "authorizeOnly": True,
            },
            capture=captured,
        )
    )

    result = await client.create_mandate_session(
        user_id="user_123",
        user_email="jane@example.com",
        total_amount="49.99",
        merchant_name="Acme Store",
        merchant_url="https://acme.example.com",
        description="Widget",
        unit_price="24.99",
        quantity=2,
        callback_url="https://acme.example.com/return",
    )

    import json

    body = json.loads(captured[0].content)
    assert captured[0].url.path == "/v1/sessions"
    assert body["total_amount"] == "49.99"
    assert body["currency"] == "USD"
    assert body["integration_type"] == "full_checkout"
    assert body["callback_url"] == "https://acme.example.com/return"
    # Exactly one entry — Prava rejects multi-merchant sessions.
    assert len(body["purchase_context"]) == 1
    ctx = body["purchase_context"][0]
    assert ctx["merchant_details"]["name"] == "Acme Store"
    assert ctx["merchant_details"]["url"] == "https://acme.example.com"
    assert ctx["merchant_details"]["country_code_iso2"] == "US"
    assert ctx["product_details"][0]["unit_price"] == "24.99"
    assert ctx["product_details"][0]["quantity"] == 2
    # mandate_setup is what makes the session authorize-only.
    assert body["mandate_setup"] == {
        "intent": "mandate_setup",
        "recurring_frequency": "one_time",
        "merchant_scope": "listed",
        "max_charges": 1,
    }
    assert result["authorizeOnly"] is True
    assert result["iframe_url"].startswith("https://")


async def test_create_mandate_session_sends_bearer_auth():
    captured: list[httpx.Request] = []
    client = make_client(json_route(200, {"session_id": SESSION_ID}, capture=captured))
    await client.create_mandate_session(
        user_id="u",
        user_email="a@b.co",
        total_amount="1.00",
        merchant_name="m",
        merchant_url="https://m.test",
        description="d",
    )
    assert captured[0].headers["authorization"] == f"Bearer {SECRET}"


async def test_create_mandate_session_rejects_an_empty_user_id():
    client = make_client(json_route(200, {}))
    with pytest.raises(ValueError, match="user_id must be"):
        await client.create_mandate_session(
            user_id="",
            user_email="a@b.co",
            total_amount="1.00",
            merchant_name="m",
            merchant_url="https://m.test",
            description="d",
        )


# ---------------------------------------------------------------------------
# charge_mandate
# ---------------------------------------------------------------------------


async def test_charge_returns_credentials_for_a_secret_key_caller():
    client = make_client(
        json_route(
            200,
            {
                "mandateId": MANDATE_ID,
                "instructionId": "ins_1",
                "transactionId": "txn_1",
                "orderId": "ord_1",
                "status": "awaiting_result",
                "fetchStatus": "SUCCESS",
                "credentials": {
                    "token": "4111111111111111",
                    "dynamicCvv": "123",
                    "expiryMonth": "12",
                    "expiryYear": "2030",
                },
                "deduplicated": False,
            },
        )
    )
    result = await client.charge_mandate(MANDATE_ID, "84.00", reference="ref-1")
    assert result["status"] == "awaiting_result"
    assert result["fetchStatus"] == "SUCCESS"
    assert result["credentials"]["token"]
    assert result["credentials"]["dynamicCvv"]


async def test_charge_replay_with_the_same_reference_is_deduplicated():
    """Same mandate + same reference returns the original charge, not a new one."""
    client = make_client(
        json_route(
            200,
            {
                "mandateId": MANDATE_ID,
                "transactionId": "txn_1",
                "status": "awaiting_result",
                "deduplicated": True,
            },
        )
    )
    result = await client.charge_mandate(MANDATE_ID, "84.00", reference="ref-1")
    assert result["deduplicated"] is True
    assert result["transactionId"] == "txn_1"


async def test_charge_omits_reference_when_not_given():
    captured: list[httpx.Request] = []
    client = make_client(
        json_route(200, {"status": "awaiting_result"}, capture=captured)
    )
    await client.charge_mandate(MANDATE_ID, "84.00")
    import json

    assert "reference" not in json.loads(captured[0].content)


async def test_charge_rejects_multi_entry_purchase_context():
    client = make_client(json_route(200, {}))
    entry = {"merchant_details": {}, "product_details": []}
    with pytest.raises(ValueError, match="exactly one entry"):
        await client.charge_mandate(
            MANDATE_ID, "84.00", purchase_context=[entry, entry]
        )


async def test_over_cap_charge_raises_threshold_exceeded():
    """The card network enforces the cap; we must surface it as its own type."""
    client = make_client(
        json_route(
            402,
            {
                "status": "failed",
                "fetchStatus": "FAILURE",
                "errorCode": "THRESHOLD_EXCEEDED",
                "errorMessage": "Amount exceeds the authorized mandate cap",
            },
        )
    )
    with pytest.raises(PravaThresholdExceeded) as exc_info:
        await client.charge_mandate(MANDATE_ID, "1008.00", reference="ref-over")

    exc = exc_info.value
    assert exc.code == "THRESHOLD_EXCEEDED"
    assert exc.status_code == 402
    assert "exceeds" in exc.message


async def test_charge_at_a_disallowed_merchant_raises_its_own_type():
    """403 MANDATE_MERCHANT_NOT_ALLOWED must not collapse into a generic 403."""
    client = make_client(
        json_route(
            403,
            {
                "errorCode": "MANDATE_MERCHANT_NOT_ALLOWED",
                "errorMessage": "Merchant is not in the mandate's listed scope",
            },
        )
    )
    with pytest.raises(PravaMerchantNotAllowed) as exc_info:
        await client.charge_mandate(MANDATE_ID, "84.00")

    assert exc_info.value.code == "MANDATE_MERCHANT_NOT_ALLOWED"
    # The distinction reconciliation depends on.
    assert not isinstance(exc_info.value, PravaThresholdExceeded)


# ---------------------------------------------------------------------------
# get_mandate
# ---------------------------------------------------------------------------


async def test_get_mandate_returns_the_reconciliation_shape():
    client = make_client(
        json_route(
            200,
            {
                "approvedAmount": "84.00",
                "currency": "USD",
                "status": "active",
                "spent": "84.00",
                "chargeCount": 1,
                "charges": [
                    {
                        "transactionId": "txn_1",
                        "amount": "84.00",
                        "currency": "USD",
                        "status": "awaiting_result",
                        "reference": "ref-1",
                        "createdAt": "2026-08-02T00:00:00Z",
                    }
                ],
            },
        )
    )
    result = await client.get_mandate(MANDATE_ID)
    # Amounts stay strings all the way through — no float ever touches them.
    assert result["spent"] == "84.00"
    assert isinstance(result["approvedAmount"], str)
    assert result["charges"][0]["reference"] == "ref-1"


async def test_missing_mandate_raises_not_found():
    client = make_client(
        json_route(404, {"code": "MANDATE_NOT_FOUND", "message": "No such mandate"})
    )
    with pytest.raises(PravaMandateNotFound) as exc_info:
        await client.get_mandate("mnd_nope")
    assert exc_info.value.status_code == 404
    assert exc_info.value.code == "MANDATE_NOT_FOUND"


async def test_bare_404_without_a_code_still_raises_not_found():
    """Status alone is enough when the body carries no code."""
    client = make_client(json_route(404, {"detail": "Not Found"}))
    with pytest.raises(PravaMandateNotFound):
        await client.get_mandate("mnd_nope")


async def test_missing_auth_raises_auth_required():
    client = make_client(
        json_route(401, {"code": "AUTH_REQUIRED", "message": "Missing bearer token"})
    )
    with pytest.raises(PravaAuthRequired):
        await client.get_mandate(MANDATE_ID)


async def test_validation_error_maps_to_val_2001():
    client = make_client(
        json_route(
            400, {"code": "VAL_2001", "message": "total_amount has too many decimals"}
        )
    )
    with pytest.raises(PravaValidationError) as exc_info:
        await client.get_mandate(MANDATE_ID)
    assert exc_info.value.code == "VAL_2001"


async def test_an_undocumented_code_stays_a_generic_prava_error():
    """Unknown codes are surfaced verbatim, not forced into a known category."""
    client = make_client(json_route(500, {"code": "SOMETHING_NEW", "message": "boom"}))
    with pytest.raises(PravaError) as exc_info:
        await client.get_mandate(MANDATE_ID)
    assert type(exc_info.value) is PravaError
    assert exc_info.value.code == "SOMETHING_NEW"


# ---------------------------------------------------------------------------
# sessions: payment-result and report-status
# ---------------------------------------------------------------------------


async def test_get_payment_result_carries_credentials_while_awaiting_result():
    client = make_client(
        json_route(
            200,
            {
                "session_id": SESSION_ID,
                "order_id": "ord_1",
                "status": "awaiting_result",
                "transactions": [
                    {
                        "txn_id": "txn_1",
                        "status": "awaiting_result",
                        "line_items": [
                            {
                                "txn_ref_id": "ref_1",
                                "merchant_name": "Northstar Supply",
                                "merchant_url": "https://breach.localhost",
                                "total_amount": "84.00",
                                "status": "awaiting_result",
                                "token": "4111111111111111",
                                "dynamic_cvv": "123",
                                "expiry_month": "12",
                                "expiry_year": "2030",
                                "products": [
                                    {
                                        "product_ref_id": "p1",
                                        "external_product_id": None,
                                        "name": "widget",
                                        "unit_price": "84.00",
                                        "quantity": 1,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        )
    )
    result = await client.get_payment_result(SESSION_ID)
    item = result["transactions"][0]["line_items"][0]
    assert item["txn_ref_id"] == "ref_1"
    assert item["total_amount"] == "84.00"
    assert item["token"]


async def test_get_payment_result_surfaces_a_nested_error_object():
    """Session errors nest under `error`, unlike a charge's flat errorCode."""
    client = make_client(
        json_route(
            403, {"error": {"code": "MANDATE_FORBIDDEN", "message": "not yours"}}
        )
    )
    with pytest.raises(PravaError) as exc_info:
        await client.get_payment_result(SESSION_ID)
    assert exc_info.value.code == "MANDATE_FORBIDDEN"
    assert exc_info.value.message == "not yours"


async def test_report_status_posts_the_documented_body():
    captured: list[httpx.Request] = []
    client = make_client(json_route(200, {"ok": True}, capture=captured))
    await client.report_status(SESSION_ID, "ref_1", "approved")

    import json

    assert captured[0].url.path == f"/v1/sessions/{SESSION_ID}/report-status"
    # Uppercased for us — the API only accepts APPROVED / DECLINED.
    assert json.loads(captured[0].content) == {
        "txn_ref_id": "ref_1",
        "txn_status": "APPROVED",
    }


async def test_report_status_rejects_an_unknown_status():
    client = make_client(json_route(200, {}))
    with pytest.raises(ValueError, match="APPROVED"):
        await client.report_status(SESSION_ID, "ref_1", "MAYBE")


async def test_revoke_session_posts_to_the_documented_path():
    captured: list[httpx.Request] = []
    client = make_client(json_route(200, {"status": "revoked"}, capture=captured))
    await client.revoke_session(SESSION_ID)

    assert captured[0].method == "POST"
    assert captured[0].url.path == f"/v1/sessions/{SESSION_ID}/revoke"


async def test_revoke_session_surfaces_invalid_state():
    """A completed or expired session is not revocable."""
    client = make_client(
        json_route(
            400, {"error": {"code": "INVALID_STATE", "message": "not revocable"}}
        )
    )
    with pytest.raises(PravaError) as exc_info:
        await client.revoke_session(SESSION_ID)
    assert exc_info.value.code == "INVALID_STATE"


# ---------------------------------------------------------------------------
# Transport failures
# ---------------------------------------------------------------------------


async def test_timeout_becomes_a_prava_timeout_not_an_httpx_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client = make_client(handler)
    with pytest.raises(PravaTimeout) as exc_info:
        await client.get_mandate(MANDATE_ID)
    assert exc_info.value.code == "CLIENT_TIMEOUT"
    assert isinstance(exc_info.value, PravaError)


async def test_connection_failure_becomes_a_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = make_client(handler)
    with pytest.raises(PravaTransportError):
        await client.health()


async def test_a_non_json_error_body_still_raises_a_typed_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>bad gateway</html>")

    client = make_client(handler)
    with pytest.raises(PravaError) as exc_info:
        await client.health()
    assert exc_info.value.status_code == 502


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redact_blanks_credentials_at_every_depth():
    payload = {
        "status": "awaiting_result",
        "credentials": {"token": "4111111111111111", "dynamicCvv": "123"},
        "transactions": [
            {"line_items": [{"token": "tok_secret", "dynamic_cvv": "999"}]}
        ],
    }
    clean = redact(payload)
    text = repr(clean)

    assert "4111111111111111" not in text
    assert "tok_secret" not in text
    assert "123" not in text
    assert "999" not in text
    # Non-secret structure survives, or the redacted output would be useless.
    assert clean["status"] == "awaiting_result"


def test_redact_catches_the_undocumented_session_token():
    """Regression: the live sandbox returns a `session_token` JWT.

    It is not in Prava's documented session response, and an exact-match
    redaction list missed it — the JWT reached the terminal and a state file
    before this was fixed. Any field whose name contains "token" is redacted
    now, documented or not.
    """
    payload = {
        "session_id": "ses_1",
        "session_token": "eyJhbGciOiJIUzI1NiJ9.payload.signature",
    }
    clean = redact(payload)
    assert "eyJhbGciOiJIUzI1NiJ9" not in repr(clean)
    assert clean["session_id"] == "ses_1"


def test_redact_catches_credential_fields_by_substring():
    payload = {
        "apiKey": "sk_live_xyz",
        "refresh_token": "rt_xyz",
        "card_cvv": "123",
        "merchant_name": "Northstar Supply",
    }
    clean = redact(payload)
    text = repr(clean)
    assert "sk_live_xyz" not in text
    assert "rt_xyz" not in text
    assert "123" not in text
    # A non-secret field must survive intact.
    assert clean["merchant_name"] == "Northstar Supply"


def test_redact_does_not_mutate_the_original():
    payload = {"credentials": {"token": "secret"}}
    redact(payload)
    assert payload["credentials"]["token"] == "secret"


async def test_exception_payload_is_redacted():
    """An exception often ends up in a log — it must not carry a live token."""
    client = make_client(
        json_route(
            403,
            {
                "errorCode": "MANDATE_MERCHANT_NOT_ALLOWED",
                "errorMessage": "nope",
                "credentials": {"token": "4111111111111111"},
            },
        )
    )
    with pytest.raises(PravaMerchantNotAllowed) as exc_info:
        await client.charge_mandate(MANDATE_ID, "84.00")
    assert "4111111111111111" not in repr(exc_info.value.payload)
