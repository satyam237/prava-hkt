"""The payment leg. The only module in the app that opens a Prava session.

Two rules hold this file in place.

**It cannot be entered without a cleared warrant.** :func:`request_session`
accepts a :class:`~app.gate.ClearedWarrant` and refuses anything else at
runtime, not just in the annotation. ``ClearedWarrant`` is unconstructible
outside :mod:`app.gate`, so a HALT has no value to pass and no way to reach the
network. ``tests/test_gate.py`` asserts by AST that ``create_mandate_session``
appears in exactly one module under ``backend/app`` — this one.

**It never returns a credential.** The session response carries an undocumented
``session_token`` JWT (``docs/PRAVA_NOTES.md`` §2.3); a charge's line items
carry ``token`` and ``dynamic_cvv``. None of them are echoed to a browser: the
session response is rebuilt field by field from a known-safe list, and the poll
passes through :func:`~app.services.prava_client.redact`.

Passkey enrolment is currently broken in the Prava sandbox — a real attempt
failed with ``PASSKEY_REG_FAILED`` after a valid OTP (§3.1), reproduced across
three browsers — so no mandate can be minted and no money can move today. The
session and its checkout link are real; the approval that follows them cannot
complete. Every response from this module says so rather than implying a
payment that did not happen.
"""

from __future__ import annotations

import os
from decimal import Decimal
from typing import Any

import httpx

from app.gate import ClearedWarrant
from app.services.prava_client import PravaClient, redact

SECRET_KEY_ENV = "PRAVA_SECRET_KEY"
USER_ID_ENV = "WARRANT_USER_ID"
USER_EMAIL_ENV = "WARRANT_USER_EMAIL"

DEFAULT_USER_ID = "warrant_demo_user"
DEFAULT_USER_EMAIL = "demo@warrant.test"

#: Observed, not assumed: reproduced on three browsers across macOS and iOS.
PASSKEY_STATUS = "BROKEN_IN_SANDBOX"
PASSKEY_NOTICE = (
    "Prava sandbox passkey enrolment fails at registration (PASSKEY_REG_FAILED), "
    "so no mandate can be minted and no charge can be made. The session and its "
    "checkout link are real; the approval step is not completable today."
)


class PaymentUnavailable(RuntimeError):
    """No payment can be requested — typically a missing secret key."""


def is_configured() -> bool:
    return bool(os.environ.get(SECRET_KEY_ENV))


def _unit_price(amount: str, quantity: int) -> str:
    """The per-unit price Prava wants, derived from the authorized total.

    Refuses rather than rounds. An authorization for a total that does not
    divide evenly across its units is a document we should not have signed, and
    silently quantizing it would send Prava an amount the user never approved.
    """

    if quantity < 1:
        raise ValueError(f"quantity must be >= 1; got {quantity}")
    if quantity == 1:
        return amount
    total = Decimal(amount)
    unit = (total / quantity).quantize(Decimal("0.01"))
    if unit * quantity != total:
        raise ValueError(
            f"authorized total {amount} does not divide evenly across {quantity} units; "
            "pass an explicit unit price"
        )
    return format(unit, "f")


async def request_session(
    cleared: ClearedWarrant,
    *,
    user_id: str | None = None,
    user_email: str | None = None,
    secret_key: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Open a Prava mandate session scoped to the warrant's merchant and amount.

    ``merchant_scope="listed"`` (the client's default) locks the mandate to this
    merchant, so a charge anywhere else is refused by the network with
    ``MANDATE_MERCHANT_NOT_ALLOWED``. That is the point: the warrant's scope
    becomes the credential's scope rather than a claim about it.

    The returned ``iframe_url`` is single-use and expires in 15 minutes. It is
    handed back unopened and must stay that way — loading it once, even to check
    that it resolves, consumes it (``docs/PRAVA_NOTES.md`` §2.4).
    """

    if not isinstance(cleared, ClearedWarrant):
        raise TypeError(
            "request_session requires a ClearedWarrant minted by app.gate; "
            f"got {type(cleared).__name__}"
        )

    key = secret_key or os.environ.get(SECRET_KEY_ENV)
    if not key:
        raise PaymentUnavailable(
            f"{SECRET_KEY_ENV} is not set; no Prava session can be requested"
        )

    warrant = cleared.warrant
    authorization = warrant.authorization
    merchant = warrant.merchant

    async with PravaClient(secret_key=key, client=client) as prava:
        payload = await prava.create_mandate_session(
            user_id=user_id or os.environ.get(USER_ID_ENV) or DEFAULT_USER_ID,
            user_email=user_email or os.environ.get(USER_EMAIL_ENV) or DEFAULT_USER_EMAIL,
            total_amount=authorization.amount,
            merchant_name=merchant.resolved_name or merchant.domain,
            merchant_url=f"https://{merchant.domain}",
            description=authorization.description,
            unit_price=_unit_price(authorization.amount, authorization.quantity),
            quantity=authorization.quantity,
            currency=authorization.currency,
        )

    # Rebuilt from a known-safe list rather than filtered: the response also
    # carries a session_token bearer JWT, and a denylist is the wrong default
    # for a field set the API can extend without telling us.
    return {
        "session_id": payload.get("session_id"),
        "order_id": payload.get("order_id"),
        "iframe_url": payload.get("iframe_url"),
        "expires_at": payload.get("expires_at"),
        "warrant_id": warrant.warrant_id,
        "warrant_hash": cleared.warrant_hash,
        "approval": {
            "status": "AWAITING_HUMAN_APPROVAL",
            "mandate_id": None,
            "passkey": PASSKEY_STATUS,
            "notice": PASSKEY_NOTICE,
        },
    }


async def poll_session(
    session_id: str,
    *,
    secret_key: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Read a session's result, redacted.

    The mandate id only exists after a successful approval and has to be read
    back from here — the session response never carried one (§2.1). On failure
    the reason is on ``transactions[].error``, not at the top level (§3.1), so
    it is surfaced explicitly instead of leaving a reader with a bare
    ``status: failed``.
    """

    key = secret_key or os.environ.get(SECRET_KEY_ENV)
    if not key:
        raise PaymentUnavailable(f"{SECRET_KEY_ENV} is not set; no session can be polled")

    async with PravaClient(secret_key=key, client=client) as prava:
        payload = await prava.get_payment_result(session_id)

    return {
        "session_id": payload.get("session_id", session_id),
        "status": payload.get("status"),
        "mandate_id": _mandate_id(payload),
        "failure": _transaction_error(payload),
        "result": redact(payload),
    }


def _mandate_id(payload: dict[str, Any]) -> str | None:
    for key in ("mandate_id", "mandateId"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    for transaction in payload.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        for key in ("mandate_id", "mandateId"):
            value = transaction.get(key)
            if isinstance(value, str):
                return value
    return None


def _transaction_error(payload: dict[str, Any]) -> dict[str, Any] | None:
    for transaction in payload.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        error = transaction.get("error")
        if isinstance(error, dict):
            return {"code": error.get("code"), "message": error.get("message")}
    return None


__all__ = [
    "DEFAULT_USER_EMAIL",
    "DEFAULT_USER_ID",
    "PASSKEY_NOTICE",
    "PASSKEY_STATUS",
    "PaymentUnavailable",
    "SECRET_KEY_ENV",
    "is_configured",
    "poll_session",
    "request_session",
]
