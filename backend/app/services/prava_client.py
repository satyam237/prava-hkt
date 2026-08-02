"""The single door to the Prava API.

Every Prava call in this project goes through :class:`PravaClient`. Two reasons
that matters more than tidiness:

1. **Money is never a float.** Prava takes and returns amounts as decimal
   strings and so do we, end to end. ``float("84.00")`` would round-trip as
   ``84.0``, and an authorization that says ``84.0`` is not the one the user
   approved. :func:`_money` is the only place an amount is normalized.
2. **Failures must stay distinguishable.** Reconciliation cares a great deal
   whether a charge was refused because it exceeded the mandate cap
   (``THRESHOLD_EXCEEDED``) or because it targeted a merchant outside the
   mandate's scope (``MANDATE_MERCHANT_NOT_ALLOWED``). A bare ``httpx`` error
   or a stringly-typed message loses that distinction, so each documented code
   maps to a named exception.

Nothing here logs a credential. Tokens, dynamic CVVs and API keys are redacted
by :func:`redact` before they can reach a log line or a traceback.
"""

from __future__ import annotations

import re
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping

import httpx

SANDBOX_BASE_URL = "https://sandbox.api.prava.space"

# Prava sessions expire 15 minutes after creation; a `one_time` mandate is
# clamped to 7 days regardless of any `valid_until` we send.
SESSION_TTL_SECONDS = 15 * 60

# Unsigned decimal, at most 2 fractional digits — Prava rejects more.
_MONEY_RE = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$")

# Field names that must never appear in a log, a repr, or an exception message.
# Matched exactly after lowercasing and stripping underscores.
_SECRET_KEYS = frozenset(
    {
        "token",
        "sessiontoken",
        "accesstoken",
        "refreshtoken",
        "dynamiccvv",
        "cvv",
        "authorization",
        "secretkey",
        "publishablekey",
        "apikey",
        "expirymonth",
        "expiryyear",
        "cardnumber",
        "pan",
    }
)

# Substrings that make a field secret regardless of its exact spelling. The
# live sandbox returned an undocumented `session_token` JWT that an
# exact-match list did not catch, so the fallback matters: an unredacted
# credential in a log is not a bug we get to find later.
_SECRET_SUBSTRINGS = ("token", "secret", "cvv", "password", "credential")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PravaErrorCode(str, Enum):
    """Error codes documented by Prava, plus two we raise ourselves.

    Only codes we have actually seen documented are listed. An undocumented
    code from the API surfaces as a plain :class:`PravaError` carrying the raw
    string, rather than being coerced into a category it may not belong to.
    """

    THRESHOLD_EXCEEDED = "THRESHOLD_EXCEEDED"
    #: Live sandbox over-cap (docs/PRAVA_NOTES.md §5.4): HTTP 200 + this code,
    #: not ``THRESHOLD_EXCEEDED``. Mapped to :class:`PravaThresholdExceeded`.
    DECLINED = "DECLINED"
    MANDATE_MERCHANT_NOT_ALLOWED = "MANDATE_MERCHANT_NOT_ALLOWED"
    MANDATE_NOT_FOUND = "MANDATE_NOT_FOUND"
    MANDATE_FORBIDDEN = "MANDATE_FORBIDDEN"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    VAL_2001 = "VAL_2001"

    # Client-side, never returned by Prava.
    TIMEOUT = "CLIENT_TIMEOUT"
    TRANSPORT = "CLIENT_TRANSPORT"


class PravaError(Exception):
    """Base for every failure crossing this module's boundary.

    Carries the HTTP status and the API's own ``code``/``message`` so a caller
    can branch on facts rather than parse prose. ``httpx`` exceptions never
    escape; they are wrapped in :class:`PravaTimeout` or
    :class:`PravaTransportError`.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        # Redacted at construction: an exception commonly ends up in a log.
        self.payload: dict[str, Any] = redact(payload) if payload else {}

    def __str__(self) -> str:
        parts = [self.message]
        if self.code:
            parts.append(f"code={self.code}")
        if self.status_code is not None:
            parts.append(f"status={self.status_code}")
        return " ".join(parts)


class PravaAuthRequired(PravaError):
    """401 ``AUTH_REQUIRED`` — the secret key is missing, wrong, or revoked."""


class PravaForbidden(PravaError):
    """403 ``MANDATE_FORBIDDEN`` — the key may not act on this mandate."""


class PravaMandateNotFound(PravaError):
    """404 ``MANDATE_NOT_FOUND`` — no such mandate for this key."""


class PravaMerchantNotAllowed(PravaError):
    """403 ``MANDATE_MERCHANT_NOT_ALLOWED``.

    The mandate was created with ``merchant_scope: "listed"`` and the charge
    named a different merchant. For Warrant this is the interesting one: it is
    the network refusing a substitution we would otherwise have to detect
    ourselves.
    """


class PravaThresholdExceeded(PravaError):
    """Over the mandate's authorized cap.

    Documented as ``THRESHOLD_EXCEEDED``; the live sandbox returns HTTP 200
    with ``errorCode: "DECLINED"`` and a message naming the cumulative
    threshold (``docs/PRAVA_NOTES.md`` §5.4). Both codes raise this type.
    """


class PravaValidationError(PravaError):
    """``VAL_2001`` — the request body failed Prava's validation."""


class PravaTimeout(PravaError):
    """A request exceeded its timeout. Retrying a charge needs a ``reference``."""


class PravaTransportError(PravaError):
    """Connection-level failure — DNS, TLS, refused connection."""


_CODE_TO_EXC: dict[str, type[PravaError]] = {
    PravaErrorCode.AUTH_REQUIRED.value: PravaAuthRequired,
    PravaErrorCode.MANDATE_FORBIDDEN.value: PravaForbidden,
    PravaErrorCode.MANDATE_NOT_FOUND.value: PravaMandateNotFound,
    PravaErrorCode.MANDATE_MERCHANT_NOT_ALLOWED.value: PravaMerchantNotAllowed,
    PravaErrorCode.THRESHOLD_EXCEEDED.value: PravaThresholdExceeded,
    PravaErrorCode.DECLINED.value: PravaThresholdExceeded,
    PravaErrorCode.VAL_2001.value: PravaValidationError,
}

# Used when the body carries no recognizable code — the status is all we have.
_STATUS_TO_EXC: dict[int, type[PravaError]] = {
    401: PravaAuthRequired,
    403: PravaForbidden,
    404: PravaMandateNotFound,
    422: PravaValidationError,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _money(value: Any, field: str = "amount") -> str:
    """Normalize an amount to a decimal string with at most 2 decimal places.

    Floats are rejected outright rather than converted: by the time a float
    holds an amount the exact value the user approved is already gone, and
    guessing at it here would hide the bug instead of surfacing it.
    """
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a decimal string, not a bool")
    if isinstance(value, float):
        raise ValueError(
            f"{field} must not be a float; money never touches float. "
            "Pass a decimal string such as '84.00', an int, or a Decimal."
        )
    if isinstance(value, Decimal):
        value = format(value, "f")
    elif isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        raise ValueError(
            f"{field} must be a decimal string, got {type(value).__name__}"
        )
    if not _MONEY_RE.match(value):
        raise ValueError(
            f"{field} {value!r} is not a valid Prava amount "
            "(expected e.g. '84.00': unsigned, max 2 decimal places, no exponent)"
        )
    return value


def redact(value: Any) -> Any:
    """Recursively blank out credential-bearing fields.

    Applied to anything that might be printed, logged, or attached to an
    exception. Card credentials are the whole point of this system; leaking one
    into a log file would be worse than the failure being diagnosed.
    """
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, inner in value.items():
            if isinstance(key, str) and _is_secret_key(key):
                out[key] = _mask(inner)
            else:
                out[key] = redact(inner)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _is_secret_key(key: str) -> bool:
    """True if a field name names a credential.

    Deliberately over-broad. A false positive redacts something harmless; a
    false negative writes a live credential to disk.
    """
    normalized = key.lower().replace("_", "").replace("-", "")
    if normalized in _SECRET_KEYS:
        return True
    return any(fragment in normalized for fragment in _SECRET_SUBSTRINGS)


def _mask(value: Any) -> str:
    """Render a secret as a length-preserving stub, never the value itself."""
    if value is None:
        return "<none>"
    text = str(value)
    return f"<redacted:{len(text)}chars>"


def key_fingerprint(key: str) -> str:
    """First 8 characters of a key, for confirming *which* key is in use.

    8 characters is enough to tell ``sk_test_`` from ``sk_live_`` and to match
    against a dashboard entry, and short enough to be useless to a thief.
    """
    return key[:8] if key else "<empty>"


def _merchant_context(
    *,
    merchant_name: str,
    merchant_url: str,
    country_code_iso2: str,
    description: str,
    unit_price: str,
    quantity: int,
) -> dict[str, Any]:
    """Build the single-entry ``purchase_context`` Prava accepts.

    Exactly one entry: Prava does not support multi-merchant sessions, and a
    second entry is rejected rather than silently ignored.
    """
    return {
        "merchant_details": {
            "name": merchant_name,
            "url": merchant_url,
            "country_code_iso2": country_code_iso2,
        },
        "product_details": [
            {
                "description": description,
                "unit_price": _money(unit_price, "unit_price"),
                "quantity": quantity,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class PravaClient:
    """Async client for the Prava sandbox/production API.

    Use as an async context manager so the underlying connection pool is
    closed::

        async with PravaClient(secret_key=key) as prava:
            await prava.health()
    """

    def __init__(
        self,
        secret_key: str,
        *,
        base_url: str = SANDBOX_BASE_URL,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not secret_key:
            raise ValueError("secret_key is required (set PRAVA_SECRET_KEY)")
        self._secret_key = secret_key
        self.base_url = base_url.rstrip("/")
        # Explicit per-phase budget. A default-less httpx client waits forever
        # on a half-open connection, which for a charge means we never learn
        # whether money moved.
        self.timeout = httpx.Timeout(timeout, connect=10.0)
        self._client = client
        self._owns_client = client is None

    @property
    def key_fingerprint(self) -> str:
        """Which key is in use, safely — first 8 chars only."""
        return key_fingerprint(self._secret_key)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers={
                    "Authorization": f"Bearer {self._secret_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        return self._client

    async def __aenter__(self) -> "PravaClient":
        self._http()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # -- transport ---------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Issue one request and return its decoded body, or raise a PravaError.

        An injected test client may lack ``base_url``, so the URL is joined
        here rather than relying on the client's own base.
        """
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        kwargs: dict[str, Any] = {}
        if json is not None:
            kwargs["json"] = json
        if params is not None:
            kwargs["params"] = dict(params)
        if timeout is not None:
            kwargs["timeout"] = httpx.Timeout(timeout, connect=10.0)

        try:
            response = await self._http().request(
                method,
                url,
                headers={"Authorization": f"Bearer {self._secret_key}"},
                **kwargs,
            )
        except httpx.TimeoutException as exc:
            raise PravaTimeout(
                f"{method} {path} timed out",
                code=PravaErrorCode.TIMEOUT.value,
            ) from exc
        except httpx.HTTPError as exc:
            raise PravaTransportError(
                f"{method} {path} failed at the transport layer: {type(exc).__name__}",
                code=PravaErrorCode.TRANSPORT.value,
            ) from exc

        return self._decode(response, method=method, path=path)

    def _decode(
        self, response: httpx.Response, *, method: str, path: str
    ) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            body = None

        if not isinstance(body, dict):
            body = {"raw": body} if body is not None else {}

        if response.is_success:
            return body

        code, message = _extract_error(body)
        exc_type = _CODE_TO_EXC.get(code or "") or _STATUS_TO_EXC.get(
            response.status_code, PravaError
        )
        raise exc_type(
            message or f"{method} {path} failed",
            status_code=response.status_code,
            code=code,
            payload=body,
        )

    # -- endpoints ---------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """``GET /health`` → ``{"status": "ok", "timestamp": ...}``.

        Short timeout on purpose: this is the liveness probe, and a slow health
        check is a failed health check.
        """
        return await self._request("GET", "/health", timeout=10.0)

    async def create_mandate_session(
        self,
        *,
        user_id: str,
        user_email: str,
        total_amount: Any,
        merchant_name: str,
        merchant_url: str,
        description: str,
        unit_price: Any | None = None,
        quantity: int = 1,
        currency: str = "USD",
        country_code_iso2: str = "US",
        recurring_frequency: str = "one_time",
        merchant_scope: str = "listed",
        max_charges: int = 1,
        integration_type: str = "full_checkout",
        callback_url: str | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/sessions`` with ``mandate_setup`` — create a mandate.

        There is no ``POST /v1/mandates``; a mandate is created by opening a
        session in authorize-only mode. The response carries ``iframe_url`` and
        ``authorizeOnly: true`` and issues **no** credentials — credentials come
        later, from :meth:`charge_mandate`.

        ``merchant_scope="listed"`` locks the mandate to the named merchant, so
        a charge elsewhere is refused with ``MANDATE_MERCHANT_NOT_ALLOWED``.
        That is the enforcement Warrant leans on, so it is the default here.

        ``total_amount`` becomes the authorized cap. ``unit_price`` defaults to
        it, which is right for the single-product case and wrong the moment
        ``quantity`` exceeds 1 — pass it explicitly then.

        ``integration_type`` defaults to ``full_checkout`` (hosted redirect),
        matching the documented CURL example. ``callback_url`` must be https
        when set.
        """
        if not 1 <= len(user_id) <= 255:
            raise ValueError("user_id must be 1–255 characters")
        if quantity < 1:
            raise ValueError("quantity must be at least 1")
        if integration_type not in {"full_checkout", "embedding"}:
            raise ValueError("integration_type must be 'full_checkout' or 'embedding'")
        if callback_url is not None and not callback_url.startswith("https://"):
            raise ValueError("callback_url must use https")

        total = _money(total_amount, "total_amount")
        unit = _money(total if unit_price is None else unit_price, "unit_price")

        body: dict[str, Any] = {
            "user_id": user_id,
            "user_email": user_email,
            "total_amount": total,
            "currency": currency.upper(),
            "purchase_context": [
                _merchant_context(
                    merchant_name=merchant_name,
                    merchant_url=merchant_url,
                    country_code_iso2=country_code_iso2,
                    description=description,
                    unit_price=unit,
                    quantity=quantity,
                )
            ],
            "integration_type": integration_type,
            "mandate_setup": {
                "intent": "mandate_setup",
                "recurring_frequency": recurring_frequency,
                "merchant_scope": merchant_scope,
                "max_charges": max_charges,
            },
        }
        if callback_url is not None:
            body["callback_url"] = callback_url
        return await self._request("POST", "/v1/sessions", json=body)

    async def get_payment_result(self, session_id: str) -> dict[str, Any]:
        """``GET /v1/sessions/{id}/payment-result`` — poll a session.

        ``token`` and ``dynamic_cvv`` appear on line items **only** while status
        is ``awaiting_result``; once it moves on they are gone for good.
        """
        return await self._request(
            "GET", f"/v1/sessions/{session_id}/payment-result", timeout=20.0
        )

    async def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        """``GET /v1/mandates/{id}`` — the reconciliation source of truth.

        Returns ``approvedAmount``, ``currency``, ``status``, ``spent``,
        ``chargeCount`` and ``charges[]``. This is network-side accounting we
        did not author, which is exactly why reconciliation reads it instead of
        trusting our own ledger.
        """
        return await self._request("GET", f"/v1/mandates/{mandate_id}", timeout=20.0)

    async def charge_mandate(
        self,
        mandate_id: str,
        amount: Any,
        *,
        reference: str | None = None,
        purchase_context: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/mandates/{id}/charge`` — draw against a mandate.

        Secret-key auth, no passkey. Pass a ``reference`` for anything that
        moves money: it is the idempotency key, and replaying the same
        (mandate, reference) returns the original charge with
        ``deduplicated: true`` instead of charging twice. A timeout without one
        leaves you unable to tell a lost response from a lost charge.

        Omit ``purchase_context`` to reuse the mandate's setup context. When
        given it must hold exactly one entry; currency always comes from the
        mandate and is not sent here.

        The per-charge cap is enforced by the card network, so an over-cap
        amount raises :class:`PravaThresholdExceeded` from this call rather
        than failing a local check.
        """
        body: dict[str, Any] = {"amount": _money(amount)}
        if reference is not None:
            body["reference"] = reference
        if purchase_context is not None:
            if len(purchase_context) != 1:
                raise ValueError(
                    "purchase_context must hold exactly one entry; "
                    "Prava does not support multi-merchant charges"
                )
            body["purchase_context"] = purchase_context

        result = await self._request(
            "POST", f"/v1/mandates/{mandate_id}/charge", json=body, timeout=60.0
        )
        # Live over-cap: HTTP 200 + status failed + DECLINED (§5.4). Raise so
        # callers do not treat a refused charge as credentials issued.
        if result.get("status") == "failed" or result.get("fetchStatus") == "FAILURE":
            code, message = _extract_error(result)
            exc_type = _CODE_TO_EXC.get(code or "") or PravaError
            raise exc_type(
                message or f"POST /v1/mandates/{mandate_id}/charge failed",
                status_code=200,
                code=code,
                payload=result,
            )
        return result

    async def list_mandates(
        self,
        *,
        external_user_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """``GET /v1/mandates`` — discover mandates after passkey approval.

        Payment-result after mandate-setup stays ``processing`` with no
        ``mandate_id`` (§5.1–§5.2). Filter by ``externalUserId`` + ``status``.
        """

        params: dict[str, str] = {}
        if external_user_id is not None:
            params["externalUserId"] = external_user_id
        if status is not None:
            params["status"] = status
        body = await self._request(
            "GET", "/v1/mandates", params=params or None, timeout=20.0
        )
        raw = body.get("raw")
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        for key in ("mandates", "data", "items"):
            value = body.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if isinstance(body.get("id"), str):
            return [body]
        return []

    async def report_status(
        self, session_id: str, txn_ref_id: str, txn_status: str
    ) -> dict[str, Any]:
        """``POST /v1/sessions/{id}/report-status`` — close the loop.

        Report every outcome, approved or declined. Prava has no other way to
        learn whether the credential it issued was actually accepted, and an
        unreported transaction stays open on their side.
        """
        status = txn_status.upper()
        if status not in {"APPROVED", "DECLINED"}:
            raise ValueError("txn_status must be 'APPROVED' or 'DECLINED'")
        return await self._request(
            "POST",
            f"/v1/sessions/{session_id}/report-status",
            json={"txn_ref_id": txn_ref_id, "txn_status": status},
        )

    async def revoke_session(self, session_id: str) -> dict[str, Any]:
        """``POST /v1/sessions/{id}/revoke`` — end a session before it is used.

        Only sessions that have not yet completed are revocable; a completed or
        expired one returns ``400 INVALID_STATE``. Sessions also expire on their
        own after 15 minutes (:data:`SESSION_TTL_SECONDS`), so revoking is about
        closing the approval window early, not about cleanup.
        """
        return await self._request("POST", f"/v1/sessions/{session_id}/revoke")


def _extract_error(body: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Pull ``(code, message)` out of an error body.

    Prava returns errors in more than one shape: ``errorCode``/``errorMessage``
    on a charge, a nested ``error {code, message}`` on a session result, and a
    flat ``code``/``message`` elsewhere. All three are checked so a caller
    always gets a code when the API supplied one.
    """
    nested = body.get("error")
    if isinstance(nested, Mapping):
        code = nested.get("code") or nested.get("errorCode")
        message = nested.get("message") or nested.get("errorMessage")
        if code or message:
            return _as_str(code), _as_str(message)

    code = body.get("errorCode") or body.get("code")
    message = body.get("errorMessage") or body.get("message") or body.get("detail")
    return _as_str(code), _as_str(message)


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


__all__ = [
    "SANDBOX_BASE_URL",
    "SESSION_TTL_SECONDS",
    "PravaClient",
    "PravaError",
    "PravaErrorCode",
    "PravaAuthRequired",
    "PravaForbidden",
    "PravaMandateNotFound",
    "PravaMerchantNotAllowed",
    "PravaThresholdExceeded",
    "PravaValidationError",
    "PravaTimeout",
    "PravaTransportError",
    "redact",
    "key_fingerprint",
]
