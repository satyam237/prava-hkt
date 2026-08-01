"""Domain models for WARRANT.

The WARRANT document is the product's central artifact: a signed statement that a
merchant was verified and that spending was authorized against that verification,
narrowly scoped. Everything else in the system either produces one or reconciles
against one.

Two rules govern this module and are enforced, not merely documented:

1. **Money is never a float.** ``amount`` is a decimal string ("84.00"). Passing a
   ``float`` raises. Use ``str``, ``int`` or ``decimal.Decimal``.
2. **Every field must serialize deterministically.** The document is signed over
   its JSON serialization (see ``app.warrant.canonical_bytes``), so any value whose
   text form could differ between two implementations is forbidden on the wire.
   That is why ``score`` is a fixed 2-decimal string and ``Signal.value`` refuses
   floats: their shortest-round-trip formatting is language-specific.

See ``docs/WARRANT_SPEC.md`` for the wire format.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer

WARRANT_VERSION = "warrant/1"
WARRANT_ID_PREFIX = "wrt_"

# ---------------------------------------------------------------------------
# Scalar contracts
# ---------------------------------------------------------------------------

# Unsigned decimal, no leading zeros, no exponent, no thousands separators.
_MONEY_RE = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
# "sha256:<hex>" — algorithm kept open so probes may pick a different digest.
_CONTENT_HASH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*:[0-9a-f]+$")


def _coerce_money(value: Any) -> str:
    """Normalize an amount to an exact decimal string, rejecting floats.

    A ``str`` input is preserved verbatim, so "84.00" stays "84.00" and never
    collapses to "84.0" or "84".
    """
    if isinstance(value, bool):
        raise ValueError("amount must be a decimal string, not a bool")
    if isinstance(value, float):
        raise ValueError(
            "amount must not be a float; money never touches float. "
            "Pass a decimal string such as '84.00', an int, or a Decimal."
        )
    if isinstance(value, Decimal):
        value = format(value, "f")
    elif isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        raise ValueError(f"amount must be a decimal string, got {type(value).__name__}")
    if not _MONEY_RE.match(value):
        raise ValueError(
            f"amount {value!r} is not a canonical decimal string "
            "(expected e.g. '84.00': no sign, no leading zeros, no exponent)"
        )
    return value


def _coerce_score(value: Any) -> str:
    """Normalize a 0..1 score to a fixed 2-decimal string, e.g. 0.87 -> '0.87'.

    Floats are accepted here (a score is not money) but never survive onto the
    wire: they are quantized to two decimals so the signed bytes are identical
    regardless of the producer's float formatting.
    """
    if isinstance(value, bool):
        raise ValueError("score must be a number or decimal string, not a bool")
    try:
        if isinstance(value, Decimal):
            dec = value
        elif isinstance(value, (int, float, str)):
            dec = Decimal(str(value))
        else:
            raise ValueError(f"score must be a number or decimal string, got {type(value).__name__}")
    except InvalidOperation as exc:  # pragma: no cover - exercised via ValidationError
        raise ValueError(f"score {value!r} is not a valid decimal") from exc
    if not dec.is_finite():
        raise ValueError("score must be finite")
    if dec < 0 or dec > 1:
        raise ValueError(f"score must be between 0 and 1 inclusive, got {value!r}")
    return format(dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), "f")


def _coerce_currency(value: Any) -> str:
    if not isinstance(value, str) or not _CURRENCY_RE.match(value):
        raise ValueError(f"currency must be a 3-letter uppercase ISO 4217 code, got {value!r}")
    return value


def _coerce_content_hash(value: Any) -> str:
    if not isinstance(value, str) or not _CONTENT_HASH_RE.match(value):
        raise ValueError(
            f"content_hash must look like 'sha256:<lowercase hex>', got {value!r}"
        )
    return value


def _coerce_signal_value(value: Any) -> Any:
    """Reject floats in ``Signal.value``.

    Signal values land in the signed bytes. Float text formatting is not portable
    across languages, so probes must emit ints, strings or bools (stringify any
    fractional measurement themselves).
    """
    if isinstance(value, float):
        raise ValueError(
            "Signal.value must not be a float (its JSON text form is not portable); "
            "stringify it, e.g. '0.87'"
        )
    return value


def _normalize_utc(value: Any) -> Any:
    """Coerce a datetime to UTC at whole-second precision.

    Second precision is part of the wire contract: it removes any ambiguity about
    how sub-second digits are rendered. Naive datetimes are assumed to be UTC.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(microsecond=0)
    return value


def rfc3339z(value: datetime) -> str:
    """Render a UTC datetime as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return _normalize_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


MoneyStr = Annotated[str, BeforeValidator(_coerce_money)]
ScoreStr = Annotated[str, BeforeValidator(_coerce_score)]
CurrencyStr = Annotated[str, BeforeValidator(_coerce_currency)]
ContentHash = Annotated[str, BeforeValidator(_coerce_content_hash)]
SignalValue = Annotated[Union[bool, int, str, None], BeforeValidator(_coerce_signal_value)]
#: Carries its own JSON serializer, so any field declared ``UtcDatetime`` is
#: canonical by construction. Pydantic's default rendering would emit
#: "+00:00" and microseconds, which is a different set of signed bytes.
UtcDatetime = Annotated[
    datetime,
    BeforeValidator(_normalize_utc),
    PlainSerializer(rfc3339z, return_type=str, when_used="json"),
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def new_warrant_id() -> str:
    return WARRANT_ID_PREFIX + secrets.token_urlsafe(16)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """Gate outcome. HALT means no payment credential is ever requested."""

    PASS = "PASS"
    REVIEW = "REVIEW"
    HALT = "HALT"


class SignalStatus(str, Enum):
    """UNAVAILABLE is excluded from the score denominator, never scored as zero."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class BreachCode(str, Enum):
    AMOUNT_EXCEEDED = "AMOUNT_EXCEEDED"
    MERCHANT_MISMATCH = "MERCHANT_MISMATCH"
    ITEM_MISMATCH = "ITEM_MISMATCH"
    QUANTITY_MISMATCH = "QUANTITY_MISMATCH"
    NON_DELIVERY = "NON_DELIVERY"


class ReconciliationStatus(str, Enum):
    SETTLED = "SETTLED"
    BREACH = "BREACH"


SignalTier = Literal["A", "B", "C", "D"]


# ---------------------------------------------------------------------------
# The WARRANT document
# ---------------------------------------------------------------------------


class StrictModel(BaseModel):
    """Base for every model on the wire.

    ``extra="forbid"`` matters here: an unrecognized field in a signed document is
    either an attack or a version mismatch, and silently dropping it would let a
    reader and a signer disagree about what the document says.
    """

    model_config = ConfigDict(extra="forbid")


class Signal(StrictModel):
    """One verification observation.

    ``tier`` records how hard the signal is to forge (A = hardest), which is the
    only reason a reader should trust it.
    """

    name: str
    tier: SignalTier
    value: SignalValue = None
    status: SignalStatus


class Merchant(StrictModel):
    domain: str
    resolved_name: str | None = None


class Verification(StrictModel):
    verdict: Verdict
    score: ScoreStr
    signals: list[Signal] = Field(default_factory=list)
    content_hash: ContentHash


class Authorization(StrictModel):
    """What the credential is locked to. Read it as a clause, not a summary."""

    sku: str
    description: str
    quantity: int = Field(ge=1)
    amount: MoneyStr
    currency: CurrencyStr
    single_use: bool = True
    expected_fulfillment_by: UtcDatetime | None = None


class Warrant(StrictModel):
    """The signed document.

    ``signature`` is excluded from the signed bytes; every other field is included.
    Never mutate a Warrant after signing — build a new one and re-sign it.
    """

    version: Literal["warrant/1"] = WARRANT_VERSION
    warrant_id: str = Field(default_factory=new_warrant_id)
    merchant: Merchant
    verification: Verification
    authorization: Authorization
    issued_at: UtcDatetime = Field(default_factory=utcnow)
    signature: str | None = None


# ---------------------------------------------------------------------------
# Reconciliation (shapes fixed here; the diff logic lives in reconcile.py)
# ---------------------------------------------------------------------------


class Outcome(StrictModel):
    """The observed side: what actually happened after the credential was used.

    Fields mirror ``Authorization`` so reconciliation is a field-by-field diff.
    ``None`` means "not observed", which is distinct from "observed as zero".
    """

    warrant_id: str
    merchant_domain: str
    sku: str | None = None
    description: str | None = None
    quantity: int | None = None
    amount: MoneyStr | None = None
    currency: CurrencyStr | None = None
    delivered: bool | None = None
    order_id: str | None = None
    source: str | None = None
    observed_at: UtcDatetime = Field(default_factory=utcnow)


class Breach(StrictModel):
    """One way the outcome departed from the warrant.

    ``expected`` and ``observed`` are rendered strings so a breach is readable
    without knowing the field's type.
    """

    code: BreachCode
    expected: str | None = None
    observed: str | None = None
    detail: str | None = None


class Reconciliation(StrictModel):
    warrant_id: str
    status: ReconciliationStatus
    breaches: list[Breach] = Field(default_factory=list)
    reconciled_at: UtcDatetime = Field(default_factory=utcnow)


__all__ = [
    "WARRANT_VERSION",
    "WARRANT_ID_PREFIX",
    "Authorization",
    "Breach",
    "BreachCode",
    "ContentHash",
    "CurrencyStr",
    "Merchant",
    "MoneyStr",
    "Outcome",
    "Reconciliation",
    "ReconciliationStatus",
    "ScoreStr",
    "Signal",
    "StrictModel",
    "SignalStatus",
    "SignalTier",
    "SignalValue",
    "UtcDatetime",
    "Verdict",
    "Verification",
    "Warrant",
    "new_warrant_id",
    "rfc3339z",
    "utcnow",
]
