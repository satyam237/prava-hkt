"""Deterministic reconciliation of an observed outcome against a signed WARRANT.

There is no model in this path, and that is the point. A dispute evidence packet
whose logic is a language model is worthless in a dispute: the opposing party
asks "why did it decide that" and there is no answer beyond a sampled token.
Every function here is a pure comparison over two documents, so the same inputs
produce the same breaches on any machine, in any year.

Where the observed side comes from
----------------------------------
From the **merchant**, not from Prava. Prava's payment result is an echo of the
``purchase_context`` we sent at session creation — ``merchant_details.name``
comes back as ``line_items[].merchant_name``, ``product_details[].quantity`` as
``products[].quantity``, and so on — so diffing a warrant against it compares a
document to itself and always settles. Prava issues tokens; it never observes
what the merchant ships or bills, and structurally cannot report it.
``docs/PRAVA_NOTES.md`` records ``products: []`` coming back empty on a real
failed transaction, which is the same limit seen from the other side.

So the honest architecture is the real-world one: reconcile the merchant's own
order confirmation against what the agent authorized.

Two classes of breach
---------------------
**PREVENTED** — the charge was refused before money moved. An over-cap charge is
refused with ``THRESHOLD_EXCEEDED`` (the cap is enforced at the card network), a
charge outside a ``listed``-scope mandate with ``MANDATE_MERCHANT_NOT_ALLOWED``.
The evidence is Prava's own error response. Nothing to dispute; the control held.

**DETECTED** — the charge succeeded *within* the cap and the merchant then
delivered something other than what was authorized: wrong SKU, wrong quantity,
nothing at all. No network control can see this. It is what post-hoc
reconciliation exists for, and the only reason to sign a dispute packet.

See ``docs/WARRANT_SPEC.md`` for the wire format of both signed documents.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import (
    Breach,
    BreachCode,
    BreachProvenance,
    DisputePacket,
    Outcome,
    Reconciliation,
    ReconciliationStatus,
    Warrant,
    rfc3339z,
    utcnow,
)
from app.warrant import sign_document

#: Prava error codes that refuse a charge outright, and the breach each one
#: proves. A refusal is evidence of an attempt, so it produces a breach even
#: though no money moved. Codes are those in ``PravaErrorCode``; anything else
#: is a transport or auth failure and says nothing about the merchant.
REFUSAL_BREACH_CODES: dict[str, BreachCode] = {
    "THRESHOLD_EXCEEDED": BreachCode.AMOUNT_EXCEEDED,
    "MANDATE_MERCHANT_NOT_ALLOWED": BreachCode.MERCHANT_MISMATCH,
}

#: Order statuses that say something about fulfillment. ``CONFIRMED`` says the
#: merchant accepted the order and nothing about whether it shipped, so it maps
#: to ``None`` — unobserved — rather than being read as delivery. Any status not
#: listed is likewise unobserved; guessing would manufacture evidence.
DELIVERY_BY_STATUS: dict[str | None, bool] = {
    "FULFILLED": True,
    "DELIVERED": True,
    "SHIPPED": True,
    "UNFULFILLED": False,
    "CANCELLED": False,
    "REFUNDED": False,
}


def normalize_domain(domain: str) -> str:
    """Fold a domain for comparison. DNS is case-insensitive; a warrant is not."""
    return domain.strip().rstrip(".").lower()


# ---------------------------------------------------------------------------
# The diff
# ---------------------------------------------------------------------------


def _amount_breach(warrant: Warrant, outcome: Outcome) -> Breach | None:
    """Over the authorized amount, or billed in a currency we never authorized.

    Comparison is on ``Decimal``, never float, and only *exceeding* the amount
    is a breach — an authorization is a ceiling, so being charged less than it
    is the merchant's business, not ours.
    """
    if outcome.amount is None:
        return None
    authorized = warrant.authorization.amount

    if outcome.currency is not None and outcome.currency != warrant.authorization.currency:
        # Amounts in different currencies are not comparable, and an
        # authorization for USD permits zero of anything else.
        return Breach(
            code=BreachCode.AMOUNT_EXCEEDED,
            expected=f"{authorized} {warrant.authorization.currency}",
            observed=f"{outcome.amount} {outcome.currency}",
            detail="charged in a currency the warrant does not authorize",
        )

    if Decimal(outcome.amount) > Decimal(authorized):
        return Breach(
            code=BreachCode.AMOUNT_EXCEEDED,
            expected=authorized,
            observed=outcome.amount,
        )
    return None


def _merchant_breach(warrant: Warrant, outcome: Outcome) -> Breach | None:
    if normalize_domain(outcome.merchant_domain) == normalize_domain(warrant.merchant.domain):
        return None
    return Breach(
        code=BreachCode.MERCHANT_MISMATCH,
        expected=warrant.merchant.domain,
        observed=outcome.merchant_domain,
    )


def _item_breach(warrant: Warrant, outcome: Outcome) -> Breach | None:
    if outcome.sku is None or outcome.sku == warrant.authorization.sku:
        return None
    return Breach(
        code=BreachCode.ITEM_MISMATCH,
        expected=warrant.authorization.sku,
        observed=outcome.sku,
        detail=outcome.description,
    )


def _quantity_breach(warrant: Warrant, outcome: Outcome) -> Breach | None:
    """Any departure, in either direction.

    Under-delivery is as much a departure from the authorization as
    over-delivery; the warrant names one quantity, not an upper bound.
    """
    if outcome.quantity is None or outcome.quantity == warrant.authorization.quantity:
        return None
    return Breach(
        code=BreachCode.QUANTITY_MISMATCH,
        expected=str(warrant.authorization.quantity),
        observed=str(outcome.quantity),
    )


def _delivery_breach(warrant: Warrant, outcome: Outcome, now: datetime) -> Breach | None:
    """Undelivered past the deadline the warrant set.

    ``delivered is None`` means nobody observed delivery either way, which is
    not the same as observing that it did not happen — a false breach in an
    evidence packet costs more than a missed one. An authorization with no
    ``expected_fulfillment_by`` is open-ended and can never be late.
    """
    if outcome.delivered is not False:
        return None
    deadline = warrant.authorization.expected_fulfillment_by
    if deadline is None or now < deadline:
        return None
    return Breach(
        code=BreachCode.NON_DELIVERY,
        expected=f"delivered by {rfc3339z(deadline)}",
        observed="not delivered",
    )


def reconcile(
    warrant: Warrant,
    outcome: Outcome,
    *,
    provenance: BreachProvenance = BreachProvenance.DETECTED,
    evidence: str | None = None,
    now: datetime | None = None,
) -> Reconciliation:
    """Diff an observed outcome against a signed warrant.

    Pure and total: no clock unless ``now`` is omitted, no network, no state.
    Every breach found is stamped with ``provenance`` — the caller knows whether
    the charge went through, the comparison cannot.
    """
    at = utcnow() if now is None else now
    found = [
        breach
        for breach in (
            _amount_breach(warrant, outcome),
            _merchant_breach(warrant, outcome),
            _item_breach(warrant, outcome),
            _quantity_breach(warrant, outcome),
            _delivery_breach(warrant, outcome, at),
        )
        if breach is not None
    ]
    breaches = [
        breach.model_copy(update={"provenance": provenance, "evidence": evidence})
        for breach in found
    ]
    return Reconciliation(
        warrant_id=warrant.warrant_id,
        status=ReconciliationStatus.BREACH if breaches else ReconciliationStatus.SETTLED,
        breaches=breaches,
        reconciled_at=at,
    )


def reconcile_refusal(
    warrant: Warrant,
    outcome: Outcome,
    error_code: str,
    *,
    detail: str | None = None,
    now: datetime | None = None,
) -> Reconciliation:
    """Record a charge that Prava or the card network refused.

    ``error_code`` is the code Prava returned (``PravaError.code``), and it is
    the evidence: the cap and the merchant scope are enforced outside this
    process, so the refusal proves the breach in a way our own arithmetic
    cannot. The same diff runs over what was attempted, but every breach is
    PREVENTED — money never moved and there is nothing to dispute.

    If the diff comes back clean the refusal still stands, so the code's own
    breach is recorded rather than reporting a refused charge as SETTLED.
    """
    result = reconcile(
        warrant,
        outcome,
        provenance=BreachProvenance.PREVENTED,
        evidence=error_code,
        now=now,
    )
    if result.breaches:
        return result

    asserted = REFUSAL_BREACH_CODES.get(error_code)
    if asserted is None:
        return result
    return result.model_copy(
        update={
            "status": ReconciliationStatus.BREACH,
            "breaches": [
                Breach(
                    code=asserted,
                    provenance=BreachProvenance.PREVENTED,
                    expected=warrant.authorization.amount
                    if asserted is BreachCode.AMOUNT_EXCEEDED
                    else warrant.merchant.domain,
                    observed=None,
                    evidence=error_code,
                    detail=detail or "refused by Prava; the local diff found nothing",
                )
            ],
        }
    )


# ---------------------------------------------------------------------------
# Merchant receipt -> Outcome
# ---------------------------------------------------------------------------


def outcome_from_receipt(
    receipt: Mapping[str, Any],
    warrant: Warrant,
    *,
    source: str | None = None,
) -> Outcome:
    """Fold a merchant's order receipt into the flat shape the diff compares.

    A warrant authorizes exactly one line, so the receipt is folded to one: the
    line matching the authorized SKU if the merchant shipped it, otherwise the
    first line, which is what surfaces a substituted item as ITEM_MISMATCH.
    ``amount`` is the receipt's own total, not the line, because the total is
    what the merchant actually billed.

    Values are taken verbatim as strings. Nothing here parses money into a float
    — ``Outcome`` would reject it, and a receipt's "84.00" must stay "84.00".
    """
    line_items = receipt.get("line_items") or []
    line: Mapping[str, Any] = {}
    for candidate in line_items:
        if isinstance(candidate, Mapping) and candidate.get("sku") == warrant.authorization.sku:
            line = candidate
            break
    else:
        if line_items and isinstance(line_items[0], Mapping):
            line = line_items[0]

    return Outcome(
        warrant_id=warrant.warrant_id,
        merchant_domain=receipt.get("merchant_domain") or warrant.merchant.domain,
        sku=line.get("sku"),
        description=line.get("description"),
        quantity=line.get("quantity"),
        amount=receipt.get("amount_charged"),
        currency=receipt.get("currency"),
        delivered=DELIVERY_BY_STATUS.get(receipt.get("status")),
        order_id=receipt.get("order_id"),
        source=source or "merchant_receipt",
        fulfilled_at=receipt.get("fulfilled_at"),
    )


# ---------------------------------------------------------------------------
# Dispute packet
# ---------------------------------------------------------------------------


def build_dispute_packet(
    warrant: Warrant,
    outcome: Outcome,
    reconciliation: Reconciliation,
    *,
    issued_at: datetime | None = None,
) -> DisputePacket:
    """Assemble the unsigned packet. ``warrant`` must already be signed.

    Refusing an unsigned warrant is the whole value of the chain: a packet whose
    inner document cannot be verified proves only that we said so twice.
    """
    if not warrant.signature:
        raise ValueError("cannot build a dispute packet around an unsigned warrant")
    if reconciliation.warrant_id != warrant.warrant_id:
        raise ValueError(
            f"reconciliation is for {reconciliation.warrant_id}, "
            f"not {warrant.warrant_id}"
        )
    if outcome.warrant_id != warrant.warrant_id:
        raise ValueError(
            f"outcome is for {outcome.warrant_id}, not {warrant.warrant_id}"
        )
    return DisputePacket(
        warrant=warrant,
        outcome=outcome,
        reconciliation=reconciliation,
        issued_at=utcnow() if issued_at is None else issued_at,
    )


def sign_dispute_packet(
    packet: DisputePacket, private_key: Ed25519PrivateKey | None = None
) -> DisputePacket:
    """Sign the packet. The embedded warrant's own signature is inside the bytes."""
    return sign_document(packet, private_key)


__all__ = [
    "DELIVERY_BY_STATUS",
    "REFUSAL_BREACH_CODES",
    "build_dispute_packet",
    "normalize_domain",
    "outcome_from_receipt",
    "reconcile",
    "reconcile_refusal",
    "sign_dispute_packet",
]
