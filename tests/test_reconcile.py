"""Reconciliation: the deterministic diff, and the signed dispute packet.

The demo-critical cases are ``test_over_delivery_is_the_demo_breach`` and
``test_an_honest_receipt_settles``. Both run against the breach merchant's own
receipt builder rather than a hand-copied fixture, so the two halves cannot
drift apart without a test noticing.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.models import (
    Authorization,
    BreachCode,
    BreachProvenance,
    DisputePacket,
    Merchant,
    Outcome,
    ReconciliationStatus,
    Warrant,
)
from app.reconcile import (
    build_dispute_packet,
    normalize_domain,
    outcome_from_receipt,
    reconcile,
    reconcile_refusal,
    sign_dispute_packet,
)
from app.warrant import canonical_bytes, sign_warrant, verify_warrant

from conftest import REPO_ROOT, build_warrant

DEADLINE = datetime(2026, 8, 12, 0, 0, 0, tzinfo=timezone.utc)
BEFORE_DEADLINE = DEADLINE - timedelta(days=1)
AFTER_DEADLINE = DEADLINE + timedelta(days=1)


@pytest.fixture(scope="module")
def merchant_receipt():
    """The breach merchant's real receipt builder, imported without its web app.

    ``merchants/`` has its own virtualenv, so the module deliberately imports
    nothing beyond the standard library and can be loaded from here by path.
    """
    path = REPO_ROOT / "merchants" / "breach" / "receipt.py"
    spec = importlib.util.spec_from_file_location("breach_receipt", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def breach_warrant(merchant_receipt) -> Warrant:
    """A warrant for the breach merchant's own product: 1 unit at 84.00."""
    return build_warrant(
        merchant=Merchant(
            domain=merchant_receipt.MERCHANT_DOMAIN, resolved_name="Northstar Supply"
        ),
        authorization=Authorization(
            sku=merchant_receipt.PRODUCT["sku"],
            description=merchant_receipt.PRODUCT["name"],
            quantity=merchant_receipt.PRODUCT["authorized_quantity"],
            amount=merchant_receipt.money(merchant_receipt.PRODUCT["price"]),
            currency=merchant_receipt.CURRENCY,
            single_use=True,
            expected_fulfillment_by=DEADLINE,
        ),
    )


def outcome(**overrides) -> Outcome:
    """An outcome that matches the fixture warrant exactly."""
    fields = dict(
        warrant_id="wrt_TESTFIXTURE0000000000",
        merchant_domain="ridge.com",
        sku="RW-TITAN-01",
        description="Ridge Titanium Wallet, Raw",
        quantity=1,
        amount="84.00",
        currency="USD",
        delivered=True,
        order_id="ord_123",
        source="merchant_receipt",
        observed_at=datetime(2026, 8, 3, 9, 0, 0, tzinfo=timezone.utc),
    )
    fields.update(overrides)
    return Outcome(**fields)


def codes(reconciliation) -> list[str]:
    return [breach.code.value for breach in reconciliation.breaches]


# ---------------------------------------------------------------------------
# The diff
# ---------------------------------------------------------------------------


def test_an_exact_match_settles(warrant):
    result = reconcile(warrant, outcome(), now=AFTER_DEADLINE)
    assert result.status is ReconciliationStatus.SETTLED
    assert result.breaches == []
    assert result.warrant_id == warrant.warrant_id


def test_over_delivery_is_the_demo_breach(warrant):
    """Authorized 1 unit at 84.00; the merchant billed 12 units at 1008.00."""
    result = reconcile(warrant, outcome(quantity=12, amount="1008.00"), now=BEFORE_DEADLINE)

    assert result.status is ReconciliationStatus.BREACH
    assert codes(result) == ["AMOUNT_EXCEEDED", "QUANTITY_MISMATCH"]
    amount, quantity = result.breaches
    assert (amount.expected, amount.observed) == ("84.00", "1008.00")
    assert (quantity.expected, quantity.observed) == ("1", "12")
    # The charge went through inside everything the network could check.
    assert all(b.provenance is BreachProvenance.DETECTED for b in result.breaches)
    assert all(b.evidence is None for b in result.breaches)


def test_being_charged_less_than_authorized_is_not_a_breach(warrant):
    """An authorization is a ceiling, not a price the merchant owes us."""
    assert reconcile(warrant, outcome(amount="20.00")).status is ReconciliationStatus.SETTLED


def test_the_authorized_amount_exactly_is_not_a_breach(warrant):
    assert reconcile(warrant, outcome(amount="84.00")).status is ReconciliationStatus.SETTLED


def test_amount_comparison_is_decimal_not_string(warrant):
    """'9.00' > '84.00' as text; the comparison must not be lexical."""
    assert reconcile(warrant, outcome(amount="9.00")).status is ReconciliationStatus.SETTLED
    assert codes(reconcile(warrant, outcome(amount="84.01"))) == ["AMOUNT_EXCEEDED"]


def test_trailing_zeros_do_not_create_a_phantom_breach(warrant):
    """'84.0' and '84.00' are different strings but the same money."""
    assert reconcile(warrant, outcome(amount="84.0")).status is ReconciliationStatus.SETTLED


def test_a_foreign_currency_is_an_amount_breach(warrant):
    """Amounts in different currencies are not comparable, so nothing is allowed."""
    result = reconcile(warrant, outcome(amount="10.00", currency="EUR"))
    assert codes(result) == ["AMOUNT_EXCEEDED"]
    assert result.breaches[0].observed == "10.00 EUR"
    assert "currency" in result.breaches[0].detail


def test_merchant_mismatch(warrant):
    result = reconcile(warrant, outcome(merchant_domain="ridge-deals-official.com"))
    assert codes(result) == ["MERCHANT_MISMATCH"]
    assert result.breaches[0].expected == "ridge.com"


@pytest.mark.parametrize("domain", ["RIDGE.COM", "ridge.com.", " Ridge.com "])
def test_domain_comparison_folds_case_and_trailing_dot(warrant, domain):
    """DNS is case-insensitive; a breach record must not be either."""
    assert reconcile(warrant, outcome(merchant_domain=domain)).breaches == []
    assert normalize_domain(domain) == "ridge.com"


def test_item_mismatch_carries_the_substituted_description(warrant):
    result = reconcile(warrant, outcome(sku="RW-PLASTIC-99", description="Plastic Wallet"))
    assert codes(result) == ["ITEM_MISMATCH"]
    assert result.breaches[0].observed == "RW-PLASTIC-99"
    assert result.breaches[0].detail == "Plastic Wallet"


def test_under_delivery_is_also_a_quantity_breach(warrant):
    """The warrant names one quantity, not an upper bound."""
    assert codes(reconcile(warrant, outcome(quantity=0))) == ["QUANTITY_MISMATCH"]


def test_non_delivery_only_once_the_deadline_has_passed(warrant):
    undelivered = outcome(delivered=False)
    assert reconcile(warrant, undelivered, now=BEFORE_DEADLINE).breaches == []
    assert codes(reconcile(warrant, undelivered, now=AFTER_DEADLINE)) == ["NON_DELIVERY"]


def test_an_open_ended_authorization_can_never_be_late():
    open_ended = build_warrant(
        authorization=Authorization(
            sku="RW-TITAN-01",
            description="Ridge Titanium Wallet, Raw",
            quantity=1,
            amount="84.00",
            currency="USD",
            single_use=True,
            expected_fulfillment_by=None,
        )
    )
    result = reconcile(open_ended, outcome(delivered=False), now=AFTER_DEADLINE)
    assert result.status is ReconciliationStatus.SETTLED


def test_unobserved_delivery_is_not_a_non_delivery(warrant):
    """None means nobody looked, which is not the same as observing a failure."""
    assert reconcile(warrant, outcome(delivered=None), now=AFTER_DEADLINE).breaches == []


def test_unobserved_fields_produce_no_breaches(warrant):
    """A thin outcome yields a thin diff rather than five false positives."""
    thin = Outcome(warrant_id=warrant.warrant_id, merchant_domain="ridge.com")
    assert reconcile(warrant, thin, now=AFTER_DEADLINE).status is ReconciliationStatus.SETTLED


def test_every_breach_code_is_reachable(warrant):
    result = reconcile(
        warrant,
        outcome(
            merchant_domain="elsewhere.example",
            sku="OTHER-SKU",
            quantity=12,
            amount="1008.00",
            delivered=False,
        ),
        now=AFTER_DEADLINE,
    )
    assert set(codes(result)) == {code.value for code in BreachCode}


def test_the_diff_is_deterministic(warrant):
    """Same inputs, same bytes. Nothing here samples, clocks, or hashes a set."""
    observed = outcome(quantity=12, amount="1008.00")
    first = reconcile(warrant, observed, now=BEFORE_DEADLINE)
    second = reconcile(warrant, observed, now=BEFORE_DEADLINE)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Prevented: refused before money moved
# ---------------------------------------------------------------------------


def test_a_refused_over_cap_charge_is_a_prevented_breach(warrant):
    """The cap is enforced at the card network, so the refusal is the evidence."""
    attempted = outcome(quantity=12, amount="1008.00")
    result = reconcile_refusal(warrant, attempted, "THRESHOLD_EXCEEDED", now=BEFORE_DEADLINE)

    assert result.status is ReconciliationStatus.BREACH
    assert codes(result) == ["AMOUNT_EXCEEDED", "QUANTITY_MISMATCH"]
    assert all(b.provenance is BreachProvenance.PREVENTED for b in result.breaches)
    assert all(b.evidence == "THRESHOLD_EXCEEDED" for b in result.breaches)


def test_a_refused_out_of_scope_charge_is_a_prevented_breach(warrant):
    result = reconcile_refusal(
        warrant, outcome(merchant_domain="elsewhere.example"), "MANDATE_MERCHANT_NOT_ALLOWED"
    )
    assert codes(result) == ["MERCHANT_MISMATCH"]
    assert result.breaches[0].provenance is BreachProvenance.PREVENTED


def test_a_refusal_the_local_diff_cannot_see_is_still_a_breach(warrant):
    """Prava refused. Reporting that as SETTLED would be a lie in the record."""
    result = reconcile_refusal(warrant, outcome(), "THRESHOLD_EXCEEDED")
    assert result.status is ReconciliationStatus.BREACH
    assert codes(result) == ["AMOUNT_EXCEEDED"]
    assert result.breaches[0].evidence == "THRESHOLD_EXCEEDED"


def test_an_unrelated_error_code_asserts_nothing(warrant):
    """A timeout or an auth failure says nothing about the merchant."""
    result = reconcile_refusal(warrant, outcome(), "CLIENT_TIMEOUT")
    assert result.status is ReconciliationStatus.SETTLED


# ---------------------------------------------------------------------------
# Merchant receipt -> Outcome
# ---------------------------------------------------------------------------


def test_the_merchants_over_delivery_reconciles_to_a_breach(breach_warrant, merchant_receipt):
    """End to end on the demo path: the merchant's own receipt, then the diff."""
    receipt = merchant_receipt.build_receipt("breach-abc123", 12, merchant_receipt.FULFILLED)
    assert receipt["amount_charged"] == "1008.00"
    assert receipt["line_items"][0]["quantity"] == 12

    observed = outcome_from_receipt(receipt, breach_warrant, source="breach.localhost/api/orders")
    assert observed.amount == "1008.00"
    assert observed.quantity == 12
    assert observed.delivered is True
    assert observed.order_id == "breach-abc123"

    result = reconcile(breach_warrant, observed, now=BEFORE_DEADLINE)
    assert result.status is ReconciliationStatus.BREACH
    assert codes(result) == ["AMOUNT_EXCEEDED", "QUANTITY_MISMATCH"]


def test_an_honest_receipt_settles(breach_warrant, merchant_receipt):
    """BREACH_QUANTITY=1 turns the same merchant into the clean demo path."""
    receipt = merchant_receipt.build_receipt("breach-abc123", 1, merchant_receipt.FULFILLED)
    assert receipt["amount_charged"] == "84.00"

    observed = outcome_from_receipt(receipt, breach_warrant)
    result = reconcile(breach_warrant, observed, now=BEFORE_DEADLINE)
    assert result.status is ReconciliationStatus.SETTLED


def test_an_unfulfilled_receipt_reconciles_to_non_delivery(breach_warrant, merchant_receipt):
    receipt = merchant_receipt.build_receipt("breach-abc123", 1, merchant_receipt.UNFULFILLED)
    assert receipt["fulfilled_at"] is None

    observed = outcome_from_receipt(receipt, breach_warrant)
    assert observed.delivered is False
    assert codes(reconcile(breach_warrant, observed, now=AFTER_DEADLINE)) == ["NON_DELIVERY"]


def test_a_confirmed_receipt_says_nothing_about_delivery(warrant):
    """CONFIRMED means the order was accepted, not that anything shipped."""
    receipt = {"merchant_domain": "ridge.com", "status": "CONFIRMED", "line_items": []}
    assert outcome_from_receipt(receipt, warrant).delivered is None


def test_the_receipt_carries_no_floats(merchant_receipt):
    """A float in the receipt would be rejected downstream, and rightly."""
    receipt = merchant_receipt.build_receipt("breach-abc123", 12, merchant_receipt.FULFILLED)
    for value in json.loads(json.dumps(receipt)).values():
        assert not isinstance(value, float)
    assert not any(isinstance(v, float) for v in receipt["line_items"][0].values())


def test_a_float_amount_in_a_receipt_is_refused(warrant):
    receipt = {"merchant_domain": "ridge.com", "amount_charged": 84.0, "line_items": []}
    with pytest.raises(ValidationError, match="must not be a float"):
        outcome_from_receipt(receipt, warrant)


def test_the_authorized_line_is_the_one_compared(warrant):
    """A receipt padded with extra lines must not hide the one we authorized."""
    receipt = {
        "merchant_domain": "ridge.com",
        "amount_charged": "84.00",
        "line_items": [
            {"sku": "GIFT-WRAP", "description": "Gift wrap", "quantity": 3},
            {"sku": "RW-TITAN-01", "description": "Ridge Titanium Wallet, Raw", "quantity": 1},
        ],
    }
    observed = outcome_from_receipt(receipt, warrant)
    assert (observed.sku, observed.quantity) == ("RW-TITAN-01", 1)


def test_a_substituted_item_still_surfaces(warrant):
    """Nothing matches the authorized SKU, so the first line is what shipped."""
    receipt = {
        "merchant_domain": "ridge.com",
        "amount_charged": "84.00",
        "line_items": [{"sku": "RW-PLASTIC-99", "description": "Plastic Wallet", "quantity": 1}],
    }
    result = reconcile(warrant, outcome_from_receipt(receipt, warrant))
    assert codes(result) == ["ITEM_MISMATCH"]


def test_an_empty_receipt_falls_back_to_the_warrants_merchant(warrant):
    observed = outcome_from_receipt({}, warrant)
    assert observed.merchant_domain == warrant.merchant.domain
    assert observed.sku is None
    assert reconcile(warrant, observed, now=BEFORE_DEADLINE).breaches == []


# ---------------------------------------------------------------------------
# The dispute packet
# ---------------------------------------------------------------------------


@pytest.fixture
def breach_case(warrant, private_key):
    signed = sign_warrant(warrant, private_key)
    observed = outcome(quantity=12, amount="1008.00")
    result = reconcile(signed, observed, now=BEFORE_DEADLINE)
    return signed, observed, result


@pytest.fixture
def signed_packet(breach_case, private_key):
    packet = build_dispute_packet(*breach_case, issued_at=datetime(2026, 8, 3, 9, 30, tzinfo=timezone.utc))
    return sign_dispute_packet(packet, private_key)


def test_the_packet_verifies(signed_packet, public_key):
    assert verify_warrant(signed_packet, public_key) is True


def test_the_embedded_warrant_still_verifies_on_its_own(signed_packet, public_key):
    """The point of the chain: lift the warrant out and it stands alone."""
    document = signed_packet.model_dump(mode="json")
    assert verify_warrant(document["warrant"], public_key) is True
    assert Warrant.model_validate(document["warrant"]).signature is not None


def test_the_embedded_warrant_is_byte_identical_to_the_one_issued(signed_packet, breach_case):
    signed_warrant = breach_case[0]
    lifted = signed_packet.model_dump(mode="json")["warrant"]
    assert canonical_bytes(lifted) == canonical_bytes(signed_warrant)
    assert lifted["signature"] == signed_warrant.signature


def test_the_outer_signature_covers_the_inner_signature(signed_packet, public_key, private_key):
    """Swapping in a differently-signed warrant must break the packet."""
    document = signed_packet.model_dump(mode="json")
    other = sign_warrant(build_warrant(warrant_id="wrt_OTHER"), private_key)
    document["warrant"] = other.model_dump(mode="json")

    assert verify_warrant(document, public_key) is False
    # ...even though the substituted warrant is itself perfectly valid.
    assert verify_warrant(document["warrant"], public_key) is True


def test_editing_the_observed_outcome_breaks_the_packet(signed_packet, public_key):
    document = signed_packet.model_dump(mode="json")
    document["outcome"]["quantity"] = 1
    assert verify_warrant(document, public_key) is False


def test_editing_a_breach_breaks_the_packet(signed_packet, public_key):
    document = signed_packet.model_dump(mode="json")
    document["reconciliation"]["breaches"] = []
    assert verify_warrant(document, public_key) is False


def test_stripping_the_inner_signature_breaks_the_packet(signed_packet, public_key):
    """Canonicalization drops only the top-level signature, so this is detected."""
    document = signed_packet.model_dump(mode="json")
    document["warrant"]["signature"] = None
    assert verify_warrant(document, public_key) is False


def test_the_packet_carries_two_timestamps(signed_packet):
    document = signed_packet.model_dump(mode="json")
    assert document["issued_at"] == "2026-08-03T09:30:00Z"
    assert document["warrant"]["issued_at"] == "2026-08-02T21:14:03Z"
    assert document["reconciliation"]["reconciled_at"].endswith("Z")


def test_the_packet_contains_no_floats(signed_packet):
    """One float anywhere and the document stops canonicalizing portably."""

    def walk(node):
        if isinstance(node, dict):
            return any(walk(value) for value in node.values())
        if isinstance(node, list):
            return any(walk(value) for value in node)
        return isinstance(node, float)

    assert walk(json.loads(json.dumps(signed_packet.model_dump(mode="json")))) is False


def test_a_packet_cannot_be_built_around_an_unsigned_warrant(warrant, breach_case):
    _, observed, result = breach_case
    with pytest.raises(ValueError, match="unsigned warrant"):
        build_dispute_packet(warrant, observed, result)


def test_a_packet_cannot_mix_documents_from_different_warrants(breach_case):
    signed, observed, result = breach_case
    with pytest.raises(ValueError, match="not wrt_TESTFIXTURE"):
        build_dispute_packet(signed, observed, result.model_copy(update={"warrant_id": "wrt_x"}))
    with pytest.raises(ValueError, match="not wrt_TESTFIXTURE"):
        build_dispute_packet(signed, observed.model_copy(update={"warrant_id": "wrt_x"}), result)


def test_the_packet_rejects_unknown_fields(signed_packet):
    document = signed_packet.model_dump(mode="json")
    document["note"] = "added later"
    with pytest.raises(ValidationError):
        DisputePacket.model_validate(document)


def test_a_settled_reconciliation_can_still_be_recorded(warrant, private_key):
    """Nothing forces a packet to be a breach; the caller decides what to sign."""
    signed = sign_warrant(warrant, private_key)
    result = reconcile(signed, outcome(), now=BEFORE_DEADLINE)
    packet = sign_dispute_packet(build_dispute_packet(signed, outcome(), result), private_key)
    assert packet.reconciliation.status is ReconciliationStatus.SETTLED


def test_money_never_becomes_a_float_in_the_comparison(warrant):
    """0.1 + 0.2 style drift must be impossible: the diff is Decimal throughout."""
    result = reconcile(warrant, outcome(amount="84.00000000000001"))
    assert codes(result) == ["AMOUNT_EXCEEDED"]
    assert Decimal(result.breaches[0].observed) > Decimal(result.breaches[0].expected)
