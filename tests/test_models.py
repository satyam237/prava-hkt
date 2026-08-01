"""Model contract tests, principally: money never touches float."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.models import (
    Authorization,
    Breach,
    BreachCode,
    Outcome,
    Reconciliation,
    ReconciliationStatus,
    Signal,
    Verdict,
    Warrant,
    new_warrant_id,
)
from app.warrant import canonical_bytes, sign_warrant, verify_warrant

from conftest import build_warrant


def make_authorization(**overrides) -> Authorization:
    fields = dict(
        sku="RW-TITAN-01",
        description="Ridge Titanium Wallet",
        quantity=1,
        amount="84.00",
        currency="USD",
        single_use=True,
    )
    fields.update(overrides)
    return Authorization(**fields)


# ---------------------------------------------------------------------------
# Decimal integrity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("amount", ["84.00", "0.01", "1234567.89", "9.999", "0", "100"])
def test_amount_strings_are_preserved_verbatim(amount):
    """'84.00' must not become '84.0' or '84'. Trailing zeros are information."""
    assert make_authorization(amount=amount).amount == amount


def test_amount_survives_sign_verify_and_json_round_trip(private_key, public_key):
    warrant = build_warrant(authorization=make_authorization(amount="84.00"))
    signed = sign_warrant(warrant, private_key)

    document = json.loads(json.dumps(signed.model_dump(mode="json")))
    assert document["authorization"]["amount"] == "84.00"
    assert '"amount":"84.00"' in canonical_bytes(document).decode("utf-8")
    assert verify_warrant(document, public_key) is True
    assert Warrant.model_validate(document).authorization.amount == "84.00"


@pytest.mark.parametrize("bad", [84.0, 84.5, 0.1])
def test_float_amounts_are_rejected(bad):
    with pytest.raises(ValidationError, match="must not be a float"):
        make_authorization(amount=bad)


def test_bool_amount_is_rejected():
    with pytest.raises(ValidationError):
        make_authorization(amount=True)


def test_decimal_and_int_amounts_are_accepted_without_exponent():
    assert make_authorization(amount=Decimal("84.00")).amount == "84.00"
    assert make_authorization(amount=Decimal("1E+2")).amount == "100"
    assert make_authorization(amount=84).amount == "84"


@pytest.mark.parametrize("bad", ["-84.00", "84.00 USD", "8,400.00", "1e5", "", "084.00", "84."])
def test_non_canonical_amount_strings_are_rejected(bad):
    with pytest.raises(ValidationError):
        make_authorization(amount=bad)


def test_no_float_appears_anywhere_in_the_canonical_bytes():
    """Every JSON number in the document must be an integer."""
    document = json.loads(canonical_bytes(build_warrant()).decode("utf-8"))

    def walk(node):
        if isinstance(node, float):
            pytest.fail(f"float found on the wire: {node!r}")
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "given,expected",
    [(0.87, "0.87"), ("0.87", "0.87"), (Decimal("0.87"), "0.87"), (1, "1.00"), (0, "0.00"), (0.875, "0.88")],
)
def test_score_normalizes_to_two_decimal_string(given, expected):
    warrant = build_warrant(
        verification={
            "verdict": "PASS",
            "score": given,
            "signals": [],
            "content_hash": "sha256:" + "00" * 32,
        }
    )
    assert warrant.verification.score == expected


@pytest.mark.parametrize("bad", [-0.1, 1.5, "abc", True])
def test_out_of_range_or_nonnumeric_scores_are_rejected(bad):
    with pytest.raises(ValidationError):
        build_warrant(
            verification={
                "verdict": "PASS",
                "score": bad,
                "signals": [],
                "content_hash": "sha256:" + "00" * 32,
            }
        )


# ---------------------------------------------------------------------------
# Field contracts
# ---------------------------------------------------------------------------


def test_version_is_pinned():
    assert build_warrant().version == "warrant/1"
    with pytest.raises(ValidationError):
        build_warrant(version="warrant/2")


def test_generated_warrant_ids_are_prefixed_and_unique():
    ids = {new_warrant_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(i.startswith("wrt_") and len(i) > 10 for i in ids)


def test_currency_must_be_iso_4217_uppercase():
    assert make_authorization(currency="USD").currency == "USD"
    for bad in ["usd", "US", "USDT", "$"]:
        with pytest.raises(ValidationError):
            make_authorization(currency=bad)


def test_quantity_must_be_at_least_one():
    with pytest.raises(ValidationError):
        make_authorization(quantity=0)


def test_content_hash_must_be_algorithm_prefixed():
    for bad in ["deadbeef", "sha256:", "SHA256:abcd"]:
        with pytest.raises(ValidationError):
            build_warrant(
                verification={
                    "verdict": "PASS",
                    "score": "0.9",
                    "signals": [],
                    "content_hash": bad,
                }
            )


def test_unknown_fields_are_rejected_not_silently_dropped():
    """A stray key in a signed document is an attack or a version skew. Fail closed."""
    document = build_warrant().model_dump(mode="json")

    with pytest.raises(ValidationError):
        Warrant.model_validate({**document, "injected": "extra"})

    nested = json.loads(json.dumps(document))
    nested["authorization"]["override_limit"] = "999999.00"
    with pytest.raises(ValidationError):
        Warrant.model_validate(nested)

    nested = json.loads(json.dumps(document))
    nested["verification"]["signals"][0]["weight"] = 1
    with pytest.raises(ValidationError):
        Warrant.model_validate(nested)


def test_a_valid_document_still_parses():
    document = build_warrant().model_dump(mode="json")
    assert Warrant.model_validate(document).model_dump(mode="json") == document


def test_signal_value_accepts_int_str_bool_null_but_not_float():
    assert Signal(name="age", tier="A", value=2847, status="PASS").value == 2847
    assert Signal(name="psp", tier="B", value="stripe", status="PASS").value == "stripe"
    assert Signal(name="ucp", tier="C", value=True, status="PASS").value is True
    assert Signal(name="registry", tier="B", value=None, status="UNAVAILABLE").value is None
    with pytest.raises(ValidationError, match="must not be a float"):
        Signal(name="ratio", tier="D", value=0.5, status="PASS")


def test_verdict_and_tier_are_constrained():
    with pytest.raises(ValidationError):
        Signal(name="x", tier="Z", status="PASS")
    with pytest.raises(ValidationError):
        build_warrant(
            verification={
                "verdict": "MAYBE",
                "score": "0.5",
                "signals": [],
                "content_hash": "sha256:" + "00" * 32,
            }
        )
    assert Verdict.HALT.value == "HALT"


# ---------------------------------------------------------------------------
# Reconciliation shapes
# ---------------------------------------------------------------------------


def test_outcome_mirrors_the_authorization_and_rejects_float_amounts():
    outcome = Outcome(
        warrant_id="wrt_abc",
        merchant_domain="ridge.com",
        sku="RW-TITAN-01",
        quantity=1,
        amount="84.00",
        currency="USD",
        delivered=True,
        order_id="ord_123",
    )
    assert outcome.amount == "84.00"
    assert outcome.model_dump(mode="json")["observed_at"].endswith("Z")

    with pytest.raises(ValidationError, match="must not be a float"):
        Outcome(warrant_id="wrt_abc", merchant_domain="ridge.com", amount=84.0)


def test_reconciliation_carries_typed_breaches():
    reconciliation = Reconciliation(
        warrant_id="wrt_abc",
        status=ReconciliationStatus.BREACH,
        breaches=[
            Breach(code=BreachCode.AMOUNT_EXCEEDED, expected="84.00", observed="129.00"),
            Breach(code=BreachCode.NON_DELIVERY, expected="delivered", observed="not delivered"),
        ],
    )
    document = reconciliation.model_dump(mode="json")
    assert document["status"] == "BREACH"
    assert [breach["code"] for breach in document["breaches"]] == ["AMOUNT_EXCEEDED", "NON_DELIVERY"]


def test_all_five_breach_codes_exist():
    assert {code.value for code in BreachCode} == {
        "AMOUNT_EXCEEDED",
        "MERCHANT_MISMATCH",
        "ITEM_MISMATCH",
        "QUANTITY_MISMATCH",
        "NON_DELIVERY",
    }


def test_settled_reconciliation_has_no_breaches():
    reconciliation = Reconciliation(warrant_id="wrt_abc", status="SETTLED")
    assert reconciliation.breaches == []
