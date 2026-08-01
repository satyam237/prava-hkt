"""Signing contract tests.

These guard the one thing that must not break: a WARRANT signed here must verify
elsewhere, and must stop verifying the instant anyone touches it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from datetime import datetime, timezone

import pytest

from app.models import Warrant
from app.warrant import (
    SIGNATURE_PREFIX,
    canonical_bytes,
    decode_signature,
    encode_signature,
    generate_keypair,
    load_private_key_b64,
    load_public_key,
    load_public_key_b64,
    private_key_to_b64,
    public_key_to_b64,
    sign_warrant,
    verify_warrant,
)

from conftest import COMMITTED_PUBLIC_KEY, VERIFY_SCRIPT, build_warrant


def _load_verify_script_module():
    """Import scripts/verify_warrant.py as a module for byte-level comparison."""
    spec = importlib.util.spec_from_file_location("verify_warrant_script", VERIFY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_sign_then_verify_passes(warrant, private_key, public_key):
    signed = sign_warrant(warrant, private_key)
    assert signed.signature is not None
    assert signed.signature.startswith(SIGNATURE_PREFIX)
    assert verify_warrant(signed, public_key) is True


def test_signing_does_not_mutate_the_input(warrant, private_key):
    assert warrant.signature is None
    sign_warrant(warrant, private_key)
    assert warrant.signature is None


def test_signature_is_64_raw_bytes(warrant, private_key):
    signed = sign_warrant(warrant, private_key)
    assert len(decode_signature(signed.signature)) == 64


def test_verifies_after_a_full_json_round_trip(warrant, private_key, public_key):
    """The wire form, not the in-memory object, is what a judge receives."""
    signed = sign_warrant(warrant, private_key)
    wire = json.dumps(signed.model_dump(mode="json"))

    as_mapping = json.loads(wire)
    assert verify_warrant(as_mapping, public_key) is True

    reparsed = Warrant.model_validate(json.loads(wire))
    assert verify_warrant(reparsed, public_key) is True
    assert canonical_bytes(reparsed) == canonical_bytes(signed)


def test_verify_rejects_a_different_key(warrant, private_key):
    signed = sign_warrant(warrant, private_key)
    _, other_public = generate_keypair()
    assert verify_warrant(signed, other_public) is False


def test_unsigned_warrant_does_not_verify(warrant, public_key):
    assert verify_warrant(warrant, public_key) is False


@pytest.mark.parametrize(
    "bad_signature",
    [
        "",
        "not-a-signature",
        "ed25519:!!!not-base64!!!",
        "ed25519:" + "AAAA",  # valid base64, wrong length
        "rsa:AAAA",
    ],
)
def test_malformed_signatures_return_false_not_raise(warrant, private_key, public_key, bad_signature):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    document["signature"] = bad_signature
    assert verify_warrant(document, public_key) is False


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,new_value",
    [
        (("authorization", "amount"), "8400.00"),
        (("authorization", "quantity"), 99),
        (("authorization", "currency"), "EUR"),
        (("authorization", "sku"), "RW-OTHER-02"),
        (("authorization", "description"), "A different item"),
        (("authorization", "single_use"), False),
        (("authorization", "expected_fulfillment_by"), "2027-01-01T00:00:00Z"),
        (("merchant", "domain"), "ridge-store-deals.com"),
        (("merchant", "resolved_name"), "Ridge Wallet Official"),
        (("verification", "verdict"), "HALT"),
        (("verification", "score"), "0.99"),
        (("verification", "content_hash"), "sha256:" + "b0b0" * 16),
        (("version",), "warrant/2"),
        (("warrant_id",), "wrt_SOMETHINGELSE"),
        (("issued_at",), "2026-08-03T00:00:00Z"),
    ],
)
def test_mutating_any_field_breaks_verification(warrant, private_key, public_key, path, new_value):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")

    node = document
    for key in path[:-1]:
        node = node[key]
    assert node[path[-1]] != new_value, "test would be vacuous: value unchanged"
    node[path[-1]] = new_value

    assert verify_warrant(document, public_key) is False


def test_mutating_a_signal_breaks_verification(warrant, private_key, public_key):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    document["verification"]["signals"][0]["value"] = 1
    assert verify_warrant(document, public_key) is False


def test_reordering_signals_breaks_verification(warrant, private_key, public_key):
    """Arrays are ordered. Only object keys get sorted."""
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    document["verification"]["signals"].reverse()
    assert verify_warrant(document, public_key) is False


def test_dropping_a_signal_breaks_verification(warrant, private_key, public_key):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    document["verification"]["signals"].pop()
    assert verify_warrant(document, public_key) is False


def test_adding_an_unknown_field_breaks_verification(warrant, private_key, public_key):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    document["injected"] = "extra"
    assert verify_warrant(document, public_key) is False


def test_dropping_a_null_field_breaks_verification(warrant, private_key, public_key):
    """Optional values are explicit null on the wire; omitting one is a mutation."""
    open_ended = build_warrant(
        authorization={
            "sku": "RW-TITAN-01",
            "description": "Ridge Titanium Wallet",
            "quantity": 1,
            "amount": "84.00",
            "currency": "USD",
            "single_use": True,
        }
    )
    signed = sign_warrant(open_ended, private_key)
    document = signed.model_dump(mode="json")
    assert document["authorization"]["expected_fulfillment_by"] is None
    del document["authorization"]["expected_fulfillment_by"]
    assert verify_warrant(document, public_key) is False


def test_signature_field_itself_is_not_covered(warrant, private_key):
    """Changing the signature changes the signature check, not the message."""
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    without = dict(document)
    without.pop("signature")
    assert canonical_bytes(document) == canonical_bytes(without)
    assert b'"signature"' not in canonical_bytes(document)


# ---------------------------------------------------------------------------
# Canonical stability
# ---------------------------------------------------------------------------


def test_key_insertion_order_does_not_change_canonical_bytes(warrant):
    """Two structurally identical documents canonicalize identically."""
    document = warrant.model_dump(mode="json")
    shuffled = {key: copy.deepcopy(document[key]) for key in reversed(list(document))}
    shuffled["merchant"] = {"resolved_name": document["merchant"]["resolved_name"],
                            "domain": document["merchant"]["domain"]}
    shuffled["authorization"] = dict(reversed(list(document["authorization"].items())))
    shuffled["verification"] = dict(reversed(list(document["verification"].items())))
    shuffled["verification"]["signals"] = [
        dict(reversed(list(signal.items()))) for signal in document["verification"]["signals"]
    ]

    assert list(shuffled) != list(document), "test would be vacuous: order unchanged"
    assert canonical_bytes(shuffled) == canonical_bytes(document)


def test_shuffled_document_verifies_under_the_original_signature(warrant, private_key, public_key):
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    shuffled = {key: document[key] for key in reversed(list(document))}
    assert verify_warrant(shuffled, public_key) is True


def test_canonical_bytes_are_sorted_compact_utf8(warrant):
    raw = canonical_bytes(warrant)
    document = json.loads(raw.decode("utf-8"))

    assert list(document) == sorted(document), "top-level keys sorted"
    assert list(document["authorization"]) == sorted(document["authorization"])
    assert list(document["verification"]["signals"][0]) == sorted(document["verification"]["signals"][0])
    assert "signature" not in document

    # Idempotence: canonicalizing the parsed form reproduces the same bytes.
    # This is the property a reimplementation must satisfy, and unlike a naive
    # whitespace scan it is not fooled by punctuation inside string values.
    assert json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") == raw


def test_non_ascii_is_not_escaped():
    """ensure_ascii=False — the merchant name is emitted as UTF-8, not \\uXXXX."""
    raw = canonical_bytes(build_warrant(merchant={"domain": "café.example", "resolved_name": "Café Ridge"}))
    assert "Café Ridge".encode("utf-8") in raw
    assert rb"\\u00e9" not in raw, "non-ASCII must not be \\uXXXX-escaped"


def test_canonical_bytes_identical_for_model_and_mapping(warrant):
    assert canonical_bytes(warrant) == canonical_bytes(warrant.model_dump(mode="json"))


def test_canonical_bytes_are_stable_across_calls(warrant):
    assert canonical_bytes(warrant) == canonical_bytes(warrant)


def test_app_and_standalone_script_agree_byte_for_byte(warrant, private_key):
    """The spec is only real if an independent implementation reproduces it."""
    script = _load_verify_script_module()
    signed = sign_warrant(warrant, private_key)
    document = signed.model_dump(mode="json")
    assert script.canonical_bytes(document) == canonical_bytes(document)
    assert script.SIGNATURE_PREFIX == SIGNATURE_PREFIX


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_keypair_survives_base64_round_trip(warrant):
    private_key, public_key = generate_keypair()
    reloaded_private = load_private_key_b64(private_key_to_b64(private_key))
    reloaded_public = load_public_key_b64(public_key_to_b64(public_key))

    signed = sign_warrant(warrant, reloaded_private)
    assert verify_warrant(signed, reloaded_public) is True
    assert verify_warrant(signed, public_key) is True


def test_committed_public_key_is_present_and_valid():
    assert COMMITTED_PUBLIC_KEY.is_file(), "keys/warrant_public.key must be committed"
    key = load_public_key(COMMITTED_PUBLIC_KEY)
    assert len(public_key_to_b64(key)) == 44  # 32 raw bytes, base64 with padding


def test_load_public_key_defaults_to_the_committed_file():
    assert public_key_to_b64(load_public_key()) == public_key_to_b64(load_public_key(COMMITTED_PUBLIC_KEY))


def test_signature_encoding_round_trip():
    raw = bytes(range(64))
    assert decode_signature(encode_signature(raw)) == raw


def test_issued_at_is_z_suffixed_utc(warrant):
    document = warrant.model_dump(mode="json")
    assert document["issued_at"] == "2026-08-02T21:14:03Z"
    assert document["authorization"]["expected_fulfillment_by"] == "2026-08-12T00:00:00Z"


def test_naive_and_offset_datetimes_normalize_to_the_same_bytes():
    """A warrant issued at 21:14:03Z is the same warrant however the caller spelled it."""
    from datetime import timedelta

    utc = build_warrant(issued_at=datetime(2026, 8, 2, 21, 14, 3, tzinfo=timezone.utc))
    naive = build_warrant(issued_at=datetime(2026, 8, 2, 21, 14, 3))
    offset = build_warrant(
        issued_at=datetime(2026, 8, 2, 23, 14, 3, tzinfo=timezone(timedelta(hours=2)))
    )
    sub_second = build_warrant(issued_at=datetime(2026, 8, 2, 21, 14, 3, 987654, tzinfo=timezone.utc))

    expected = canonical_bytes(utc)
    assert canonical_bytes(naive) == expected
    assert canonical_bytes(offset) == expected
    assert canonical_bytes(sub_second) == expected
