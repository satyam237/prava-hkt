"""The gate is structural. These tests are the proof of that claim.

Three properties, and the PRD's headline (§3.1) needs all three:

1. A ``ClearedWarrant`` cannot be constructed outside :mod:`app.gate`.
2. ``create_mandate_session`` has exactly one call site in the application.
3. That call site refuses anything that is not a ``ClearedWarrant``, before it
   touches the network.

Together they mean a HALT has no value it could pass to reach Prava.
``tests/test_api.py`` closes the loop end to end: a HALT run constructs zero
``PravaClient`` instances.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app import gate, payment
from app.gate import ClearedWarrant, GateBypass, GateRefused, Halted
from app.models import Authorization, Merchant, Verdict
from app.probes.base import Signal, SignalStatus
from app.warrant import canonical_bytes, generate_keypair, sign_warrant
from conftest import build_warrant

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "backend" / "app"


def _authorization() -> Authorization:
    return Authorization(
        sku="RW-TITAN-01",
        description="Ridge Titanium Wallet, Raw",
        quantity=1,
        amount="84.00",
        currency="USD",
    )


def _passing_signals() -> list[Signal]:
    return [
        Signal("domain_age_days", "A", 2847, SignalStatus.PASS, "registered 2847 days ago"),
        Signal("safe_browsing", "A", "no_match", SignalStatus.PASS, "no threat"),
        Signal("tls_certificate", "A", "valid", SignalStatus.PASS, "valid certificate"),
        Signal("injection_scan", "D", "clean", SignalStatus.PASS, "clean"),
    ]


def _halting_signals() -> list[Signal]:
    signals = _passing_signals()
    signals[1] = Signal("safe_browsing", "A", "match", SignalStatus.FAIL, "SOCIAL_ENGINEERING")
    return signals


# ---------------------------------------------------------------------------
# 1. The sentinel
# ---------------------------------------------------------------------------


def test_cleared_warrant_cannot_be_constructed_outside_the_gate(warrant):
    with pytest.raises(GateBypass):
        ClearedWarrant(warrant=warrant, warrant_hash="sha256:00")


def test_gate_mints_a_signed_warrant_on_pass(private_key):
    decision = gate.decide(
        merchant=Merchant(domain="ridge.com", resolved_name="Ridge Wallet"),
        authorization=_authorization(),
        signals=_passing_signals(),
        content_hash="sha256:" + "a3f1" * 16,
        score=1.0,
        private_key=private_key,
    )
    assert isinstance(decision, ClearedWarrant)
    assert decision.warrant.verification.verdict is Verdict.PASS
    assert decision.warrant.signature is not None
    assert decision.warrant_hash == gate.warrant_hash(decision.warrant)


def test_gate_returns_no_warrant_on_halt(monkeypatch, tmp_path):
    # No signing key reachable at all: a HALT must not need one, because on
    # HALT nothing is ever signed.
    monkeypatch.delenv("WARRANT_SIGNING_KEY", raising=False)
    monkeypatch.setattr("app.warrant.DEFAULT_PRIVATE_KEY_PATH", tmp_path / "absent.key")

    decision = gate.decide(
        merchant=Merchant(domain="spoof.example"),
        authorization=_authorization(),
        signals=_halting_signals(),
        content_hash="sha256:" + "00" * 32,
        score=0.75,
    )
    assert isinstance(decision, Halted)
    assert decision.verdict is Verdict.HALT
    assert "safe_browsing" in decision.reason
    assert not hasattr(decision, "warrant")


def test_halt_reason_names_the_corroboration_floor():
    signals = [
        Signal("tls_certificate", "A", "valid", SignalStatus.PASS, ""),
        Signal("domain_age_days", "A", None, SignalStatus.UNAVAILABLE, "RDAP timed out"),
    ]
    assert "corroboration" in gate.halt_reason(signals)


def test_signed_signal_order_is_stable_regardless_of_arrival_order(private_key):
    forward = _passing_signals()
    reversed_arrival = list(reversed(forward))
    first = gate.decide(
        merchant=Merchant(domain="ridge.com"),
        authorization=_authorization(),
        signals=forward,
        content_hash="sha256:" + "a3f1" * 16,
        score=1.0,
        private_key=private_key,
    )
    second = gate.decide(
        merchant=Merchant(domain="ridge.com"),
        authorization=_authorization(),
        signals=reversed_arrival,
        content_hash="sha256:" + "a3f1" * 16,
        score=1.0,
        private_key=private_key,
    )
    names = [signal.name for signal in first.warrant.verification.signals]
    assert names == [signal.name for signal in second.warrant.verification.signals]


def test_clear_issued_refuses_a_halt_verdict(monkeypatch, tmp_path, keypair):
    private_key, public_key = keypair
    _install_public_key(monkeypatch, tmp_path, public_key)
    halted = sign_warrant(build_warrant(), private_key).model_copy(deep=True)
    halted.verification.verdict = Verdict.HALT
    with pytest.raises(GateRefused):
        gate.clear_issued(halted)


def test_clear_issued_refuses_a_tampered_document(monkeypatch, tmp_path, keypair):
    private_key, public_key = keypair
    _install_public_key(monkeypatch, tmp_path, public_key)
    signed = sign_warrant(build_warrant(), private_key)
    tampered = signed.model_copy(deep=True)
    tampered.authorization.amount = "8400.00"
    with pytest.raises(GateRefused):
        gate.clear_issued(tampered)


def test_clear_issued_accepts_an_intact_pass(monkeypatch, tmp_path, keypair):
    private_key, public_key = keypair
    _install_public_key(monkeypatch, tmp_path, public_key)
    signed = sign_warrant(build_warrant(), private_key)
    cleared = gate.clear_issued(signed)
    assert cleared.warrant_hash.startswith("sha256:")
    assert canonical_bytes(cleared.warrant) == canonical_bytes(signed)


def _install_public_key(monkeypatch, tmp_path, public_key) -> None:
    from app.warrant import public_key_to_b64

    path = tmp_path / "warrant_public.key"
    path.write_text(public_key_to_b64(public_key), encoding="ascii")
    monkeypatch.setenv("WARRANT_PUBLIC_KEY", str(path))


# ---------------------------------------------------------------------------
# 2. One call site
# ---------------------------------------------------------------------------


def test_prava_sessions_have_exactly_one_call_site_in_the_app():
    """Read by AST, not by grep: a comment mentioning the method is not a call.

    If this fails, someone added a second door to the Prava session API and the
    gate no longer covers every path to a credential.
    """

    callers: set[str] = set()
    for path in sorted(APP_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "create_mandate_session":
                callers.add(path.relative_to(REPO_ROOT).as_posix())
    assert callers == {"backend/app/payment.py"}


# ---------------------------------------------------------------------------
# 3. The call site refuses anything else
# ---------------------------------------------------------------------------


class _ForbiddenPravaClient:
    """Any construction at all is a failure."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("PravaClient must not be constructed without a ClearedWarrant")


@pytest.mark.parametrize("impostor", [None, "wrt_forgery", {"warrant": "x"}, object()])
async def test_request_session_refuses_anything_but_a_cleared_warrant(monkeypatch, impostor):
    monkeypatch.setattr(payment, "PravaClient", _ForbiddenPravaClient)
    monkeypatch.setenv(payment.SECRET_KEY_ENV, "sk_test_should_never_be_used")
    with pytest.raises(TypeError):
        await payment.request_session(impostor)


async def test_request_session_refuses_a_halted_decision(monkeypatch):
    monkeypatch.setattr(payment, "PravaClient", _ForbiddenPravaClient)
    monkeypatch.setenv(payment.SECRET_KEY_ENV, "sk_test_should_never_be_used")
    halted = Halted(score="0.50", reason="safe_browsing: match")
    with pytest.raises(TypeError):
        await payment.request_session(halted)


async def test_request_session_without_a_key_never_reaches_the_network(monkeypatch, keypair):
    private_key, _ = keypair
    monkeypatch.setattr(payment, "PravaClient", _ForbiddenPravaClient)
    monkeypatch.delenv(payment.SECRET_KEY_ENV, raising=False)
    cleared = gate.decide(
        merchant=Merchant(domain="ridge.com"),
        authorization=_authorization(),
        signals=_passing_signals(),
        content_hash="sha256:" + "a3f1" * 16,
        score=1.0,
        private_key=private_key,
    )
    with pytest.raises(payment.PaymentUnavailable):
        await payment.request_session(cleared)


def test_unit_price_refuses_a_total_that_does_not_divide_evenly():
    assert payment._unit_price("84.00", 1) == "84.00"
    with pytest.raises(ValueError):
        payment._unit_price("84.00", 9)


def test_generated_keypair_is_usable():
    private_key, _ = generate_keypair()
    assert sign_warrant(build_warrant(), private_key).signature is not None
