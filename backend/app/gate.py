"""The gate. PASS mints a signed WARRANT; HALT mints nothing at all.

The claim in the PRD (§3.1) is that the gate is *structural, not advisory*: on
HALT the code path that requests a Prava session is never reached, so there is
no credential to misuse. A boolean flag checked by the caller would not be that
— it would be a convention, and conventions are what get bypassed at 3am.

So the gate is a type. :func:`decide` returns either a :class:`ClearedWarrant`
or a :class:`Halted`, and :class:`ClearedWarrant` cannot be constructed outside
this module: its initializer demands a private sentinel that only this module
holds. :func:`app.payment.request_session` takes a ``ClearedWarrant`` and
nothing else, and it is the only place in the codebase that opens a Prava
session. Possession of the value *is* the authorization. There is no argument a
HALT path can pass that reaches the network.

``tests/test_gate.py`` pins all three halves of that: the sentinel, the single
call site, and zero ``PravaClient`` construction on a HALT run.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import (
    Authorization,
    Merchant,
    Signal as WarrantSignal,
    Verdict,
    Verification,
    Warrant,
)
from app.probes.base import MIN_AVAILABLE_TIER_A, Signal, SignalStatus, available_tier_a
from app.probes.base import verdict as verdict_of
from app.warrant import canonical_bytes, sign_warrant, verify_warrant

#: Held only by this module. Nothing else can produce a ClearedWarrant.
_MINT = object()


class GateRefused(Exception):
    """The verdict was not PASS, so no credential may be requested."""


class GateBypass(RuntimeError):
    """Someone tried to construct a ClearedWarrant without going through the gate."""


@dataclass(frozen=True)
class ClearedWarrant:
    """Proof that verification passed and the warrant is signed.

    Holding one of these is the only way to reach :mod:`app.payment`. It is
    minted by :func:`decide` and :func:`clear_issued` and by nothing else.
    """

    warrant: Warrant
    warrant_hash: str
    _mint: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._mint is not _MINT:
            raise GateBypass(
                "ClearedWarrant may only be minted by app.gate.decide() or "
                "app.gate.clear_issued(); a payment credential is not requestable "
                "without a PASS verdict"
            )


@dataclass(frozen=True)
class Halted:
    """The gate refused. There is no warrant, by construction."""

    score: str
    reason: str
    verdict: Verdict = Verdict.HALT


def warrant_hash(warrant: Warrant) -> str:
    """``sha256:<hex>`` over the exact bytes that were signed.

    Not over the JSON as transmitted: the digest has to identify the *document*,
    so two renderings of the same warrant must hash alike.
    """

    return "sha256:" + hashlib.sha256(canonical_bytes(warrant)).hexdigest()


def halt_reason(signals: Iterable[Signal]) -> str:
    """Why the gate refused, in the interface's voice: what happened, flatly."""

    signal_list = list(signals)
    failures = [signal for signal in signal_list if signal.status is SignalStatus.FAIL]
    if failures:
        first = failures[0]
        detail = first.detail or f"{first.name} returned {first.value!r}"
        return f"{first.name}: {detail}"
    tier_a = available_tier_a(signal_list)
    if tier_a < MIN_AVAILABLE_TIER_A:
        return (
            f"insufficient corroboration: {tier_a} of {MIN_AVAILABLE_TIER_A} required "
            "Tier A signals produced evidence"
        )
    return "verification score below threshold"


def build_verification(
    signals: Iterable[Signal],
    *,
    content_hash: str,
    score: float,
    decision: str,
) -> Verification:
    """Assemble the verification block of the document.

    Signals are ordered by tier then name rather than by arrival. Arrival order
    is a property of the network on the day, and two runs over identical
    evidence must produce identical signed bytes. The live arrival order is what
    the SSE stream shows; it is not what gets signed. ``detail`` is dropped here
    — it is a human string, it is not in the wire spec, and it would put
    third-party prose inside the signature.
    """

    ordered = sorted(signals, key=lambda signal: (signal.tier, signal.name))
    return Verification(
        verdict=decision,
        score=score,
        signals=[
            WarrantSignal(
                name=signal.name,
                tier=signal.tier,
                value=signal.value,
                status=SignalStatus(signal.status).value,
            )
            for signal in ordered
        ],
        content_hash=content_hash,
    )


def decide(
    *,
    merchant: Merchant,
    authorization: Authorization,
    signals: Iterable[Signal],
    content_hash: str,
    score: float,
    private_key: Ed25519PrivateKey | None = None,
) -> ClearedWarrant | Halted:
    """Run the gate. PASS returns a signed warrant; HALT returns a refusal.

    ``score`` is passed in rather than recomputed so the number the stream
    showed and the number inside the signature are the same number.
    """

    signal_list = list(signals)
    decision = verdict_of(signal_list)
    verification = build_verification(
        signal_list, content_hash=content_hash, score=score, decision=decision
    )

    if decision != Verdict.PASS.value:
        return Halted(score=verification.score, reason=halt_reason(signal_list))

    warrant = sign_warrant(
        Warrant(merchant=merchant, verification=verification, authorization=authorization),
        private_key,
    )
    return ClearedWarrant(warrant=warrant, warrant_hash=warrant_hash(warrant), _mint=_MINT)


def clear_issued(warrant: Warrant) -> ClearedWarrant:
    """Re-open the gate for a warrant read back out of storage.

    The stored document is re-checked rather than trusted: the verdict must be
    PASS and the signature must verify against the committed public key. A row
    edited in the database is not an authorization.
    """

    if warrant.verification.verdict is not Verdict.PASS:
        raise GateRefused(
            f"warrant {warrant.warrant_id} carries verdict "
            f"{warrant.verification.verdict.value}; no credential may be requested"
        )
    if not verify_warrant(warrant):
        raise GateRefused(f"warrant {warrant.warrant_id} does not verify against the public key")
    return ClearedWarrant(warrant=warrant, warrant_hash=warrant_hash(warrant), _mint=_MINT)


__all__ = [
    "ClearedWarrant",
    "GateBypass",
    "GateRefused",
    "Halted",
    "build_verification",
    "clear_issued",
    "decide",
    "halt_reason",
    "warrant_hash",
]
