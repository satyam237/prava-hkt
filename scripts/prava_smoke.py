#!/usr/bin/env python3
"""Live smoke test against the Prava sandbox.

Run in two halves, because the middle of the flow needs a human:

    python scripts/prava_smoke.py create   # health, open a mandate session, stop
    # ...a person opens the printed iframe_url and approves with a passkey...
    python scripts/prava_smoke.py resume   # poll to active, charge, reconcile

The split is not a convenience. A mandate only becomes ``active`` after a real
passkey approval (Touch ID) inside the hosted iframe, which no script can
perform. ``create`` therefore stops at the approval boundary and writes what it
learned to a state file so ``resume`` can pick it up later.

Every response is printed through ``redact`` — tokens and dynamic CVVs are
never written to the terminal or to the state file.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass

from app.services.prava_client import (  # noqa: E402
    PravaClient,
    PravaError,
    PravaThresholdExceeded,
    key_fingerprint,
    redact,
)

STATE_PATH = REPO_ROOT / ".prava_smoke_state.json"

# Defaults mirror the Create Session CURL example in docs.prava.space so a
# support engineer comparing our body to theirs sees the same shape.
MERCHANT_NAME = os.environ.get("SMOKE_MERCHANT_NAME", "Acme Store")
# Forwarded to Visa as merchant of record. Must be https. Prefer a plain
# storefront-shaped URL over github.com / *.localhost — session-create only
# checks the scheme, but the Visa passkey leg may reject non-merchant hosts.
MERCHANT_URL = os.environ.get("SMOKE_MERCHANT_URL", "https://acme.example.com")
TOTAL_AMOUNT = os.environ.get("SMOKE_AMOUNT", "49.99")
OVER_CAP_AMOUNT = os.environ.get("SMOKE_OVER_CAP_AMOUNT", "1008.00")
CURRENCY = os.environ.get("SMOKE_CURRENCY", "USD")
CALLBACK_URL = os.environ.get("SMOKE_CALLBACK_URL", "https://acme.example.com/return")

# Stable, NOT random per run. Prava keys the customer — and therefore the saved
# cards and the per-browser passkey — off user_id. A fresh uuid each run makes
# every session a first-time customer, which forces card entry + OTP + passkey
# *registration* every time and makes the returning-customer path (passkey
# *verification* against an enrolled card, no OTP) unreachable. Override only to
# deliberately start over as a new customer.
SMOKE_USER_ID = os.environ.get("SMOKE_USER_ID", "user_123")
SMOKE_USER_EMAIL = os.environ.get("SMOKE_USER_EMAIL", "jane@example.com")


def load_env() -> str:
    """Return the secret key. Never prints the key itself."""
    key = os.environ.get("PRAVA_SECRET_KEY", "")
    if not key:
        sys.exit("PRAVA_SECRET_KEY is not set. Copy .env into the repo root.")
    return key


def step(n: str, title: str) -> None:
    print(f"\n{'=' * 68}\n  STEP {n}  {title}\n{'=' * 68}")


def show(label: str, value: Any) -> None:
    print(f"\n{label}:")
    print(json.dumps(redact(value), indent=2, sort_keys=True, default=str))


def save_state(**kwargs: Any) -> None:
    state = read_state()
    state.update(kwargs)
    STATE_PATH.write_text(json.dumps(redact(state), indent=2, default=str))
    print(f"\n  state -> {STATE_PATH.name}")


def read_state() -> dict[str, Any]:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {}


def find_first(payload: Any, *keys: str) -> Any:
    """Search a nested response for the first of ``keys`` that has a value.

    The exact nesting of ``mandate_id``/``session_id`` in the session response
    is not something the docs pin down, so rather than hardcode a path that may
    be wrong we look for the key wherever it lives. Discrepancies get recorded
    in docs/PRAVA_NOTES.md.
    """
    wanted = {k.lower().replace("_", "") for k in keys}
    stack = [payload]
    while stack:
        node = stack.pop(0)
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.lower().replace("_", "") in wanted and v:
                    return v
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


# ---------------------------------------------------------------------------
# Phase 1 — up to the passkey wall
# ---------------------------------------------------------------------------


async def phase_create() -> int:
    key = load_env()
    async with PravaClient(secret_key=key) as prava:
        print(f"  base_url     {prava.base_url}")
        print(f"  secret key   {key_fingerprint(key)}… (first 8 chars only)")

        step("1", "GET /health")
        health = await prava.health()
        show("health", health)
        if str(health.get("status", "")).lower() != "ok":
            print("\n  health is not ok — stopping.")
            return 1
        print("\n  ✓ sandbox is up")

        step("2", f"POST /v1/sessions — mandate_setup, ${TOTAL_AMOUNT} {CURRENCY}")
        session = await prava.create_mandate_session(
            user_id=SMOKE_USER_ID,
            user_email=SMOKE_USER_EMAIL,
            total_amount=TOTAL_AMOUNT,
            merchant_name=MERCHANT_NAME,
            merchant_url=MERCHANT_URL,
            description="Widget",
            unit_price="24.99",
            quantity=2,
            currency=CURRENCY,
            integration_type="full_checkout",
            callback_url=CALLBACK_URL,
        )
        show("session (redacted)", session)

        step("3", "identifiers")
        session_id = find_first(session, "session_id", "sessionId", "id")
        mandate_id = find_first(session, "mandate_id", "mandateId")
        iframe_url = find_first(session, "iframe_url", "iframeUrl")
        authorize_only = find_first(session, "authorizeOnly", "authorize_only")

        print(f"  session_id     {session_id}")
        print(f"  mandate_id     {mandate_id}")
        print(f"  authorizeOnly  {authorize_only}")
        print(f"  iframe_url     {iframe_url}")

        save_state(
            session_id=session_id,
            mandate_id=mandate_id,
            iframe_url=iframe_url,
            session_response=session,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        step("4", "STOP — human approval required")
        print(
            "\n  A person must now open the iframe_url above, enter a sandbox\n"
            "  test card and OTP, and approve with a real passkey (Touch ID).\n"
            "\n  !! The link is SINGLE-USE and expires in 15 minutes. Do not open\n"
            "     it to check that it works — one load consumes it and the next\n"
            "     shows 'Session Already Used'. Only the approver opens it.\n\n"
            "  Then run:  python scripts/prava_smoke.py resume\n"
        )
        return 0


# ---------------------------------------------------------------------------
# Phase 2 — after approval
# ---------------------------------------------------------------------------


async def poll_until_active(
    prava: PravaClient, mandate_id: str, *, attempts: int = 30, delay: float = 4.0
) -> dict[str, Any]:
    """Poll GET /v1/mandates/{id} until status is active.

    Terminal states other than ``active`` stop the poll immediately — waiting
    out a ``cancelled`` mandate only burns the session's 15-minute window.
    """
    terminal = {"consumed", "cancelled", "expired"}
    last: dict[str, Any] = {}
    for i in range(1, attempts + 1):
        last = await prava.get_mandate(mandate_id)
        status = str(last.get("status", "")).lower()
        print(f"  [{i:>2}/{attempts}] status={status or '?'}")
        if status == "active":
            return last
        if status in terminal:
            raise SystemExit(f"mandate reached terminal status {status!r}, not active")
        await asyncio.sleep(delay)
    raise SystemExit(f"mandate never reached active after {attempts} polls")


async def discover_mandate_id(prava: PravaClient, session_id: str) -> str:
    """Find the mandate id, which POST /v1/sessions does not return.

    Live sandbox (2026-08-02): payment-result after a successful mandate-setup
    approval stays at ``status: "processing"`` / txn ``authorized`` and never
    carries a ``mandate_id``. The mandate is readable from ``GET /v1/mandates``
    once passkey approval lands — look for ``externalUserId`` matching the
    smoke user and ``status: "active"``.
    """
    result = await prava.get_payment_result(session_id)
    show("payment-result (redacted)", result)
    mandate_id = find_first(result, "mandate_id", "mandateId")
    if mandate_id:
        print(f"\n  discovered mandate_id  {mandate_id} (from payment-result)")
        return mandate_id

    listed = await prava._request("GET", "/v1/mandates")
    show("mandates list (redacted)", listed)
    candidates = [
        m
        for m in (listed.get("mandates") or [])
        if isinstance(m, dict)
        and str(m.get("externalUserId") or "") == SMOKE_USER_ID
        and str(m.get("status") or "").lower() == "active"
    ]
    if not candidates:
        raise SystemExit(
            "No active mandate for this user yet.\n"
            f"  session status: {result.get('status')!r}\n"
            f"  user_id: {SMOKE_USER_ID!r}\n"
            "  If the session is still pending, the passkey approval has not landed."
        )
    # Prefer the newest active mandate for this user.
    candidates.sort(key=lambda m: str(m.get("createdAt") or ""), reverse=True)
    mandate_id = candidates[0]["id"]
    print(f"\n  discovered mandate_id  {mandate_id} (from GET /v1/mandates)")
    return mandate_id


async def phase_resume() -> int:
    key = load_env()
    state = read_state()
    mandate_id = state.get("mandate_id")
    session_id = state.get("session_id")
    if not session_id:
        sys.exit("No session_id in state. Run `prava_smoke.py create` first.")

    async with PravaClient(secret_key=key) as prava:
        print(f"  session_id   {session_id}")

        if not mandate_id:
            step("4b", "GET /v1/sessions/{id}/payment-result — find the mandate id")
            mandate_id = await discover_mandate_id(prava, session_id)
            save_state(mandate_id=mandate_id)
        print(f"  mandate_id   {mandate_id}")

        step("5", "poll GET /v1/mandates/{id} until active")
        mandate = await poll_until_active(prava, mandate_id)
        show("mandate @ active", mandate)

        step("6", f"POST /v1/mandates/{{id}}/charge — {TOTAL_AMOUNT}")
        reference = f"warrant-smoke-{uuid.uuid4().hex[:12]}"
        print(f"  reference    {reference}")
        charge = await prava.charge_mandate(
            mandate_id, TOTAL_AMOUNT, reference=reference
        )
        show("charge (redacted)", charge)

        creds = charge.get("credentials") or {}
        has_token = bool(creds.get("token"))
        has_cvv = bool(creds.get("dynamicCvv") or creds.get("dynamic_cvv"))
        print(f"\n  credentials.token      present={has_token}")
        print(f"  credentials.dynamicCvv present={has_cvv}")
        print(f"  status                 {charge.get('status')}")
        print(f"  fetchStatus            {charge.get('fetchStatus')}")
        if not (has_token and has_cvv):
            print("\n  ✗ no credentials returned — see errorCode above")

        step("7", "GET /v1/mandates/{id} — reconcile")
        after = await prava.get_mandate(mandate_id)
        show("mandate after charge", after)
        print(f"\n  approvedAmount  {after.get('approvedAmount')}")
        print(f"  spent           {after.get('spent')}")
        print(f"  chargeCount     {after.get('chargeCount')}")
        print(f"  charges[]       {len(after.get('charges') or [])} entr(y|ies)")

        save_state(
            mandate_active=mandate,
            charge_response=charge,
            charge_reference=reference,
            mandate_after_charge=after,
        )

        over_cap: dict[str, Any] = {}
        if has_token and has_cvv:
            step(
                "8",
                f"BONUS — over-cap charge {OVER_CAP_AMOUNT} against a ${TOTAL_AMOUNT} mandate",
            )
            print("  a decline here is the expected result, not a failure")
            try:
                result = await prava.charge_mandate(
                    mandate_id,
                    OVER_CAP_AMOUNT,
                    reference=f"warrant-smoke-overcap-{uuid.uuid4().hex[:12]}",
                )
                show("over-cap charge (redacted)", result)
                code = result.get("errorCode")
                print(f"\n  status={result.get('status')} errorCode={code}")
                over_cap = {"outcome": "http_200", "response": result}
            except PravaThresholdExceeded as exc:
                print(f"\n  ✓ declined with THRESHOLD_EXCEEDED — {exc}")
                over_cap = {"outcome": "THRESHOLD_EXCEEDED", "detail": str(exc)}
            except PravaError as exc:
                print(f"\n  declined with a different error: {exc}")
                over_cap = {
                    "outcome": type(exc).__name__,
                    "code": exc.code,
                    "detail": str(exc),
                }
            save_state(over_cap_charge=over_cap)

        print("\n  Record the observed shapes in docs/PRAVA_NOTES.md.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        nargs="?",
        default="create",
        choices=["create", "resume"],
        help="create: health + mandate session, stops at passkey. "
        "resume: after approval, poll + charge + reconcile.",
    )
    args = parser.parse_args()
    runner = phase_create if args.phase == "create" else phase_resume
    try:
        return asyncio.run(runner())
    except PravaError as exc:
        print(f"\n  PravaError: {exc}", file=sys.stderr)
        if exc.payload:
            print(json.dumps(exc.payload, indent=2, default=str), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
