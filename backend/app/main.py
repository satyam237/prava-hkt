"""FastAPI surface for Warrant: a live verification trace and the gate behind it.

The interesting endpoint is the SSE stream. Probes run concurrently and each
result is pushed the instant it lands, so a verification that takes a couple of
seconds *reads* as a couple of seconds of work rather than a spinner. Run
sequentially the same four probes take about eight seconds and look broken.

The stream ends in one of two ways and there is no third:

``PASS``  a signed WARRANT with its hash, persisted and retrievable.
``HALT``  a reason, and nothing else. No warrant row exists, so the payment
          endpoint has nothing to load and returns 404. The refusal is
          structural — see :mod:`app.gate` for why that is a type and not a flag.

Every Prava call goes through :mod:`app.payment`, which cannot be entered
without a value only the gate can mint.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from html.parser import HTMLParser

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import Field
from sse_starlette import EventSourceResponse

from app import gate, payment, store
from app.models import (
    WARRANT_VERSION,
    Authorization,
    CurrencyStr,
    Merchant,
    MoneyStr,
    StrictModel,
    UtcDatetime,
    Verdict,
    Warrant,
)
from app.probes import injection, rdap, safebrowsing, tls
from app.probes.base import Signal, SignalStatus, iter_probe_results, score_signals
from app.resolve import UnresolvableMerchant, resolve
from app.services.prava_client import PravaError
from app.warrant import DEFAULT_PRIVATE_KEY_PATH, WarrantKeyError

#: The probe set this app runs. Declared here rather than left to
#: ``iter_probe_results``'s default so the list announced to the UI and the list
#: actually executed cannot drift apart.
DEFAULT_PROBES = (rdap.run, safebrowsing.run, tls.run, injection.run)

#: Budget for reading the merchant page for ``content_hash``. Runs concurrently
#: with the probes, so it costs nothing on the wall clock.
CONTENT_READ_TIMEOUT = 4.0
CONTENT_READ_LIMIT = 2 * 1024 * 1024

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Merchant page read
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PageRead:
    """The bytes the agent read from the merchant, digested."""

    content_hash: str
    byte_count: int
    title: str | None = None
    error: str | None = None


class _TitleParser(HTMLParser):
    """First ``<title>`` only. The name is merchant-declared, never evidence."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag == "title" and self.title is None:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            cleaned = " ".join(data.split())
            self.title = cleaned[:120] or None


async def read_merchant_page(url: str) -> PageRead:
    """Fetch the merchant page and digest exactly the bytes that came back.

    A failed read is recorded as such rather than hidden: the digest of zero
    bytes is well defined, ``byte_count`` is 0, and ``error`` says why. The
    verification record keeps all three, so "we read nothing" is never
    indistinguishable from "we read an empty page".
    """

    try:
        async with httpx.AsyncClient(
            timeout=CONTENT_READ_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Warrant/1.0 (+verification)"},
        ) as client:
            response = await client.get(url)
            body = response.content[:CONTENT_READ_LIMIT]
    except Exception as exc:  # noqa: BLE001 - a merchant page is a third party.
        return PageRead(
            content_hash=f"sha256:{_EMPTY_SHA256}",
            byte_count=0,
            error=f"{type(exc).__name__}: {exc}",
        )

    parser = _TitleParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - malformed HTML must not fail a verification.
        pass
    return PageRead(
        content_hash="sha256:" + hashlib.sha256(body).hexdigest(),
        byte_count=len(body),
        title=parser.title,
        error=None if response.is_success else f"HTTP {response.status_code}",
    )


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class ResolveRequest(StrictModel):
    reference: str


class IntentRequest(StrictModel):
    """What to buy and the ceiling, plus the merchant reference to verify."""

    reference: str
    sku: str
    description: str
    quantity: int = Field(default=1, ge=1)
    amount: MoneyStr
    currency: CurrencyStr = "USD"
    expected_fulfillment_by: UtcDatetime | None = None


# ---------------------------------------------------------------------------
# Seams
# ---------------------------------------------------------------------------


def get_probes() -> Sequence[object]:
    """The probes a verification runs. Overridden in tests."""

    return DEFAULT_PROBES


def get_page_reader():
    """How the merchant page is read. Overridden in tests to stay offline."""

    return read_merchant_page


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # get_engine, not configure: a test that has already pointed the store at a
    # temporary database must not have it swapped out from under it on startup.
    store.get_engine()
    yield


app = FastAPI(
    title="Warrant",
    version=WARRANT_VERSION,
    summary="Proves the merchant to the agent, and makes that proof a precondition "
    "of the payment credential.",
    lifespan=lifespan,
)

# The UI is a separate Vite origin and EventSource is subject to CORS. Nothing
# here is authenticated by cookie, so a permissive default costs nothing;
# WARRANT_CORS_ORIGINS narrows it when that stops being true.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.environ.get("WARRANT_CORS_ORIGINS", "*").split(",")
        if origin.strip()
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, object]:
    """Liveness plus an honest capability report.

    ``payment.configured`` false means the payment leg will refuse rather than
    pretend, and the passkey status says what is broken upstream today.
    """

    return {
        "status": "ok",
        "service": "warrant",
        "version": WARRANT_VERSION,
        "signing_key": bool(os.environ.get("WARRANT_SIGNING_KEY"))
        or _default_signing_key_present(),
        "payment": {
            "configured": payment.is_configured(),
            "passkey": payment.PASSKEY_STATUS,
            "notice": payment.PASSKEY_NOTICE,
        },
    }


@app.post("/v1/merchants/resolve")
async def resolve_merchant(body: ResolveRequest) -> dict[str, str]:
    """Read one registrable domain out of a URL or an intent sentence."""

    return _merchant_payload(_resolve_or_422(body.reference))


@app.post("/v1/intents", status_code=201)
async def create_intent(body: IntentRequest) -> dict[str, object]:
    """Record what is about to be verified, and return the id the stream uses.

    Split from the stream because ``EventSource`` can only issue a GET with no
    body, and an authorization does not belong in a query string.
    """

    merchant = _resolve_or_422(body.reference)
    record = store.IntentRecord(
        intent_id="int_" + secrets.token_urlsafe(12),
        reference=body.reference,
        domain=merchant.domain,
        host=merchant.host,
        url=merchant.url,
        source=merchant.source,
        sku=body.sku,
        description=body.description,
        quantity=body.quantity,
        amount=body.amount,
        currency=body.currency,
        expected_fulfillment_by=body.expected_fulfillment_by,
    )
    store.save(record)
    return {
        "intent_id": record.intent_id,
        "merchant": _merchant_payload(merchant),
        "authorization": _authorization_payload(record),
    }


@app.get("/v1/intents/{intent_id}/verify")
async def verify_stream(
    intent_id: str,
    request: Request,
    probes: Sequence[object] = Depends(get_probes),
    page_reader=Depends(get_page_reader),
):
    """Stream the verification trace, then the verdict.

    Events, in order: one ``started``, one ``probe`` per signal as it completes,
    then exactly one ``verdict`` — or one ``error`` if the run could not reach a
    verdict at all. A ``verdict`` carries the signed warrant only on PASS.
    """

    intent = store.get_intent(intent_id)
    if intent is None:
        raise HTTPException(status_code=404, detail=f"no intent {intent_id}")

    return EventSourceResponse(
        _verification_events(intent, request, probes=probes, page_reader=page_reader)
    )


@app.get("/v1/verifications/{verification_id}")
async def read_verification(verification_id: str) -> dict[str, object]:
    record = store.get_verification(verification_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no verification {verification_id}")
    return _verification_payload(record)


@app.get("/v1/warrants/{warrant_id}")
async def read_warrant(warrant_id: str) -> dict[str, object]:
    """The signed document and the verification run that produced it."""

    record = store.get_warrant(warrant_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no warrant {warrant_id}")
    verification = store.get_verification_for_warrant(warrant_id)
    return {
        "warrant": record.document,
        "warrant_hash": record.warrant_hash,
        "verification": _verification_payload(verification) if verification else None,
    }


@app.get("/v1/warrants/{warrant_id}/document")
async def download_warrant(warrant_id: str) -> Response:
    """The document alone, serialized so a judge can verify it offline.

    Rendered with sorted keys and no whitespace, so the saved file minus its
    ``signature`` key is byte-for-byte the message that was signed. Check it
    with ``python scripts/verify_warrant.py <file>``.
    """

    record = store.get_warrant(warrant_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no warrant {warrant_id}")
    body = json.dumps(
        record.document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{warrant_id}.json"'},
    )


@app.post("/v1/warrants/{warrant_id}/session")
async def open_session(warrant_id: str) -> dict[str, object]:
    """Request a Prava session scoped to a cleared warrant.

    Reachable only with a stored warrant, which only a PASS produces. The
    warrant is re-verified before the gate reopens, so an edited row is not an
    authorization.

    The returned ``iframe_url`` is single-use and expires in 15 minutes. Do not
    prefetch it — hand it to the person at the keyboard, unopened.
    """

    record = store.get_warrant(warrant_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"no warrant {warrant_id}")

    try:
        cleared = gate.clear_issued(Warrant.model_validate(record.document))
    except gate.GateRefused as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        result = await payment.request_session(cleared)
    except payment.PaymentUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except PravaError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    store.save(
        store.SessionRecord(
            session_id=result["session_id"],
            warrant_id=warrant_id,
            order_id=result.get("order_id"),
            iframe_url=result.get("iframe_url"),
            expires_at=result.get("expires_at"),
        )
    )
    return result


@app.get("/v1/sessions/{session_id}/result")
async def read_session_result(session_id: str) -> dict[str, object]:
    """Poll a session. Credentials are redacted before they reach a client."""

    try:
        return await payment.poll_session(session_id)
    except payment.PaymentUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except PravaError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# The stream
# ---------------------------------------------------------------------------


async def _verification_events(
    intent: store.IntentRecord,
    request: Request,
    *,
    probes: Sequence[object],
    page_reader,
) -> AsyncIterator[dict[str, str]]:
    verification_id = "ver_" + secrets.token_urlsafe(12)
    page_task = asyncio.create_task(page_reader(intent.url))

    yield _event(
        "started",
        {
            "verification_id": verification_id,
            "intent_id": intent.intent_id,
            "merchant": {"domain": intent.domain, "host": intent.host, "url": intent.url},
            "probes": [
                {
                    "name": getattr(fn, "probe_name", getattr(fn, "__name__", "probe")),
                    "tier": getattr(fn, "probe_tier", "D"),
                }
                for fn in probes
            ],
        },
    )

    signals: list[Signal] = []
    try:
        async for signal in iter_probe_results(intent.domain, probes):
            signals.append(signal)
            yield _event("probe", _signal_payload(signal))
            if await request.is_disconnected():
                page_task.cancel()
                return
    except Exception as exc:  # noqa: BLE001 - a dead stream must still say why.
        page_task.cancel()
        yield _event("error", {"error": f"{type(exc).__name__}: {exc}"})
        return

    page: PageRead = await page_task
    score = score_signals(signals)

    try:
        decision = gate.decide(
            merchant=Merchant(domain=intent.domain, resolved_name=page.title),
            authorization=_authorization(intent),
            signals=signals,
            content_hash=page.content_hash,
            score=score,
        )
    except WarrantKeyError as exc:
        yield _event("error", {"error": str(exc)})
        return

    cleared = decision if isinstance(decision, gate.ClearedWarrant) else None
    record = store.VerificationRecord(
        verification_id=verification_id,
        intent_id=intent.intent_id,
        domain=intent.domain,
        resolved_name=page.title,
        verdict=Verdict.PASS.value if cleared else Verdict.HALT.value,
        score=cleared.warrant.verification.score if cleared else decision.score,
        content_hash=page.content_hash,
        signals=[_signal_payload(signal) for signal in signals],
        halt_reason=None if cleared else decision.reason,
        warrant_id=cleared.warrant.warrant_id if cleared else None,
    )
    if cleared is None:
        store.save(record)
    else:
        store.save(
            record,
            store.WarrantRecord(
                warrant_id=cleared.warrant.warrant_id,
                verification_id=verification_id,
                domain=intent.domain,
                warrant_hash=cleared.warrant_hash,
                document=cleared.warrant.model_dump(mode="json"),
                issued_at=cleared.warrant.issued_at,
            ),
        )

    yield _event(
        "verdict",
        {
            "verification_id": verification_id,
            "verdict": record.verdict,
            "score": record.score,
            "content_hash": page.content_hash,
            "content_bytes": page.byte_count,
            "content_error": page.error,
            "signals": record.signals,
            "halt_reason": record.halt_reason,
            "warrant": cleared.warrant.model_dump(mode="json") if cleared else None,
            "warrant_hash": cleared.warrant_hash if cleared else None,
            "payment": {
                "available": bool(cleared) and payment.is_configured(),
                "passkey": payment.PASSKEY_STATUS,
                "notice": payment.PASSKEY_NOTICE,
            },
        },
    )


def _event(name: str, payload: object) -> dict[str, str]:
    return {"event": name, "data": json.dumps(payload, separators=(",", ":"))}


def _signal_payload(signal: Signal) -> dict[str, object]:
    return {
        "name": signal.name,
        "tier": signal.tier,
        "value": signal.value,
        "status": SignalStatus(signal.status).value,
        "detail": signal.detail,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_or_422(reference: str):
    try:
        return resolve(reference)
    except UnresolvableMerchant as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _merchant_payload(merchant) -> dict[str, str]:
    return {
        "domain": merchant.domain,
        "host": merchant.host,
        "url": merchant.url,
        "source": merchant.source,
    }


def _authorization(intent: store.IntentRecord) -> Authorization:
    return Authorization(
        sku=intent.sku,
        description=intent.description,
        quantity=intent.quantity,
        amount=intent.amount,
        currency=intent.currency,
        single_use=True,
        expected_fulfillment_by=intent.expected_fulfillment_by,
    )


def _authorization_payload(intent: store.IntentRecord) -> dict[str, object]:
    return _authorization(intent).model_dump(mode="json")


def _verification_payload(record: store.VerificationRecord) -> dict[str, object]:
    return {
        "verification_id": record.verification_id,
        "intent_id": record.intent_id,
        "domain": record.domain,
        "resolved_name": record.resolved_name,
        "verdict": record.verdict,
        "score": record.score,
        "content_hash": record.content_hash,
        "signals": record.signals,
        "halt_reason": record.halt_reason,
        "warrant_id": record.warrant_id,
        "created_at": record.created_at.isoformat(),
    }


def _default_signing_key_present() -> bool:
    return DEFAULT_PRIVATE_KEY_PATH.is_file()


__all__ = ["CONTENT_READ_TIMEOUT", "DEFAULT_PROBES", "PageRead", "app", "read_merchant_page"]
