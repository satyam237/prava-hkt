"""RDAP domain-age probe."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import tldextract

from app.probes.base import ProbeUnavailable, Signal, SignalStatus, fetch_json, probe

TIER = "A"
NAME = "domain_age_days"
_RDAP_URL = "https://rdap.org/domain/{domain}"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_CACHE: dict[str, Signal] = {}


def registered_domain(value: str) -> str:
    extracted = _EXTRACT(value)
    domain = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain
    if not domain:
        raise ProbeUnavailable("could not determine registrable domain")
    return domain.lower()


def _parse_rdap_registration_date(payload: Any) -> datetime:
    if not isinstance(payload, dict):
        raise ProbeUnavailable("malformed RDAP payload")
    events = payload.get("events")
    if not isinstance(events, list):
        raise ProbeUnavailable("RDAP payload missing events[]")
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") != "registration":
            continue
        event_date = event.get("eventDate")
        if not isinstance(event_date, str):
            raise ProbeUnavailable("RDAP registration event missing eventDate")
        try:
            parsed = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProbeUnavailable("RDAP registration eventDate is malformed") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    raise ProbeUnavailable("RDAP payload has no registration event")


@probe(NAME, TIER)
async def run(domain: str, *, client: httpx.AsyncClient | None = None, now: datetime | None = None) -> Signal:
    registrable = registered_domain(domain)
    if client is None and registrable in _CACHE:
        return _CACHE[registrable]

    response = await fetch_json("GET", _RDAP_URL.format(domain=registrable), client=client)
    registered_at = _parse_rdap_registration_date(response.payload)
    as_of = now or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    age_days = max(0, (as_of.astimezone(timezone.utc) - registered_at).days)
    status = SignalStatus.PASS if age_days >= 30 else SignalStatus.FAIL
    signal = Signal(
        name=NAME,
        tier=TIER,
        value=age_days,
        status=status,
        detail=f"{registrable} registered {registered_at.date().isoformat()} ({age_days} days old)",
    )
    if client is None:
        _CACHE[registrable] = signal
    return signal


__all__ = ["run", "registered_domain"]
