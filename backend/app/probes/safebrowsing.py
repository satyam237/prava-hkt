"""Google Safe Browsing Lookup v4 probe."""

from __future__ import annotations

import os
from typing import Any

import httpx

from app.probes.base import ProbeUnavailable, Signal, SignalStatus, fetch_json, probe

NAME = "safe_browsing"
TIER = "A"
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def _merchant_url(domain_or_url: str) -> str:
    return domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}/"


def _request_body(domain_or_url: str) -> dict[str, Any]:
    return {
        "client": {"clientId": "warrant", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": _merchant_url(domain_or_url)}],
        },
    }


@probe(NAME, TIER)
async def run(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    api_key: str | None = None,
) -> Signal:
    key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return Signal(NAME, TIER, None, SignalStatus.UNAVAILABLE, "GOOGLE_SAFE_BROWSING_API_KEY is not set")

    response = await fetch_json("POST", _ENDPOINT.format(key=key), client=client, json=_request_body(domain))
    payload = response.payload
    if not isinstance(payload, dict):
        raise ProbeUnavailable("malformed Safe Browsing payload")
    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        raise ProbeUnavailable("malformed Safe Browsing matches[]")
    if matches:
        first = matches[0] if isinstance(matches[0], dict) else {}
        threat = first.get("threatType", "threat match")
        return Signal(NAME, TIER, "match", SignalStatus.FAIL, f"Google Safe Browsing match: {threat}")
    return Signal(NAME, TIER, "no_match", SignalStatus.PASS, "Google Safe Browsing returned no matches")


__all__ = ["run"]
