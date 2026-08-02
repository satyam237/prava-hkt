"""Google Web Risk threat-reputation probe.

Web Risk, not Safe Browsing v4. The v4 APIs carry a deprecation banner
(https://developers.google.com/safe-browsing/v4/) and their terms restrict use to
non-commercial purposes; v5 replaced the simple URL lookup with a hash-prefix
scheme that requires local canonicalisation and SHA256 work. Web Risk's
``uris:search`` is a plain GET with a published free tier of 100,000 calls per
month (https://cloud.google.com/web-risk/pricing), which is the same signal for
materially less code.

A hit here is dispositive and short-circuits scoring as a hard fail.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlencode

import httpx

from app.probes.base import (
    ProbeUnavailable,
    Signal,
    SignalStatus,
    fetch_json,
    probe,
    timeout_for,
)

NAME = "safe_browsing"
TIER = "A"
_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")


def _merchant_url(domain_or_url: str) -> str:
    return domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}/"


def _request_url(domain_or_url: str, key: str) -> str:
    # threatTypes repeats rather than taking a comma-joined list.
    params = [("threatTypes", threat) for threat in _THREAT_TYPES]
    params.append(("uri", _merchant_url(domain_or_url)))
    params.append(("key", key))
    return f"{_ENDPOINT}?{urlencode(params)}"


@probe(NAME, TIER)
async def run(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    api_key: str | None = None,
) -> Signal:
    key = api_key or os.getenv("GOOGLE_WEB_RISK_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return Signal(NAME, TIER, None, SignalStatus.UNAVAILABLE, "GOOGLE_WEB_RISK_API_KEY is not set")

    response = await fetch_json(
        "GET",
        _request_url(domain, key),
        client=client,
        timeout=timeout_for(NAME),
    )
    payload = response.payload
    if not isinstance(payload, dict):
        raise ProbeUnavailable("malformed Web Risk payload")

    # A clean URI returns `{}` — an absent `threat` key is the pass case, and is
    # deliberately distinct from a transport failure, which raises above.
    threat = payload.get("threat")
    if threat is None:
        return Signal(NAME, TIER, "no_match", SignalStatus.PASS, "Google Web Risk returned no threat")
    if not isinstance(threat, dict):
        raise ProbeUnavailable("malformed Web Risk threat object")

    types: Any = threat.get("threatTypes")
    named = ", ".join(str(t) for t in types) if isinstance(types, list) and types else "threat match"
    return Signal(NAME, TIER, "match", SignalStatus.FAIL, f"Google Web Risk match: {named}")


__all__ = ["run"]
