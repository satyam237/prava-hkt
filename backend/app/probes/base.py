"""Shared probe contract and concurrent fan-out.

Every external verifier is wrapped here so callers never see exceptions from a
flaky third party. Manual RDAP smoke test (no key required):

    uv run python -c "import asyncio; from app.probes.rdap import run; print(asyncio.run(run('example.com')))"
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Literal, TypeVar

import httpx

PROBE_TIMEOUT_SECONDS = 2.0
SignalTier = Literal["A", "B", "C", "D"]


class SignalStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class Signal:
    """One UI-facing verification observation.

    ``UNAVAILABLE`` means the probe produced no usable evidence and is therefore
    excluded from score denominators by ``score_signals``.
    """

    name: str
    tier: SignalTier
    value: bool | int | str | None
    status: SignalStatus | str
    detail: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.value, float):
            raise TypeError("Signal.value must not be a float; stringify fractional values")
        object.__setattr__(self, "status", SignalStatus(self.status))


class ProbeUnavailable(Exception):
    """Raised inside probes when an external response cannot be used as evidence."""


@dataclass(frozen=True)
class JsonResponse:
    payload: Any
    headers: httpx.Headers


ProbeCallable = Callable[..., Awaitable[Signal]]
T = TypeVar("T", bound=ProbeCallable)


def unavailable(name: str, tier: SignalTier, detail: str) -> Signal:
    return Signal(name=name, tier=tier, value=None, status=SignalStatus.UNAVAILABLE, detail=detail)


def _normalize_signal(result: Any, *, name: str, tier: SignalTier) -> Signal:
    if not isinstance(result, Signal):
        raise ProbeUnavailable(f"probe returned malformed result {type(result).__name__}")
    if result.name != name or result.tier != tier:
        return Signal(name=name, tier=tier, value=result.value, status=result.status, detail=result.detail)
    return result


async def _run_with_contract(fn: ProbeCallable, *args: Any, name: str, tier: SignalTier, **kwargs: Any) -> Signal:
    try:
        result = await asyncio.wait_for(fn(*args, **kwargs), timeout=PROBE_TIMEOUT_SECONDS)
        return _normalize_signal(result, name=name, tier=tier)
    except asyncio.TimeoutError:
        return unavailable(name, tier, f"{name} timed out after {PROBE_TIMEOUT_SECONDS:.0f}s")
    except ProbeUnavailable as exc:
        return unavailable(name, tier, str(exc))
    except Exception as exc:  # noqa: BLE001 - the contract forbids escaping probe errors.
        return unavailable(name, tier, f"{name} unavailable: {type(exc).__name__}: {exc}")


def probe(name: str, tier: SignalTier) -> Callable[[T], T]:
    """Decorate a probe implementation with the mandatory failure contract."""

    def decorator(fn: T) -> T:
        @wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> Signal:
            return await _run_with_contract(fn, *args, name=name, tier=tier, **kwargs)

        setattr(wrapped, "probe_name", name)
        setattr(wrapped, "probe_tier", tier)
        setattr(wrapped, "_warrant_probe_wrapped", True)
        return wrapped  # type: ignore[return-value]

    return decorator


async def _call_probe(fn: ProbeCallable, domain: str) -> Signal:
    name = getattr(fn, "probe_name", getattr(fn, "__name__", "probe"))
    tier = getattr(fn, "probe_tier", "D")
    if getattr(fn, "_warrant_probe_wrapped", False):
        return await fn(domain)
    return await _run_with_contract(fn, domain, name=name, tier=tier)


async def run_probes(domain: str, probes: Iterable[ProbeCallable] | None = None) -> list[Signal]:
    """Run probes concurrently and return when the slowest probe completes."""

    if probes is None:
        from app.probes import injection, rdap, safebrowsing, tls

        probes = (rdap.run, safebrowsing.run, tls.run, injection.run)
    return list(await asyncio.gather(*(_call_probe(fn, domain) for fn in probes)))


async def iter_probe_results(domain: str, probes: Iterable[ProbeCallable] | None = None) -> AsyncIterator[Signal]:
    """Yield probe results as they complete for future SSE streaming."""

    if probes is None:
        from app.probes import injection, rdap, safebrowsing, tls

        probes = (rdap.run, safebrowsing.run, tls.run, injection.run)
    tasks = [asyncio.create_task(_call_probe(fn, domain)) for fn in probes]
    for task in asyncio.as_completed(tasks):
        yield await task


def score_signals(signals: Iterable[Signal]) -> float:
    """Fraction of available probes that passed; UNAVAILABLE is not a zero."""

    available = [signal for signal in signals if signal.status is not SignalStatus.UNAVAILABLE]
    if not available:
        return 0.0
    passed = sum(1 for signal in available if signal.status is SignalStatus.PASS)
    return passed / len(available)


def verdict(signals: Iterable[Signal], *, threshold: float = 0.70) -> str:
    """Binary PASS/HALT gate with hard-fail signals before corroboration score."""

    signal_list = list(signals)
    for signal in signal_list:
        if signal.status is not SignalStatus.FAIL:
            continue
        if signal.name in {"safe_browsing", "domain_age_days", "injection_scan", "tls_certificate", "tls"}:
            return "HALT"
    return "PASS" if score_signals(signal_list) >= threshold else "HALT"


async def fetch_json(method: str, url: str, *, client: httpx.AsyncClient | None = None, **kwargs: Any) -> JsonResponse:
    """Fetch JSON or raise ``ProbeUnavailable`` for non-200/malformed responses."""

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=True)
    try:
        assert client is not None
        response = await client.request(method, url, **kwargs)
        if response.status_code != 200:
            retry = response.headers.get("Retry-After")
            suffix = f"; retry after {retry}" if retry else ""
            raise ProbeUnavailable(f"HTTP {response.status_code}{suffix}")
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            raise ProbeUnavailable("malformed JSON payload") from exc
        return JsonResponse(payload=payload, headers=response.headers)
    finally:
        if owns_client and client is not None:
            await client.aclose()


async def fetch_text(method: str, url: str, *, client: httpx.AsyncClient | None = None, **kwargs: Any) -> str:
    """Fetch text or raise ``ProbeUnavailable`` for non-200 responses."""

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=True)
    try:
        assert client is not None
        response = await client.request(method, url, **kwargs)
        if response.status_code != 200:
            raise ProbeUnavailable(f"HTTP {response.status_code}")
        return response.text
    finally:
        if owns_client and client is not None:
            await client.aclose()
