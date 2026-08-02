"""TLS certificate validity probe."""

from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urlparse

from app.probes.base import PROBE_TIMEOUT_SECONDS, ProbeUnavailable, Signal, SignalStatus, probe

NAME = "tls_certificate"
TIER = "A"


def _host(domain_or_url: str) -> str:
    parsed = urlparse(domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}")
    host = parsed.hostname
    if not host:
        raise ProbeUnavailable("could not determine TLS host")
    return host.rstrip(".").lower()


def _check_tls_sync(host: str) -> Signal:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=PROBE_TIMEOUT_SECONDS) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return Signal(NAME, TIER, "invalid", SignalStatus.FAIL, f"TLS certificate verification failed: {exc.verify_message}")
    except (TimeoutError, socket.timeout, OSError) as exc:
        raise ProbeUnavailable(f"TLS host unreachable: {exc}") from exc
    if not cert:
        return Signal(NAME, TIER, "invalid", SignalStatus.FAIL, "TLS peer did not present a certificate")
    issuer = cert.get("issuer", ())
    issuer_text = ", ".join("=".join(part) for group in issuer for part in group) if issuer else "unknown issuer"
    return Signal(NAME, TIER, "valid", SignalStatus.PASS, f"valid hostname-matching certificate ({issuer_text})")


@probe(NAME, TIER)
async def run(domain: str) -> Signal:
    host = _host(domain)
    return await asyncio.to_thread(_check_tls_sync, host)


__all__ = ["run"]
