"""Merchant resolution: a URL or a free-text intent to one registrable domain.

The domain is the merchant's identity in a WARRANT, so it has to be derived the
same way a browser and a certificate authority derive it — from the Public
Suffix List, not from a regex. ``shop.example.co.uk`` is ``example.co.uk``; a
regex that takes the last two labels says ``co.uk`` and verifies the wrong
party.

Resolution is offline and does no network I/O: ``tldextract`` is pinned to its
bundled snapshot so the first call on a cold demo machine cannot block on a
fetch of the suffix list.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

#: ``suffix_list_urls=()`` forces the bundled snapshot. The alternative is a
#: silent HTTP fetch on first use, which is both a hang risk and a test
#: dependency on the network.
_extract = tldextract.TLDExtract(suffix_list_urls=())

#: Trailing punctuation that survives whitespace tokenization of prose.
_TRIM = ".,;:!?)]}>\"'`"

#: Hosts with no public suffix that are still legitimate targets — the spoof and
#: breach storefronts in ``merchants/`` are served locally. They resolve, and
#: then fail verification on their own merits, which is the point of the demo.
_LITERAL_HOSTS = frozenset({"localhost"})


class UnresolvableMerchant(ValueError):
    """No registrable domain could be read out of the reference."""


@dataclass(frozen=True)
class ResolvedMerchant:
    """What the agent decided it is about to transact with.

    ``domain`` is the registrable domain and the merchant's identity. ``host``
    keeps the subdomain, because that is the host the agent actually reads and
    the one TLS is presented for.
    """

    domain: str
    host: str
    url: str
    source: str
    reference: str


def _host_of(candidate: str) -> str | None:
    """The hostname of a URL or bare authority, or None if there isn't one."""

    if not candidate or any(character.isspace() for character in candidate):
        return None
    try:
        parts = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = parts.hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _resolve_host(host: str) -> str | None:
    extracted = _extract(host)
    if extracted.registered_domain:
        return extracted.registered_domain
    if host in _LITERAL_HOSTS or host.endswith(".localhost"):
        return host
    return None


def resolve(reference: str) -> ResolvedMerchant:
    """Resolve a URL or an intent sentence to one merchant.

    A bare reference is tried whole; prose is tokenized on whitespace and the
    first token carrying a public suffix wins. Only the suffix decision is
    delegated to ``tldextract`` — the tokenizer never decides what a domain is.
    """

    text = reference.strip()
    if not text:
        raise UnresolvableMerchant("reference is empty")

    host = _host_of(text)
    if host is not None:
        domain = _resolve_host(host)
        if domain is not None:
            return _build(domain, host, text, source="url", original=text)

    for token in text.split():
        candidate = token.strip(_TRIM)
        token_host = _host_of(candidate)
        if token_host is None:
            continue
        domain = _resolve_host(token_host)
        if domain is not None:
            return _build(domain, token_host, candidate, source="intent", original=text)

    raise UnresolvableMerchant(
        f"no registrable domain in {reference!r}; name the merchant's site"
    )


def _build(domain: str, host: str, matched: str, *, source: str, original: str) -> ResolvedMerchant:
    url = matched if "://" in matched else f"https://{host}/"
    return ResolvedMerchant(domain=domain, host=host, url=url, source=source, reference=original)


__all__ = ["ResolvedMerchant", "UnresolvableMerchant", "resolve"]
