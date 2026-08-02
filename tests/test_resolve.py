"""Merchant resolution must produce the registrable domain, not a guess at one."""

from __future__ import annotations

import pytest

from app.resolve import UnresolvableMerchant, resolve


def test_url_resolves_to_registrable_domain():
    merchant = resolve("https://www.ridge.com/products/titanium?ref=x")
    assert merchant.domain == "ridge.com"
    assert merchant.host == "www.ridge.com"
    assert merchant.url == "https://www.ridge.com/products/titanium?ref=x"
    assert merchant.source == "url"


def test_multi_label_suffix_is_not_the_last_two_labels():
    # The case a regex gets wrong: eTLD+1 here is example.co.uk, not co.uk.
    assert resolve("https://shop.example.co.uk/cart").domain == "example.co.uk"


def test_bare_domain_resolves():
    merchant = resolve("ridge.com")
    assert merchant.domain == "ridge.com"
    assert merchant.url == "https://ridge.com/"


def test_intent_sentence_resolves_the_named_site():
    merchant = resolve("Buy me the titanium wallet from ridge.com, under $90.")
    assert merchant.domain == "ridge.com"
    assert merchant.source == "intent"


def test_host_is_lowercased():
    assert resolve("HTTPS://WWW.Ridge.COM/x").domain == "ridge.com"


def test_local_storefront_resolves_so_it_can_fail_verification_on_its_merits():
    merchant = resolve("http://spoof.localhost:8001/")
    assert merchant.domain == "spoof.localhost"


@pytest.mark.parametrize("reference", ["", "   ", "buy me a wallet", "just some words"])
def test_unresolvable_references_raise(reference):
    with pytest.raises(UnresolvableMerchant):
        resolve(reference)
