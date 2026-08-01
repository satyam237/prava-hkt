"""Shared fixtures for the WARRANT test suite."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.models import Authorization, Merchant, Signal, Verification, Warrant
from app.warrant import generate_keypair

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_warrant.py"
COMMITTED_PUBLIC_KEY = REPO_ROOT / "keys" / "warrant_public.key"


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def private_key(keypair):
    return keypair[0]


@pytest.fixture
def public_key(keypair):
    return keypair[1]


def build_warrant(**overrides) -> Warrant:
    """A complete, realistic WARRANT with every field populated deterministically."""
    fields = dict(
        warrant_id="wrt_TESTFIXTURE0000000000",
        merchant=Merchant(domain="ridge.com", resolved_name="Ridge Wallet"),
        verification=Verification(
            verdict="PASS",
            score="0.87",
            signals=[
                Signal(name="domain_age_days", tier="A", value=2847, status="PASS"),
                Signal(name="safe_browsing", tier="A", value="no_match", status="PASS"),
                Signal(name="cert_first_seen_days", tier="A", value=2790, status="PASS"),
                Signal(name="psp_fingerprint", tier="B", value="stripe", status="PASS"),
                Signal(name="ucp_manifest", tier="C", value=True, status="PASS"),
                Signal(name="business_registry", tier="B", value=None, status="UNAVAILABLE"),
                Signal(name="injection_scan", tier="D", value="clean", status="PASS"),
            ],
            content_hash="sha256:" + "a3f1" * 16,
        ),
        authorization=Authorization(
            sku="RW-TITAN-01",
            description="Ridge Titanium Wallet, Raw",
            quantity=1,
            amount="84.00",
            currency="USD",
            single_use=True,
            expected_fulfillment_by=datetime(2026, 8, 12, 0, 0, 0, tzinfo=timezone.utc),
        ),
        issued_at=datetime(2026, 8, 2, 21, 14, 3, tzinfo=timezone.utc),
    )
    fields.update(overrides)
    return Warrant(**fields)


@pytest.fixture
def warrant() -> Warrant:
    return build_warrant()
