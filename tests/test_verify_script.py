"""End-to-end test of the offline verifier a judge actually runs.

Every test here shells out to ``scripts/verify_warrant.py`` in a subprocess with
the committed public key, because that is the exact path a third party takes.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from app.warrant import load_public_key, sign_warrant
from app.models import Warrant

from conftest import COMMITTED_PUBLIC_KEY, VERIFY_SCRIPT, build_warrant


def run_verifier(*args: str) -> subprocess.CompletedProcess:
    """Run the verifier the way a judge would: plain python, no PYTHONPATH."""
    return subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def signing_key():
    """Sign with the real project key so the committed public key is the verifier."""
    from app.warrant import load_signing_key

    try:
        return load_signing_key()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"project signing key unavailable: {exc}")


@pytest.fixture
def signed_file(tmp_path, signing_key):
    signed = sign_warrant(build_warrant(), signing_key)
    path = tmp_path / "signed_warrant.json"
    path.write_text(json.dumps(signed.model_dump(mode="json"), indent=2), encoding="utf-8")
    return path


def test_committed_public_key_matches_the_project_signing_key(signing_key):
    """If this fails, the committed key cannot verify anything we issue."""
    from app.warrant import public_key_to_b64

    assert public_key_to_b64(signing_key.public_key()) == public_key_to_b64(
        load_public_key(COMMITTED_PUBLIC_KEY)
    )


def test_verifies_a_freshly_signed_warrant(signed_file):
    result = run_verifier(str(signed_file))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID" in result.stdout
    assert "INVALID" not in result.stdout


def test_output_shows_merchant_amount_and_issued_at(signed_file):
    result = run_verifier(str(signed_file))
    assert "ridge.com" in result.stdout
    assert "Ridge Wallet" in result.stdout
    assert "84.00 USD" in result.stdout
    assert "2026-08-02T21:14:03Z" in result.stdout
    assert "PASS" in result.stdout


def test_the_script_imports_nothing_from_the_application():
    """It must run standalone: stdlib plus cryptography, nothing else."""
    source = VERIFY_SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("from app", "import app", "fastapi", "pydantic", "sqlmodel"):
        assert forbidden not in source, f"verifier must not depend on {forbidden}"


def test_detects_a_tampered_amount(tmp_path, signed_file):
    document = json.loads(signed_file.read_text(encoding="utf-8"))
    document["authorization"]["amount"] = "8400.00"
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")

    result = run_verifier(str(tampered))
    assert result.returncode == 1
    assert "INVALID" in result.stdout


def test_detects_a_swapped_merchant(tmp_path, signed_file):
    document = json.loads(signed_file.read_text(encoding="utf-8"))
    document["merchant"]["domain"] = "ridge-deals-official.com"
    tampered = tmp_path / "swapped.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")

    result = run_verifier(str(tampered))
    assert result.returncode == 1
    assert "INVALID" in result.stdout


def test_rejects_a_warrant_signed_by_an_unknown_key(tmp_path):
    from app.warrant import generate_keypair

    rogue_key, _ = generate_keypair()
    signed = sign_warrant(build_warrant(), rogue_key)
    path = tmp_path / "rogue.json"
    path.write_text(json.dumps(signed.model_dump(mode="json")), encoding="utf-8")

    result = run_verifier(str(path))
    assert result.returncode == 1
    assert "INVALID" in result.stdout


def test_rejects_an_unsigned_warrant(tmp_path):
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(build_warrant().model_dump(mode="json")), encoding="utf-8")

    result = run_verifier(str(path))
    assert result.returncode == 1
    assert "INVALID" in result.stdout


def test_key_reordering_still_verifies(tmp_path, signed_file):
    """Canonicalization means the on-disk key order is irrelevant."""
    document = json.loads(signed_file.read_text(encoding="utf-8"))
    shuffled = {key: document[key] for key in reversed(list(document))}
    path = tmp_path / "shuffled.json"
    path.write_text(json.dumps(shuffled), encoding="utf-8")

    result = run_verifier(str(path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID" in result.stdout


def test_show_canonical_prints_the_signed_bytes(signed_file):
    result = run_verifier(str(signed_file), "--show-canonical")
    assert result.returncode == 0
    assert "signed bytes:" in result.stdout
    assert '"warrant_id":"wrt_TESTFIXTURE0000000000"' in result.stdout
    assert '"signature"' not in result.stdout.split("signed bytes:")[1].split("\n")[1]


def test_missing_file_is_a_usage_error(tmp_path):
    result = run_verifier(str(tmp_path / "nope.json"))
    assert result.returncode == 2
    assert "error" in result.stderr


def test_malformed_json_is_a_usage_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    result = run_verifier(str(path))
    assert result.returncode == 2


def test_explicit_public_key_flag(tmp_path, signed_file):
    result = run_verifier(str(signed_file), "--public-key", str(COMMITTED_PUBLIC_KEY))
    assert result.returncode == 0
    assert "VALID" in result.stdout


def test_worked_example_in_the_spec_verifies(tmp_path):
    """The example in docs/WARRANT_SPEC.md must be a genuinely valid warrant."""
    from conftest import REPO_ROOT

    spec = (REPO_ROOT / "docs" / "WARRANT_SPEC.md").read_text(encoding="utf-8")
    marker = "<!-- worked-example:begin -->"
    assert marker in spec, "spec must delimit its worked example"

    block = spec.split(marker, 1)[1].split("<!-- worked-example:end -->", 1)[0]
    payload = block.split("```json", 1)[1].split("```", 1)[0]
    document = json.loads(payload)

    path = tmp_path / "spec_example.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = run_verifier(str(path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID" in result.stdout

    # And it must be a well-formed Warrant, not just well-signed bytes.
    Warrant.model_validate(document)
