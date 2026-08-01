"""Canonical serialization, ed25519 signing, and verification for WARRANT.

This module is the trust root of the whole system. A judge must be able to take a
signed WARRANT to another machine — possibly to another language — and verify it
with nothing but the committed public key. That is only possible if the bytes we
sign are reproducible from the JSON document alone.

Canonical form
--------------
Given a WARRANT document as JSON:

1. Remove the ``signature`` key. Nothing else is removed; optional values are
   present as explicit ``null``.
2. Serialize with keys sorted (byte-wise on the UTF-8 key text), no whitespace
   between tokens, and non-ASCII characters left unescaped.
3. Encode as UTF-8.

In Python that is exactly::

    json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

Those bytes are the message. There is no length prefix, no domain separator, no
hashing step — ed25519 hashes internally.

``canonical_bytes`` is the single implementation used by both signing and
verification, so the two can never drift. ``scripts/verify_warrant.py`` carries a
deliberately independent reimplementation; ``tests/test_warrant.py`` asserts the
two agree byte-for-byte, which is what makes the spec trustworthy.

See ``docs/WARRANT_SPEC.md``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.models import Warrant

#: Fields omitted from the signed bytes. Only the signature itself.
UNSIGNED_FIELDS: frozenset[str] = frozenset({"signature"})

#: Algorithm tag prefixed to the base64 signature on the wire.
SIGNATURE_PREFIX = "ed25519:"

#: Environment variable holding the base64 raw private key (32 bytes).
SIGNING_KEY_ENV = "WARRANT_SIGNING_KEY"
#: Environment variable overriding the public key file location.
PUBLIC_KEY_ENV = "WARRANT_PUBLIC_KEY"

_REPO_ROOT = Path(__file__).resolve().parents[2]
#: Gitignored. Never commit this file.
DEFAULT_PRIVATE_KEY_PATH = _REPO_ROOT / "keys" / "warrant_private.key"
#: Committed, so anyone can verify offline.
DEFAULT_PUBLIC_KEY_PATH = _REPO_ROOT / "keys" / "warrant_public.key"


class WarrantKeyError(RuntimeError):
    """Raised when a signing or verification key cannot be found or parsed."""


# ---------------------------------------------------------------------------
# Canonical serialization
# ---------------------------------------------------------------------------


def to_document(warrant: Warrant | Mapping[str, Any]) -> dict[str, Any]:
    """Render a Warrant (or an already-parsed JSON mapping) as a plain JSON dict."""
    if isinstance(warrant, Warrant):
        return warrant.model_dump(mode="json")
    if isinstance(warrant, Mapping):
        return dict(warrant)
    raise TypeError(f"expected a Warrant or a mapping, got {type(warrant).__name__}")


def canonical_bytes(warrant: Warrant | Mapping[str, Any]) -> bytes:
    """Return the exact bytes that are signed and verified.

    Accepts either a :class:`~app.models.Warrant` or the raw JSON mapping loaded
    from disk, and produces identical output for both — a document that round
    trips through JSON must verify.
    """
    document = to_document(warrant)
    for field in UNSIGNED_FIELDS:
        document.pop(field, None)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    """Base64 of the 32 raw private key bytes. Treat the result as a secret."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    """Base64 of the 32 raw public key bytes. This is what gets committed."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _decode_key_b64(encoded: str, *, what: str) -> bytes:
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WarrantKeyError(f"{what} is not valid base64") from exc
    if len(raw) != 32:
        raise WarrantKeyError(f"{what} must decode to 32 bytes, got {len(raw)}")
    return raw


def load_private_key_b64(encoded: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_decode_key_b64(encoded, what="private key"))


def load_public_key_b64(encoded: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_decode_key_b64(encoded, what="public key"))


def load_signing_key(path: Path | str | None = None) -> Ed25519PrivateKey:
    """Load the private signing key.

    Order: ``WARRANT_SIGNING_KEY`` (base64 raw), then ``keys/warrant_private.key``.
    The file is gitignored; the key never enters version control.
    """
    encoded = os.environ.get(SIGNING_KEY_ENV)
    if encoded:
        return load_private_key_b64(encoded)

    key_path = Path(path) if path is not None else DEFAULT_PRIVATE_KEY_PATH
    if not key_path.is_file():
        raise WarrantKeyError(
            f"no signing key: set {SIGNING_KEY_ENV} (base64 raw ed25519 private key) "
            f"or create {key_path}. Generate one with: python -m app.warrant keygen"
        )
    return load_private_key_b64(key_path.read_text(encoding="ascii"))


def load_public_key(path: Path | str | None = None) -> Ed25519PublicKey:
    """Load the public key. Order: explicit path, ``WARRANT_PUBLIC_KEY``, committed file."""
    if path is None:
        env_path = os.environ.get(PUBLIC_KEY_ENV)
        key_path = Path(env_path) if env_path else DEFAULT_PUBLIC_KEY_PATH
    else:
        key_path = Path(path)
    if not key_path.is_file():
        raise WarrantKeyError(f"public key not found at {key_path}")
    return load_public_key_b64(key_path.read_text(encoding="ascii"))


# ---------------------------------------------------------------------------
# Sign and verify
# ---------------------------------------------------------------------------


def encode_signature(raw_signature: bytes) -> str:
    return SIGNATURE_PREFIX + base64.b64encode(raw_signature).decode("ascii")


def decode_signature(signature: str) -> bytes:
    """Parse ``ed25519:<base64>`` into raw signature bytes."""
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise ValueError(f"signature must start with {SIGNATURE_PREFIX!r}")
    body = signature[len(SIGNATURE_PREFIX) :]
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature body is not valid base64") from exc
    if len(raw) != 64:
        raise ValueError(f"ed25519 signature must be 64 bytes, got {len(raw)}")
    return raw


def sign_warrant(warrant: Warrant, private_key: Ed25519PrivateKey | None = None) -> Warrant:
    """Return a copy of ``warrant`` carrying a valid signature.

    The input is not mutated. Any signature already present is ignored — it is
    excluded from the signed bytes, so re-signing is well defined.
    """
    key = private_key if private_key is not None else load_signing_key()
    raw_signature = key.sign(canonical_bytes(warrant))
    return warrant.model_copy(update={"signature": encode_signature(raw_signature)})


def verify_warrant(
    warrant: Warrant | Mapping[str, Any],
    public_key: Ed25519PublicKey | None = None,
) -> bool:
    """Return True iff the document's signature matches its canonical bytes.

    Returns False rather than raising for every failure mode a hostile document
    can cause — missing, malformed, or wrong signature — so callers can treat this
    as a plain predicate.
    """
    key = public_key if public_key is not None else load_public_key()
    document = to_document(warrant)
    signature = document.get("signature")
    if not signature:
        return False
    try:
        raw_signature = decode_signature(signature)
    except ValueError:
        return False
    try:
        key.verify(raw_signature, canonical_bytes(document))
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# Key generation CLI
# ---------------------------------------------------------------------------


def _keygen(argv: list[str]) -> int:
    """Print a fresh keypair. The private key is printed, never written."""
    private_key, public_key = generate_keypair()
    public_b64 = public_key_to_b64(public_key)

    print("ed25519 keypair for WARRANT")
    print()
    print(f"  public  (commit to {DEFAULT_PUBLIC_KEY_PATH.name}): {public_b64}")
    print(f"  private (SECRET, store it now):                     {private_key_to_b64(private_key)}")
    print()
    print(f"Store the private key as {SIGNING_KEY_ENV} or in {DEFAULT_PRIVATE_KEY_PATH} (gitignored).")

    if "--write-public" in argv:
        DEFAULT_PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_PUBLIC_KEY_PATH.write_text(public_b64 + "\n", encoding="ascii")
        print(f"Wrote public key to {DEFAULT_PUBLIC_KEY_PATH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "keygen":
        return _keygen(args[1:])
    print("usage: python -m app.warrant keygen [--write-public]")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_PRIVATE_KEY_PATH",
    "DEFAULT_PUBLIC_KEY_PATH",
    "PUBLIC_KEY_ENV",
    "SIGNATURE_PREFIX",
    "SIGNING_KEY_ENV",
    "UNSIGNED_FIELDS",
    "WarrantKeyError",
    "canonical_bytes",
    "decode_signature",
    "encode_signature",
    "generate_keypair",
    "load_private_key_b64",
    "load_public_key",
    "load_public_key_b64",
    "load_signing_key",
    "private_key_to_b64",
    "public_key_to_b64",
    "sign_warrant",
    "to_document",
    "verify_warrant",
]
