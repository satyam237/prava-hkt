#!/usr/bin/env python3
"""Verify a signed WARRANT offline.

    python scripts/verify_warrant.py signed_warrant.json

Depends on nothing but ``cryptography`` and the standard library. No FastAPI, no
application config, no database — hand this file, the JSON document, and
``keys/warrant_public.key`` to anyone and they can check the signature themselves.

The canonical serialization below is written out longhand rather than imported
from the application on purpose: it is an independent reimplementation of
``docs/WARRANT_SPEC.md``, and the test suite asserts it produces byte-identical
output to the signer. If this file and the app ever disagree, the spec is wrong.

Exit codes: 0 valid, 1 invalid, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.stderr.write("error: this verifier needs the 'cryptography' package (pip install cryptography)\n")
    raise SystemExit(2)

SIGNATURE_PREFIX = "ed25519:"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PUBLIC_KEY_PATH = REPO_ROOT / "keys" / "warrant_public.key"

# Box drawing kept to plain ASCII so it survives any terminal or screen recording.
RULE = "-" * 62


def canonical_bytes(document: dict[str, Any]) -> bytes:
    """The exact bytes covered by the signature.

    Drop ``signature``; serialize with sorted keys, no whitespace, unescaped
    non-ASCII; encode UTF-8. Nothing else is removed or reordered.
    """
    payload = {key: value for key, value in document.items() if key != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_public_key(path: Path) -> Ed25519PublicKey:
    raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    if len(raw) != 32:
        raise ValueError(f"public key must be 32 raw bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def decode_signature(signature: Any) -> bytes:
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise ValueError(f"signature must be a string starting with {SIGNATURE_PREFIX!r}")
    raw = base64.b64decode(signature[len(SIGNATURE_PREFIX) :], validate=True)
    if len(raw) != 64:
        raise ValueError(f"ed25519 signature must be 64 bytes, got {len(raw)}")
    return raw


def _get(document: dict[str, Any], *path: str, default: str = "-") -> Any:
    """Read a nested key defensively — an unverified document may be anything."""
    node: Any = document
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return default if node is None else node


def _clean(value: Any, limit: int | None = 120) -> str:
    """Render an untrusted value as a single safe line of terminal output.

    Everything printed below the WARRANT header comes from a document whose
    signature has not been checked yet. Left raw, a crafted string could use
    newlines to print its own "VALID" line, or ANSI escapes to erase the real
    verdict — the summary this tool exists to produce would then be a forgery.
    C0/C1 controls and DEL are escaped, not emitted, and long values are capped.
    A legitimate document contains none of these and renders unchanged.
    """
    text = value if isinstance(value, str) else str(value)
    safe = "".join(
        f"\\x{ord(ch):02x}"
        if ord(ch) < 0x20 or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F
        else ch
        for ch in text
    )
    if limit is not None and len(safe) > limit:
        safe = safe[:limit] + "..."
    return safe


def describe(document: dict[str, Any], key_path: Path) -> str:
    """Human-readable summary of what this warrant actually authorizes.

    Nothing here is trustworthy yet — the signature is checked after this prints.
    """
    domain = _clean(_get(document, "merchant", "domain"), limit=80)
    name = _clean(_get(document, "merchant", "resolved_name", default=""), limit=80)
    merchant = f"{domain} ({name})" if name else domain

    verdict = _clean(_get(document, "verification", "verdict"), limit=16)
    score = _clean(_get(document, "verification", "score"), limit=16)
    quantity = _clean(_get(document, "authorization", "quantity"), limit=16)
    amount = _clean(_get(document, "authorization", "amount"), limit=32)
    currency = _clean(_get(document, "authorization", "currency"), limit=16)
    single_use = _get(document, "authorization", "single_use")
    description = _clean(_get(document, "authorization", "description", default=""))

    lines = [
        f"  warrant     {_clean(_get(document, 'warrant_id'), limit=80)}",
        f"  version     {_clean(_get(document, 'version'), limit=40)}",
        f"  merchant    {merchant}",
        f"  verdict     {verdict}  (score {score})",
        f"  amount      {amount} {currency}",
        f"  authorizes  {quantity} x {description}".rstrip(),
        f"  single use  {'yes' if single_use is True else 'no' if single_use is False else _clean(single_use, limit=16)}",
        f"  issued at   {_clean(_get(document, 'issued_at'), limit=40)}",
        f"  public key  {key_path}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_warrant.py",
        description="Verify the ed25519 signature on a WARRANT document, offline.",
    )
    parser.add_argument("warrant", type=Path, help="path to a signed WARRANT JSON file")
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=f"public key file (default: $WARRANT_PUBLIC_KEY or {DEFAULT_PUBLIC_KEY_PATH})",
    )
    parser.add_argument(
        "--show-canonical",
        action="store_true",
        help="print the exact bytes the signature covers",
    )
    args = parser.parse_args(argv)

    key_path = args.public_key
    if key_path is None:
        env_path = os.environ.get("WARRANT_PUBLIC_KEY")
        key_path = Path(env_path) if env_path else DEFAULT_PUBLIC_KEY_PATH

    try:
        document = json.loads(args.warrant.read_text(encoding="utf-8"))
    except OSError as exc:
        sys.stderr.write(f"error: cannot read {args.warrant}: {exc}\n")
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"error: {args.warrant} is not valid JSON: {exc}\n")
        return 2
    if not isinstance(document, dict):
        sys.stderr.write(f"error: {args.warrant} must contain a JSON object\n")
        return 2

    try:
        public_key = load_public_key(key_path)
    except OSError as exc:
        sys.stderr.write(f"error: cannot read public key {key_path}: {exc}\n")
        return 2
    except ValueError as exc:
        sys.stderr.write(f"error: bad public key {key_path}: {exc}\n")
        return 2

    try:
        message = canonical_bytes(document)
    except (ValueError, TypeError) as exc:
        # json.loads accepts NaN and Infinity; canonical serialization does not.
        sys.stderr.write(f"error: {args.warrant} cannot be canonicalized: {exc}\n")
        return 2

    print("WARRANT")
    print(describe(document, key_path))
    if args.show_canonical:
        print(RULE)
        print("  signed bytes:")
        print(f"  {_clean(message.decode('utf-8'), limit=None)}")
    print(RULE)

    try:
        raw_signature = decode_signature(document.get("signature"))
    except ValueError as exc:  # binascii.Error subclasses ValueError
        print(f"  INVALID - {exc}")
        return 1

    try:
        public_key.verify(raw_signature, message)
    except InvalidSignature:
        print("  INVALID - signature does not match this document")
        print("            the document was altered after signing, or was signed by another key")
        return 1

    print(f"  VALID - ed25519 signature verified over {len(message)} canonical bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
