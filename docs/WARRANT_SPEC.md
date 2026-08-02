# WARRANT — wire format and signature specification

**Versions:** `warrant/1` (§1–§8), `dispute/1` (§9)
**Status:** stable for the hackathon build. Any change to canonical serialization is a version bump, not a patch.

A WARRANT is a signed statement that a merchant was verified and that spending was authorized against that verification, scoped narrowly. It is the system's portable artifact: it leaves the machine that produced it, and anyone holding the public key can check it without contacting us.

This document is written so that someone with only this file, a WARRANT JSON document, and `keys/warrant_public.key` can implement a verifier in any language. If any statement here disagrees with the code, the code is wrong.

> **Naming.** The Warrant PRD calls this artifact a "mandate". It is named **warrant** everywhere in this codebase because Prava has its own first-class `mandate` primitive and the collision is confusing.

---

## 1. Document structure

A WARRANT is a JSON object with exactly seven top-level keys. No key is optional, and no additional key is permitted; a value that is not known is JSON `null`, never absent.

| Field | Type | Notes |
|---|---|---|
| `version` | string | Always `"warrant/1"` for this specification |
| `warrant_id` | string | `"wrt_"` followed by URL-safe base64 random (128 bits) |
| `merchant` | object | Who the credential is locked to |
| `verification` | object | What was checked and what it concluded |
| `authorization` | object | What may be spent, on what |
| `issued_at` | string | RFC 3339 UTC, second precision, `Z` suffix |
| `signature` | string or null | `"ed25519:"` + base64 signature. **Excluded from the signed bytes** |

### 1.1 `merchant`

| Field | Type | Notes |
|---|---|---|
| `domain` | string | eTLD+1 the credential is bound to, e.g. `"ridge.com"` |
| `resolved_name` | string or null | Human-readable name, `null` if resolution failed |

### 1.2 `verification`

| Field | Type | Notes |
|---|---|---|
| `verdict` | string | `"PASS"` \| `"REVIEW"` \| `"HALT"` |
| `score` | string | Decimal string, exactly two decimal places, `"0.00"`–`"1.00"` |
| `signals` | array | Ordered list of signal objects. **Order is significant** (see §2.4) |
| `content_hash` | string | `"<algorithm>:<lowercase hex>"`, e.g. `"sha256:a3f1…"` — digest of the merchant content the agent read |

Each element of `signals` is:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Probe name, e.g. `"domain_age_days"` |
| `tier` | string | `"A"` \| `"B"` \| `"C"` \| `"D"` — how hard the signal is to forge, A being hardest |
| `value` | string, integer, boolean, or null | **Never a floating-point number** (see §2.3) |
| `status` | string | `"PASS"` \| `"FAIL"` \| `"UNAVAILABLE"` |

`UNAVAILABLE` means the probe could not run. It is excluded from the scoring denominator rather than counted as a failure, so one flaky third party cannot halt a legitimate purchase.

### 1.3 `authorization`

| Field | Type | Notes |
|---|---|---|
| `sku` | string | Merchant's item identifier |
| `description` | string | Human-readable item description |
| `quantity` | integer | ≥ 1 |
| `amount` | string | **Decimal string, never a number** (see §2.2), e.g. `"84.00"` |
| `currency` | string | Three uppercase letters, ISO 4217, e.g. `"USD"` |
| `single_use` | boolean | Whether the credential dies after one capture |
| `expected_fulfillment_by` | string or null | RFC 3339 UTC, second precision, `Z` suffix; `null` if open-ended |

---

## 2. Value encoding rules

These rules exist so that two implementations produce byte-identical output. They are not stylistic.

### 2.1 Timestamps

Every timestamp is UTC, truncated to whole seconds, formatted exactly:

```
YYYY-MM-DDTHH:MM:SSZ
```

Literal uppercase `T` separator, literal uppercase `Z`. No fractional seconds, no numeric offsets (`+00:00` is not valid on the wire). A producer given a timestamp with a non-UTC offset converts it to UTC; given sub-second precision, it truncates.

Second precision is deliberate. Fractional-second rendering differs between languages (trailing-zero handling, 3 vs 6 digits), and any such difference would change the signed bytes.

### 2.2 Money

`amount` is **always a JSON string** holding a decimal number, and is preserved verbatim:

- Valid: `"84.00"`, `"0.01"`, `"1234567.89"`, `"100"`, `"0"`
- Invalid: `84.00` (JSON number), `"-84.00"` (sign), `"084.00"` (leading zero), `"8,400.00"` (separator), `"1e5"` (exponent), `"84."` (trailing point)

Grammar: `(0|[1-9][0-9]*)(\.[0-9]+)?`

`"84.00"` and `"84.0"` are **different strings and therefore different documents**, even though they are the same quantity. A verifier must compare bytes, never parsed decimals. Trailing zeros carry the merchant's own presentation and are preserved.

Money never touches a binary float anywhere in the producing implementation.

### 2.3 Numbers generally

The only JSON numbers in a WARRANT are **integers**: `quantity`, and any integer `Signal.value`. There are no floating-point values anywhere in the document.

This is the single most important portability rule in this spec. Shortest-round-trip float formatting is language-specific — `0.1 + 0.2` renders differently across runtimes, and even a well-behaved float can serialize as `0.87` in one language and `8.7e-1` in another. So:

- `score` is a fixed two-decimal **string** (`"0.87"`), not the number `0.87`.
- `Signal.value` accepts strings, integers, booleans and null, but **not** floats. A probe with a fractional measurement stringifies it itself.

A verifier therefore never needs to reason about float formatting. Integers serialize identically everywhere.

### 2.4 Arrays

Array order is preserved exactly and is part of the signature. Reordering `signals` invalidates the document. **Only object keys are sorted, never array elements.**

### 2.5 Absent values

There is no such thing as an absent field. Every field defined in §1 is present in every WARRANT; unknown or inapplicable values are explicit JSON `null`. Deleting a `null` field changes the canonical bytes and invalidates the signature.

Conversely, a document carrying a field not defined in §1 is invalid — an unexpected key is either an attack or a version mismatch, and both must fail loudly rather than be dropped.

---

## 3. Canonical serialization

**This is the whole contract.** The signature covers exactly these bytes.

Given a WARRANT document `D`:

1. **Remove the `signature` key.** Nothing else is removed and nothing is added. All other fields, including those whose value is `null`, are retained.
2. **Serialize to JSON** with:
   - object keys sorted ascending by their Unicode code points;
   - **no whitespace** between any tokens — the separator between a key and its value is `:` and between members is `,`;
   - non-ASCII characters emitted **literally as UTF-8**, not `\uXXXX`-escaped;
   - strings escaped per RFC 8259: `"` → `\"`, `\` → `\\`, and control characters `U+0000`–`U+001F` as `\b \f \n \r \t` where defined, otherwise `\u00XX` lowercase-hex.
3. **Encode the result as UTF-8.** No BOM. No trailing newline.

The resulting byte string is the message.

In Python that is exactly:

```python
import json

def canonical_bytes(document: dict) -> bytes:
    payload = {k: v for k, v in document.items() if k != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
```

In JavaScript, `JSON.stringify` does **not** sort keys, so sorting must be done recursively before stringifying:

```javascript
function sortDeep(node) {
  if (Array.isArray(node)) return node.map(sortDeep);           // order preserved
  if (node && typeof node === "object") {
    return Object.fromEntries(
      Object.keys(node).sort().map((k) => [k, sortDeep(node[k])])
    );
  }
  return node;
}

function canonicalBytes(document) {
  const { signature, ...payload } = document;
  return new TextEncoder().encode(JSON.stringify(sortDeep(payload)));
}
```

`JSON.stringify` already emits no whitespace and leaves non-ASCII literal, so it matches. Note that `Object.keys().sort()` sorts by UTF-16 code unit, which differs from code-point order only for characters above the BMP; no WARRANT field name contains such a character.

### 3.1 What is *not* done

Do not hash the document before signing — ed25519 hashes internally (SHA-512 over the message). There is no domain-separation prefix, no length prefix, no nonce, and no envelope. The canonical bytes are handed to `sign` unchanged.

---

## 4. Signature

**Algorithm:** ed25519 (RFC 8032), pure variant — not Ed25519ph, not Ed25519ctx.

**Keys:** 32 raw bytes each, encoded as standard base64 **with** padding (RFC 4648 §4, the `+/=` alphabet). Not base64url. `keys/warrant_public.key` holds one such base64 string, optionally followed by a newline.

**Signature field format:**

```
signature = "ed25519:" <base64 of the 64 raw signature bytes>
```

The base64 body is standard base64 with padding, so a 64-byte signature is always 88 characters and the field is always 96 characters.

### 4.1 Verification algorithm

```
1. Parse the document as JSON. It must be an object.
2. Read `signature`. If absent, null, or not a string beginning with
   "ed25519:", the document is INVALID.
3. Base64-decode the remainder. It must decode to exactly 64 bytes,
   otherwise INVALID.
4. Compute the canonical bytes of the document per §3.
5. Verify the ed25519 signature over those bytes with the public key.
   Success -> VALID. Failure -> INVALID.
```

Verification is a pure function of the document and the public key. It requires no network access, no clock, and no application state.

Steps 2–5 answer only "was this document signed by the holder of this key, and is it unaltered". They deliberately do **not** answer "is this warrant still in force" — expiry, single-use exhaustion, and reconciliation against the observed outcome are separate concerns layered on top of a valid signature, never a substitute for it.

---

## 5. Verifying offline

With the repository checked out:

```console
$ python scripts/verify_warrant.py signed_warrant.json
```

`scripts/verify_warrant.py` depends on nothing but `cryptography` and the standard library — no web framework, no application config, no database. It reads `keys/warrant_public.key`, recomputes the canonical bytes, and verifies.

Options:

- `--public-key PATH` — verify against a different key (default: `$WARRANT_PUBLIC_KEY`, else `keys/warrant_public.key`)
- `--show-canonical` — print the exact bytes the signature covers

Exit codes: `0` valid, `1` invalid, `2` usage or input error.

Sample output:

```
WARRANT
  warrant     wrt_TESTFIXTURE0000000000
  version     warrant/1
  merchant    ridge.com (Ridge Wallet)
  verdict     PASS  (score 0.87)
  amount      84.00 USD
  authorizes  1 x Ridge Titanium Wallet, Raw
  single use  yes
  issued at   2026-08-02T21:14:03Z
  public key  keys/warrant_public.key
--------------------------------------------------------------
  VALID - ed25519 signature verified over 999 canonical bytes
```

---

## 6. Worked example

The following is a complete, genuinely signed WARRANT. It verifies against the `keys/warrant_public.key` committed in this repository, and the test suite re-verifies it on every run — if this block is edited, `tests/test_verify_script.py::test_worked_example_in_the_spec_verifies` fails.

<!-- worked-example:begin -->

**Public key** (`keys/warrant_public.key`, base64 of 32 raw bytes):

```
DzpbMH3nw9yjOVIKYQM+mIbjZCuid+wu+y0zRxPdV1A=
```

**The document**, as it appears on disk (pretty-printed; whitespace here is irrelevant, only the canonical form is signed):

```json
{
  "version": "warrant/1",
  "warrant_id": "wrt_TESTFIXTURE0000000000",
  "merchant": {
    "domain": "ridge.com",
    "resolved_name": "Ridge Wallet"
  },
  "verification": {
    "verdict": "PASS",
    "score": "0.87",
    "signals": [
      {
        "name": "domain_age_days",
        "tier": "A",
        "value": 2847,
        "status": "PASS"
      },
      {
        "name": "safe_browsing",
        "tier": "A",
        "value": "no_match",
        "status": "PASS"
      },
      {
        "name": "cert_first_seen_days",
        "tier": "A",
        "value": 2790,
        "status": "PASS"
      },
      {
        "name": "psp_fingerprint",
        "tier": "B",
        "value": "stripe",
        "status": "PASS"
      },
      {
        "name": "ucp_manifest",
        "tier": "C",
        "value": true,
        "status": "PASS"
      },
      {
        "name": "business_registry",
        "tier": "B",
        "value": null,
        "status": "UNAVAILABLE"
      },
      {
        "name": "injection_scan",
        "tier": "D",
        "value": "clean",
        "status": "PASS"
      }
    ],
    "content_hash": "sha256:a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1"
  },
  "authorization": {
    "sku": "RW-TITAN-01",
    "description": "Ridge Titanium Wallet, Raw",
    "quantity": 1,
    "amount": "84.00",
    "currency": "USD",
    "single_use": true,
    "expected_fulfillment_by": "2026-08-12T00:00:00Z"
  },
  "issued_at": "2026-08-02T21:14:03Z",
  "signature": "ed25519:AI3z0mzEGHafTnXR03p2eu7EOCXTuckyCYc/pLBbEFzbcif1FpnLmKkDbAigqRNmBumTX9SsKn6KJnviMJQwBg=="
}
```

<!-- worked-example:end -->

**The canonical bytes** — 999 bytes of UTF-8, the exact message the signature covers. Note the keys are sorted (`authorization` first, `warrant_id` last; inside each signal, `name`, `status`, `tier`, `value`), `signature` is gone, `signals` order is untouched, and `"value":null` is retained:

```
{"authorization":{"amount":"84.00","currency":"USD","description":"Ridge Titanium Wallet, Raw","expected_fulfillment_by":"2026-08-12T00:00:00Z","quantity":1,"single_use":true,"sku":"RW-TITAN-01"},"issued_at":"2026-08-02T21:14:03Z","merchant":{"domain":"ridge.com","resolved_name":"Ridge Wallet"},"verification":{"content_hash":"sha256:a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1","score":"0.87","signals":[{"name":"domain_age_days","status":"PASS","tier":"A","value":2847},{"name":"safe_browsing","status":"PASS","tier":"A","value":"no_match"},{"name":"cert_first_seen_days","status":"PASS","tier":"A","value":2790},{"name":"psp_fingerprint","status":"PASS","tier":"B","value":"stripe"},{"name":"ucp_manifest","status":"PASS","tier":"C","value":true},{"name":"business_registry","status":"UNAVAILABLE","tier":"B","value":null},{"name":"injection_scan","status":"PASS","tier":"D","value":"clean"}],"verdict":"PASS"},"version":"warrant/1","warrant_id":"wrt_TESTFIXTURE0000000000"}
```

**Signature** (base64 of 64 raw bytes):

```
EouS9feQoMKY6XGguw8S54S+sSMPqOY3eh/o/Tl8uYS6LiRBH9KHnfSFvznrYy9RYwHKsVy5bo9/b6WIeuZDDg==
```

To check an implementation from scratch: canonicalize the document above, confirm you get byte-for-byte the 999-byte string shown, then verify the signature with the public key. If the canonical bytes match and verification still fails, the bug is in base64 handling or key loading, not in serialization.

---

## 7. Keys and key handling

| | |
|---|---|
| Public key | `keys/warrant_public.key` — **committed**, base64 of 32 raw bytes |
| Private key | `keys/warrant_private.key` — **gitignored, never committed**, or `WARRANT_SIGNING_KEY` in the environment |

The signer resolves its key in this order: `WARRANT_SIGNING_KEY` (base64 raw), then `keys/warrant_private.key`. If neither is present, signing raises `WarrantKeyError` rather than silently issuing an unsigned document.

Generate a keypair:

```console
$ python -m app.warrant keygen
```

This prints both halves to stdout and writes nothing tracked. Store the private half immediately; it is not recoverable.

**Honest limitation.** Right now the only thing a valid signature proves is that *this project* issued the document. That is a real trust root for a demo and a real trust-root problem at scale — the key that signs merchant verifications should ultimately belong to a payment network or a consortium, not to a single vendor. See PRD §8.4.

---

## 8. Implementation map

| Concern | File |
|---|---|
| Document and reconciliation models | `backend/app/models.py` |
| Canonical serialization, signing, verification | `backend/app/warrant.py` |
| Deterministic diff and dispute packet | `backend/app/reconcile.py` |
| Observed side of the diff (demo merchant receipt) | `merchants/breach/receipt.py` |
| Standalone offline verifier | `scripts/verify_warrant.py` |
| Contract tests | `tests/test_warrant.py`, `tests/test_models.py`, `tests/test_reconcile.py`, `tests/test_verify_script.py` |

`canonical_bytes()` in `backend/app/warrant.py` is the single implementation used by both signing and verification, so those two can never drift apart. `scripts/verify_warrant.py` carries a deliberately **independent** reimplementation of §3 — that is the point of it, and `tests/test_warrant.py::test_app_and_standalone_script_agree_byte_for_byte` asserts the two agree. If they ever disagree, this specification is ambiguous and must be fixed here first.

---

## 9. The dispute packet

**Version:** `dispute/1`

A WARRANT says what was authorized. A dispute packet says what then happened, and binds the two together. It is emitted when reconciliation returns `BREACH`.

It is a JSON object with exactly six top-level keys, obeying every rule in §2 and §3 unchanged:

| Field | Type | Notes |
|---|---|---|
| `version` | string | Always `"dispute/1"` |
| `dispute_id` | string | `"dsp_"` followed by URL-safe base64 random (128 bits) |
| `warrant` | object | **The original WARRANT, verbatim, including its own `signature`** |
| `outcome` | object | What was observed |
| `reconciliation` | object | The verdict and the enumerated breaches |
| `issued_at` | string | RFC 3339 UTC, second precision, `Z` suffix |
| `signature` | string or null | `"ed25519:"` + base64. **Excluded from the signed bytes** |

### 9.1 The nesting rule

Canonicalization (§3) removes the `signature` key **at the top level only**. The embedded warrant keeps its own signature, and that single detail is what makes the chain hold in both directions:

- the outer signature is computed over bytes that include the inner signature, so the warrant inside a packet cannot be swapped, softened, or re-dated;
- the inner document is unchanged from the day it was issued, so it can be lifted out of the packet and verified entirely on its own.

Two signatures, two timestamps, one verifiable chain: here is what was authorized and when, here is what happened.

### 9.2 `outcome`

What the observer saw. `null` means *not observed*, which is not the same as observed to be absent.

| Field | Type | Notes |
|---|---|---|
| `warrant_id` | string | Must equal `warrant.warrant_id` |
| `merchant_domain` | string | Who was actually charged |
| `sku` | string or null | |
| `description` | string or null | |
| `quantity` | integer or null | |
| `amount` | string or null | Decimal string, §2.2 |
| `currency` | string or null | ISO 4217 |
| `delivered` | boolean or null | |
| `order_id` | string or null | The merchant's own identifier |
| `source` | string or null | Who reported this |
| `fulfilled_at` | string or null | RFC 3339 UTC, second precision |
| `observed_at` | string | RFC 3339 UTC, second precision |

**Where an outcome comes from matters.** It comes from the merchant, not from the payment provider. Prava's payment result echoes back the `purchase_context` the agent itself submitted, so diffing a warrant against it compares a document to itself and always settles. Prava issues tokens and never observes what ships.

### 9.3 `reconciliation`

| Field | Type | Notes |
|---|---|---|
| `warrant_id` | string | Must equal `warrant.warrant_id` |
| `status` | string | `"SETTLED"` \| `"BREACH"`. Binary — there is no review state |
| `breaches` | array | Ordered; order is part of the signature (§2.4) |
| `reconciled_at` | string | RFC 3339 UTC, second precision |

Each breach is:

| Field | Type | Notes |
|---|---|---|
| `code` | string | `AMOUNT_EXCEEDED` \| `MERCHANT_MISMATCH` \| `ITEM_MISMATCH` \| `QUANTITY_MISMATCH` \| `NON_DELIVERY` |
| `provenance` | string | `"PREVENTED"` \| `"DETECTED"` — see below |
| `expected` | string or null | Rendered, so a breach is readable without knowing the field's type |
| `observed` | string or null | |
| `evidence` | string or null | The refusing authority's own error code, for `PREVENTED` |
| `detail` | string or null | |

`PREVENTED` means the charge was refused before money moved — the amount cap is enforced at the card network and merchant scope inside Prava, so `evidence` carries Prava's code (`THRESHOLD_EXCEEDED`, `MANDATE_MERCHANT_NOT_ALLOWED`) and the proof is the refusal, not our arithmetic. `DETECTED` means the charge succeeded within everything the network could check and the departure is visible only in what the merchant says it fulfilled. Only the second kind is worth disputing.

The diff producing these is deterministic and contains no model. Amounts are compared as decimals and never as floats or as text; domains are compared case-folded and without a trailing dot; an authorization is a ceiling, so being charged *less* than it is not a breach.

### 9.4 Verifying a packet

```console
$ python scripts/verify_warrant.py dispute_packet.json
```

The verifier dispatches on `version`, checks the outer signature over the outer canonical bytes, then lifts out `warrant` and checks that independently. Exit code `0` only if both hold. An outer signature over a warrant that does not verify proves only that we said so twice.

---

## 10. Changing this specification

Any change to §2 or §3 changes what bytes get signed, which silently invalidates every previously issued WARRANT. Such a change requires a new `version` value (`warrant/2`), and verifiers must dispatch on `version` before canonicalizing.

Adding a field is *not* backward compatible: §2.5 forbids absent fields, so an old verifier rejects a new document and a new verifier rejects an old one. That is the intended behaviour for a security artifact — fail closed.
