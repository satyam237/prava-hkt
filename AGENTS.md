# Warrant — project memory

Warrant proves the *merchant* to the *agent*, and makes that proof a precondition of the payment credential. Product spec: `docs/WARRANT_PRD.md`.

## Naming: warrant, not mandate

The PRD calls the signed artifact a "mandate". In code, filenames and docs it is **`warrant` / `Warrant`** — Prava has its own first-class `mandate` primitive and the collision is confusing. Do not reintroduce "mandate" for our document.

## The signing contract is the load-bearing part

`docs/WARRANT_SPEC.md` is authoritative for the wire format and canonical serialization. Read it before touching `backend/app/models.py`, `backend/app/warrant.py`, or `scripts/verify_warrant.py`.

Two consequences that bite if you don't know them:

- **Nothing on the wire may be a float.** `amount` and `score` are decimal strings; `Signal.value` rejects floats. Float text formatting is language-specific, and a signed document must canonicalize identically in any language. The models enforce this — a float raises rather than silently converting.
- **Any change to a model's fields changes the signed bytes** and invalidates every previously issued WARRANT. Adding a field is a `version` bump (`warrant/2`), not a patch. Optional values are explicit `null`; fields are never omitted, and unknown fields are rejected.

`canonical_bytes()` in `backend/app/warrant.py` is the single implementation used by both signing and verification. `scripts/verify_warrant.py` deliberately carries an *independent* reimplementation — that is the point of it, and a test asserts the two agree byte-for-byte. Keep it dependency-free (stdlib + `cryptography` only); it is the artifact a judge runs.

## Keys

`keys/warrant_public.key` is committed. The private key is `WARRANT_SIGNING_KEY` (base64 raw) or `keys/warrant_private.key`, both gitignored — never commit it. Generate with `python -m app.warrant keygen`.

## Layout and running things

Python 3.11+. The importable package is `app`, rooted at `backend/` (`from app.warrant import ...`), wired via `pythonpath` in `pyproject.toml` so tests run without installing. Tests import shared fixtures with `from conftest import ...`.

```
uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest
```

Dependencies are deliberately minimal and listed in `pyproject.toml`; ask before adding one. `python-whois` is specifically ruled out (PRD §7.2) — use RDAP over `httpx`.

## Prava

Every Prava API call goes through `PravaClient` in `backend/app/services/prava_client.py` — do not call the API directly from a probe, a route, or a script. It normalizes money, applies timeouts, redacts credentials, and maps Prava's error codes to named exceptions so reconciliation can tell `THRESHOLD_EXCEEDED` from `MANDATE_MERCHANT_NOT_ALLOWED`.

`docs/PRAVA_NOTES.md` records where the live sandbox disagrees with Prava's published docs, and is authoritative over them. Read it before writing Prava code — several findings are not guessable, notably that the session response returns **no** `mandate_id` (the mandate is minted at passkey approval, so the id must be read back from `/payment-result`) and that errors nest under `error {code, message}` rather than the documented flat `errorCode`.

`scripts/prava_smoke.py create|resume` is the live flow. It splits in two because the middle needs a human passkey approval; sessions expire 15 minutes after creation, so create the session only when someone is ready to approve.

Sandbox keys live in `.env` (gitignored, never committed). Show at most the first 8 characters of a key in any output.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
