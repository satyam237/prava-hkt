# Prava sandbox — observed behaviour

What the live sandbox actually returned, versus what the docs describe. Written
while building `backend/app/services/prava_client.py`. Where the two disagree,
**the observed column is what the client is built against.**

Base URL `https://sandbox.api.prava.space` · auth `Authorization: Bearer <PRAVA_SECRET_KEY>`.

Status of this document: steps 1–4 (through session creation) are verified
against the live sandbox. Steps 5–8 (post-approval: active mandate, charge,
reconciliation, over-cap decline) require a human passkey approval and are
marked **unverified** below until that run completes.

---

## 1. `GET /health` — matches the docs

```json
{ "status": "ok", "timestamp": "2026-08-01T19:30:13.861Z" }
```

`timestamp` is ISO-8601 with milliseconds and a `Z` suffix.

---

## 2. `POST /v1/sessions` (with `mandate_setup`) — three discrepancies

Request body as documented was accepted verbatim: `user_id`, `user_email`,
`total_amount`, `currency`, single-entry `purchase_context`, and `mandate_setup`
with `intent` / `recurring_frequency` / `merchant_scope` / `max_charges`. No
validation complaints.

Observed response (values from a real run, token redacted):

```json
{
  "session_id":    "ses_01KYZCWEE5WFEY6QJ5HPRKN289",
  "order_id":      "ord_01KYZCWEE5WFEY6QJ5HPRKN28A",
  "iframe_url":    "https://sandbox.collect.prava.space?session=ses_01KYZ…",
  "session_token": "<JWT, ~481 chars>",
  "expires_at":    "2026-08-01T19:45:14.085Z"
}
```

### 2.1 No `mandate_id` is returned — the mandate does not exist yet

The docs read as though the session response identifies the mandate. It does
not. There is **no `mandate_id` field anywhere in the response.**

Confirmed by polling the session before approval:

```json
{ "session_id": "ses_…", "order_id": "ord_…", "status": "pending", "transactions": [] }
```

The mandate appears to be minted **at passkey approval time**, not at session
creation. Consequence for callers: you cannot store a mandate id at creation
and you cannot call `GET /v1/mandates/{id}` until a human has approved. The id
has to be read back from `GET /v1/sessions/{id}/payment-result` afterwards —
which is what `scripts/prava_smoke.py` does in `discover_mandate_id`.

### 2.2 No `authorizeOnly: true` field

The docs state the response carries `authorizeOnly: true` alongside
`iframe_url`. **It does not appear at all.** The session did behave as
authorize-only (no credentials were issued at creation), so the behaviour is
right and only the field is missing. Do not branch on `authorizeOnly` — it will
be `None`.

### 2.3 Undocumented `session_token` — a credential, treat it as one

The response includes a `session_token` JWT that is not in the documented
shape. Decoded header/claims (no secret) show `merchantAccountId`, `merchantId`,
`customerId`, `externalUserId`, `tokenLockerId`, `customerEmail`, and a
15-minute `exp` matching `expires_at`.

This is a bearer credential. It is redacted by `redact()` in the client —
**this was found the hard way**: the original exact-match redaction list keyed
on `token` and missed `session_token`, so the JWT reached the terminal and the
smoke state file on the first run. `redact()` now matches any field name
containing `token` / `secret` / `cvv` / `password` / `credential`, and
`tests/test_prava_client.py` pins the regression. Prefer over-redacting.

### 2.4 `expires_at` is returned explicitly

15 minutes after creation, matching the documented session TTL. Use the
returned value rather than computing it locally.

---

## 3. Error envelope — **nested**, not flat

The docs describe charge errors as flat `errorCode` / `errorMessage`. The live
sandbox returns errors nested under `error`:

```
GET /v1/mandates/mnd_does_not_exist  →  404
{ "error": { "code": "MANDATE_NOT_FOUND", "message": "Mandate not found" } }
```

`_extract_error()` in the client checks the nested `error {code, message}` shape
first, then falls back to flat `errorCode`/`errorMessage` and to plain
`code`/`message`, so both work. If you write your own parsing, **check the
nested shape** — a flat-only reader gets `None` for the code and loses the
ability to distinguish `THRESHOLD_EXCEEDED` from `MANDATE_MERCHANT_NOT_ALLOWED`.

`404 MANDATE_NOT_FOUND` confirmed exactly as documented, including the code
string.

---

## 4. `revoke_session` — no such endpoint

No session-revocation endpoint is documented, and none was found. The client's
`revoke_session()` deliberately raises `NotImplementedError` rather than
guessing a verb and path: a method that appears to revoke and silently does
nothing is worse than an honest failure.

To end a session early, report the transaction `DECLINED` via
`POST /v1/sessions/{id}/report-status`. Otherwise sessions expire on their own
after 15 minutes.

---

## 5. Post-approval flow — UNVERIFIED

Blocked on a human passkey approval (Touch ID in the hosted iframe), which no
script can perform. Once that lands, `python scripts/prava_smoke.py resume`
exercises and this section should record:

- [ ] `GET /v1/mandates/{id}` → does `status` actually pass through `pending` → `active`?
- [ ] Are `approvedAmount` / `spent` decimal **strings** as documented, or numbers?
- [ ] `POST /v1/mandates/{id}/charge` → does `credentials` carry `token` + `dynamicCvv`?
- [ ] Does `charges[]` use `transactionId` / `createdAt` camelCase as documented?
      (Note: sessions use `snake_case` and mandates use `camelCase` — the two
      endpoint families disagree, so do not assume one convention.)
- [ ] Over-cap charge of `1008.00` against an `84.00` mandate → `THRESHOLD_EXCEEDED`?
- [ ] Does `deduplicated: true` come back on a reference replay?

---

## Practical notes for later blocks

- **Sessions expire in 15 minutes**, and approval needs a human at a keyboard.
  Create the session immediately before the person is ready to approve, not
  ahead of time. A demo that creates the session early will show an expired
  page.
- **Case conventions differ by endpoint family.** Session endpoints return
  `snake_case` (`session_id`, `iframe_url`, `expires_at`); mandate endpoints are
  documented as `camelCase` (`approvedAmount`, `chargeCount`, `transactionId`).
  Do not write one normalizer and assume it covers both.
- **`iframe_url` is on a different host** (`sandbox.collect.prava.space`) from
  the API (`sandbox.api.prava.space`), and passes the session as a query
  parameter.
- **Amounts are strings everywhere.** Keep them strings. `_money()` in the
  client rejects floats outright rather than converting — by the time a float
  holds an amount, the exact value the user approved is already gone.
