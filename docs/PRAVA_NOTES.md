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

### 2.4 `iframe_url` is SINGLE-USE — do not open it to "check" it

Learned by breaking one. Loading the checkout URL once consumes it; a second
load renders:

> **Session Already Used** — This session link has already been used. It may be
> active in another tab. Please request a new session link.

There is no way to reopen or reset it. Practical consequences:

- **Never open the URL programmatically**, not even to screenshot it, snapshot
  the DOM, or verify it resolves. An agent that "checks the link works" has
  destroyed it. This burned a session during this build.
- Hand the URL to the human **unopened**, and mint it only when they are
  actually at the keyboard — the 15-minute expiry plus single-use means a link
  generated in advance is usually already worthless.
- A failed or abandoned approval is not recoverable on the same link. Mint a
  fresh session.

### 2.5 `expires_at` is returned explicitly

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

## 3.1 Observed failure: `PASSKEY_REG_FAILED` (undocumented code)

A real approval attempt failed at passkey registration on the card-network
page, *after* a valid OTP. `GET /v1/sessions/{id}/payment-result` returned
verbatim (credentials redacted, all `<none>`):

```json
{
  "session_id": "ses_01KYZDJEFW1AVK6C6NMR4FCP93",
  "order_id":   "ord_01KYZDJEFW1AVK6C6NMR4FCP94",
  "status": "failed",
  "transactions": [{
    "txn_id": "txn_01KYZDMKJMAB0BSZ63ST4STZ34",
    "status": "failed",
    "error": { "code": "PASSKEY_REG_FAILED", "message": "Request failed with status code 400" },
    "line_items": [{
      "txn_ref_id": "tli_01KYZDMKJS2CJKPE5WB87PRN6S",
      "merchant_name": "Northstar Supply",
      "merchant_url": "https://breach.localhost",
      "total_amount": "84.00",
      "status": "pending",
      "token": null, "dynamic_cvv": null, "expiry_month": null, "expiry_year": null,
      "products": []
    }]
  }]
}
```

Four things worth knowing from this:

1. **`PASSKEY_REG_FAILED` is not in the documented error-code list**, and its
   message is a passed-through upstream string (`"Request failed with status
   code 400"`) rather than anything actionable. Do not expect the documented
   codes to be exhaustive; the client keeps unknown codes verbatim as a plain
   `PravaError` rather than forcing them into a known category.
2. **The error lives on the transaction, not at the top level.** The response
   root has no `error` key at all — a reader that only checks a top-level
   `error` sees `status: "failed"` with no reason. Walk `transactions[].error`,
   and note the docs describe `error` only as a sibling of `status`.
3. **`status` disagrees between levels**: the transaction is `failed` while its
   line item is still `pending`. Trust the transaction status; the line item's
   is not updated on this path.
4. **`products: []` comes back empty** even though the session was created with
   one product in `purchase_context`. The product detail is not echoed on a
   failed transaction, so do not rely on `products[]` to recover what was
   ordered — keep your own copy.

**No mandate is created on this path.** There is no `mandate_id` anywhere in the
response, consistent with §2.1 (the mandate is minted at *successful* approval).
So there is nothing to poll at `GET /v1/mandates/{id}` after a failed approval —
the failure is only visible via the session.

The session is terminal at this point: `status: "failed"` and the checkout link
is already consumed (§2.4). Recovery is a brand-new session, not a retry.

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

- **Sessions expire in 15 minutes and the checkout link is single-use** (§2.4),
  and approval needs a human at a keyboard. Create the session immediately
  before the person is ready to approve, never ahead of time and never to test
  that it works. A demo that creates the session early shows an expired page;
  an agent that opens the link to verify it shows "Session Already Used".
- **The sandbox test card and OTP are not published** anywhere reachable from
  this repo or `docs.prava.space`. They have to come from whoever provisioned
  the sandbox account. Do not guess card numbers against the live sandbox.
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
