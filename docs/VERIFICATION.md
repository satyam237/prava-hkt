# Warrant verification findings

Synthesis source: `/Users/satyamjadhav/Base/firstmate/data/warrant-phase1/report.md`, backed by the Prava, protocol, and library research reports listed in the task brief. This document records what was checked, where it was checked, the research verdict, and what it means for the build.

## Status meanings

- **CONFIRMED** — primary/source-report evidence supports the claim.
- **REFUTED** — primary/source-report evidence contradicts the claim.
- **VERIFY** — incomplete, conflicting, or insufficient evidence; do not present as fact.
- **BLOCKED-NEEDS-ME** — human/tool/access required; no invention or substitution.

## Corrections to the PRD

These findings override `docs/WARRANT_PRD.md` wherever they conflict. Line references are the original PRD references recorded by the synthesis report.

- `docs/WARRANT_PRD.md:403` / `:419`: the Prava CLI has no sandbox mode. Use SDK/API sandbox; CLI talks to live API and agent-linked CLI payments use real cards.
- `docs/WARRANT_PRD.md:77` / `:192`: Prava sessions are confirmed as scoped to one merchant/customer/order and amount, but **multi-merchant sessions are not supported**.
- `docs/WARRANT_PRD.md:357`: `create_session(merchant, amount)` is under-specified/wrong as an API shape. Real session creation requires documented fields including `user_id`, `user_email`, `total_amount`, `currency`, and one `purchase_context`.
- `docs/WARRANT_PRD.md:421`: the USD 50 scoped session vs USD 52 attempted checkout zero-tolerance question is **BLOCKED-NEEDS-ME**. The documented amount cap exists, but that exact one-time tolerance scenario has not been confirmed or executed.
- `docs/WARRANT_PRD.md:135`: UCP `UCP-Agent` / `request-signature` semantics are refuted by the reviewed official sources. `UCP-Agent` carries a profile URI; current UCP signature docs list `Signature-Input`, `Signature`, and `Content-Digest`.
- `docs/WARRANT_PRD.md:135`: `payment_handlers` do not prove a real acquirer relationship. Official UCP docs say they are specifications, not entities.
- UCP official sources conflict on `keys[]` vs `signing_keys[]`; pin a concrete source/version before coding.
- `docs/WARRANT_PRD.md:104`: Tranco is not a plain CSV assumption; the homepage points to `top-1m.csv.zip`.
- crt.sh cannot be treated as a reliable 2-second synchronous dependency; observed probes timed out or returned 502.
- Safe Browsing exact default quota is not public in reviewed docs; console access is needed.
- `docs/WARRANT_PRD.md:370`: no reviewed primary source supports SEA availability. Current primary Prava pages reviewed support US/Visa language.
- Library/API details for FastAPI, SQLModel, httpx, LangGraph, sse-starlette, and cryptography Ed25519 remain blocked because Context7 was unavailable.

## Open questions and blockers

- **UCP `keys[]` vs `signing_keys[]`:** official raw schema/docs and rendered docs conflict; pin source/version before implementation.
- **Certificate-transparency reliability plan:** crt.sh failed the 2-second budget; no authoritative fallback was identified. Do not name or add a fallback without approved, source-backed research.
- **Library-API documentation verification:** FastAPI, SQLModel, httpx, LangGraph HITL, sse-starlette, and cryptography Ed25519 verification are all BLOCKED-NEEDS-ME until Context7 or an approved alternate source is available.
- **Over-amount tolerance:** the USD 50 vs USD 52 test procedure in the research was never executed and requires written Prava/test-merchant authorization before any run.
- **Safe Browsing quota:** exact default quota requires Google Cloud Console access.
- **Known-good public UCP endpoint:** no public live `/.well-known/ucp` endpoint was confirmed in the reviewed sources/probes.

## Credentials and access still needed

- Prava sandbox test keys: `sk_test_*` and `pk_test_*`.
- A passkey/WebAuthn-capable browser or device.
- A Google Safe Browsing API key from an enabled Google Cloud project.
- An authorized sandbox merchant capable of safe over-amount testing, if that question is pursued.

## Mandatory implementation rules

1. **No invented API shapes.** Use documented Prava paths/fields only; UCP must be pinned to a concrete official source/version before implementation.
2. **No mock payment represented as real.** Any spoof merchant or sandbox payment must be labeled as such; CLI is live/real-card territory.
3. **Two-second hard timeout for all probes.** Keep this as a hard contract.
4. **`UNAVAILABLE` excluded from scoring denominators.** Network/tool failures are not zero scores.
5. **Hard-fail short circuits before weighted scoring.** Safe Browsing hit, too-young domain, injection, invalid TLS, etc. must HALT before weights.
6. **No `python-whois`.** Use RDAP over HTTP/JSON; parse `events[]`.
7. **No new dependency recommendation without approval.** Library docs are blocked pending Context7 or explicitly approved alternate verification.

## Assumption-verification table

| Area | Claim checked | Status | Exact URL | Short exact supporting quote | Practical consequence for Warrant |
|---|---|---:|---|---|---|
| Prava | SDK/API sandbox is available. | CONFIRMED | https://docs.prava.space/api-reference/testing.md | “Sandbox is **self-serve**: sign up at dashboard.prava.space, create `pk_test_*`/`sk_test_*` keys, and you can create sessions immediately against `https://sandbox.api.prava.space`.” | Use SDK/API sandbox for demo and tests. |
| Prava | CLI has sandbox mode. | REFUTED | https://docs.prava.space/api-reference/testing.md | “**Prava Pay (CLI) has no separate sandbox host.** The CLI talks to the live API; agent-linked payments use real cards.” | Do not use CLI for sandbox demo; never represent CLI payment as mock/sandbox. |
| Prava | Auth/base URLs/key prefixes. | CONFIRMED | https://docs.prava.space/authentication.md | “Include the key as a Bearer token: `Authorization: Bearer sk_test_xxx` or `Authorization: Bearer sk_live_xxx`”; Sandbox `https://sandbox.api.prava.space`, Production `https://api.prava.space`. | Require key provisioning and env separation. |
| Prava | Dashboard starts with sandbox keys. | CONFIRMED | https://docs.prava.space/dashboard.md | “New accounts start in **sandbox**: keys work immediately against `sandbox.api.prava.space`, no waiting and no verification.” | Human must enroll/provide dashboard sandbox keys. |
| Prava | Session is scoped to one merchant/order and amount. | CONFIRMED | https://docs.prava.space/api-reference/create-session.md | “Create a short-lived, single-use session tied to one merchant, customer, and order.” / “`total_amount`… This value becomes the authorized amount cap.” | Gate must create session only after PASS, with verified merchant and amount. |
| Prava | Multi-merchant sessions are supported. | REFUTED | https://docs.prava.space/api-reference/create-session.md | “`purchase_context`… Exactly one entry — multi-merchant sessions are not yet supported.” | Hackathon flow must be single merchant. |
| Prava | Simplified `create_session(merchant, amount)` is enough. | REFUTED | https://docs.prava.space/api-reference/create-session.md | Required fields: “`user_id`, `user_email`, `total_amount`, `currency`, `purchase_context`.” | Do not invent simplified API shape; implementation needs full documented fields. |
| Prava | Payment-result polling path and one-time credential fields. | CONFIRMED | https://docs.prava.space/api-reference/get-payment-result.md | “`GET /v1/sessions/{sessionId}/payment-result`”; “`token`… Virtual card number”; “`dynamic_cvv`… Single-use CVV.” | Poll documented endpoint; handle credentials only when status permits. |
| Prava | `processing` status should be handled. | VERIFY | https://docs.prava.space/concepts/checkout-flow.md | Status table includes “`processing` — Entering card, verifying or registering a passkey…” | Docs conflict/omit status in places; handle `processing` defensively. |
| Prava | There is a generic REST “complete checkout” endpoint. | REFUTED | https://docs.prava.space/guides/rest-checkout-walkthrough.md | “Use them at the merchant's checkout like a normal card”; then “Report `DECLINED` if the checkout failed; either way, always report.” | Checkout occurs at merchant; Warrant must call report-status afterward. |
| Prava | Report-status endpoint. | CONFIRMED | https://docs.prava.space/api-reference/report-status.md | “`POST /v1/sessions/{sessionId}/report-status`”; body requires `txn_ref_id`, `txn_status`. | Always report approved/declined outcome. |
| Prava | Amount cap/network-level enforcement. | CONFIRMED | https://docs.prava.space/concepts/guardrails.md | “The mandate's **amount** is enforced at the card-network level… a transaction outside the mandate amount is declined.” | Safe to say caps are documented; still do not rely on declines as primary UX. |
| Prava | Over-cap decline code for mandate charges. | CONFIRMED | https://docs.prava.space/api-reference/mandate-charge.md | “The per-charge cap is enforced by the card network — an over-cap charge is declined (`THRESHOLD_EXCEEDED`).” | Useful evidence, but do not overgeneralize to one-time capture tolerance. |
| Prava | USD 50 scoped session will hard-decline USD 52 with zero tolerance. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-prava-research/report.md | “Docs do not explicitly say whether every over-amount merchant authorization/capture is a hard decline with zero tolerance…” | Needs Prava confirmation or authorized sandbox procedure above. |
| Prava | New-device sandbox OTP/passkey behavior. | CONFIRMED | https://docs.prava.space/concepts/checkout-flow.md | “New browser/device… OTP challenge… register a new passkey”; “In sandbox, enter the test code `456789`.” | Demo setup needs WebAuthn-capable browser/device. |
| Prava | US/SEA rail scope. | VERIFY | https://www.prava.space/pay | “Prava is available for use in US on all Visa cards & merchants”; “Prava Wallet supports Visa currently.” | Do not claim SEA availability unless a current primary Prava source is provided. |
| UCP | Business discovery path is `/.well-known/ucp`. | CONFIRMED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/docs/specification/overview.md | “Businesses publish their profile at `"/.well-known/ucp"`.” | Probe can fetch this path, but presence alone is not proof of trust. |
| UCP | Required manifest registries/fields. | CONFIRMED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/docs/specification/overview.md | “For both business and platform profiles, `ucp.version`, `ucp.services`, and `ucp.payment_handlers` are required.” / “`ucp.capabilities` is optional.” | Validate required/optional fields exactly; do not assume all PRD-listed fields are required. |
| UCP | Current signing-key field name is settled. | VERIFY | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/source/schemas/profile.json | “`keys`: { … `Canonical UCP profile field for publishing signing keys`” | Official sources conflict with rendered docs showing `signing_keys`; pin source/version before coding. |
| UCP | `payment_handlers` prove a real acquirer relationship. | REFUTED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/docs/specification/overview.md | “Payment Handlers are specifications (not entities).” | Do not assign large trust weight to handler declaration as acquirer proof. |
| UCP | `payment_handlers` registry shape. | CONFIRMED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/source/schemas/ucp.json | “Payment handler registry keyed by reverse-domain name.” | Treat handler IDs/specs as manifest metadata, not KYB/acquirer evidence. |
| UCP | `UCP-Agent` carries fingerprints/Visa TAP signatures. | REFUTED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/docs/specification/overview.md | “UCP-Agent: profile=`"https://agent.example/profiles/shopping-agent.json"`.” | Do not implement fingerprint semantics from PRD text. |
| UCP | `request-signature` is current UCP header. | REFUTED | https://raw.githubusercontent.com/Universal-Commerce-Protocol/ucp/main/docs/specification/signatures.md | `request-signature`: “NOT FOUND” in source report; docs list “`Signature-Input`”, “`Signature`”, “`Content-Digest`”. | Use only current official signature headers after pinned-source review. |
| UCP | Live known-good public UCP endpoint exists in reviewed sources. | BLOCKED-NEEDS-ME | https://shopify.com/.well-known/ucp | Observed body: “Not found.” | Human must provide a known-good endpoint if a positive live probe is required. |
| RDAP | `https://rdap.org/domain/{domain}` returns RDAP JSON with registration event. | CONFIRMED | https://rdap.org/domain/openai.com | `"objectClassName":"domain"` … `"eventAction":"registration","eventDate":"2007-01-19T19:28:24Z"`. | Good Tier A signal; parse `events[]`, not nonexistent top-level date. |
| RDAP | Registration date field semantics. | CONFIRMED | https://www.rfc-editor.org/rfc/rfc9083.html | “`eventAction` -- a REQUIRED string”; example “`eventAction` : `"registration"`”; “`eventDate` -- a REQUIRED string…” | Implement robust event parsing per TLD/operator differences. |
| RDAP | Failure/rate-limit behavior. | CONFIRMED | https://www.rfc-editor.org/rfc/rfc7480.html | “it returns a 404 response”; “400 (Bad Request)”; “429 (Too Many Requests)” and “honor the Retry-After header”. | 404/400/429 become probe statuses; unavailable/error excluded from denominator. |
| RDAP | Exact numeric `rdap.org` rate limit is public. | VERIFY | https://www.rfc-editor.org/rfc/rfc7480.html | Source report found “No numeric limit statement”; RFC only standardizes 429 behavior. | Add backoff/cache; do not claim a numeric quota. |
| crt.sh | Current JSON shape was confirmed. | VERIFY | https://crt.sh/?q=openai.com&output=json | Longer retry observed “502 Bad Gateway”; 2-second probes timed out. | Do not invent JSON fields; code must tolerate `UNAVAILABLE`. |
| crt.sh | Fits mandatory 2-second synchronous budget. | REFUTED | https://crt.sh/?q=example.com&output=json | 2-second probe outcome: “TIMEOUT”; longer retry: “502 Bad Gateway.” | Treat as unreliable for blocking checkout; exclude unavailable from scoring denominator. |
| crt.sh | Authoritative fallback is identified. | VERIFY | file:///Users/satyamjadhav/Base/firstmate/data/warrant-protocol-research/report.md | “I found no authoritative source in this pass that endorses a specific fallback service.” | No fallback recommendation without separate approval/research. |
| Google Safe Browsing | Lookup API v4 POST endpoint/body exists. | CONFIRMED | https://developers.google.com/safe-browsing/v4/lookup-api | “`POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY`.” | Implement only with key; hit is a hard fail. |
| Google Safe Browsing | No-match/match response shape. | CONFIRMED | https://developers.google.com/safe-browsing/v4/lookup-api | “If there are no matches … returns an empty object”; matches returned in `matches[]`. | `{}` means no known hit; `matches[]` means HALT. |
| Google Safe Browsing | API key and enablement required. | CONFIRMED | https://developers.google.com/safe-browsing/v4/get-started | “you need a Google Account, a Google Developer Console project, and an API key. You also need to activate the Safe Browsing APIs…” | Human must provision API key/project. |
| Google Safe Browsing | Cost. | CONFIRMED | https://developers.google.com/safe-browsing/v4/pricing | “All use of Safe Browsing APIs is free of charge.” | No direct API cost expected; still handle quotas. |
| Google Safe Browsing | Exact public default quota. | BLOCKED-NEEDS-ME | https://developers.google.com/safe-browsing/v4/usage-limits | “Current allocation and usage can be viewed in the Google Developer Console.” | Needs GCP console access; do not claim a number. |
| Tranco | Current latest-list link. | CONFIRMED | https://tranco-list.eu/ | Anchor href observed: `https://tranco-list.eu/latest_list`. | Use official latest-list redirect/link if ingesting. |
| Tranco | Direct permanent top-1M file is plain CSV. | REFUTED | https://tranco-list.eu/ | Anchor href observed: `https://tranco-list.eu/top-1m.csv.zip`; “The file uses the same format as the Alexa and Cisco Umbrella lists.” | Handle ZIP/CSV, not raw plain CSV only. |
| Library docs | FastAPI current API docs verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “No Context7 MCP tools are exposed.” | Do not implement from memory; connect Context7 or approve alternate doc source. |
| Library docs | SQLModel current API docs verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “Context7 is unavailable.” | Same blocker. |
| Library docs | httpx async patterns verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “I could not perform the requested current-API verification…” | Same blocker; still enforce explicit 2s timeout if later implemented. |
| Library docs | LangGraph human-in-the-loop interrupts verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “All are **BLOCKED-NEEDS-ME**.” | Do not plan HITL interrupt implementation from remembered APIs. |
| Library docs | sse-starlette current API docs verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “Context7 not connected.” | No unapproved dependency/API claim. |
| Library docs | cryptography Ed25519 current API docs verified. | BLOCKED-NEEDS-ME | file:///Users/satyamjadhav/Base/firstmate/data/warrant-library-research/report.md | “Do not implement Warrant dependencies from memory.” | Keep Ed25519 attestation as product requirement, but verify APIs before coding. |
