# Warrant — PRD & Build Spec v1.0

> **Verification note:** Several assumptions in this PRD were checked after it was written; some were confirmed and some were refuted. Read `docs/VERIFICATION.md` first, and treat it as overriding this PRD wherever they conflict.

**Working name:** Warrant. A warrant is both a legal authorization to act and a guarantee that something is true. That is exactly the product: the agent cannot spend until it can prove where it is spending.

Alternatives if you dislike it: Bonafide, Clearance, Provenance, Attest.

**Event:** Agentic Commerce Hackathon (Devfolio, Prava). Hard deadline Aug 2, 3:00 PM PT / Aug 3, 3:30 AM IST.

---

## 1. One-liner

Visa's Trusted Agent Protocol proves the *agent* to the *merchant*. Warrant proves the *merchant* to the *agent*, and makes that proof a precondition of the payment credential.

If verification fails, no credential is issued. The agent does not "decline to buy." It becomes structurally unable to.

---

## 2. The problem

### 2.1 The asymmetry

The entire agentic-commerce trust stack points one direction. Visa TAP, Mastercard Agent Pay, Cloudflare Web Bot Auth, ACP authentication — all of it exists so merchants can tell good agents from bots. Every dollar of infrastructure investment protects the seller.

Nobody protects the buyer's agent from the seller.

### 2.2 It is already exploited

- Guardio Labs' Scamlexity tests: an agentic AI browser purchased an "Apple Watch" from a counterfeit Walmart site, auto-filling saved card details without questioning the store's legitimacy or asking for confirmation.
- F-Secure built a shopping agent and a mock marketplace, then manipulated it with an indirect prompt injection planted in a product review.
- Palo Alto Unit 42 has documented indirect prompt injection observed in the wild on scam storefronts, including hidden instructions inside pages advertising fake discounts.

### 2.3 Visa says it themselves

From Visa's own agentic-commerce threat writeup: AI shopping agents "can be deceived by sophisticated counterfeit merchants engineered specifically to exploit them," and a fraudulent storefront "may look entirely legitimate, pass automated security checks, and offer prices far below market rate." They add that fraudsters are porting the SEO playbook to agentic search, manipulating the logic behind agent shopping results.

This is the judge's own stated threat model. Build for it.

### 2.4 Scale

- 45% of consumers now use AI somewhere in the buying journey; AI referral traffic to US retail grew 393% YoY in Q1 2026.
- 94% of shoppers are concerned about AI-generated fake businesses; 91% about AI-written fake reviews.
- Prompt injection is unsolved by consensus. OpenAI's CISO calls it a frontier problem; the UK NCSC has said it may never be fully mitigated.

Capability is compounding. Trust is not. The gap is the product.

> Verify all figures above against the linked primary sources before putting them on a slide. They came from secondary reporting.

---

## 3. Product

### 3.1 Users

**Primary:** a person who has delegated spending to an agent. They are not watching. That is the whole point of delegation, and the whole reason they are exposed.

**Secondary (post-hackathon):** agent framework developers who need a verification call before checkout, and want to ship it rather than build it.

### 3.2 Core loop

```
intent → resolve merchant → verify → gate
                                      ├─ PASS   → scoped Prava session → passkey → checkout → order + attestation
                                      ├─ REVIEW → escalate to human with evidence → logged override
                                      └─ HALT   → no session requested → block record
```

The gate is not advisory. On HALT, the code path that requests a Prava session is never reached. There is no credential to misuse.

### 3.3 Scope for the hackathon

**In:**
- Merchant resolution from a URL or product intent
- Seven-probe verification fan-out (§4)
- Weighted scoring with hard-fail short circuits
- Signed, portable attestation document
- Prava session scoped to verified merchant + amount
- Live verification trace UI (the signature screen)
- Two-merchant demo: one real pass, one engineered halt

**Out (say so explicitly in the submission):**
- Multi-merchant comparison shopping
- Price watching (this was TriggerBuy; disclose it as pre-existing, do not present it as new work)
- Any merchant appeals or dispute flow
- Persistent user accounts

### 3.4 Non-goals

Warrant does not judge product quality, price fairness, or shipping reliability. It answers one question: *is this a real merchant I can safely hand a payment credential to.* Narrow is the point.

---

## 4. Verification signals

The single most important design decision: **rank signals by how hard they are to forge**, not by how impressive they sound. A judge from Visa will ask "can't a scammer just fake that?" about every one. Have the answer ready per signal.

### Tier A — expensive or impossible to forge

| Signal | Source | Key | Why it holds |
|---|---|---|---|
| Domain registration age | RDAP: `https://rdap.org/domain/{domain}` | none | Time cannot be faked. Scam storefronts skew days-to-weeks old. Strongest single cheap signal. |
| Certificate first-seen | crt.sh: `https://crt.sh/?q={domain}&output=json` | none | CT logs are append-only and public. Corroborates or contradicts RDAP. |
| Threat reputation | Google Safe Browsing Lookup API v4 | free API key | Known-bad list. A hit is dispositive. |
| Domain popularity | Tranco top-1M list (downloadable CSV) | none | Real merchants rank. Ranking is earned over time. |

### Tier B — moderate cost to forge

| Signal | Source | Key | Why it holds |
|---|---|---|---|
| TLS certificate profile | Python `ssl` + `socket` | none | Issuer, validity window, SAN list. Cheap certs are free now, so this is corroborating, not decisive. |
| PSP fingerprint | HTML/JS of checkout page | none | Stripe, Adyen, Braintree, Shopify signatures. Requires a real acquirer relationship, which requires KYB. |
| Business registry | OpenCorporates API | key, limited free tier | Global coverage is uneven. Treat as bonus, not baseline. |

### Tier C — trivially forgeable, use only as corroboration

| Signal | Source | Key | Why it is weak |
|---|---|---|---|
| UCP manifest | `GET https://{domain}/.well-known/ucp` | none | **Anyone can host a JSON file.** See §4.1. |
| security.txt | `/.well-known/security.txt` | none | Same. Presence is a mild professionalism signal only. |

### Tier D — model-derived

| Signal | Source | Key |
|---|---|---|
| Prompt-injection scan of all content the agent read | OpenAI, structured output | `OPENAI_API_KEY` |
| Review authenticity heuristic | OpenAI | same |
| Storefront copy anomaly (impossible discount, manufactured urgency) | OpenAI | same |

### 4.1 The UCP nuance you must get right

UCP discovery works by fetching a JSON manifest at `/.well-known/ucp`. The manifest declares protocol version, services, capabilities, transports (rest / mcp / a2a), and `payment_handlers`. UCP was announced 11 Jan 2026 by Google and Shopify, spec at ucp.dev under Apache 2.0.

**A scammer can trivially serve a valid-looking manifest.** So "speaks UCP" is worthless alone.

What is *not* trivial: the manifest's declared `payment_handlers` resolving to a real acquirer, and the UCP `UCP-Agent` / `request-signature` header semantics, which reference public-key fingerprints or Visa TAP signatures. A manifest that declares a payment handler it cannot actually honour fails on first contact.

**Your scoring must reflect this.** Manifest present = +small. Manifest present AND payment handler resolves AND signature verifies = +large. Say this out loud in the demo. It is the difference between a naive checker and a real one.

### 4.2 Scoring: do not use a weighted average

A naive weighted sum lets five weak positives outvote one fatal signal. That is exactly how a well-engineered scam site passes.

```
def verdict(signals):
    # Hard fails short-circuit. No score can rescue these.
    if signals.safe_browsing.hit:            return HALT("known threat")
    if signals.domain_age_days < 30:         return HALT("domain younger than 30 days")
    if signals.injection.detected:           return HALT("injected instruction in merchant content")
    if signals.tls.invalid:                  return HALT("certificate invalid")

    score = weighted(tier_a=0.5, tier_b=0.35, tier_c=0.15)
    if score >= 0.75:  return PASS
    if score >= 0.45:  return REVIEW
    return HALT("insufficient corroboration")
```

Tune the thresholds against your two demo merchants, then leave them alone.

### 4.3 The attestation

Every verification emits a signed document. This is the product's real artifact and it is what makes it sellable after the weekend.

```json
{
  "merchant": {"domain": "...", "resolved_name": "..."},
  "verdict": "PASS",
  "score": 0.87,
  "signals": [{"name": "domain_age", "tier": "A", "value": 2847, "weight": 0.2, "passed": true}],
  "scope": {"amount": "84.00", "currency": "USD", "single_use": true},
  "content_hash": "sha256:...",
  "issued_at": "2026-08-02T...Z",
  "signature": "ed25519:..."
}
```

Sign with ed25519 (`cryptography` or `pynacl`). Ship the public key in the repo. A judge can verify an attestation offline. That detail lands.

---

## 5. Architecture

### 5.1 Flow

```
                                    ┌──────────────── probes (async fan-out, httpx.gather) ─────────────┐
                                    │  rdap   crt.sh   tls   safebrowsing   psp   ucp   injection       │
                                    └───────────────────────────┬──────────────────────────────────────┘
 intent ──▶ resolve ──▶ fetch content ──▶ ────────────────────► scoring ──▶ gate
                                                                              │
                                             PASS ─────────────────────────────┤
                                               │                               │
                                    Prava session (merchant + amount scoped)   │
                                               │                               │
                                        passkey approval                  HALT │
                                               │                               │
                                          checkout                       block record
                                               │                          + attestation
                                        order + attestation
```

### 5.2 LangGraph nodes

`resolve → fetch → probe_fanout → score → gate → {quote → session → await_approval → pay → settle} | {block → attest}`

Reuse your existing state machine shape. `EXPIRED` still re-arms on quote or session lapse.

**Design note:** run all probes concurrently with `asyncio.gather` and stream each result to the UI as it lands. Sequential probing takes 8+ seconds and looks broken. Concurrent probing takes ~1.5s and *streaming* it makes that 1.5s feel like the product working rather than the product hanging.

### 5.3 Repo layout

```
backend/
  app/
    main.py                 FastAPI, SSE endpoint for the probe stream
    models.py               Merchant / Attestation / Session / Order
    scoring.py              verdict(), weights, hard-fail table
    attest.py               ed25519 sign + verify
    probes/
      rdap.py  ct.py  tls.py  safebrowsing.py  psp.py  ucp.py  injection.py
      base.py               Signal dataclass, timeout + failure contract
    services/
      prava_client.py       PORTED to SDK/API. All Prava calls live here.
  agent/
    graph.py                LangGraph state machine
frontend/
  src/                      Vite + React + Tailwind
merchants/
  legit/                    pointer to your real UCP demo merchant
  spoof/                    the storefront you host for the HALT demo
docs/
  ATTESTATION_SPEC.md
```

### 5.4 Probe failure contract

Every probe must return within a hard timeout (2s) and must be allowed to fail without failing the request. A probe that errors returns `Signal(status=UNAVAILABLE)` and is excluded from the denominator, not scored as zero. Scoring zero on an unavailable probe means one flaky third party HALTs a legitimate purchase. That is the failure mode that would kill this in production and a judge may well ask.

---

## 6. UX

You want this to be the best-looking thing in the room. Here is a direction that is not the default AI look.

### 6.1 Concept

**Instrument, not dashboard.** The reference is lab equipment and pre-flight checklists, not fintech SaaS. This is a device that clears or refuses. It should feel mechanical and certain, not friendly and rounded.

Avoid, deliberately: cream backgrounds with serif display and terracotta accents; near-black with acid green; broadsheet hairline columns. All three read as machine-generated right now.

### 6.2 Tokens

```css
--ink:    #10151C;  /* deep slate, not pure black */
--paper:  #F2F4F3;  /* cool off-white, not cream */
--steel:  #5C6B7A;  /* structure, rules, secondary text */
--verify: #1F7A5C;  /* deep pine. verdict only. */
--halt:   #B3341F;  /* oxide red. verdict only. */
--amber:  #C9922B;  /* review state only */
```

Signal colours appear **only** on verdicts. Nowhere else. That restraint is what makes the halt land.

### 6.3 Type

- Display: **Archivo** or **Space Grotesk**, tight tracking, heavy weight, used sparingly
- Body: **IBM Plex Sans**
- Evidence and data: **IBM Plex Mono**

All on Google Fonts, so no asset pipeline at 3am. Do not use Inter. Everyone uses Inter.

The mono face carries the personality here: every piece of evidence renders as monospaced raw data, because the claim is that this is measurement, not opinion.

### 6.4 Signature moment

**The stamp.**

Probes stream in as a staggered list, each row showing name, raw value, tier, and a resolving state. When the last one lands, a verdict seal composites over the merchant card: `CLEARED` in pine with the attestation hash and timestamp, or a `HALT` overstamp in oxide red, slightly rotated, with the failing signal named beneath it.

One orchestrated sequence. Nothing else on the page animates. Respect `prefers-reduced-motion` by rendering the final state directly.

This is the screenshot that goes in the submission.

### 6.5 Screens (four, no more)

1. **Intent** — what to buy, ceiling price. Minimal.
2. **Verification trace** — the signature screen. Live probe stream, evidence visible, verdict stamp.
3. **Approval** — Prava passkey handoff, showing exactly what the credential is locked to. The scope line should read like a legal clause, not a summary.
4. **Receipt** — order ID and attestation, or the block record with full reasoning.

### 6.6 Copy

Errors state what happened and what to do. No apologies, no vagueness. The interface's voice is an instrument's: flat, exact, unhedged.

- Not "Oops! We couldn't verify this store." → **"Halted. Domain registered 6 days ago. Minimum is 30."**
- Not "Purchase successful!" → **"Paid $84.00 to ridge.com. Credential expired."**
- Empty state is an instruction, not a mood.

### 6.7 Transport

Server-Sent Events for the probe stream. `sse-starlette` on FastAPI, `EventSource` in React. Far simpler than WebSockets for one-way streaming and it will be working in twenty minutes.

---

## 7. Technical requirements

### 7.1 Keys

| Key | Where | Cost | Time to get |
|---|---|---|---|
| `PRAVA_SECRET_KEY` | dashboard.prava.space | free sandbox | minutes, **do this first** |
| `OPENAI_API_KEY` | you have this | hackathon credits | done |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Cloud Console, enable Safe Browsing API | free | ~5 min |
| `SENSO_API_KEY` | only if chasing the $7,500 track | — | ask in Discord |
| `OPENCORPORATES_API_KEY` | optional, registry lookups | limited free | skip for demo |

No key needed: RDAP, crt.sh, TLS inspection, `.well-known` probes, Tranco.

### 7.2 Python

```
fastapi
uvicorn[standard]
sse-starlette
sqlmodel
httpx              # async fan-out; use AsyncClient with explicit timeouts
pydantic
tldextract         # correct eTLD+1 parsing, do not regex domains
selectolax         # fast HTML parsing for PSP fingerprint
cryptography       # ed25519 attestation signing
langgraph
openai             # raw SDK is simpler than langchain-openai for structured output
```

**Do not use `python-whois`.** It is a screen-scraper over inconsistent WHOIS text and it will break on you. RDAP over httpx returns clean JSON.

### 7.3 Frontend

```
vite  react  tailwindcss  framer-motion
```

Hand-build the components. A component library will make it look like everyone else's, which defeats the entire point of this section.

### 7.4 Functions to write

```python
# probes/base.py
@dataclass
class Signal:
    name: str; tier: Literal["A","B","C","D"]
    status: Literal["PASS","FAIL","UNAVAILABLE"]
    value: Any; evidence: str; weight: float

# probes/*.py  — each is: async def run(domain: str) -> Signal
# scoring.py   — def verdict(signals: list[Signal]) -> Verdict
# attest.py    — def sign(payload: dict) -> str ; def verify(doc: dict) -> bool
# prava_client.py — async def create_session(merchant, amount) / get_payment_result(id)
```

---

## 8. Global scale (the "what happens next" answer)

Judges ask this explicitly. Have real answers, not aspiration.

1. **Registry coverage is uneven.** RDAP is global and consistent. Business registries are not. OpenCorporates covers much of the OECD well and the rest patchily. Outside the US/EU, weight Tier A higher and drop registry from the denominator rather than penalising the merchant.
2. **Caching.** Verification results cache by eTLD+1 with a TTL (24h for Tier A, 1h for reputation). Without this, every purchase costs seven network calls and you rate-limit yourself out of Safe Browsing.
3. **False positives are the real cost.** A blocked legitimate merchant is a lost sale and an angry brand. You need an appeals path and a merchant-initiated pre-verification. This is also the wedge into a B2B product: merchants will pay to be pre-cleared.
4. **Who signs the attestation.** Right now, you. At scale that is a trust-root problem and the honest answer is that this belongs with a network (Visa) or a consortium, not a startup. Saying that to a Visa judge is a strength, not a concession.
5. **Rails.** Prava is US-first (their site states US Visa cards and merchants; the homepage also claims SEA). Verification logic is rail-agnostic and ports the day coverage expands.

---

## 9. Honest limits (put these in the submission)

- **Pre-existing work:** the LangGraph orchestration patterns and Prava client wrapper come from TriggerBuy, built before the event. The verification pipeline, scoring, attestation, and UI are new. Disclose this plainly. The rules explicitly punish non-disclosure and explicitly permit building on existing work.
- **The spoof merchant is one you host.** That is legitimate and necessary. It is not legitimate to dress it up as a real brand. Call it what it is on screen.
- **Verification is probabilistic.** A sufficiently funded adversary who ages a domain, buys a real PSP relationship, and passes KYB defeats this. Warrant raises the cost of attack; it does not eliminate it. Say so before a judge says it for you.
- **Tier C signals are near-free to forge** and weighted accordingly.

---

## 10. Judging map

| Criterion | Answer |
|---|---|
| End-to-end functionality | Real sandbox checkout on PASS, real refusal on HALT, both on camera |
| Creativity and novelty | Inverts the industry's trust direction. TAP protects merchants; nothing protected buyers. |
| User value and feasibility | 94% consumer concern, documented live exploitation, named by Visa as a threat |
| Prava implementation | Verification output *is* the mandate scope. Not a payment button. |
| Track implementation | Visa: agent-side controls. Senso: verified context changing the decision. OpenAI: injection detection + reasoning. |
| Product experience | The trace screen and the stamp |
| What happens next | SDK for agent frameworks; pre-clearance product for merchants; trust root belongs with a network |

---

## 11. Remaining-time plan

Assumes ~24 usable hours. Adjust the clock, keep the order.

| Block | Work | Gate |
|---|---|---|
| **0 (2h)** | Prava sandbox key. Port `prava_client.py` CLI→SDK. One successful sandbox session end to end. | **If this does not work, everything below is worthless. Do not proceed until it does.** |
| 1 (3h) | Tier A probes: rdap, crt.sh, tls, safebrowsing. Concurrent fan-out. Print signals to console. | Four real signals on two real domains |
| 2 (2h) | Scoring + hard fails + attestation signing | Verdict object with valid signature |
| 3 (2h) | Spoof storefront, hosted, with one injected review | Your own agent gets fooled by it *before* the gate exists |
| 4 (2h) | Injection probe + PSP fingerprint + UCP manifest | Spoof now HALTs, real merchant PASSes |
| 5 (1h) | Wire gate into LangGraph. PASS path reaches Prava; HALT path cannot. | Code-path proof, not a UI check |
| 6 (5h) | Frontend: four screens, SSE stream, the stamp | The screenshot exists |
| 7 (2h) | Demo rehearsal, both paths, twice | Under 3 minutes, zero terminal on camera |
| 8 (2h) | Video, README, disclosure, submission | Submitted with 2h buffer, not 10min |

**Cut list, in the order you cut:** OpenCorporates → Tranco → security.txt → review-authenticity probe → the REVIEW state (collapse to binary PASS/HALT). Do not cut: Tier A probes, the attestation signature, the stamp, the rehearsal.

---

## 12. Open questions to resolve today

1. Does Prava CLI have any sandbox mode, or is SDK/API the only path? (Discord, Birdie)
2. Is there in fact a UX or hardware prize? It is on neither the handbook nor the live Devfolio prize page. (Discord)
3. Does a Prava session hard-decline an over-amount capture, or is there tolerance? (Test: scope $50, attempt $52.)
4. Is Senso worth wiring for $7,500, or is it a two-hour distraction? (Read their docs, decide in 15 minutes, do not drift.)
