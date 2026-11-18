# Warrant — PRD & Build Spec v2.0

**Supersedes v1.0.** v1 covered pre-purchase verification only. v2 extends the same artifact through the full purchase lifecycle.

**Event:** Agentic Commerce Hackathon (Devfolio, Prava). Hard deadline Aug 2, 3:00 PM PT / Aug 3, 3:30 AM IST.

---

## 1. The one sentence

**An agent should only be able to spend where it verified, and should be able to prove exactly what it agreed to.**

One signed document does three jobs:
1. **Verification output** — what we checked about the merchant, and what we found
2. **Credential scope** — the Prava session is bounded by it
3. **Dispute evidence** — reality is reconciled against it after the fact

If you cannot explain Warrant in that sentence, you are building two products and you will run out of time. Every scope decision below defends that sentence.

### Why the name works now

A *warrant* is (a) authorization to act, (b) a guarantee that something is true, (c) in commercial law, a warranty — a promise of recourse if the thing is not as described. All three meanings are load-bearing.

---

## 2. The problem, both halves

### 2.1 Before the purchase: nothing protects the buyer

The entire agentic-commerce trust stack points one way. Visa TAP, Mastercard Agent Pay, Cloudflare Web Bot Auth: all built so merchants can identify agents. Nothing lets an agent identify a merchant.

Visa states the threat themselves: AI shopping agents "can be deceived by sophisticated counterfeit merchants engineered specifically to exploit them," and a fraudulent storefront "may look entirely legitimate, pass automated security checks, and offer prices far below market rate."

Already exploited in practice. Guardio Labs' Scamlexity tests had an agentic browser buy an "Apple Watch" from a counterfeit Walmart site, auto-filling saved card details without questioning legitimacy. F-Secure manipulated a shopping agent with an injection planted in a product review.

### 2.2 After the purchase: nothing resolves the dispute

Agents can buy. They cannot un-buy.

At Fortune Brainstorm Tech 2026, Akoya's head of policy said there is still no agreement on how to handle fraud, refunds and returns, and that liability when an agent buys something the customer says they did not intend is one of the biggest unsolved problems holding agentic commerce back. As of 2026, no jurisdiction has enacted regulation specifically addressing autonomous AI purchasing.

The canonical failure, from a UK payments writeup: an agent reorders supplies weekly; a feed error misprices a 12-pack; the agent treats it as a normal reorder; twelve cases arrive; £6 becomes £72; the money is already gone.

### 2.3 The bridge

Reportedly, the CFPB's January 2026 advisory held that a consumer's right of recourse is **not extinguished by an agent mandate, only narrowed where the mandate is appropriately scoped.**

Read that carefully. **Scope quality has legal weight.** A well-formed, signed, tamper-evident mandate is not compliance decoration. It is the evidence that decides the dispute.

That is why verification and recourse are the same product. Verification is what makes the mandate trustworthy. The mandate is what makes recourse possible.

Meanwhile the networks are already paying to fix half of it: Amex introduced an agentic commerce developer kit in early 2026 with a commitment to cover erroneous purchases by registered agents, issuing credentials to verified agents and authenticating cardholders first.

> Verify every figure and claim in this section against primary sources before it goes on a slide. All of it came from secondary reporting.

---

## 3. Product

### 3.1 Lifecycle

```
  AUTHORIZE                    EXECUTE                   RECONCILE
┌──────────────┐         ┌────────────────┐         ┌──────────────────┐
│ resolve      │         │ Prava session  │         │ poll outcome     │
│ verify       │────────▶│ scoped BY the  │────────▶│ diff vs mandate  │
│ sign MANDATE │         │ mandate        │         │ SETTLED / BREACH │
└──────────────┘         └────────────────┘         └──────────────────┘
       │                                                      │
    HALT: no session is ever requested            BREACH: signed dispute packet
```

The gate is structural, not advisory. On HALT the code path that requests a Prava session is never reached. There is no credential to misuse.

### 3.2 In scope

**Authorize**
- Merchant resolution from URL or intent
- Four verification probes (§4)
- Hard-fail scoring
- ed25519-signed mandate

**Execute**
- Prava session scoped to the mandate's merchant and amount
- Passkey approval
- Real sandbox checkout

**Reconcile**
- Deterministic diff of outcome against mandate
- SETTLED or BREACH verdict
- Signed dispute packet embedding the original mandate

**UI**
- Live verification trace
- Mandate/reality diff view
- Two stamps: CLEARED/HALT, SETTLED/BREACH

### 3.3 Explicitly out (say so in the submission)

- **Filing the return or chargeback.** Warrant produces the evidence packet. Filing is issuer and merchant dependent and is roadmap. Do not claim otherwise.
- Price watching (this was TriggerBuy, pre-existing, disclose it)
- Multi-merchant comparison
- Merchant appeals flow
- Persistent accounts
- The REVIEW verdict state. Binary PASS/HALT only.

### 3.4 Non-goals

Warrant does not judge product quality, price fairness, or shipping speed. Two questions only: *is this merchant safe to hand a credential to*, and *did what happened match what was authorized.*

---

## 4. Verification signals

Rank by **cost to forge**, not by how impressive they sound. A Visa judge will ask "can't a scammer fake that?" about every one. Have the answer per signal.

Cut to four probes. This is deliberate. Four probes you can defend beat nine you cannot.

| Probe | Source | Key | Tier | Why it holds |
|---|---|---|---|---|
| Domain age | RDAP `https://rdap.org/domain/{domain}` | none | A | Time cannot be faked. Scam storefronts skew days old. Strongest cheap signal. |
| Certificate history | crt.sh `?q={domain}&output=json` | none | A | CT logs are append-only and public. Corroborates or contradicts RDAP. |
| Threat reputation | Google Safe Browsing Lookup v4 | free key | A | A hit is dispositive. |
| Injection scan | OpenAI, structured output | `OPENAI_API_KEY` | D | Scans everything the agent read before deciding. |

**Cut from v1, do not rebuild:** OpenCorporates, Tranco, security.txt, review authenticity, PSP fingerprint, UCP manifest presence.

### 4.1 If you have spare time, add exactly one: PSP fingerprint

Detecting Stripe/Adyen/Braintree/Shopify signatures in checkout HTML is the best remaining signal because a real acquirer relationship requires KYB. `selectolax` over the checkout page. Twenty minutes. Nothing else on the cut list is worth reinstating.

### 4.2 The UCP trap

If you mention UCP at all, get this right or a judge will take it apart: **anyone can host a JSON file at `/.well-known/ucp`.** Protocol presence proves nothing. What is expensive is a declared `payment_handler` that actually resolves to a real acquirer. Say the weakness out loud before a judge finds it. That distinction is what separates a real checker from a checklist.

### 4.3 Scoring

Never a weighted average. Five weak positives must not outvote one fatal signal.

```python
def verdict(signals) -> Verdict:
    if signals.safe_browsing.hit:       return HALT("known threat")
    if signals.domain_age_days < 30:    return HALT("domain younger than 30 days")
    if signals.injection.detected:      return HALT("injected instruction in merchant content")
    if signals.tls.invalid:             return HALT("certificate invalid")
    return PASS if score(signals) >= 0.70 else HALT("insufficient corroboration")
```

### 4.4 Probe failure contract

2s hard timeout each. A probe that errors returns `UNAVAILABLE` and is **excluded from the denominator**, never scored zero. Scoring zero on an unavailable probe means one flaky third party blocks a legitimate purchase. That is the failure mode that would kill this in production, and it is the kind of thing a Visa judge asks about.

---

## 5. The mandate

The central artifact. Build this early; everything else attaches to it.

```json
{
  "version": "warrant/1",
  "mandate_id": "wrt_...",
  "merchant": {"domain": "...", "resolved_name": "..."},
  "verification": {
    "verdict": "PASS",
    "score": 0.86,
    "signals": [
      {"name": "domain_age", "tier": "A", "value": 2847, "status": "PASS"}
    ],
    "content_hash": "sha256:..."
  },
  "authorization": {
    "sku": "...", "description": "...", "quantity": 1,
    "amount": "84.00", "currency": "USD",
    "single_use": true,
    "expected_fulfillment_by": "2026-08-09T00:00:00Z"
  },
  "issued_at": "2026-08-02T...Z",
  "signature": "ed25519:..."
}
```

Sign with ed25519 (`cryptography`). Ship the public key in the repo. **A judge can verify an attestation offline.** That detail lands harder than any architecture slide.

---

## 6. Reconciliation

### 6.1 Deterministic, not model-based

```python
def reconcile(mandate: Mandate, outcome: Outcome) -> Reconciliation:
    breaches = []
    if outcome.amount_charged > mandate.amount:
        breaches.append(Breach("AMOUNT_EXCEEDED", mandate.amount, outcome.amount_charged))
    if outcome.merchant_domain != mandate.merchant.domain:
        breaches.append(Breach("MERCHANT_MISMATCH", ...))
    if outcome.sku != mandate.authorization.sku:
        breaches.append(Breach("ITEM_MISMATCH", ...))
    if outcome.quantity != mandate.authorization.quantity:
        breaches.append(Breach("QUANTITY_MISMATCH", ...))
    if outcome.status == "UNFULFILLED" and past(mandate.expected_fulfillment_by):
        breaches.append(Breach("NON_DELIVERY", ...))
    return SETTLED if not breaches else BREACH(breaches)
```

**Why no LLM here, and say this in the demo:** a dispute evidence packet whose logic is a language model is worthless in a dispute. The opposing party asks "why did it decide that" and there is no answer. Determinism is not a shortcut, it is the requirement. The LLM belongs in the injection probe, where judgment is the job. It does not belong anywhere near the evidence.

### 6.2 The dispute packet

On BREACH, emit a signed document embedding the original signed mandate plus the observed outcome plus the enumerated breaches. Two signatures, two timestamps, one verifiable chain: *here is what was authorized and when, here is what happened.*

### 6.3 Where outcome data comes from

From the checkout result and any order-status endpoint Prava surfaces. **This is the highest-uncertainty dependency in v2.** If Prava's checkout result does not carry line-item detail, your reconciliation reduces to amount and merchant only.

That is still a working product. AMOUNT_EXCEEDED alone demos the £6→£72 case. Plan for the reduced version and treat richer fields as upside.

---

## 7. UX

You want this to be the best-looking submission. Direction below is deliberately not the default AI look.

### 7.1 Concept

**Instrument, not dashboard.** Lab equipment and pre-flight checklists, not fintech SaaS. This device clears, refuses, and adjudicates. Mechanical and certain, not friendly and rounded.

Deliberately avoid: cream + serif + terracotta; near-black + acid green; broadsheet hairline columns. All three read as machine-generated right now.

### 7.2 Tokens

```css
--ink:    #10151C;   /* deep slate, not pure black */
--paper:  #F2F4F3;   /* cool off-white, not cream */
--steel:  #5C6B7A;   /* structure, rules, secondary text */
--verify: #1F7A5C;   /* deep pine  — verdicts only */
--halt:   #B3341F;   /* oxide red  — verdicts only */
```

Signal colours appear **only** on verdicts. Nowhere else. That restraint is what makes a HALT land.

### 7.3 Type

- Display: **Archivo** or **Space Grotesk**, tight tracking, heavy, used sparingly
- Body: **IBM Plex Sans**
- Evidence and data: **IBM Plex Mono**

Google Fonts, no asset pipeline at 3am. Not Inter. Everyone uses Inter.

The mono face carries the personality: all evidence renders as monospaced raw data, because the claim is measurement, not opinion.

### 7.4 Signature: two stamps, one language

**Stamp one, authorize.** Probes stream in as a staggered list showing name, raw value, tier, resolving state. When the last lands, a seal composites over the merchant card: `CLEARED` in pine with the mandate hash, or a slightly rotated `HALT` overstamp in oxide red with the failing signal named beneath.

**Stamp two, reconcile.** The mandate/reality diff renders as two monospaced columns, authorized on the left, observed on the right, mismatched fields struck through in oxide. Then `SETTLED` in pine or `BREACH` in oxide, same seal treatment.

Same visual grammar at both ends. That is what makes it feel like one product rather than two features. Nothing else on either page animates. Respect `prefers-reduced-motion` by rendering final state directly.

### 7.5 Screens (five, no more)

1. **Intent** — what to buy, ceiling. Minimal.
2. **Verification trace** — live probe stream, evidence, stamp one.
3. **Approval** — Prava passkey handoff. The scope line reads like a legal clause, not a summary.
4. **Reconciliation** — the diff, stamp two.
5. **Record** — the signed mandate and, on breach, the dispute packet. Downloadable.

### 7.6 Copy

The interface's voice is an instrument's: flat, exact, unhedged. Errors state what happened and what to do.

- Not "Oops! We couldn't verify this store." → **"Halted. Domain registered 6 days ago. Minimum is 30."**
- Not "Purchase successful!" → **"Paid $84.00 to ridge.com. Credential expired."**
- Not "Something went wrong with your order." → **"Breach. Authorized 1 unit at $84.00. Charged 12 units at $1,008.00."**

### 7.7 Transport

SSE for the probe stream. `sse-starlette` + `EventSource`. Simpler than WebSockets for one-way streaming, working in twenty minutes.

**Design note:** run probes concurrently with `asyncio.gather` and stream each as it lands. Sequential probing takes 8s and looks broken. Concurrent takes ~1.5s, and streaming it makes that 1.5s feel like the product working rather than hanging.

---

## 8. Architecture

```
backend/app/
  main.py              FastAPI, SSE probe stream
  models.py            Mandate / Outcome / Reconciliation / Session
  mandate.py           build, ed25519 sign, verify
  scoring.py           verdict(), hard-fail table
  reconcile.py         deterministic diff, dispute packet
  probes/
    base.py            Signal dataclass, timeout + failure contract
    rdap.py  ct.py  safebrowsing.py  injection.py
  services/
    prava_client.py    PORTED CLI→SDK. All Prava calls live here.
agent/
  graph.py             LangGraph state machine
frontend/src/          Vite + React + Tailwind, hand-built components
merchants/
  spoof/               storefront that fails verification
  breach/              storefront that passes, then over-delivers
docs/
  MANDATE_SPEC.md
```

**LangGraph nodes:** `resolve → fetch → probe_fanout → score → gate → {sign_mandate → session → await_approval → pay → poll_outcome → reconcile} | {halt → record}`

### 8.1 Dependencies

```
fastapi  uvicorn[standard]  sse-starlette  sqlmodel  pydantic
httpx           # async fan-out, explicit timeouts
tldextract      # correct eTLD+1, do not regex domains
selectolax      # only if you add PSP fingerprint
cryptography    # ed25519
langgraph
openai          # raw SDK, simpler than langchain-openai for structured output
```

Frontend: `vite react tailwindcss framer-motion`. Hand-build components. A component library makes it look like everyone else's, which defeats §7 entirely.

**Do not use `python-whois`.** It scrapes inconsistent WHOIS text and will break. RDAP over httpx returns clean JSON.

### 8.2 Keys

| Key | Where | Time |
|---|---|---|
| `PRAVA_SECRET_KEY` | dashboard.prava.space | minutes, **first** |
| `OPENAI_API_KEY` | have it | done |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Cloud Console | ~5 min |

No key: RDAP, crt.sh, TLS.

---

## 9. Demo

Two storefronts you host. Both labelled on screen as your own. Dressing either up as a real brand is a disqualification risk.

| Beat | Content | Time |
|---|---|---|
| Cold open | Agent **without** Warrant buys from the spoof site. Fooled. | 0:30 |
| Gate on | Same site. HALT, with the failing signal and its evidence. | 0:30 |
| Clear | Real merchant. CLEARED. Real sandbox payment. Mandate signed. | 0:45 |
| Breach | Merchant delivers 12 units against a mandate for 1. Agent detects, emits signed dispute packet. | 0:45 |
| Close | One document, three jobs. | 0:15 |

**Total 2:45.** Build the spoof merchant *before* the gate exists and film your own agent getting fooled. That footage is the cold open and it is worth more than any architecture diagram.

---

## 10. Time plan (~24h, zero slack)

| # | Block | Hrs | Exit gate |
|---|---|---|---|
| 0 | Prava sandbox key. Port `prava_client.py` CLI→SDK. One real session end to end. | 2 | **Nothing below matters until this passes. Do not proceed.** |
| 1 | Mandate: model, ed25519 sign, verify | 2 | Signed doc that verifies offline |
| 2 | Four probes, concurrent fan-out | 3 | Real signals on two real domains |
| 3 | Scoring + hard fails + gate wiring | 1.5 | HALT path cannot reach Prava, proven in code |
| 4 | Spoof merchant + breach merchant | 2 | Own agent gets fooled by spoof pre-gate |
| 5 | Reconciliation + dispute packet | 2.5 | BREACH on the breach merchant |
| 6 | LangGraph wiring, full loop | 1.5 | Intent to reconciliation, one command |
| 7 | Frontend, five screens, SSE, two stamps | 5 | Screenshots exist |
| 8 | Rehearsal, both paths, twice | 2 | Under 3 min, no terminal on camera |
| 9 | Video, README, disclosure, submit | 2 | Submitted with 2h buffer |

### 10.1 Checkpoint ladder — read this at every checkpoint

This is the safety valve that makes v2 shippable. **Check the clock, not your optimism.**

| At T-minus | If you have not finished... | Then |
|---|---|---|
| 20h | Block 0 | **Abandon Prava integration.** Ship verification only, disclose no live transaction. You will not place. Submit anyway. |
| 16h | Block 3 | Cut reconciliation entirely. Ship v1 Warrant. Recourse becomes a roadmap slide. **This is a good outcome, not a failure.** |
| 10h | Block 5 | Freeze backend. Reconciliation ships CLI-only, no UI. |
| 6h | Block 7 | Frontend ships three screens: intent, trace, record. Drop the diff view. |
| 4h | anything | Stop building. Rehearse and film with what exists. |

**An unshipped perfect product scores zero. A shipped narrow one places.**

---

## 11. Honest limits (put these in the submission)

- **Pre-existing:** LangGraph orchestration patterns and the Prava client wrapper come from TriggerBuy, built before the event. Verification, mandate, reconciliation, and UI are new. Disclose plainly. The rules permit building on existing work and punish non-disclosure.
- **Both demo storefronts are ours.** Necessary and legitimate. Labelled as such on screen.
- **Warrant produces dispute evidence. It does not file disputes.** Filing is issuer and merchant dependent. Roadmap.
- **Verification is probabilistic.** An adversary who ages a domain, passes KYB, and buys a real acquirer relationship defeats this. Warrant raises attack cost; it does not eliminate it. Say it before a judge does.
- **Reconciliation is only as rich as the outcome data available.** If Prava's result lacks line items, this reduces to amount and merchant matching.

---

## 12. Judging map

| Criterion | Answer |
|---|---|
| End-to-end functionality | Real sandbox checkout, real refusal, real breach detection. All on camera. |
| Creativity and novelty | Inverts the trust direction, then extends the same artifact into the recourse gap the industry openly calls unsolved. |
| User value and feasibility | Documented live exploitation pre-purchase; named-by-Fortune-panel unsolved liability post-purchase. |
| Prava implementation | The mandate *is* the credential scope. Not a payment button. |
| Track fit | Visa: agent-side controls plus dispute evidence. OpenAI: injection detection. Localhost: this is an SDK others would buy. |
| Product experience | Two stamps, one visual grammar |
| What happens next | Filing integration, merchant pre-clearance, trust root belongs with a network |

---

## 13. Open questions to resolve immediately

1. Does Prava CLI have a sandbox, or is SDK/API the only path? (Discord / Birdie)
2. **What exactly does the Prava checkout result return?** Line items? Quantity? SKU? This sets the ceiling on reconciliation. Highest-value unknown in v2.
3. Does a scoped session hard-decline an over-amount capture, or is there tolerance? (Test: scope $50, attempt $52.) If there is tolerance, AMOUNT_EXCEEDED becomes your most important breach type rather than a redundant one.
4. Is there actually a UX or hardware prize? It appears on neither the handbook nor the live Devfolio prize page ($73,500 across seven named partners, none of them a design award). Confirm in Discord before trading anything away for it.
