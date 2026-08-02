# Warrant — founder brief

Plain-English answers for Discord, judges, friends. Source: `WARRANT_PRD_v2.md`. Nothing invented.

---

**1. What is it?**
A signed proof that an AI shopping agent verified the merchant *before* it could spend, and can prove exactly what was authorized when something goes wrong after.

**2. What are we building?** (hackathon ship)
End-to-end loop: resolve merchant → run verification probes → hard gate (HALT = no Prava session) → ed25519-signed Warrant → Prava sandbox checkout scoped to that Warrant → deterministic reconcile (SETTLED / BREACH) → signed dispute packet on breach. Five-screen instrument UI (intent, live verification trace, passkey approval, mandate/reality diff, downloadable record). Demo: spoof site HALT, real merchant CLEARED + pay, breach merchant → dispute packet.

**3. Agent or web app?**
Both, different jobs. The **agent / orchestration** does the buying loop (intent → verify → pay → reconcile). The **web UI** is the instrument: live probe stream, CLEARED/HALT and SETTLED/BREACH stamps, evidence you can show a judge. Prava is the payment rail (scoped session + passkey), not the product.

**4. Main task**
Only spend where we verified — and keep a signed, checkable record of what was agreed so reality can be diffed against it.

**5. What’s special?**
Trust runs the other way: Visa TAP / merchant-side agent auth help merchants identify agents; Warrant helps the *agent* identify the *merchant*, and blocks the credential until that passes. Vs plain Prava checkout: payment is gated by verification, scoped by the same signed artifact, then that artifact becomes dispute evidence. One document, three jobs — not a payment button with a score bolted on.

**6. What it tries to solve**
- **Pre-purchase:** Agents get fooled by counterfeit / injection-shaped storefronts; nothing in the stack lets the agent refuse a bad merchant before a credential exists.
- **Post-purchase:** Agents can buy but can’t un-buy; when amount, merchant, or item diverges from intent, there’s no portable, signed evidence of what was authorized. Warrant bridges both: verification makes the scope trustworthy; the signed scope makes recourse possible.

**7. Who for / threat model**
For a **buyer using an AI shopping agent**. Defends against: counterfeit merchants engineered for agents, prompt/injection tricks that steer checkout, and post-pay mismatches (wrong amount, merchant, SKU/qty, non-delivery) relative to what was signed. Not a merchant trust badge product.

**8. One-sentence pitch**
*An agent should only spend where it verified — and prove exactly what it agreed to when reality doesn’t match.*

**9. Honest limits** (PRD §11)
- Produces dispute **evidence**; does **not** file returns/chargebacks.
- Verification is **probabilistic** — raises attack cost; a determined adversary with aged domain + real acquirer can still defeat it.
- Reconciliation is only as rich as Prava’s outcome data (may shrink to amount + merchant).

---

### Glossary
| Term | Meaning |
|---|---|
| **Warrant** | *Our* ed25519-signed document: verification + spend scope + (on breach) dispute chain. PRD sometimes says “mandate”; code/docs say **warrant**. |
| **Prava mandate** | *Their* spend-authorization primitive inside Prava. Different thing — do not conflate names. |
