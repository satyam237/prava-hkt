# Warrant

Warrant is a merchant-verification gate for agentic commerce. Visa's Trusted Agent Protocol and related agentic-commerce infrastructure help merchants decide whether an agent is legitimate. Warrant inverts the missing side: before an agent receives a payment credential, the merchant must be verified for the buyer's agent.

The product idea is simple: **no verification, no credential**. A PASS result may create a scoped Prava payment session for the verified merchant and amount. A HALT result stops before any Prava session request, so there is no card credential for the agent or a counterfeit storefront to misuse.

## Why it matters

The PRD records the asymmetry and the threat model: agentic browsers and shopping agents can be steered toward counterfeit storefronts or manipulated by indirect prompt injection. It cites public exploitation examples from Guardio Labs, F-Secure, Palo Alto Unit 42, and Visa's own warning that AI shopping agents can be deceived by sophisticated counterfeit merchants.

Warrant's answer is not another merchant-side bot credential. It is an agent-side preflight check that ties payment credential issuance to merchant evidence.

## Current repository state

This repository is documentation-only today. There is no application implementation yet. The product direction lives in the PRD, but a Phase 1 verification pass found several PRD assumptions that were wrong or unverified.

Start with these documents before building:

- [docs/VERIFICATION.md](docs/VERIFICATION.md) — required findings; overrides the PRD wherever they conflict.
- [docs/WARRANT_PRD.md](docs/WARRANT_PRD.md) — product requirements and build spec, with some assumptions corrected by verification.
- [docs/README.md](docs/README.md) — documentation index.

## Critical verified corrections

Do not build from the PRD alone. The verification report records that the Prava CLI has no sandbox and uses live cards; multi-merchant sessions are unsupported; the simplified `create_session(merchant, amount)` shape is under-specified; UCP `request-signature`, `UCP-Agent` fingerprint semantics, and `payment_handlers` as acquirer proof are refuted; crt.sh did not satisfy the 2-second probe budget; Tranco ships as ZIP/CSV; and no reviewed primary Prava source supports SEA availability.

## Where to go next

1. Read [docs/VERIFICATION.md](docs/VERIFICATION.md) and keep its mandatory implementation rules in force.
2. Use [docs/WARRANT_PRD.md](docs/WARRANT_PRD.md) for product intent and demo shape only after applying verified corrections.
3. Resolve the documented blockers before implementation: Prava sandbox keys, passkey-capable browser, Google Safe Browsing API key, authorized sandbox merchant, UCP source/version, CT reliability plan, and library API documentation verification.
