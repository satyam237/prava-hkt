# Project agent memory

- Project scope: Warrant is a merchant-verification layer for agentic commerce; see `README.md` for the overview, `docs/README.md` for navigation, and `docs/WARRANT_PRD.md` for product intent.
- Verification source of truth: `docs/VERIFICATION.md` overrides the PRD wherever they conflict. Read it before planning or implementing.
- Repository maturity: documentation-only for now. Treat anything not covered by the PRD plus verification report as undecided rather than inventing it from context.
- Refuted/blocked facts to preserve: Prava CLI has no sandbox and uses live cards; multi-merchant Prava sessions are unsupported; `create_session(merchant, amount)` is under-specified; UCP `request-signature` and `UCP-Agent` fingerprint semantics are refuted; `payment_handlers` are specs, not acquirer proof; crt.sh cannot be a reliable 2s dependency; Tranco direct file is ZIP/CSV; no reviewed primary source supports SEA availability.
- Mandatory build rules from verification: no invented API shapes; no mock payment presented as real; hard 2-second probe timeout; exclude `UNAVAILABLE` from scoring denominators; run hard-fail short circuits before weighted scoring; use RDAP over HTTP/JSON instead of `python-whois`; add no dependency without approved documentation verification.
- Open blockers are tracked in `docs/VERIFICATION.md`: Prava sandbox keys, passkey-capable browser, Google Safe Browsing API key/quota, authorized sandbox merchant, UCP source/version and live-good endpoint, CT reliability plan, and library API docs verification.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
