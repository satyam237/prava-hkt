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

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |
