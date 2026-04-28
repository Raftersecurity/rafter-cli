# AI-Generation Quality Audit — rafter CLI

**Bead:** rf-wt1k
**Reviewer:** raftercli/polecats/quartz
**Scope:** Open-source rafter CLI (`node/src/`, `python/rafter_cli/`, tests, docs)
**Date:** 2026-04-28
**Methodology:** Walk codebase for canonical low-quality AI-generated code smells, cross-reference suspect files with git blame, run a critic pass to separate style preference from quality issues.

---

## TL;DR

The rafter codebase is **substantially AI-assisted** — 303 of 481 commits (≈63%) carry an explicit `Co-Authored-By: Claude` trailer. Despite that, the code does **not** read as low-quality LLM output. Comments are why-focused, no aspirational docstrings, no `NotImplementedError` placeholders, no AI-tell phrases ("as requested," "let me know if"), no mixed naming conventions, and no marketing-style aspirational text in source files.

The few real findings are **localized**:

- A small cluster of **pointless wrapper methods** in `regex_scanner.py` and `secret_patterns.py` / `secret-patterns.ts`.
- One file (`notify.py`) **mixes `urllib` and `requests`** for HTTP without obvious reason.
- The Node platform-integration test file is **structural copy-paste across 6 platforms** — refactor opportunity, not a quality bug.
- Two **redundant defensive checks** in TS and Python.

Nothing in the HIGH-CONFIDENCE bucket. Most findings sit in PATTERNS where a human should glance once and move on. The FALSE-ALARMS-AVOIDED list is much longer than the findings list — that is the headline.

---

## HIGH-CONFIDENCE AI tells (likely truly low-quality)

**None.**

Pre-critic, the strongest candidate was the wrapper-method cluster in `regex_scanner.py:82-89`. After re-reading, the wrappers form a deliberate (if thin) public-facade over an internal `_engine` — annoying but defensible as encapsulation. Promoted to PATTERNS, not HIGH-CONFIDENCE.

This bucket being empty is the most important finding of this audit: the codebase has been groomed.

---

## PATTERNS (worth a human glance)

### P1. Triple thin-wrapper facade in `regex_scanner.py`

`python/rafter_cli/scanners/regex_scanner.py:82-89` exposes three one-liners that pure-delegate to a private `_engine`:

```python
def scan_text(self, text: str) -> list[PatternMatch]:
    return self._engine.scan(text)
def redact(self, text: str) -> str:
    return self._engine.redact_text(text)
def has_secrets(self, text: str) -> bool:
    return self._engine.has_matches(text)
```

If `RegexScanner` is the public-API class and `_engine` is the implementation, this is a textbook facade. If callers reach for `_engine` anyway (worth a `grep`), then these methods are dead weight. Spot-check `grep -rn "_engine" python/rafter_cli/` to decide.

### P2. `getCriticalPatterns` / `get_critical_patterns` shortcut

`node/src/scanners/secret-patterns.ts:167` and `python/rafter_cli/scanners/secret_patterns.py:151` each define a one-liner that calls `getPatternsBySeverity("critical")`. Mild AI smell — convenience is fine, but the same shortcut isn't given to "high" or "medium". That asymmetry hints the code was generated reactively rather than designed.

### P3. `notify.py` mixes `urllib` and `requests` in one file

`python/rafter_cli/commands/notify.py:7` imports `urllib.request` at module level (used in `_post_webhook`, line 290), then `_fetch_scan` at line 309 lazy-imports `requests` and uses it for the backend GET. There's a defensible reading (urllib for unauth webhooks, requests for backend with headers/params), but the rest of the project is split: `backend.py` uses `requests` only, `audit_logger.py` uses `urllib` only. Mixing both inside one file is the inconsistency. Pick one and stick to it.

### P4. Confusing double-negation in `skill/review.ts`

`node/src/commands/skill/review.ts:846`:

```ts
if (!resolvedVersion || !(!opts.noCache && contentIsUsable(cacheRoot, probeKey(resolvedVersion)))) {
```

De Morgan it: `!resolvedVersion || opts.noCache || !contentIsUsable(...)`. The current shape is correct but reads like the LLM was negating its way to a cache-fall-through condition rather than thinking it through. Refactor for legibility.

### P5. Redundant null check in `agent_components.py`

`python/rafter_cli/commands/agent_components.py:961` defines `config_enabled` as `config_entry.get("enabled") if isinstance(...) else installed`. Line 977 then guards `bool(config_enabled) if config_enabled is not None else installed`. In the `else` branch of line 961, `installed` is a bool — never `None`. The `is not None` guard is partially redundant. Tighten or remove.

### P6. Per-platform test duplication

`node/tests/platform-integration.test.ts` and `python/tests/test_agent_init.py` repeat near-identical describe/class blocks per platform (Cursor, Windsurf, Aider, Gemini, Continue, Claude Code). Each block tests "creates from scratch / preserves existing settings / idempotent / corrupted JSON recovery" with only path strings differing. This **is** a real refactor opportunity (table-driven tests / parametrize), but it's not strictly a quality bug — each platform's install path is genuinely different and explicit duplication arguably helps future-debugging.

### P7. Shallow assertions in `github-action.test.ts`

`node/tests/github-action.test.ts:64-68` asserts only `expect(action.name).toBeTruthy()` etc. on `action.yml` metadata — checks fields exist, not content. Marginal. Either remove or assert specific values.

---

## FALSE-ALARMS-AVOIDED (considered, ruled out)

These were initially flagged, then dismissed after closer reading. Listed because they are exactly the kinds of patterns a fast-pass scan over-flags:

- **`handleScopeError` in `node/src/utils/api.ts:38`** — explicitly `@deprecated` back-compat alias. Intentional.
- **`isAgentMode` in `node/src/utils/formatter.ts:9`** — module-state getter; pairs with `setAgentMode`. Encapsulation, not a wrapper smell.
- **`is_available()` in `python/rafter_cli/scanners/gitleaks.py:39`** — public-property convenience over a structured `check()` result. Reasonable.
- **`_resolve_skill` in `python/rafter_cli/commands/skill.py:113`** — adds `.strip()`. Not a pure wrapper; legitimate adaptation.
- **`tool_response?.output` in `node/src/commands/hook/posttool.ts:136,139`** — `tool_response` is parsed JSON from an external Claude Code hook payload. Optional chaining at a trust boundary is correct, not over-defensive.
- **The `else` block in `skill/review.ts:780-803`** — initially flagged as a dead branch. On closer reading, the two inner `if (!opts.noCache)` and `if (opts.noCache)` are sequential but mutually exclusive in execution path; both branches are reachable depending on `opts.noCache`. Logic is correct, just complex.
- **"powerful" / "seamless" in `instruction-block.ts` and `README.md`** — these strings are user-facing marketing copy in the agent instruction block, not in-source aspirational documentation. Tone choice, not a code-quality issue.
- **"comprehensive" in test-file headers** (`error-handling-gauntlet.test.ts`) — describes actual scope. Appropriate.
- **JSDoc/docstrings throughout** — checked a sample; comments explain *why* (e.g., `audit-logger.ts:27` on IPv6 brackets, `command-interceptor.ts:42` on blocked-pattern context). No "would do," "as requested," "feel free to" phrasing found.
- **Generic identifier names like `data`** — every occurrence inspected was in a JSON-parse / encode context where `data` is appropriate.
- **Imports** — no unused imports, no AI-hallucinated package names, no duplicate-purpose imports outside P3.
- **Try/catch hygiene** — no empty handlers, no re-raise-as-same patterns, no try around uncatchable code.
- **`NotImplementedError` / `TODO: implement`** — zero occurrences in shipped code.
- **Mixed naming conventions** — none. TS uses camelCase + PascalCase per convention; Python uses snake_case per PEP 8.

---

## Provenance correlation (git blame)

Spot-checked: all P1–P5 findings live in files with `Co-Authored-By: Claude` history. So does virtually every other file in the repo, so this is signal-poor. Authorship is not the discriminator here — quality is — and quality is high.

---

## Recommendation

The author asked us to find "AI-generated in a bad way." The honest answer is **we did not find much**. The codebase has been groomed and reviewed. The few findings above are routine cleanup, not red flags.

**Suggested follow-ups (file as separate beads if desired):**

1. Decide whether the `regex_scanner.py` thin-wrappers serve callers or should be removed (P1).
2. Pick one HTTP library inside `notify.py` (P3).
3. Refactor the double-negation at `skill/review.ts:846` for legibility (P4).
4. Tighten the redundant `is not None` in `agent_components.py:977` (P5).
5. Consider parametrizing the per-platform test duplication if the suite grows (P6).

Do **not** create a sweep PR — these are genuinely small. Pick them up opportunistically when the surrounding code is being touched.

---

## Critic B self-review

Did this report confuse style preferences with quality issues?

- **Style-as-quality risk**: P4 (double-negation) and P7 (shallow assertions) sit on the line. Both are flagged as PATTERNS, not HIGH-CONFIDENCE — appropriate.
- **Quality-as-style risk**: HIGH-CONFIDENCE bucket is empty rather than padded. Resisted the temptation to promote P1 or P3 just to have content there.
- **Provenance bias**: The 63% Claude-coauthor rate could have biased the audit toward finding more. Counter-balanced by the long FALSE-ALARMS-AVOIDED list, which documents the patterns we explicitly chose not to flag.
- **Tone**: Findings describe code, not authorship. No blame attached.

Verdict: report is calibrated. The AI-generated "bad way" hypothesis is **not supported** by the evidence in this codebase.
