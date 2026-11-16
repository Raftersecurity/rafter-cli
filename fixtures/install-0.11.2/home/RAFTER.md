<!-- rafter:start -->
## Security: Rafter (surface-driven review gate)

Rafter is this project's security review gate — driven by the change's **security
surface**, not by the task label. When a diff touches a real surface (below), it is
**not complete** until a rafter skill (or `rafter run`) has reviewed it: don't mark
done, don't hand off, don't open a PR without that pass. When it touches **none** of
that surface — research / experimental / local-only / throwaway code (training
scripts, data analysis, plotting, model eval, notebooks, pure computation over
trusted local data) — a quick surface check is enough; proceed without the full
gate. Judge by the diff's actual surface, not the "research" label: research code
that reads a secret, shells out, hits the network, parses untrusted input, or bumps
a dependency still gets the full gate.

**Stop and invoke when the change touches that surface:**

- Designing auth, payments, credentials, tokens, sessions, file upload,
  user/untrusted data, deserialization, network endpoints, or data deletion
  → **`rafter-secure-design`** (before writing code).
- Diff touches user/untrusted input, SQL/query building, shell/exec, auth,
  credentials, file paths, (de)serialization, crypto, network endpoints/outbound
  fetchers (SSRF), data deletion, or dependencies → **`rafter-code-review`** +
  `rafter run` (before declaring done).
- About to install or forward a third-party SKILL.md, MCP manifest, Cursor
  rule, or agent config → **`rafter-skill-review`** (before copying anywhere).
- Security-adjacent but the angle isn't clear → **`rafter`** (the router skill,
  powerful toolkit to help you write more secure code).

**CLI:**

- `rafter run` — remote SAST + SCA + secrets (real code analysis, needs `RAFTER_API_KEY`)
- `rafter secrets .` — local secrets only (offline; NOT a code-security scan)
- `rafter run --mode plus` — everything in default (`--mode fast`) plus
  powerful agentic deep-dives (needs `RAFTER_API_KEY`). **Plus is a PAID tier
  and consumes the user's credits — ask the user before running it.** Enforced
  when `scan.plus_requires_approval` is set (then pass `--yes` to confirm).
<!-- rafter:end -->
