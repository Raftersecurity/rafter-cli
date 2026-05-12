# SLB — Research Analysis
**Date:** 2026-05-12 | **Author:** polecat pearl | **Bead:** sable-tws

---

## What slb Is

[slb (Simultaneous Launch Button)](https://github.com/Dicklesworthstone/slb) is a Go CLI
implementing a **two-person rule** for AI coding agents. When an agent wants to run a
high-risk command, slb blocks execution and routes the request to a second reviewer (human
or another agent) for explicit approval before anything runs.

**Core flow:**
1. Agent calls `slb run "rm -rf ./build" --reason "..."` instead of running directly
2. slb classifies the command by risk tier and emits a request
3. A second agent (or human) runs `slb approve <id>` after reviewing
4. The original command executes only after approval

**Risk tiers** (maps closely to Rafter's existing 4-tier model):

| Tier | Approvals required | Examples |
|------|--------------------|---------|
| CRITICAL | 2+ | `rm -rf /`, `DROP DATABASE`, `terraform destroy`, `git push --force` |
| DANGEROUS | 1 | `rm -rf ./build`, `git reset --hard`, `DROP TABLE` |
| CAUTION | 0 (auto after 30s) | single file delete, `git branch -d` |
| SAFE | 0 (immediate) | `rm *.log`, `git stash`, cache clean |

**Infrastructure:** SQLite state DB at `.slb/state.db`, background daemon, TUI dashboard,
MCP Agent Mail integration, JSON output on every command, full audit history with search.

---

## Why It's Interesting for Rafter

Rafter already owns two adjacent capabilities:

1. **`command-interceptor.ts`** — classifies commands into 4 tiers and enforces policy
   (allow / block / warn) based on `.rafter.yml` rules.
2. **`rafter hook pretool`** — Claude Code pre-tool hook that intercepts Bash calls before
   execution and surfaces risk via the MCP `evaluate_command` tool.

The gap Rafter doesn't cover: **what happens when blocking isn't the right answer**.

Today Rafter's hook choices are binary — allow or block. Many teams need a middle option:
*"don't block this, but don't run it solo either — get a second pair of eyes first."* That
is exactly what slb provides. slb's model is also **multi-agent aware**: approvers can be
other Claude instances (different models for diversity of judgement), not just humans.

Concrete user pain slb solves that Rafter does not:
- A single agent runs a destructive command at 2 AM; no human is awake to catch it.
- Two agents work the same repo; either could force-push and overwrite the other's work.
- Compliance teams want an audit trail with a human sign-off, not just a block log.

---

## What Concrete Adoption Would Look Like

### Option A — Rafter wraps slb as a backend (thin integration, low risk)

Add a new hook action `require-approval` alongside today's `allow` / `block`:

```yaml
# .rafter.yml
hooks:
  pretool:
    - pattern: "rm -rf"
      action: require-approval      # new action
      via: slb                       # delegate to slb
      reason: "Destructive delete — needs peer review"
```

When the hook fires and the action is `require-approval`, `rafter hook pretool` shells out
to `slb run "<cmd>" --reason "..."` and inherits slb's blocking/approval loop. Rafter owns
classification; slb owns the approval workflow. Net-new code: ~100 lines in
`command-interceptor.ts` + a matching Python implementation.

**Pros:** No duplication, slb handles the hard parts (SQLite, TUI, daemon).
**Cons:** Adds a binary dependency users must install separately; breaks offline use.

### Option B — Rafter ships its own approval queue (full ownership, more scope)

Extend the MCP server with two new tools:

- `request_approval(command, reason, tier)` → returns a `request_id`, blocks
- `approve_command(request_id, reviewer_session)` → unblocks the waiter

State lives in a lightweight file or SQLite at `.rafter/approvals.db`. Agents on the same
project connect to the same file. This mirrors slb's architecture but uses Rafter's existing
audit logger and MCP transport. Estimated scope: ~2–3 days per implementation (Node + Python),
plus tests.

**Pros:** Zero extra dependency, single tool, integrates with existing audit trail.
**Cons:** Re-implementing what slb already does well; maintenance burden.

### Option C — Document slb as a recommended companion (no code, minimal effort)

Add slb to the Rafter docs as a companion tool:
- `rafter agent init --with-slb` installs slb alongside Rafter
- Recipe at `recipes/slb.md` shows the combined `.rafter.yml` + `.slb/config.toml` setup
- README callout: "For two-person-rule enforcement, see slb"

**Pros:** Zero code. Delivers value today. Keeps Rafter's scope tight.
**Cons:** Fragmented UX; users must manage two tools.

---

## Recommendation: **Option C now, Option A later**

**Now (zero-code):** Document slb as a companion in `recipes/slb.md` and add a one-line
mention in the README alongside the existing hook documentation. This costs ~30 minutes and
delivers value immediately for teams that want the two-person rule.

**Later (if demand materialises):** Option A (Rafter wraps slb via `require-approval`
hook action) is the right long-term path. It keeps Rafter as the single configuration
surface, avoids re-implementing slb's approval loop, and adds no net maintenance burden
beyond the integration shim. Gate this on user requests — the two-person rule is a
governance/compliance feature; not every Rafter user needs it.

**Do not build Option B.** slb already exists, is MIT-licensed, and does the job well.
Duplicating it inside Rafter without a strong reason would waste effort and create a
maintenance burden.

---

## Actionable Follow-ups

- `slb-recipe` bead: Write `recipes/slb.md` companion setup guide (Option C, ~30 min)
- `slb-hook-action` bead: Design `require-approval` hook action for Option A integration
  (gate on user demand; file as `deferred` until 2+ user requests)
