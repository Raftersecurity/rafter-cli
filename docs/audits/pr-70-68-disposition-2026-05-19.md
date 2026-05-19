# Disposition: closed PRs #70 (rf-v85b) and #68 (rf-93jx)

**Date:** 2026-05-19
**Bead:** sable-dhj (maylist B4)

Both PRs were closed by Rome 2026-04-30 with the reason "shouldn't have ended up in the repo." The closure rejected the **audit documents themselves** as repo content; the **findings inside** them were meant to be triaged into actionable beads and concrete fixes. This doc records where each landed.

## PR #70 — `docs(review): consumer-perspective OS code review (rf-v85b)`

The closed PR added `docs/reviews/consumer-perspective-2026-04-27.md`. That file is NOT in main. It contained a consumer-perspective P0 review with three named findings (P0-1, P0-2, P0-3) plus secondary observations.

| Finding | Bead | Status |
|---|---|---|
| P0-1 `agent init --all` is high-blast-radius; no `--dry-run`, no uninstall, SHA256 buried | sable-b74 | CLOSED — PR #98 shipped `--dry-run`; PR #110 surfaced SHA256 + quickstart soften + verify hint; PR #116 (sable-3ep) shipped `rafter agent uninstall` |
| P0-2 README badge URL points at wrong repo | sable-vcx | CLOSED — PR #109 + sable-vcx |
| P0-3 Pre-commit `rev:` pins drifted | sable-vcx | CLOSED — same PR + drift guard in `validate-release.yml` |
| Quickstart writes `.env` in cwd (destructive) | sable-jqo | CLOSED — PR #130 scratch-dir wrap |
| Quickstart agent-tool prerequisite undocumented | sable-cu4 | CLOSED — PR #114 |
| 21+ patterns framing too vague; `--agent` flag is confusing | sable-1mr | OPEN |
| `rafter scan local` vs `rafter agent scan` naming collision | sable-8vh | OPEN |

**Salvaged: 5 of 7 findings shipped; 2 remain as open beads.** The audit doc itself stays unmerged per Rome's intent.

## PR #68 — `docs: documentation quality audit + platform integration tests (rf-93jx)`

The closed PR added two artifacts:
- `docs/audit-docs-quality-2026-04-27.md` — NOT in main (rejected by Rome).
- `node/tests/platform-integration.test.ts` — **IS in main**. At HEAD on maylist the file is 1,734 lines (started at +480 in #68; grown via subsequent PRs).

So the **test suite** from PR #68 shipped via a different landing; only the audit doc was rejected. The audit's underlying findings (docs accuracy items, platform-coverage gaps) were rolled into the broader maylist follow-ups:
- README accuracy audit + restructure → sable-mnp / PR #123
- Platform parity audit re-run → sable-2vz / PR #132 (+ 7 gap beads)

**Salvaged: test suite in production; audit-driven fixes shipped as part of mnp + 2vz.**

## Conclusion

sable-dhj (B4) is resolved. Both closed PRs produced lasting value through child beads and (for #68) a surviving test file. The audit docs themselves remain unmerged, which is what Rome asked for. No further action.
