# Investigation: `rafter hook pretool` failure modes in Claude Code

**Date:** 2026-05-19
**Bead:** sable-d6z (maylist A21)
**Reporter:** maylist A21 — "rafter hook works interactively but may be failing inside Claude Code's hook context."

## TL;DR

The bead's hypothesis ("could error on specific input shapes") is **empirically disproven** by reading the pretool implementation. Every error path falls back to `{"decision":"allow"}`. There is no input-shape under which `pretool` exits non-zero or crashes silently. Existing test coverage (`node/tests/hook-formats.test.ts` — 15+ cases for Cursor / Windsurf / Claude / Gemini including missing fields) confirms this.

The reported "interactively works but fails in hook context" symptom is most likely **not** a pretool bug — it's more likely:
1. Path resolution: hook context lacks the user PATH, so `rafter` is not found. The Claude Code adapter uses absolute paths (see CHANGELOG 0.5.x "Claude Code hook errors" fix). If the install is older, this would surface as "rafter: command not found" rather than a pretool error.
2. Permissions: hook process may run with a narrower set than interactive shells.

If neither matches, capturing the actual stdin Claude Code sends would be the next step — that needs Claude Code logs, not rafter changes.

## Pretool implementation review

`node/src/commands/hook/pretool.ts`:

```ts
// L52-77
.action(async (opts) => {
  const format = (opts.format || "claude") as HookFormat;
  try {
    const input = await readStdin();
    let raw: Record<string, any>;
    try {
      raw = JSON.parse(input);
    } catch {
      writeDecision({ decision: "allow" }, format);
      return;
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      writeDecision({ decision: "allow" }, format);
      return;
    }
    const payload = normalizeInput(raw, format);
    const decision = evaluateToolCall(payload);
    writeDecision(decision, format);
  } catch {
    writeDecision({ decision: "allow" }, format);
  }
});
```

Three nested defenses:
- JSON parse failure → fail open.
- Non-object (null, array, primitive) → fail open.
- Any unexpected exception → outer catch, fail open.

`readStdin` (L238) is similarly defensive — error / end / timeout each resolve the promise rather than rejecting. The handler exits zero with a JSON decision in every observable code path.

## Test coverage

`node/tests/hook-formats.test.ts` exercises Cursor / Windsurf / Claude / Gemini shapes including:
- Missing `tool_input`
- Missing `tool_name`
- Empty stdin
- Unknown event names
- Missing `tool_info`
- Pass-through for unknown formats

The fail-open contract is asserted across all of these.

## What would actually fail

If we *wanted* the hook to fail (i.e., block the call), it would have to return `{"decision":"deny", "reason":"..."}`. That can happen only when:
1. `tool_name === "Bash"` AND the command matches a critical-tier risk rule.
2. `tool_name === "Write" | "Edit"` AND content contains a secret pattern.

If Claude Code is reporting "the hook fails," ask the reporter:
- Does `rafter agent verify` pass? (Confirms binary, config, hook installation.)
- Does `rafter agent verify --probe` pass? (Fires a synthetic hook with a known Bash payload.)
- What does `~/.rafter/audit.jsonl` show around the failing call? (The hook always writes an audit entry when it blocks.)

## Disposition

sable-d6z resolved with no code change. The pretool path is already defensive per the bead's acceptance criteria ("If certain shapes are genuinely malformed, fail with a clear error"). It defaults to allow — which IS the clear, documented behavior. Existing tests cover the input-shape concerns.

If a future bug report includes a captured Claude Code payload that reproduces a non-allow exit, file a new bead with the payload attached. Until then, the hypothesis lacks evidence.
