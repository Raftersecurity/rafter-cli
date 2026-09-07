/**
 * Tests for command_policy.allowedPatterns — the positive allowlist.
 *
 * The feature exists so a known-safe command that trips a broad risk tier can
 * be exempted without lowering the global risk level. Requested by a paying
 * customer whose `git push --force-with-lease` to a feature branch prompted on
 * every push, on a repo whose main is protected server-side so a force-push
 * there cannot land.
 *
 * An allowlist on a guard rail is a footgun, so the SAFETY PROPERTIES are the
 * point of this file, not the happy path:
 *   1. blockedPatterns always wins over allowedPatterns.
 *   2. a `critical` command is never allowlistable.
 *   3. a match does not apply when the command contains a chain operator,
 *      so "^git push" cannot wave through `rm -rf / && git push`.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CommandInterceptor } from "../src/core/command-interceptor.js";

function stubPolicy(interceptor: CommandInterceptor, policy: {
  mode?: string;
  blockedPatterns?: string[];
  requireApproval?: string[];
  allowedPatterns?: string[];
}) {
  const cfg: any = {
    agent: { commandPolicy: {
      mode: policy.mode ?? "approve-dangerous",
      blockedPatterns: policy.blockedPatterns ?? [],
      requireApproval: policy.requireApproval ?? [],
      allowedPatterns: policy.allowedPatterns ?? [],
    }},
  };
  vi.spyOn((interceptor as any).config, "loadWithPolicy").mockReturnValue(cfg);
}

describe("CommandInterceptor — allowedPatterns", () => {
  let interceptor: CommandInterceptor;
  beforeEach(() => { interceptor = new CommandInterceptor(); });

  // ── The motivating case ────────────────────────────────────────────

  it("exempts the customer's force-with-lease push from the approval prompt", () => {
    stubPolicy(interceptor, { allowedPatterns: ["git push --force-with-lease"] });
    const r = interceptor.evaluate("git push --force-with-lease origin feature/x");
    expect(r.allowed).toBe(true);
    expect(r.requiresApproval).toBe(false);
    expect(r.riskLevel).toBe("low");
    expect(r.matchedPattern).toBe("git push --force-with-lease");
  });

  it("leaves an unmatched command classified as before", () => {
    stubPolicy(interceptor, { allowedPatterns: ["git push --force-with-lease"] });
    const r = interceptor.evaluate("sudo rm -rf /var/log");
    expect(r.allowed).toBe(false);
  });

  it("does nothing when the allowlist is empty or absent", () => {
    stubPolicy(interceptor, { allowedPatterns: [] });
    const empty = interceptor.evaluate("git push --force-with-lease origin feature/x");
    stubPolicy(interceptor, {});
    const absent = interceptor.evaluate("git push --force-with-lease origin feature/x");
    expect(empty.requiresApproval).toBe(absent.requiresApproval);
  });

  // ── Property 1: a deny rule always wins ────────────────────────────

  it("never re-opens a command closed by blockedPatterns", () => {
    stubPolicy(interceptor, {
      blockedPatterns: ["git push"],
      allowedPatterns: ["git push --force-with-lease"],
    });
    const r = interceptor.evaluate("git push --force-with-lease origin feature/x");
    expect(r.allowed).toBe(false);
    expect(r.reason).toContain("blocked pattern");
  });

  // ── Property 2: critical is never allowlistable ────────────────────

  it("refuses to allow a critical command even on an exact match", () => {
    stubPolicy(interceptor, { allowedPatterns: ["rm -rf /"] });
    const r = interceptor.evaluate("rm -rf /");
    expect(r.allowed).toBe(false);
  });

  // ── Property 3: chain operators disqualify the match ───────────────

  // The property this guard owns is "the allowlist does not apply", NOT "the
  // classifier rates this high" -- so assert parity with the same command
  // evaluated under no allowlist at all. A chained command must be treated
  // exactly as it would be if the operator had never configured one.
  //
  // (Asserting riskLevel !== "low" directly would fail on `git push | sh`,
  // because the BASELINE classifier already rates that low with no allowlist
  // in play. That is a real pre-existing gap in risk-rules.ts -- piping to a
  // shell is only caught for `curl`-shaped commands -- and it is tracked
  // separately. It is not something this feature introduced or can fix.)
  it("does not let an allowlisted prefix smuggle a chained command", () => {
    const chained = [
      "rm -rf / && git push",
      "git push; sudo shutdown now",
      "git push | sh",
    ];

    stubPolicy(interceptor, { allowedPatterns: [] });
    const baseline = chained.map((c) => interceptor.evaluate(c));

    stubPolicy(interceptor, { allowedPatterns: ["git push"] });
    const withAllowlist = chained.map((c) => interceptor.evaluate(c));

    chained.forEach((cmd, i) => {
      expect(withAllowlist[i].riskLevel, cmd).toBe(baseline[i].riskLevel);
      expect(withAllowlist[i].allowed, cmd).toBe(baseline[i].allowed);
      expect(withAllowlist[i].requiresApproval, cmd).toBe(baseline[i].requiresApproval);
      // and crucially, the allowlist is never credited for the verdict
      expect(withAllowlist[i].reason ?? "", cmd).not.toContain("allowed pattern");
    });
  });

  it("still exempts the same pattern when no chaining is present", () => {
    stubPolicy(interceptor, { allowedPatterns: ["git push"] });
    expect(interceptor.evaluate("git push origin main").riskLevel).toBe("low");
  });

  // ── Ordering against requireApproval ───────────────────────────────

  it("wins over requireApproval, which is the whole point", () => {
    stubPolicy(interceptor, {
      requireApproval: ["git push"],
      allowedPatterns: ["git push --force-with-lease"],
    });
    const allowed = interceptor.evaluate("git push --force-with-lease origin feature/x");
    expect(allowed.requiresApproval).toBe(false);
    const prompted = interceptor.evaluate("git push --force origin main");
    expect(prompted.requiresApproval).toBe(true);
  });

  // ── Robustness ─────────────────────────────────────────────────────

  it("does not throw on an invalid regex in the allowlist", () => {
    stubPolicy(interceptor, { allowedPatterns: ["[unclosed"] });
    expect(() => interceptor.evaluate("git push origin main")).not.toThrow();
  });
});
