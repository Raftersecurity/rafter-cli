import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { assessCommandRisk, modifiesRafterSecurityConfig } from "../src/core/risk-rules.js";

/**
 * sable-36oe: a shell command that writes into rafter's own dir (~/.rafter)
 * disarms the gate as surely as `rafter agent config set agent.hooks.enabled
 * false` (rf-vnxs). Each protected case is paired with a benign twin, so the
 * table fails if the rule stops catching the write OR starts blocking the read.
 *
 * The battery JSON is shared byte-for-byte with the Python suite
 * (python/tests/test_risk_rules_rafter_dir.py).
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const batteryPath = path.resolve(here, "../../sable-36oe-rafter-dir-battery.json");
const battery: Array<{ label: string; cmd: string; protected: boolean }> = JSON.parse(
  readFileSync(batteryPath, "utf8"),
);

describe("sable-36oe: shell writes into the rafter dir are protected", () => {
  it.each(battery)("$label", ({ cmd, protected: want }) => {
    expect(modifiesRafterSecurityConfig(cmd)).toBe(want);
    if (want) expect(assessCommandRisk(cmd)).toBe("critical");
  });

  // Fails if the scan goes superlinear: ~500 KB of `.rafter/` and `cat `
  // fragments, the shapes the component and glob walks touch.
  it("classifies a ~500 KB adversarial command quickly", () => {
    const cmd = "cat ~/.rafter/" + "a.rafter/.raf*[/.rafter/cat ".repeat(18000) + "| tee ~/.rafter/config.json";
    expect(cmd.length).toBeGreaterThan(500_000);
    const t0 = performance.now();
    expect(modifiesRafterSecurityConfig(cmd)).toBe(true);
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});
