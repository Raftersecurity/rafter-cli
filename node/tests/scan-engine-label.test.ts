import { describe, it, expect } from "vitest";
import { engineLabel } from "../src/commands/agent/scan.js";

/**
 * issue #231 item 6 — `rafter secrets .` printed `(both)` for the engine
 * label with no explanation of what "both" means. The label must name the
 * two engines; single-engine values are already self-explanatory and pass
 * through unchanged.
 */
describe("engineLabel", () => {
  it("names both engines instead of the bare word 'both'", () => {
    const label = engineLabel("both");
    expect(label).toContain("betterleaks");
    expect(label).toContain("patterns");
    expect(label).not.toBe("both");
  });

  it("leaves single-engine values unchanged", () => {
    expect(engineLabel("betterleaks")).toBe("betterleaks");
    expect(engineLabel("patterns")).toBe("patterns");
  });
});
