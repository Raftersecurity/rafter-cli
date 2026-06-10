import { describe, it, expect } from "vitest";
import { autoUpdateEnabled } from "../src/commands/agent/scan.js";

/**
 * sable-o4k — stale-binary auto-update is on by default; either the
 * `--no-auto-update` CLI flag (opts.autoUpdate === false) or the
 * `scan.auto_update_betterleaks: false` config key opts out.
 */
describe("autoUpdateEnabled (sable-o4k)", () => {
  it("defaults to enabled with no flag and no config", () => {
    expect(autoUpdateEnabled({}, undefined)).toBe(true);
    expect(autoUpdateEnabled({}, {})).toBe(true);
  });

  it("disabled by the --no-auto-update flag", () => {
    expect(autoUpdateEnabled({ autoUpdate: false }, {})).toBe(false);
  });

  it("disabled by the config key", () => {
    expect(autoUpdateEnabled({}, { autoUpdateBetterleaks: false })).toBe(false);
  });

  it("config true keeps it enabled", () => {
    expect(autoUpdateEnabled({}, { autoUpdateBetterleaks: true })).toBe(true);
  });

  it("either opt-out wins over the other being permissive", () => {
    expect(autoUpdateEnabled({ autoUpdate: false }, { autoUpdateBetterleaks: true })).toBe(false);
    expect(autoUpdateEnabled({ autoUpdate: true }, { autoUpdateBetterleaks: false })).toBe(false);
  });
});
