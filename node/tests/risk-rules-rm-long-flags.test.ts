import { describe, it, expect } from "vitest";
import { assessCommandRisk, normalizeRmFlags } from "../src/core/risk-rules.js";

/**
 * Regression tests for the `rm` long-flag evasion (sable-urvj).
 *
 * The risk rules spell rm's flags the short way (`-rf`, `-r -f`, `-fr`). GNU rm
 * accepts long spellings meaning exactly the same thing, and those evaded every
 * rule: `rm --recursive --force /` assessed LOW and was silently allowed.
 *
 * The inversion is what makes this severe: modern coreutils REFUSES `rm -rf /`
 * unless `--no-preserve-root` is also given, so the only interactive form that
 * actually wipes root was precisely the form the hard-block missed.
 */

describe("rm long-flag evasion (sable-urvj)", () => {

  describe("long-form flags reach the unconditional hard-block", () => {
    it("blocks fully long-form rm on /", () => {
      expect(assessCommandRisk("rm --recursive --force /")).toBe("critical");
    });

    it("blocks long-form flags in either order on a critical dir", () => {
      expect(assessCommandRisk("rm --force --recursive /home")).toBe("critical");
      expect(assessCommandRisk("rm --recursive --force /etc")).toBe("critical");
    });

    it("blocks mixed short and long spellings", () => {
      expect(assessCommandRisk("rm -r --force /etc")).toBe("critical");
      expect(assessCommandRisk("rm --recursive -f /usr")).toBe("critical");
    });

    it("blocks long flags written in --flag=value form", () => {
      // GNU rm's long options take no argument, so this is in truth an error;
      // reading it as recursive is the conservative direction for a blocker.
      expect(assessCommandRisk("rm --recursive=yes -f /")).toBe("critical");
      expect(assessCommandRisk("rm --recursive=yes --force=yes /boot")).toBe("critical");
    });

    it("blocks the form that actually wipes root on modern coreutils", () => {
      // `rm -rf /` alone is refused by coreutils; this is the one that isn't.
      expect(assessCommandRisk("rm --recursive --force --no-preserve-root /")).toBe("critical");
      expect(assessCommandRisk("rm -rf --no-preserve-root /")).toBe("critical");
    });

    it("blocks long-form rm behind sudo and through chains", () => {
      expect(assessCommandRisk("sudo rm --recursive --force /usr")).toBe("critical");
      expect(assessCommandRisk("echo ok && rm --recursive --force /boot")).toBe("critical");
      expect(assessCommandRisk("cd /tmp; rm --force --recursive /lib")).toBe("critical");
    });

    it("still rates long-form rm on a non-critical path as high", () => {
      expect(assessCommandRisk("rm --recursive --force /tmp/build")).toBe("high");
      expect(assessCommandRisk("rm --recursive --force ./node_modules")).toBe("high");
    });
  });

  describe("no new false positives", () => {
    it("leaves rm without a recursive or force flag alone", () => {
      expect(assessCommandRisk("rm -i -v notes.txt")).toBe("low");
      expect(assessCommandRisk("rm notes.txt")).toBe("low");
      expect(assessCommandRisk("rm --interactive notes.txt")).toBe("low");
    });

    it("does not treat an operand after -- as a flag", () => {
      expect(assessCommandRisk("rm -- --weird-file")).toBe("low");
    });

    it("does not let the flag run swallow a following chained command", () => {
      // A naive `.*` rule spans chain operators; the run must stop at them.
      expect(assessCommandRisk("rm -r dir && cp -r a b")).toBe("high");
      expect(assessCommandRisk("rm -i f; ls -la")).toBe("low");
    });

    it("still treats a force-flag mention inside prose as data", () => {
      expect(assessCommandRisk('git commit -m "never rm --recursive --force /"')).toBe("low");
      expect(assessCommandRisk('echo "rm --recursive --force /" > notes.txt')).toBe("low");
    });

    it("does not rewrite commands that merely contain the letters rm", () => {
      expect(assessCommandRisk("npm run format")).toBe("low");
      expect(assessCommandRisk("chmod --recursive 755 dir")).toBe("medium");
    });
  });

  describe("normalizeRmFlags", () => {
    it("collapses a flag run to a canonical short cluster", () => {
      expect(normalizeRmFlags("rm --recursive --force /")).toBe("rm -rf /");
      expect(normalizeRmFlags("rm -r --force --no-preserve-root /")).toBe("rm -rf /");
      expect(normalizeRmFlags("rm --recursive /tmp")).toBe("rm -r /tmp");
    });

    it("returns the input untouched when there is nothing to canonicalize", () => {
      expect(normalizeRmFlags("rm -i -v notes.txt")).toBe("rm -i -v notes.txt");
      expect(normalizeRmFlags("ls -la")).toBe("ls -la");
    });

    it("normalizes every rm in a chain", () => {
      expect(normalizeRmFlags("rm --recursive a && rm --force b")).toBe("rm -r a && rm -f b");
    });
  });
});
