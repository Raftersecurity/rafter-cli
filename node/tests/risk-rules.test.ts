import { describe, it, expect } from "vitest";
import { assessCommandRisk, HIGH_PATTERNS, DEFAULT_REQUIRE_APPROVAL } from "../src/core/risk-rules.js";

describe("Force push detection", () => {
  describe("HIGH_PATTERNS", () => {
    it("detects git push --force", () => {
      expect(assessCommandRisk("git push --force origin main")).toBe("high");
    });

    it("detects git push --force (bare)", () => {
      expect(assessCommandRisk("git push --force")).toBe("high");
    });

    it("detects git push -f", () => {
      expect(assessCommandRisk("git push -f origin main")).toBe("high");
    });

    it("detects git push -f (bare)", () => {
      expect(assessCommandRisk("git push -f")).toBe("high");
    });

    it("detects git push --force-with-lease", () => {
      expect(assessCommandRisk("git push --force-with-lease origin main")).toBe("high");
    });

    it("detects git push --force-with-lease (bare)", () => {
      expect(assessCommandRisk("git push --force-with-lease")).toBe("high");
    });

    it("detects git push --force-if-includes", () => {
      expect(assessCommandRisk("git push --force-if-includes origin main")).toBe("high");
    });

    it("detects git push --force-if-includes (bare)", () => {
      expect(assessCommandRisk("git push --force-if-includes")).toBe("high");
    });

    it("detects refspec git push origin +main", () => {
      expect(assessCommandRisk("git push origin +main")).toBe("high");
    });

    it("detects refspec git push origin +refs/heads/main", () => {
      expect(assessCommandRisk("git push origin +refs/heads/main")).toBe("high");
    });

    it("detects combined flags git push -vf", () => {
      expect(assessCommandRisk("git push -vf origin main")).toBe("high");
    });

    it("detects git push origin --force (flag after remote)", () => {
      expect(assessCommandRisk("git push origin --force")).toBe("high");
    });

    it("detects git push origin -f (flag after remote)", () => {
      expect(assessCommandRisk("git push origin -f")).toBe("high");
    });

    it("does not flag normal git push", () => {
      expect(assessCommandRisk("git push origin main")).toBe("low");
    });

    it("does not flag git push with no args", () => {
      expect(assessCommandRisk("git push")).toBe("low");
    });

    it("does not false positive on branch names with hyphens", () => {
      expect(assessCommandRisk("git push origin feature-fix")).toBe("low");
    });
  });

  describe("DEFAULT_REQUIRE_APPROVAL includes force push variants", () => {
    it("includes git push --force", () => {
      expect(DEFAULT_REQUIRE_APPROVAL).toContain("git push --force");
    });

    it("includes git push -f", () => {
      expect(DEFAULT_REQUIRE_APPROVAL).toContain("git push -f");
    });

    it("includes git push --force-with-lease", () => {
      expect(DEFAULT_REQUIRE_APPROVAL).toContain("git push --force-with-lease");
    });

    it("includes git push --force-if-includes", () => {
      expect(DEFAULT_REQUIRE_APPROVAL).toContain("git push --force-if-includes");
    });

    it("includes refspec pattern", () => {
      expect(DEFAULT_REQUIRE_APPROVAL).toContain("git push .* \\+");
    });
  });

  describe("HIGH_PATTERNS count", () => {
    it("has patterns for all force push variants", () => {
      const forcePushPatterns = HIGH_PATTERNS.filter(p =>
        p.test("git push --force") ||
        p.test("git push -f") ||
        p.test("git push origin +main")
      );
      expect(forcePushPatterns.length).toBeGreaterThanOrEqual(3);
    });
  });
});
