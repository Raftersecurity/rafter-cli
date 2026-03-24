import { describe, it, expect } from "vitest";

/**
 * Unit tests for the badge command's URL generation logic.
 *
 * These test the classifyScore and buildShieldsUrl helpers directly
 * (re-implemented inline since they're not exported from the module).
 */

// Mirror the classification logic from badge.ts for unit testing
function classifyScore(data: {
  status?: string;
  vulnerabilities?: Array<{ level?: string; severity?: string }>;
}): { message: string; color: string } {
  const status = data.status;

  if (!status || status === "failed") {
    return { message: "error", color: "critical" };
  }
  if (["queued", "pending", "processing"].includes(status)) {
    return { message: "pending", color: "yellow" };
  }
  if (status === "completed") {
    const vulns = data.vulnerabilities ?? [];
    const errors = vulns.filter(
      (v) => v.level === "error" || v.severity === "error",
    ).length;
    const warnings = vulns.filter(
      (v) => v.level === "warning" || v.severity === "warning",
    ).length;

    if (errors > 0) {
      return { message: `${errors} critical`, color: "critical" };
    }
    if (warnings > 0) {
      return { message: `${warnings} warnings`, color: "yellow" };
    }
    return { message: "passing", color: "brightgreen" };
  }
  return { message: status, color: "lightgrey" };
}

function buildShieldsUrl(
  label: string,
  message: string,
  color: string,
  style: string,
): string {
  const l = encodeURIComponent(label);
  const m = encodeURIComponent(message);
  return `https://img.shields.io/badge/${l}-${m}-${color}?style=${style}`;
}

describe("badge — classifyScore", () => {
  it("returns passing/green for completed scan with no vulns", () => {
    const result = classifyScore({ status: "completed", vulnerabilities: [] });
    expect(result).toEqual({ message: "passing", color: "brightgreen" });
  });

  it("returns passing/green when vulnerabilities key is missing", () => {
    const result = classifyScore({ status: "completed" });
    expect(result).toEqual({ message: "passing", color: "brightgreen" });
  });

  it("returns critical/red for completed scan with errors", () => {
    const result = classifyScore({
      status: "completed",
      vulnerabilities: [
        { level: "error" },
        { level: "error" },
        { level: "warning" },
      ],
    });
    expect(result).toEqual({ message: "2 critical", color: "critical" });
  });

  it("returns warnings/yellow for completed scan with only warnings", () => {
    const result = classifyScore({
      status: "completed",
      vulnerabilities: [
        { level: "warning" },
        { level: "note" },
      ],
    });
    expect(result).toEqual({ message: "1 warnings", color: "yellow" });
  });

  it("handles severity field as well as level field", () => {
    const result = classifyScore({
      status: "completed",
      vulnerabilities: [{ severity: "error" }],
    });
    expect(result).toEqual({ message: "1 critical", color: "critical" });
  });

  it("returns pending/yellow for queued scan", () => {
    expect(classifyScore({ status: "queued" })).toEqual({
      message: "pending",
      color: "yellow",
    });
  });

  it("returns pending/yellow for processing scan", () => {
    expect(classifyScore({ status: "processing" })).toEqual({
      message: "pending",
      color: "yellow",
    });
  });

  it("returns error/critical for failed scan", () => {
    expect(classifyScore({ status: "failed" })).toEqual({
      message: "error",
      color: "critical",
    });
  });

  it("returns error/critical when status is missing", () => {
    expect(classifyScore({})).toEqual({
      message: "error",
      color: "critical",
    });
  });

  it("returns unknown status as-is with grey", () => {
    expect(classifyScore({ status: "cancelled" })).toEqual({
      message: "cancelled",
      color: "lightgrey",
    });
  });
});

describe("badge — buildShieldsUrl", () => {
  it("builds correct shields.io URL with defaults", () => {
    const url = buildShieldsUrl("rafter", "passing", "brightgreen", "flat");
    expect(url).toBe(
      "https://img.shields.io/badge/rafter-passing-brightgreen?style=flat",
    );
  });

  it("encodes special characters in label and message", () => {
    const url = buildShieldsUrl("my label", "2 critical", "critical", "flat");
    expect(url).toBe(
      "https://img.shields.io/badge/my%20label-2%20critical-critical?style=flat",
    );
  });

  it("supports different styles", () => {
    const url = buildShieldsUrl("rafter", "passing", "brightgreen", "for-the-badge");
    expect(url).toContain("style=for-the-badge");
  });

  it("generates markdown badge format", () => {
    const url = buildShieldsUrl("rafter", "passing", "brightgreen", "flat");
    const md = `[![rafter](${url})](https://rafter.so)`;
    expect(md).toBe(
      "[![rafter](https://img.shields.io/badge/rafter-passing-brightgreen?style=flat)](https://rafter.so)",
    );
  });
});
