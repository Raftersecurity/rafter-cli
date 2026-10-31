import { describe, it, expect } from "vitest";
import {
  formatSlackPayload,
  formatDiscordPayload,
  formatGenericPayload,
} from "../src/commands/notify.js";

/**
 * rf-x3vj: `rafter notify` must read the real scan API shape — a
 * `vulnerabilities[]` array whose `summary` carries `errors`/`warnings`/`notes`
 * — and map severities the way the GitHub Action and `rafter get` do
 * (critical / error|high / warning|medium / note|low). The old code read
 * `findings` and `summary.critical`/`summary.high`, all absent from a real
 * payload, so it always reported "Clean" even when the scan found issues.
 */

// Real scan API shape: `vulnerabilities[]`, severities "critical" and "error",
// and a `summary` keyed on errors/warnings/notes. None of the fields the old
// code read are present, so the old code reports Clean here.
const SCAN_VULNERABILITIES = {
  status: "completed",
  repository_name: "acme/payments",
  scan_id: "scan-vuln1",
  branch_name: "main",
  vulnerabilities: [
    {
      severity: "critical",
      level: "critical",
      rule_id: "sql-injection",
      message: "SQL injection in query builder",
      file: "src/db.ts",
      line: 42,
    },
    {
      severity: "error",
      level: "error",
      rule_id: "hardcoded-secret",
      message: "Hardcoded credential",
      file: "config/prod.yaml",
      line: 7,
    },
  ],
  summary: { errors: 2, warnings: 0, notes: 0 },
};

const SCAN_EMPTY_VULNS = {
  status: "completed",
  repository_name: "acme/clean",
  scan_id: "scan-clean1",
  vulnerabilities: [],
  summary: { errors: 0, warnings: 0, notes: 0 },
};

// Legacy cached payload: `findings` with tier severities, no `vulnerabilities`.
const SCAN_LEGACY_FINDINGS = {
  status: "completed",
  repository_name: "acme/api-server",
  scan_id: "scan-def456",
  findings: [
    { severity: "critical", title: "SQL Injection", file: "src/db.py" },
    { severity: "high", title: "Hardcoded Secret", location: "config/prod.yml:12" },
    { severity: "medium", title: "Missing CSRF Token", file: "views/form.py" },
  ],
  summary: { critical: 1, high: 1, medium: 1, low: 0 },
};

describe("notify vulnerabilities payload (rf-x3vj)", () => {
  it("slack reports vulnerabilities, not Clean", () => {
    const payload = formatSlackPayload(SCAN_VULNERABILITIES);
    const blob = JSON.stringify(payload);
    expect(payload.text).not.toContain("Clean");
    expect(payload.text).toContain("2 issues found");
    // Red-alert header, because a critical/high finding is present.
    const blocks = payload.blocks as Array<any>;
    expect(blocks[0].text.text).toContain("rotating_light");
    // critical stays critical; error maps to high (the action's mapping).
    expect(blob).toContain("Critical: *1*");
    expect(blob).toContain("High: *1*");
    // Findings are listed, sourced from rule_id + file:line.
    expect(blob).toContain("sql-injection");
    expect(blob).toContain("hardcoded-secret");
    expect(blob).toContain("src/db.ts:42");
  });

  it("discord reports vulnerabilities, not Clean", () => {
    const payload = formatDiscordPayload(SCAN_VULNERABILITIES);
    const blob = JSON.stringify(payload);
    expect(payload.content).toContain("2 issues found");
    const embed = (payload.embeds as Array<any>)[0];
    expect(embed.color).toBe(0xe74c3c); // red: has critical/high
    expect(blob).toContain("Critical: **1**");
    expect(blob).toContain("High: **1**");
    expect(blob).toContain("sql-injection");
  });

  it("generic reports vulnerabilities, not Clean", () => {
    const payload = formatGenericPayload(SCAN_VULNERABILITIES);
    expect(payload.text).not.toContain("Clean");
    expect(payload.text).toContain("2 issues");
  });

  it("empty vulnerabilities is still Clean (no over-correction)", () => {
    const slack = formatSlackPayload(SCAN_EMPTY_VULNS);
    expect(slack.text).toContain("Clean");
    const discord = formatDiscordPayload(SCAN_EMPTY_VULNS);
    expect((discord.embeds as Array<any>)[0].color).toBe(0x2ecc71); // green
    const generic = formatGenericPayload(SCAN_EMPTY_VULNS);
    expect(generic.text).toContain("Clean");
  });

  it("legacy findings payloads are still counted (back-compat)", () => {
    const payload = formatSlackPayload(SCAN_LEGACY_FINDINGS);
    expect(payload.text).toContain("3 issues found");
    expect(payload.text).not.toContain("Clean");
  });
});

// sable-ur8k: the real scan API shape uses `file_path`/`line_start`, not the
// pre-rename `file`/`line`. Before the fix, normalizeScan's location logic only
// read file/line, so a real finding's location was always blank.
const SCAN_VULNERABILITIES_FILE_PATH = {
  status: "completed",
  repository_name: "acme/payments",
  scan_id: "scan-vuln2",
  branch_name: "main",
  vulnerabilities: [
    {
      severity: "error",
      rule_id: "sql-injection",
      title: "SQL injection in query builder",
      file_path: "src/db.ts",
      line_start: 42,
    },
  ],
};

describe("notify location fields (sable-ur8k)", () => {
  it("shows file_path:line_start in the location", () => {
    const blob = JSON.stringify(formatSlackPayload(SCAN_VULNERABILITIES_FILE_PATH));
    expect(blob).toContain("src/db.ts:42");
  });
});
