import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { assessCommandRisk } from "../src/core/risk-rules.js";

/**
 * rf-6pqx + rf-3rsj + public #230 regression battery.
 *
 * A newline is a statement separator (rf-6pqx): `echo x\nrm -rf /` must NOT be
 * hidden by the leading text-exec. Heredoc bodies a command consumes as DATA are
 * stripped so the newline fix does not make ordinary documentation writes CRITICAL
 * (rf-3rsj) — the same over-block #230 reported — while a body EXECUTED by a
 * shell/eval owner (`bash <<EOF`) stays scannable (se-y6vo). Also covers
 * backslash-newline line continuations and fail-closed-on-unterminated-quote.
 *
 * The battery JSON is shared BYTE-FOR-BYTE with the Python suite
 * (python/tests/test_risk_rules_newline_heredoc.py) so a Node-clean result cannot
 * hide a Python bug, and vice versa. Co-designed with kerckhoffs (se-ijzs) and
 * achebe (#230).
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const batteryPath = path.resolve(here, "../../rf-6pqx-newline-heredoc-battery.json");
const battery: Array<{ label: string; cmd: string; want: string[] }> = JSON.parse(
  readFileSync(batteryPath, "utf8"),
);

describe("rf-6pqx/rf-3rsj/#230: newline + heredoc classifier battery", () => {
  it.each(battery)("$label", ({ cmd, want }) => {
    expect(want).toContain(assessCommandRisk(cmd));
  });
});
