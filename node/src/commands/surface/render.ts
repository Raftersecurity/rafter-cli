import chalk from "chalk";

import type { Transition, Unanalyzed } from "../../core/surface/model.js";
import { isAgentMode } from "../../utils/formatter.js";

/** Everything the text renderer needs. Never the wire object — §9.1 is a contract for machines. */
export interface RenderModel {
  baseLabel: string;
  headLabel: string;
  transitions: readonly Transition[];
  unanalyzed: readonly Unanalyzed[];
  degraded: boolean;
  inconclusive: boolean;
}

export interface RenderOptions {
  minSeverity: "low" | "medium" | "high" | "critical";
  includeDecreased: boolean;
  all: boolean;
  explain: boolean;
  onInconclusive: "exit" | "warn";
}

const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;
const MAX_ROWS = 10;

function severityRank(severity: string): number {
  return SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
}

function paintSeverity(severity: string): string {
  if (isAgentMode()) return severity;
  switch (severity) {
    case "critical": return chalk.red.bold(severity);
    case "high": return chalk.yellow.bold(severity);
    case "medium": return chalk.blue(severity);
    default: return chalk.green(severity);
  }
}

function pad(text: string, width: number): string {
  return text.length >= width ? `${text} ` : text.padEnd(width);
}

function truncate(text: string, width: number): string {
  return text.length <= width ? text : `${text.slice(0, width - 1)}…`;
}

function plural(count: number, singular: string, pluralForm: string): string {
  return count === 1 ? singular : pluralForm;
}

function evidenceOf(transition: Transition): string {
  const evidence = transition.headEvidence ?? transition.baseEvidence;
  if (evidence === null) return "";
  return evidence.line === null ? evidence.file : `${evidence.file}:${evidence.line}`;
}

/**
 * The delta phrase. Per amendment A1, `transitions[].label` is the endpoint
 * property's own description and carries no delta prose, so every "widened to X"
 * phrasing is composed here and nowhere else.
 */
export function deltaPhrase(transition: Transition): string {
  if (transition.danger === "incomparable") return "incomparable — review by hand";
  if (transition.danger === "unknown") return "unknown — coverage loss on the other side";
  if (transition.change === "added") return transition.danger === "increased" ? "new" : "added";
  if (transition.change === "removed") return "removed";
  const moved = transition.axes.filter((axis) => axis.order !== "equal");
  if (moved.length === 0) return "unchanged";
  const direction = transition.danger === "decreased" ? "narrowed" : "widened";
  return moved
    .map((axis) => `${axis.axis} ${direction}: ${axis.from ?? "absent"} → ${axis.to ?? "absent"}`)
    .join(", ");
}

function visibleTransitions(
  model: RenderModel,
  options: RenderOptions,
): Transition[] {
  return model.transitions.filter((transition) => {
    if (transition.danger === "decreased") return options.includeDecreased;
    if (transition.severity === null) return options.all;
    return severityRank(transition.severity) >= severityRank(options.minSeverity);
  });
}

function headline(model: RenderModel, visible: readonly Transition[], pair: string): string {
  const increased = visible.filter((transition) => transition.danger === "increased").length;
  const ambiguous = visible.filter((transition) => transition.danger === "incomparable").length;
  const parts: string[] = [];
  if (increased > 0) {
    parts.push(`${increased} ${plural(increased, "property", "properties")} became more dangerous`);
  }
  if (ambiguous > 0) {
    parts.push(`${ambiguous} ${plural(ambiguous, "is", "are")} ambiguous`);
  }
  if (parts.length === 0) parts.push("no property became more dangerous");
  return `Attack surface: ${parts.join(", ")}  ${pair}`;
}

function inconclusiveBlock(model: RenderModel, options: RenderOptions): string[] {
  const blocking = model.unanalyzed.filter((item) => item.changed);
  const lines = [
    `Attack surface: INCONCLUSIVE — ${blocking.length} ${plural(blocking.length, "file", "files")} `
      + `changed in this diff could not be analyzed.`,
    "",
  ];
  for (const item of blocking.slice(0, MAX_ROWS)) {
    lines.push(`  ${pad(truncate(item.file, 40), 42)}${item.detail} (${item.reason})`);
  }
  if (blocking.length > MAX_ROWS) lines.push(`  +${blocking.length - MAX_ROWS} more (--json)`);
  lines.push("");
  if (options.onInconclusive === "warn") {
    lines.push("Downgraded to a warning by --on-inconclusive warn — the exit code does not");
    lines.push("reflect it. This is still not a clean result.");
  } else {
    lines.push("This is not a clean result. Fix the file, or pass --on-inconclusive warn to");
    lines.push("downgrade this to a warning.");
  }
  return lines;
}

/** The human-readable report (§9.2). Result lines only — status belongs on stderr. */
export function renderText(model: RenderModel, options: RenderOptions): string {
  const pair = `(${model.baseLabel} → ${model.headLabel})`;
  const visible = visibleTransitions(model, options);
  const lines: string[] = [];

  if (visible.length > 0 || model.transitions.length > 0) {
    lines.push(headline(model, visible, pair));
    if (visible.length > 0) lines.push("");
    for (const transition of visible.slice(0, MAX_ROWS)) {
      const severity = transition.severity ?? "-";
      // Pad on the plain string; color codes must not count toward column width.
      lines.push(
        `  ${paintSeverity(severity)}${" ".repeat(Math.max(1, 10 - severity.length))}`
        + `${pad(truncate(transition.label, 38), 40)}`
        + `${pad(truncate(evidenceOf(transition), 28), 30)}`
        + deltaPhrase(transition),
      );
    }
    if (visible.length > MAX_ROWS) {
      lines.push(`  +${visible.length - MAX_ROWS} more (--json)`);
    }
    const hiddenDecreased = options.includeDecreased
      ? 0
      : model.transitions.filter((transition) => transition.danger === "decreased").length;
    if (hiddenDecreased > 0) {
      lines.push("");
      const note = `${hiddenDecreased} ${plural(hiddenDecreased, "property", "properties")} became safer`;
      lines.push(`  ${pad(note, 50)}(--include-decreased)`);
    }
    if (!options.explain && model.unanalyzed.length > 0) {
      const count = model.unanalyzed.length;
      const note = `${count} ${plural(count, "file", "files")} could not be analyzed`;
      if (hiddenDecreased === 0) lines.push("");
      lines.push(`  ${pad(note, 50)}(--explain)`);
    }
  } else if (!model.inconclusive) {
    // Three outcomes that must never read alike: clean, degraded-clean, inconclusive.
    if (model.degraded) {
      lines.push(
        `Attack surface: no change detected, but ${model.unanalyzed.length} `
        + `${plural(model.unanalyzed.length, "file", "files")} could not be analyzed  ${pair}`
        + `${options.explain ? "" : "  (--explain)"}`,
      );
    } else {
      lines.push(`Attack surface unchanged  ${pair}`);
    }
  }

  if (model.inconclusive) {
    if (lines.length > 0) lines.push("");
    lines.push(...inconclusiveBlock(model, options));
  }

  if (options.explain && model.unanalyzed.length > 0) {
    lines.push("");
    lines.push(`Unanalyzed candidates (${model.unanalyzed.length}):`);
    for (const item of model.unanalyzed) {
      lines.push(
        `  ${pad(truncate(item.file, 40), 42)}${item.side}  ${item.reason}`
        + `${item.detail ? ` — ${item.detail}` : ""}${item.changed ? "  [changed]" : ""}`,
      );
    }
  }

  return `${lines.join("\n")}\n`;
}

/** §4.4 / §9.2 — the actionable exit-3 message. Never a bare "base not found". */
export function renderBaseUnresolved(ref: string, shallow: boolean): string {
  const branch = ref.includes("/") ? ref.slice(ref.lastIndexOf("/") + 1) : ref;
  const cause = shallow
    ? `Cannot resolve base ref '${ref}' — this is a shallow clone.`
    : `Cannot resolve base ref '${ref}' — no such commit in this repository.`;
  return [
    cause,
    "actions/checkout defaults to fetch-depth: 1. Fix with either:",
    "    - uses: actions/checkout@v4",
    "      with: { fetch-depth: 0 }",
    `    - run: git fetch --no-tags --depth=1 origin ${branch}`,
    "Or run with --fetch-base to fetch it now.",
  ].join("\n");
}
