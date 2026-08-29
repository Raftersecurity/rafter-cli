import type { KindSpec, Transition, Unanalyzed } from "./model.js";

const MAX_SAFE_INTEGER = 2 ** 53 - 1;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function normalizeString(value: string): string {
  let repaired = "";
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        repaired += value[index] + value[index + 1];
        index += 1;
      } else {
        repaired += "\ufffd";
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      repaired += "\ufffd";
    } else {
      repaired += value[index];
    }
  }
  return repaired.normalize("NFC");
}

function canonicalize(value: unknown): JsonValue {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return normalizeString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new TypeError("canonical JSON accepts only safe integers");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== "object") throw new TypeError(`unsupported JSON value: ${typeof value}`);

  const input = value as Record<string, unknown>;
  const output = Object.create(null) as Record<string, JsonValue>;
  for (const key of Object.keys(input).sort()) {
    if (!/^[\x00-\x7f]+$/.test(key)) throw new TypeError(`non-ASCII object key: ${key}`);
    output[key] = canonicalize(input[key]);
  }
  return output;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sortUnanalyzed(items: readonly Unanalyzed[]): Unanalyzed[] {
  return [...items].sort((left, right) => {
    const fileOrder = Buffer.compare(Buffer.from(left.file, "utf8"), Buffer.from(right.file, "utf8"));
    if (fileOrder !== 0) return fileOrder;
    return left.side === right.side ? 0 : left.side < right.side ? -1 : 1;
  });
}

export function transitionToWire(transition: Transition): JsonValue {
  return {
    kind: transition.kind,
    key: transition.key,
    subject: transition.subject,
    label: transition.label,
    change: transition.change,
    danger: transition.danger,
    severity: transition.severity,
    axes: transition.axes.map((axis) => ({
      axis: axis.axis,
      from: axis.from,
      to: axis.to,
      order: axis.order,
    })),
    from: transition.from,
    to: transition.to,
    confidence: transition.confidence,
    base_evidence: transition.baseEvidence === null
      ? null
      : { file: transition.baseEvidence.file, line: transition.baseEvidence.line },
    head_evidence: transition.headEvidence === null
      ? null
      : { file: transition.headEvidence.file, line: transition.headEvidence.line },
    attrs: { ...transition.attrs },
    paired: transition.paired,
  };
}

export function kindSpecToWire(spec: KindSpec): JsonValue {
  const output: Record<string, JsonValue> = {
    kind: spec.kind,
    comparator: spec.comparator,
    axes: spec.axes.map((axis) => ({
      name: axis.name,
      derivedFrom: [...axis.derivedFrom],
      ranks: [...axis.ranks],
      absentRank: axis.absentRank,
      severityAtTop: axis.severityAtTop,
    })),
    invertDanger: spec.invertDanger,
    allowResidualPairing: spec.allowResidualPairing,
    keyMayRepeat: spec.keyMayRepeat,
    display: spec.display,
  };
  if (spec.severityByLevel !== undefined) output.severityByLevel = [...spec.severityByLevel];
  if (spec.severityWhenAbsent !== undefined) output.severityWhenAbsent = spec.severityWhenAbsent;
  if (spec.severityWhenIncomparable !== undefined) {
    output.severityWhenIncomparable = spec.severityWhenIncomparable;
  }
  return output;
}

export function kindSpecsToWire(specs: readonly KindSpec[]): JsonValue {
  return specs.map(kindSpecToWire);
}
