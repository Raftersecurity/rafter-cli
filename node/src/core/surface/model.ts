import type { CommandRiskLevel } from "../risk-rules.js";

export type SurfaceSeverity = CommandRiskLevel | null;
export type Confidence = "certain";

export type PropertyKind =
  | "container.port"
  | "iam.allow"
  | "iam.deny"
  | "pkg.lifecycle_script";

export type Change = "added" | "removed" | "modified";
export type Danger =
  | "increased"
  | "decreased"
  | "unchanged"
  | "incomparable"
  | "unknown";

export type AxisOrder = "equal" | "greater" | "less" | "unknown";

export interface Evidence {
  /** Repo-relative, forward slashes, NFC-normalized. */
  file: string;
  /** 1-based; null when the artifact has no meaningful line. */
  line: number | null;
}

/** What an extractor produces. One observed security property on ONE side. */
export interface Property {
  kind: PropertyKind;
  /** Stable identity. See the §3.2 rules. */
  key: string;
  /** Stable identity with locative key components elided. */
  discriminator: string;
  /** Human-facing name of the thing this property is about. */
  subject: string;
  /** Axis name to level name. Null means observed but not decidable. */
  levels: Readonly<Record<string, string | null>>;
  label: string;
  attrs: Readonly<Record<string, string | number | boolean | null>>;
  evidence: Evidence;
  confidence: Confidence;
  /** Optional scope for conservative residual pairing. */
  pairingScope: string | null;
}

export interface AxisSpec {
  name: string;
  /** Artifact fields from which this comparison axis is derived. */
  derivedFrom: readonly string[];
  /** Safest first. */
  ranks: readonly string[];
  absentRank: "below" | "above";
  severityAtTop: SurfaceSeverity;
}

export interface KindSpec {
  kind: PropertyKind;
  comparator: "ordinal" | "lattice";
  axes: readonly AxisSpec[];
  severityByLevel?: readonly SurfaceSeverity[];
  severityWhenAbsent?: SurfaceSeverity;
  severityWhenIncomparable?: SurfaceSeverity;
  invertDanger: boolean;
  allowResidualPairing: boolean;
  keyMayRepeat: boolean;
  display: string;
}

export interface AxisTransition {
  axis: string;
  from: string | null;
  to: string | null;
  /** Direction of head relative to base, before kind-level inversion. */
  order: AxisOrder;
}

export interface Transition {
  kind: PropertyKind;
  key: string;
  subject: string;
  label: string;
  change: Change;
  danger: Danger;
  severity: SurfaceSeverity;
  axes: AxisTransition[];
  from: string | null;
  to: string | null;
  confidence: Confidence;
  baseEvidence: Evidence | null;
  headEvidence: Evidence | null;
  attrs: Readonly<Record<string, string | number | boolean | null>>;
  paired: boolean;
}

export type UnanalyzedReason =
  | "parse_error"
  | "unsupported_syntax"
  | "too_large"
  | "too_many_candidates"
  | "binary"
  | "symlink"
  | "timeout";

export interface Unanalyzed {
  file: string;
  side: "base" | "head";
  reason: UnanalyzedReason;
  detail: string;
  changed: boolean;
}

export interface ExtractResult {
  properties: Property[];
  unanalyzed: Unanalyzed[];
}

export interface Extractor {
  id: string;
  version: number;
  kinds: readonly PropertyKind[];
  candidate(path: string, sizeBytes: number): boolean;
  extract(files: ReadonlyMap<string, string>): ExtractResult;
}
