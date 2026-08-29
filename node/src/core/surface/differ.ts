import {
  dangerFor,
  flipOrder,
  latticeCompare,
  ordinalCompare,
  severityFor,
} from "./compare.js";
import { KIND_SPECS } from "./kind-specs.js";
import type {
  KindSpec,
  Property,
  PropertyKind,
  SurfaceSeverity,
  Transition,
  Unanalyzed,
} from "./model.js";

export interface DiffCoverage {
  unanalyzed: Unanalyzed[];
  blocksAbsenceProof?: (transition: Transition) => boolean;
}

const SEVERITY_RANK: Readonly<Record<Exclude<SurfaceSeverity, null>, number>> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function indexUnique(
  properties: readonly Property[],
  side: "base" | "head",
  coverage: DiffCoverage,
): Map<string, Property> {
  const groups = new Map<string, Property[]>();
  for (const property of properties) {
    const group = groups.get(property.key) ?? [];
    group.push(property);
    groups.set(property.key, group);
  }
  const indexed = new Map<string, Property>();
  for (const [key, group] of groups) {
    if (group.length === 1) {
      indexed.set(key, group[0]);
      continue;
    }
    for (const file of new Set(group.map((property) => property.evidence.file))) {
      coverage.unanalyzed.push({
        file,
        side,
        reason: "parse_error",
        detail: `duplicate property key '${key}'`,
        changed: false,
      });
    }
  }
  return indexed;
}

function specMap(specs: readonly KindSpec[]): Map<PropertyKind, KindSpec> {
  return new Map(specs.map((spec) => [spec.kind, spec]));
}

function classify(
  base: Property | null,
  head: Property | null,
  specs: ReadonlyMap<PropertyKind, KindSpec>,
  paired = false,
): Transition[] {
  const endpoint = head ?? base;
  if (endpoint === null) return [];
  if (base !== null && head !== null && base.kind !== head.kind) {
    throw new Error(`cannot compare ${base.kind} with ${head.kind}`);
  }
  const spec = specs.get(endpoint.kind);
  if (spec === undefined) throw new Error(`missing kind spec for ${endpoint.kind}`);
  const comparison = spec.comparator === "ordinal"
    ? ordinalCompare(spec, base, head)
    : latticeCompare(spec, base, head);
  const semanticOrder = spec.invertDanger ? flipOrder(comparison.order) : comparison.order;
  const danger = dangerFor(semanticOrder);
  if (danger === "unchanged" && !paired) return [];
  const change = base === null ? "added" : head === null ? "removed" : "modified";
  const key = paired && base !== null && head !== null
    ? [base.key, head.key].sort(compareUtf8)[0]
    : endpoint.key;
  const severity = severityFor(spec, base, head, danger, comparison.axes);
  return [{
    kind: endpoint.kind,
    key,
    subject: endpoint.subject,
    change,
    danger,
    severity,
    axes: comparison.axes,
    from: comparison.axes.length === 1 ? comparison.axes[0].from : null,
    to: comparison.axes.length === 1 ? comparison.axes[0].to : null,
    confidence: endpoint.confidence,
    baseEvidence: base?.evidence ?? null,
    headEvidence: head?.evidence ?? null,
    attrs: endpoint.attrs,
    paired,
  }];
}

function residualPairs(
  base: readonly Property[],
  head: readonly Property[],
  specs: ReadonlyMap<PropertyKind, KindSpec>,
): { pairs: Array<[Property, Property]>; leftBase: Property[]; leftHead: Property[] } {
  const scopeKey = (property: Property): string | null => {
    const spec = specs.get(property.kind);
    if (!spec?.allowResidualPairing || property.pairingScope === null) return null;
    return `${property.kind}\0${property.pairingScope}`;
  };
  const baseGroups = new Map<string, Property[]>();
  const headGroups = new Map<string, Property[]>();
  for (const property of base) {
    const key = scopeKey(property);
    if (key !== null) baseGroups.set(key, [...(baseGroups.get(key) ?? []), property]);
  }
  for (const property of head) {
    const key = scopeKey(property);
    if (key !== null) headGroups.set(key, [...(headGroups.get(key) ?? []), property]);
  }
  const usedBase = new Set<Property>();
  const usedHead = new Set<Property>();
  const pairs: Array<[Property, Property]> = [];
  const scopes = [...baseGroups.keys()].filter((key) => headGroups.has(key)).sort(compareUtf8);
  for (const scope of scopes) {
    const baseGroup = baseGroups.get(scope)!;
    const headGroup = headGroups.get(scope)!;
    if (baseGroup.length === 1 && headGroup.length === 1) {
      pairs.push([baseGroup[0], headGroup[0]]);
      usedBase.add(baseGroup[0]);
      usedHead.add(headGroup[0]);
    }
  }
  return {
    pairs,
    leftBase: base.filter((property) => !usedBase.has(property)),
    leftHead: head.filter((property) => !usedHead.has(property)),
  };
}

function defaultBlocksAbsenceProof(transition: Transition, unanalyzed: readonly Unanalyzed[]): boolean {
  if (transition.change === "added") return unanalyzed.some((item) => item.side === "base");
  if (transition.change === "removed") return unanalyzed.some((item) => item.side === "head");
  return false;
}

export function diffProperties(
  baseProperties: readonly Property[],
  headProperties: readonly Property[],
  specs: readonly KindSpec[] = KIND_SPECS,
  coverage: DiffCoverage = { unanalyzed: [] },
): Transition[] {
  const byKind = specMap(specs);
  const base = indexUnique(baseProperties, "base", coverage);
  const head = indexUnique(headProperties, "head", coverage);
  const out: Transition[] = [];

  const exactKeys = [...base.keys()].filter((key) => head.has(key)).sort(compareUtf8);
  for (const key of exactKeys) out.push(...classify(base.get(key)!, head.get(key)!, byKind));

  const unmatchedBase = [...base.entries()]
    .filter(([key]) => !head.has(key))
    .map(([, property]) => property);
  const unmatchedHead = [...head.entries()]
    .filter(([key]) => !base.has(key))
    .map(([, property]) => property);
  const residual = residualPairs(unmatchedBase, unmatchedHead, byKind);
  for (const [baseProperty, headProperty] of residual.pairs) {
    out.push(...classify(baseProperty, headProperty, byKind, true));
  }
  for (const property of residual.leftBase) out.push(...classify(property, null, byKind));
  for (const property of residual.leftHead) out.push(...classify(null, property, byKind));

  for (const transition of out) {
    const blocked = coverage.blocksAbsenceProof?.(transition)
      ?? defaultBlocksAbsenceProof(transition, coverage.unanalyzed);
    if (blocked) {
      transition.danger = "unknown";
      transition.severity = null;
    }
  }

  return out.sort((left, right) => {
    const leftRank = left.severity === null ? -1 : SEVERITY_RANK[left.severity];
    const rightRank = right.severity === null ? -1 : SEVERITY_RANK[right.severity];
    if (leftRank !== rightRank) return rightRank - leftRank;
    const kindOrder = compareUtf8(left.kind, right.kind);
    return kindOrder !== 0 ? kindOrder : compareUtf8(left.key, right.key);
  });
}
