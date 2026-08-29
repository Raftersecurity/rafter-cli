import type {
  AxisOrder,
  AxisSpec,
  AxisTransition,
  Danger,
  KindSpec,
  Property,
  SurfaceSeverity,
} from "./model.js";

export type ComparatorOrder = AxisOrder | "incomparable";

export interface Comparison {
  order: ComparatorOrder;
  axes: AxisTransition[];
}

const SEVERITY_RANK: Readonly<Record<Exclude<SurfaceSeverity, null>, number>> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function rankOf(axis: AxisSpec, value: string | null, present: boolean): number | null {
  if (!present) {
    return axis.absentRank === "below" ? -1 : axis.ranks.length;
  }
  if (value === null) return null;
  const rank = axis.ranks.indexOf(value);
  return rank >= 0 ? rank : null;
}

function compareAxis(
  axis: AxisSpec,
  base: Property | null,
  head: Property | null,
): AxisTransition {
  const from = base?.levels[axis.name] ?? null;
  const to = head?.levels[axis.name] ?? null;
  const baseRank = rankOf(axis, from, base !== null);
  const headRank = rankOf(axis, to, head !== null);
  let order: AxisOrder;
  if (baseRank === null || headRank === null) order = "unknown";
  else if (headRank === baseRank) order = "equal";
  else order = headRank > baseRank ? "greater" : "less";
  return { axis: axis.name, from, to, order };
}

function aggregate(axes: readonly AxisTransition[]): ComparatorOrder {
  if (axes.some((axis) => axis.order === "unknown")) return "unknown";
  const greater = axes.some((axis) => axis.order === "greater");
  const less = axes.some((axis) => axis.order === "less");
  if (greater && less) return "incomparable";
  if (greater) return "greater";
  if (less) return "less";
  return "equal";
}

export function ordinalCompare(
  spec: KindSpec,
  base: Property | null,
  head: Property | null,
): Comparison {
  if (spec.axes.length !== 1) throw new Error(`ordinal kind ${spec.kind} must have one axis`);
  const axes = [compareAxis(spec.axes[0], base, head)];
  return { order: axes[0].order, axes };
}

export function latticeCompare(
  spec: KindSpec,
  base: Property | null,
  head: Property | null,
): Comparison {
  const axes = spec.axes.map((axis) => compareAxis(axis, base, head));
  return { order: aggregate(axes), axes };
}

export function flipOrder(order: ComparatorOrder): ComparatorOrder {
  if (order === "greater") return "less";
  if (order === "less") return "greater";
  return order;
}

export function dangerFor(order: ComparatorOrder): Danger {
  return {
    equal: "unchanged",
    greater: "increased",
    less: "decreased",
    incomparable: "incomparable",
    unknown: "unknown",
  }[order] as Danger;
}

function maximumSeverity(values: readonly SurfaceSeverity[]): SurfaceSeverity {
  let best: SurfaceSeverity = null;
  for (const value of values) {
    if (value !== null && (best === null || SEVERITY_RANK[value] > SEVERITY_RANK[best])) {
      best = value;
    }
  }
  return best;
}

export function severityFor(
  spec: KindSpec,
  base: Property | null,
  head: Property | null,
  danger: Danger,
  axes: readonly AxisTransition[],
): SurfaceSeverity {
  if (danger === "incomparable") return spec.severityWhenIncomparable ?? null;
  if (danger !== "increased") return null;

  if (spec.comparator === "ordinal") {
    const axis = spec.axes[0];
    const arrival = spec.invertDanger ? base : head;
    if (arrival === null) {
      return axis.absentRank === "above" ? spec.severityWhenAbsent ?? null : null;
    }
    const level = arrival.levels[axis.name];
    if (level === null || level === undefined) return null;
    const rank = axis.ranks.indexOf(level);
    return rank >= 0 ? spec.severityByLevel?.[rank] ?? null : null;
  }

  const increasingOrder: AxisOrder = spec.invertDanger ? "less" : "greater";
  const increasingAxes = axes.filter((axis) => axis.order === increasingOrder);
  const severity = maximumSeverity(
    increasingAxes.map((transition) => {
      const axis = spec.axes.find((candidate) => candidate.name === transition.axis);
      return axis?.severityAtTop ?? null;
    }),
  );
  const topCount = increasingAxes.filter((transition) => {
    const axis = spec.axes.find((candidate) => candidate.name === transition.axis);
    const endpoint = spec.invertDanger ? transition.from : transition.to;
    return axis !== undefined && endpoint === axis.ranks[axis.ranks.length - 1];
  }).length;
  return topCount >= 2 ? "critical" : severity;
}
