import type { KindSpec, PropertyKind } from "./model.js";

const IAM_AXES = [
  {
    name: "action",
    ranks: ["literal", "service-wildcard", "global-wildcard"],
    absentRank: "below",
    severityAtTop: "high",
  },
  {
    name: "resource",
    ranks: ["literal", "prefix-wildcard", "global-wildcard"],
    absentRank: "below",
    severityAtTop: "high",
  },
  {
    name: "principal",
    ranks: ["absent-or-literal", "wildcard"],
    absentRank: "below",
    severityAtTop: "critical",
  },
  {
    name: "condition",
    ranks: ["present", "absent"],
    absentRank: "below",
    severityAtTop: "medium",
  },
] as const;

export const KIND_SPECS: readonly KindSpec[] = [
  {
    kind: "container.port",
    comparator: "ordinal",
    axes: [
      {
        name: "binding",
        ranks: ["not-published", "loopback-published", "host-published"],
        absentRank: "below",
        severityAtTop: "high",
      },
    ],
    severityByLevel: [null, "low", "high"],
    invertDanger: false,
    allowResidualPairing: true,
    display: "published ports",
  },
  {
    kind: "iam.allow",
    comparator: "lattice",
    axes: IAM_AXES,
    severityWhenIncomparable: "medium",
    invertDanger: false,
    allowResidualPairing: true,
    display: "IAM allows",
  },
  {
    kind: "iam.deny",
    comparator: "lattice",
    axes: IAM_AXES,
    severityWhenIncomparable: "medium",
    invertDanger: true,
    allowResidualPairing: true,
    display: "IAM denies",
  },
  {
    kind: "pkg.lifecycle_script",
    comparator: "ordinal",
    axes: [
      {
        name: "fetch",
        ranks: ["local", "fetches-remote", "pipes-remote-to-interpreter"],
        absentRank: "below",
        severityAtTop: "critical",
      },
    ],
    severityByLevel: [null, "medium", "critical"],
    invertDanger: false,
    allowResidualPairing: false,
    display: "lifecycle scripts",
  },
];

export const KIND_SPEC_BY_KIND = new Map(
  KIND_SPECS.map((spec) => [spec.kind, spec] as const),
);

/** Domain identity components, named separately from comparison axes. */
export const KEY_COMPONENTS: Readonly<Record<PropertyKind, readonly string[]>> = {
  "container.port": ["path", "service", "container_port", "protocol"],
  "iam.allow": ["path", "effect", "sid", "action_hash", "principal_hash"],
  "iam.deny": ["path", "effect", "sid", "action_hash", "principal_hash"],
  "pkg.lifecycle_script": ["path", "script_name"],
};
