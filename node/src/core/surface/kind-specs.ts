import type { KindSpec, PropertyKind } from "./model.js";

const IAM_AXES = [
  {
    name: "action",
    derivedFrom: ["Action"],
    ranks: ["literal", "service-wildcard", "global-wildcard"],
    absentRank: "below",
    severityByRank: [null, "medium", "high"],
  },
  {
    name: "resource",
    derivedFrom: ["Resource"],
    ranks: ["literal", "prefix-wildcard", "global-wildcard"],
    absentRank: "below",
    severityByRank: [null, "medium", "high"],
  },
  {
    name: "principal",
    derivedFrom: ["Principal"],
    ranks: ["absent-or-literal", "wildcard"],
    absentRank: "below",
    severityByRank: [null, "critical"],
  },
  {
    name: "condition",
    derivedFrom: ["Condition"],
    ranks: ["present", "absent"],
    absentRank: "below",
    severityByRank: [null, "medium"],
  },
] as const;

export const KIND_SPECS: readonly KindSpec[] = [
  {
    kind: "container.port",
    comparator: "ordinal",
    axes: [
      {
        name: "binding",
        derivedFrom: ["ports[].host_ip", "ports[].published", "ports[].mode", "expose"],
        ranks: ["not-published", "loopback-published", "host-published"],
        absentRank: "below",
        severityByRank: [null, "low", "high"],
      },
    ],
    invertDanger: false,
    allowResidualPairing: true,
    keyMayRepeat: false,
    display: "published ports",
  },
  {
    kind: "iam.allow",
    comparator: "lattice",
    axes: IAM_AXES,
    severityWhenIncomparable: "medium",
    invertDanger: false,
    allowResidualPairing: true,
    keyMayRepeat: true,
    display: "IAM allows",
  },
  {
    kind: "iam.deny",
    comparator: "lattice",
    axes: IAM_AXES,
    severityWhenIncomparable: "medium",
    invertDanger: true,
    allowResidualPairing: true,
    keyMayRepeat: true,
    display: "IAM denies",
  },
  {
    kind: "pkg.lifecycle_script",
    comparator: "ordinal",
    axes: [
      {
        name: "fetch",
        derivedFrom: ["scripts.<name>.body"],
        ranks: ["local", "fetches-remote", "pipes-remote-to-interpreter"],
        absentRank: "below",
        severityByRank: [null, "medium", "critical"],
      },
    ],
    invertDanger: false,
    allowResidualPairing: false,
    keyMayRepeat: false,
    display: "lifecycle scripts",
  },
];

export const KIND_SPEC_BY_KIND = new Map(
  KIND_SPECS.map((spec) => [spec.kind, spec] as const),
);

export interface KeyComponentSpec {
  component: string;
  derivedFrom: readonly string[];
  locative: boolean;
}

/** Domain identity components and their artifact-field provenance. */
export const KEY_COMPONENTS: Readonly<Record<PropertyKind, readonly KeyComponentSpec[]>> = {
  "container.port": [
    { component: "path", derivedFrom: ["file-path"], locative: true },
    { component: "service", derivedFrom: ["service-name"], locative: false },
    { component: "container_port", derivedFrom: ["ports[].target"], locative: false },
    { component: "protocol", derivedFrom: ["ports[].protocol"], locative: false },
  ],
  "iam.allow": [
    { component: "path", derivedFrom: ["file-path"], locative: true },
    { component: "effect", derivedFrom: ["Effect"], locative: false },
    { component: "sid", derivedFrom: ["Sid"], locative: false },
  ],
  "iam.deny": [
    { component: "path", derivedFrom: ["file-path"], locative: true },
    { component: "effect", derivedFrom: ["Effect"], locative: false },
    { component: "sid", derivedFrom: ["Sid"], locative: false },
  ],
  "pkg.lifecycle_script": [
    { component: "path", derivedFrom: ["file-path"], locative: true },
    { component: "script_name", derivedFrom: ["scripts.<name>"], locative: false },
  ],
};
