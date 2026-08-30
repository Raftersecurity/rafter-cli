import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { diffProperties, type DiffCoverage } from "../src/core/surface/differ.js";
import { KEY_COMPONENTS, KIND_SPECS } from "../src/core/surface/kind-specs.js";
import { parentScope } from "../src/core/surface/paths.js";
import type { KindSpec, Property, PropertyKind } from "../src/core/surface/model.js";
import {
  canonicalJson,
  kindSpecsToWire,
  sortUnanalyzed,
  transitionToWire,
} from "../src/core/surface/serialize.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function property(
  kind: PropertyKind,
  key: string,
  levels: Record<string, string | null>,
  options: Partial<Property> = {},
): Property {
  return {
    kind,
    key,
    discriminator: options.discriminator ?? key,
    subject: options.subject ?? key,
    levels,
    label: options.label ?? key,
    attrs: options.attrs ?? {},
    evidence: options.evidence ?? { file: kind.startsWith("iam.") ? "policy.json" : "compose.yml", line: 5 },
    confidence: "certain",
    pairingScope: options.pairingScope ?? null,
  };
}

const iamLevels = (overrides: Partial<Record<string, string | null>> = {}) => ({
  action: "literal",
  resource: "prefix-wildcard",
  principal: "absent-or-literal",
  condition: "absent",
  ...overrides,
});

function expectedTransition(caseId: string): Record<string, unknown> {
  const expected = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "fixtures/surface/cases", caseId, "expected.json"), "utf8"),
  );
  return expected.transitions[0];
}

function expectCase(caseId: string, base: Property[], head: Property[]): void {
  const transitions = diffProperties(base, head);
  expect(transitions).toHaveLength(1);
  expect(transitionToWire(transitions[0])).toEqual(expectedTransition(caseId));
}

describe("surface semantic fixtures", () => {
  it("classifies a Compose port appearance", () => {
    expectCase("compose-port-appears", [], [
      property(
        "container.port",
        "container.port:compose:compose.yml|redis|6379/tcp",
        { binding: "host-published" },
        {
          subject: "service redis",
          label: "redis port 6379 published on 0.0.0.0",
          attrs: { service: "redis", bind: "0.0.0.0", container_port: 6379, protocol: "tcp" },
        },
      ),
    ]);
  });

  it("classifies a Compose port narrowed to loopback", () => {
    const key = "container.port:compose:compose.yml|redis|6379/tcp";
    expectCase(
      "compose-port-narrowed",
      [property("container.port", key, { binding: "host-published" }, { subject: "service redis" })],
      [property("container.port", key, { binding: "loopback-published" }, {
        subject: "service redis",
        label: "redis port 6379 published on 127.0.0.1",
        attrs: { service: "redis", bind: "127.0.0.1", container_port: 6379, protocol: "tcp" },
      })],
    );
  });

  it("emits a residually paired Compose rename as unchanged", () => {
    expectCase(
      "compose-service-renamed",
      [property("container.port", "container.port:compose:compose.yml|redis|6379/tcp", { binding: "host-published" }, {
        subject: "service redis",
        pairingScope: "compose.yml",
      })],
      [property("container.port", "container.port:compose:compose.yml|cache|6379/tcp", { binding: "host-published" }, {
        subject: "service cache",
        label: "cache port 6379 published on 0.0.0.0",
        pairingScope: "compose.yml",
        attrs: { service: "cache", bind: "0.0.0.0", container_port: 6379, protocol: "tcp" },
      })],
    );
  });

  it("classifies an IAM resource widening with Sid", () => {
    const key = "iam.allow:iam-json:policy.json|sid=AppBucketAccess";
    expectCase(
      "iam-resource-widened-sid",
      [property("iam.allow", key, iamLevels(), { subject: "statement AppBucketAccess" })],
      [property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "statement AppBucketAccess",
        label: "Allow s3:GetObject on *",
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
      })],
    );
  });

  it("classifies an IAM resource widening without Sid", () => {
    const key = "iam.allow:iam-json:policy.json|nosid";
    expectCase(
      "iam-resource-widened-no-sid",
      [property("iam.allow", key, iamLevels(), { subject: "unnamed statement" })],
      [property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "unnamed statement",
        label: "Allow s3:GetObject on *",
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
      })],
    );
  });

  it("reports an IAM mixed-axis transition as incomparable", () => {
    const key = "iam.allow:iam-json:policy.json|nosid";
    expectCase(
      "iam-incomparable",
      [property("iam.allow", key, iamLevels({ action: "service-wildcard" }), {
        subject: "unnamed statement",
        discriminator: "",
      })],
      [property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "unnamed statement",
        label: "Allow s3:GetObject on *",
        discriminator: "",
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
      })],
    );
  });

  it("inverts danger when a broad IAM Deny is removed", () => {
    expectCase("iam-deny-removed", [
      property("iam.deny", "iam.deny:iam-json:policy.json|sid=BlockAllS3", iamLevels({
        action: "global-wildcard",
        resource: "global-wildcard",
      }), {
        subject: "statement BlockAllS3",
        label: "Deny * on *",
        attrs: { effect: "Deny", action: "*", resource: "*" },
      }),
    ], []);
  });

  it("classifies removal of an IAM Condition", () => {
    const key = "iam.allow:iam-json:policy.json|sid=OfficeOnly";
    expectCase(
      "iam-condition-removed",
      [property("iam.allow", key, iamLevels({ condition: "present" }), { subject: "statement OfficeOnly" })],
      [property("iam.allow", key, iamLevels(), {
        subject: "statement OfficeOnly",
        label: "Allow s3:GetObject on arn:aws:s3:::app-bucket/*",
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "arn:aws:s3:::app-bucket/*" },
      })],
    );
  });
});

describe("surface differ", () => {
  it("does not emit unchanged exact-key properties", () => {
    const prop = property("container.port", "same", { binding: "host-published" });
    expect(diffProperties([prop], [prop])).toEqual([]);
  });

  it("drops duplicate keys and marks the file parse_error", () => {
    const coverage: DiffCoverage = { unanalyzed: [] };
    const duplicate = property("container.port", "duplicate", { binding: "host-published" });
    expect(diffProperties([duplicate, { ...duplicate }], [], KIND_SPECS, coverage)).toEqual([]);
    expect(coverage.unanalyzed).toEqual([{
      file: "compose.yml",
      side: "base",
      reason: "parse_error",
      detail: "duplicate property key 'duplicate'",
      changed: false,
    }]);
  });

  it("cancels identical vectors within a repeated-key bucket before classifying the residue", () => {
    const key = "iam.allow:iam-json:policy.json|nosid";
    expectCase(
      "iam-two-nosid-statements-changed",
      [
        property("iam.allow", key, iamLevels({ resource: "literal" }), {
          subject: "unnamed statement",
          discriminator: "",
          evidence: { file: "policy.json", line: 5 },
        }),
        property("iam.allow", key, iamLevels(), {
          subject: "unnamed statement",
          discriminator: "",
          evidence: { file: "policy.json", line: 10 },
        }),
      ],
      [
        property("iam.allow", key, iamLevels({ resource: "literal" }), {
          subject: "unnamed statement",
          discriminator: "",
          evidence: { file: "policy.json", line: 5 },
        }),
        property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
          subject: "unnamed statement",
          label: "Allow s3:GetObject on *",
          discriminator: "",
          evidence: { file: "policy.json", line: 10 },
          attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
        }),
      ],
    );
  });

  it("matches unique discriminators across a file relocation without emitting no-ops", () => {
    const relocated = (
      file: string,
      service: string,
      port: number,
    ) => property(
      "container.port",
      `container.port:compose:${file}|${service}|${port}/tcp`,
      { binding: "host-published" },
      {
        subject: `service ${service}`,
        discriminator: `${service}|${port}/tcp`,
        pairingScope: "infra",
        evidence: { file, line: 5 },
      },
    );
    const specsWithoutPhase2 = KIND_SPECS.map((spec) => spec.kind === "container.port"
      ? { ...spec, allowResidualPairing: false }
      : spec);
    expect(diffProperties(
      [
        relocated("infra/docker-compose.yml", "redis", 6379),
        relocated("infra/docker-compose.yml", "web", 8080),
      ],
      [
        relocated("infra/compose.prod.yml", "redis", 6379),
        relocated("infra/compose.prod.yml", "web", 8080),
      ],
      specsWithoutPhase2,
    )).toEqual([]);
  });

  it("supports absentRank above", () => {
    const spec: KindSpec = {
      ...KIND_SPECS[0],
      axes: [{ ...KIND_SPECS[0].axes[0], absentRank: "above" }],
      severityWhenAbsent: "high",
      allowResidualPairing: false,
    };
    const transition = diffProperties(
      [property("container.port", "protected", { binding: "host-published" })],
      [],
      [spec],
    )[0];
    expect(transition).toMatchObject({ change: "removed", danger: "increased", severity: "high" });
    expect(transition.axes[0]).toMatchObject({ from: "host-published", to: null, order: "greater" });
  });

  it("keeps a null severityByRank transition non-reportable", () => {
    const transition = diffProperties([], [
      property("container.port", "internal", { binding: "not-published" }),
    ])[0];
    expect(transition).toMatchObject({ danger: "increased", severity: null });
  });

  it("returns unknown when any lattice axis is unknown", () => {
    const key = "unknown-condition";
    const transition = diffProperties(
      [property("iam.allow", key, iamLevels({ condition: "present" }))],
      [property("iam.allow", key, iamLevels({ condition: null }))],
    )[0];
    expect(transition).toMatchObject({ danger: "unknown", severity: null });
  });

  it("pairs only a unique 1:1 residual", () => {
    const oneBase = property("container.port", "a", { binding: "host-published" }, { pairingScope: "scope" });
    const oneHead = property("container.port", "b", { binding: "host-published" }, { pairingScope: "scope" });
    expect(diffProperties([oneBase], [oneHead])).toHaveLength(1);
    expect(diffProperties(
      [oneBase, { ...oneBase, key: "c" }],
      [oneHead, { ...oneHead, key: "d" }],
    )).toEqual(expect.arrayContaining([
      expect.objectContaining({ change: "added", paired: false }),
      expect.objectContaining({ change: "removed", paired: false }),
    ]));
    expect(diffProperties(
      [oneBase, { ...oneBase, key: "c" }],
      [oneHead, { ...oneHead, key: "d" }],
    )).toHaveLength(4);
  });

  it("forces a coverage-blocked addition to unknown", () => {
    const coverage: DiffCoverage = {
      unanalyzed: [{
        file: "broken.yml",
        side: "base",
        reason: "parse_error",
        detail: "invalid YAML",
        changed: true,
      }],
    };
    const transition = diffProperties(
      [],
      [property("container.port", "added", { binding: "host-published" })],
      KIND_SPECS,
      coverage,
    )[0];
    expect(transition).toMatchObject({ change: "added", danger: "unknown", severity: null });
  });

  it("sorts keys by UTF-8 bytes", () => {
    const transitions = diffProperties([], [
      property("container.port", "é", { binding: "host-published" }),
      property("container.port", "z", { binding: "host-published" }),
    ]);
    expect(transitions.map((transition) => transition.key)).toEqual(["z", "é"]);
  });
});

describe("surface cancellation determinism", () => {
  // IAM `Statement[]` order carries no meaning, so reordering a document must not
  // change which property survives cancellation. Ordering cancellation by input
  // position instead of by content makes the surviving label and evidence depend
  // on emission order — reorder-variance the W7 M1 mutation would fail on.
  const key = "iam.allow:iam-json:policy.json|nosid";
  const bucket = (subject: string, line: number): Property =>
    property("iam.allow", key, iamLevels(), {
      subject,
      label: `Allow s3:GetObject on ${subject}`,
      discriminator: "",
      evidence: { file: "policy.json", line },
      attrs: { effect: "Allow", action: "s3:GetObject", resource: subject },
    });

  it("picks the same cancellation survivor regardless of input order", () => {
    const alpha = bucket("bucket-alpha", 5);
    const beta = bucket("bucket-beta", 12);
    const head = [bucket("bucket-alpha", 5)];

    const forward = diffProperties([alpha, beta], head).map(transitionToWire);
    const reversed = diffProperties([beta, alpha], head).map(transitionToWire);

    expect(canonicalJson(forward)).toBe(canonicalJson(reversed));
    expect(forward).toHaveLength(1);
    expect(forward[0]).toMatchObject({ change: "removed", subject: "bucket-beta" });
  });
});

describe("surface severity by arrival rank", () => {
  // A2 F2. Severity is a function of the rank an axis ARRIVED at, never of the
  // fact that it moved. Before the fix every IAM axis moved from absent (rank -1)
  // to present, each contributed its old `severityAtTop`, and `principal`'s was
  // `critical` — so the narrowest expressible statement gated CI at `critical`.
  it("scores the narrowest expressible added Allow as severity null", () => {
    const transition = diffProperties([], [
      property("iam.allow", "iam.allow:iam-json:policy.json|sid=NarrowRead", {
        action: "literal",
        resource: "literal",
        principal: "absent-or-literal",
        condition: "present",
      }, {
        subject: "statement NarrowRead",
        label: "Allow s3:GetObject on arn:aws:s3:::app-bucket/report.csv",
      }),
    ])[0];
    expect(transition).toMatchObject({
      change: "added",
      danger: "increased",
      severity: null,
    });
  });

  // The accepted false positive: an added Allow with no Condition arrives at
  // `condition: absent`, a single `medium` contributor. Visible, never gating.
  it("scores an added Allow with no Condition as medium, not critical", () => {
    const transition = diffProperties([], [
      property("iam.allow", "iam.allow:iam-json:policy.json|sid=NoCondition", {
        action: "literal",
        resource: "literal",
        principal: "absent-or-literal",
        condition: "absent",
      }),
    ])[0];
    expect(transition).toMatchObject({ danger: "increased", severity: "medium" });
  });

  // The upper bound the fix must not flatten: two axes arriving at a `high` rank
  // promote to critical.
  it("promotes two strong contributing axes to critical", () => {
    const transition = diffProperties([], [
      property("iam.allow", "iam.allow:iam-json:policy.json|sid=Admin", {
        action: "global-wildcard",
        resource: "global-wildcard",
        principal: "absent-or-literal",
        condition: "absent",
      }),
    ])[0];
    expect(transition).toMatchObject({ danger: "increased", severity: "critical" });
  });

  it("gives every axis a severityByRank entry per rank, in both tables", () => {
    for (const spec of KIND_SPECS) {
      for (const axis of spec.axes) {
        expect(axis.severityByRank).toHaveLength(axis.ranks.length);
      }
    }
    const shared = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "fixtures/surface/kind-specs.json"), "utf8"),
    ) as Array<{ axes: Array<{ ranks: string[]; severityByRank: unknown[] }> }>;
    for (const spec of shared) {
      for (const axis of spec.axes) {
        expect(axis.severityByRank).toHaveLength(axis.ranks.length);
      }
    }
  });
});

describe("surface sort totality", () => {
  // A2 F8b. Under `keyMayRepeat`, two transitions can share severity, kind and
  // key; the v1 three-component sort left that tie to a stable sort, so the order
  // was a function of emission order — i.e. of `Statement[]` position.
  it("orders same-key transitions by content, not by emission order", () => {
    const key = "iam.allow:iam-json:policy.json|nosid";
    const statement = (resource: string, line: number): Property =>
      property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "unnamed statement",
        label: `Allow s3:GetObject on ${resource}`,
        discriminator: "",
        evidence: { file: "policy.json", line },
        attrs: { effect: "Allow", action: "s3:GetObject", resource },
      });
    const alpha = statement("*", 5);
    const beta = statement("**", 12);

    const forward = diffProperties([], [alpha, beta]);
    const reversed = diffProperties([], [beta, alpha]);

    expect(forward).toHaveLength(2);
    expect(forward.map((transition) => transition.key)).toEqual([key, key]);
    expect(forward.map((transition) => transition.severity)).toEqual(["high", "high"]);
    expect(canonicalJson(forward.map(transitionToWire)))
      .toBe(canonicalJson(reversed.map(transitionToWire)));
    expect(forward.map((transition) => transition.attrs.resource)).toEqual(["*", "**"]);
  });

  // The last resort: two byte-identical statements in one file differ only by
  // evidence line, and must still order deterministically.
  it("falls back to evidence for content-identical transitions", () => {
    const key = "iam.allow:iam-json:policy.json|nosid";
    const twin = (line: number): Property =>
      property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "unnamed statement",
        label: "Allow s3:GetObject on *",
        discriminator: "",
        evidence: { file: "policy.json", line },
      });
    const forward = diffProperties([], [twin(5), twin(12)]);
    const reversed = diffProperties([], [twin(12), twin(5)]);
    expect(forward.map((transition) => transition.headEvidence?.line)).toEqual([5, 12]);
    expect(canonicalJson(forward.map(transitionToWire)))
      .toBe(canonicalJson(reversed.map(transitionToWire)));
  });
});

describe("surface paired provenance", () => {
  // A2 F5. Every non-comparison field of a paired transition comes from the head
  // endpoint. The keys here are chosen so the deleted min-of-two rule would pick
  // the base key: all ten committed fixtures pass under either rule.
  it("takes the head-side key for a paired transition", () => {
    const transition = diffProperties(
      [property("container.port", "container.port:compose:a/compose.yml|cache|6379/tcp", {
        binding: "host-published",
      }, { subject: "service cache", pairingScope: "a" })],
      [property("container.port", "container.port:compose:a/compose.yml|redis|6379/tcp", {
        binding: "host-published",
      }, { subject: "service redis", pairingScope: "a" })],
    )[0];
    expect(transition).toMatchObject({
      key: "container.port:compose:a/compose.yml|redis|6379/tcp",
      subject: "service redis",
      paired: true,
      danger: "unchanged",
    });
  });
});

describe("surface path scopes", () => {
  // A2 F10. The repo root is spelled "", never "." and never "/". The empty
  // string is a valid scope and is not null, so callers must test `!== null`.
  it("takes the POSIX dirname with the repo root spelled empty", () => {
    expect(parentScope("compose.yml")).toBe("");
    expect(parentScope("a/compose.yml")).toBe("a");
    expect(parentScope("a/b/compose.yml")).toBe("a/b");
  });
});

describe("surface structure and serialization", () => {
  it("keeps key-component provenance disjoint from compared-axis provenance", () => {
    for (const spec of KIND_SPECS) {
      const keyFields = new Set(KEY_COMPONENTS[spec.kind].flatMap((component) => component.derivedFrom));
      const axisFields = new Set(spec.axes.flatMap((axis) => axis.derivedFrom));
      expect([...keyFields].filter((field) => axisFields.has(field)).sort()).toEqual([]);
    }
  });

  it("derives a discriminator by eliding locative key components", () => {
    const key = "container.port:compose:infra/docker-compose.yml|redis|6379/tcp";
    const observed = property("container.port", key, { binding: "host-published" }, {
      discriminator: "redis|6379/tcp",
    });
    const keyBody = key.split(":compose:")[1];
    expect(KEY_COMPONENTS[observed.kind].filter((component) => component.locative).map(
      (component) => component.component,
    )).toEqual(["path"]);
    expect(observed.discriminator).toBe(keyBody.split("|").slice(1).join("|"));
  });

  it("serializes the complete transition key set in schema order", () => {
    const transition = diffProperties([], [
      property("container.port", "added", { binding: "host-published" }, { label: "published port" }),
    ])[0];
    expect(Object.keys(transitionToWire(transition))).toEqual([
      "kind",
      "key",
      "subject",
      "label",
      "change",
      "danger",
      "severity",
      "axes",
      "from",
      "to",
      "confidence",
      "base_evidence",
      "head_evidence",
      "attrs",
      "paired",
    ]);
  });

  it("matches the canonical shared kind-spec dump", () => {
    const expected = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "fixtures/surface/kind-specs.json"), "utf8"),
    );
    expect(canonicalJson(kindSpecsToWire(KIND_SPECS))).toBe(canonicalJson(expected));
  });

  it("keeps every expected fixture internally consistent with the output schema", () => {
    const severityRank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
    const casesRoot = path.join(REPO_ROOT, "fixtures/surface/cases");
    const caseIds = fs.readdirSync(casesRoot);
    expect(caseIds).toHaveLength(10);
    for (const caseId of caseIds) {
      const expected = JSON.parse(fs.readFileSync(path.join(casesRoot, caseId, "expected.json"), "utf8"));
      expect(expected.schema_version).toBe(1);
      expect(expected.summary.reportable).toBe(
        expected.transitions.filter((transition: { severity: string | null }) => transition.severity !== null).length,
      );
      for (const danger of ["increased", "decreased", "incomparable", "unchanged", "unknown"] as const) {
        expect(expected.summary[danger]).toBe(
          expected.transitions.filter((transition: { danger: string }) => transition.danger === danger).length,
        );
      }
      for (const change of ["added", "removed", "modified"] as const) {
        expect(expected.summary[change]).toBe(
          expected.transitions.filter((transition: { change: string }) => transition.change === change).length,
        );
      }
      const severities = expected.transitions
        .map((transition: { severity: keyof typeof severityRank | null }) => transition.severity)
        .filter((severity: keyof typeof severityRank | null): severity is keyof typeof severityRank => severity !== null)
        .sort((left: keyof typeof severityRank, right: keyof typeof severityRank) => severityRank[right] - severityRank[left]);
      expect(expected.summary.highest_severity).toBe(severities[0] ?? null);
      expect(expected.coverage.degraded).toBe(expected.coverage.unanalyzed.length > 0);
      expect(expected.coverage.inconclusive).toBe(
        expected.coverage.unanalyzed.some((item: { changed: boolean }) => item.changed),
      );
      for (const transition of expected.transitions) {
        expect(Object.keys(transition)).toEqual([
          "kind", "key", "subject", "label", "change", "danger", "severity", "axes",
          "from", "to", "confidence", "base_evidence", "head_evidence", "attrs", "paired",
        ]);
        const spec = KIND_SPECS.find((candidate) => candidate.kind === transition.kind)!;
        expect(transition.axes.map((axis: { axis: string }) => axis.axis)).toEqual(
          spec.axes.map((axis) => axis.name),
        );
        expect(Object.keys(transition.attrs).every((key) => /^[\x00-\x7f]+$/.test(key))).toBe(true);
        expect(Object.values(transition.attrs).every(
          (value) => typeof value !== "number" || Number.isSafeInteger(value),
        )).toBe(true);
      }
    }
  });

  it("normalizes strings and recursively sorts canonical JSON", () => {
    expect(canonicalJson({ z: "e\u0301", a: "\ud800", n: 9007199254740991 })).toBe(
      "{\"a\":\"�\",\"n\":9007199254740991,\"z\":\"é\"}",
    );
    expect(() => canonicalJson({ value: 1.5 })).toThrow("safe integers");
    expect(() => canonicalJson({ value: 9007199254740992 })).toThrow("safe integers");
    expect(() => canonicalJson({ "é": 1 })).toThrow("non-ASCII object key");
    expect(canonicalJson(JSON.parse('{"__proto__":"value"}'))).toBe('{"__proto__":"value"}');
  });

  it("sorts unanalyzed paths by UTF-8 bytes", () => {
    const item = (file: string) => ({
      file,
      side: "base" as const,
      reason: "parse_error" as const,
      detail: "bad",
      changed: false,
    });
    expect(sortUnanalyzed([item("é.yml"), item("z.yml")]).map((entry) => entry.file)).toEqual([
      "z.yml",
      "é.yml",
    ]);
  });
});
