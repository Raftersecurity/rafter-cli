import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { diffProperties, type DiffCoverage } from "../src/core/surface/differ.js";
import { KEY_COMPONENTS, KIND_SPECS } from "../src/core/surface/kind-specs.js";
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
  const { label: _label, ...transition } = expected.transitions[0];
  return transition;
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
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
      })],
    );
  });

  it("classifies an IAM resource widening without Sid", () => {
    const key = "iam.allow:iam-json:policy.json|act=f084bba5e84ede8168b6c5b1ac07f2eea93c5e78290171b83d8f3f2709d10ba1|prin=none";
    expectCase(
      "iam-resource-widened-no-sid",
      [property("iam.allow", key, iamLevels(), { subject: "statement 1" })],
      [property("iam.allow", key, iamLevels({ resource: "global-wildcard" }), {
        subject: "statement 1",
        attrs: { effect: "Allow", action: "s3:GetObject", resource: "*" },
      })],
    );
  });

  it("reports an IAM mixed-axis transition as incomparable", () => {
    const baseKey = "iam.allow:iam-json:policy.json|act=1e63caf99cd654591e8916273241630a7117703bb5f6129bf7108ccef9e9ef52|prin=none";
    const headKey = "iam.allow:iam-json:policy.json|act=f084bba5e84ede8168b6c5b1ac07f2eea93c5e78290171b83d8f3f2709d10ba1|prin=none";
    expectCase(
      "iam-incomparable",
      [property("iam.allow", baseKey, iamLevels({ action: "service-wildcard" }), {
        subject: "statement 1",
        pairingScope: "policy.json",
      })],
      [property("iam.allow", headKey, iamLevels({ resource: "global-wildcard" }), {
        subject: "statement 1",
        pairingScope: "policy.json",
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

  it("keeps a null severityByLevel transition non-reportable", () => {
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

describe("surface structure and serialization", () => {
  it("keeps identity component names disjoint from axis names", () => {
    for (const spec of KIND_SPECS) {
      const axes = new Set(spec.axes.map((axis) => axis.name));
      expect(KEY_COMPONENTS[spec.kind].filter((component) => axes.has(component))).toEqual([]);
    }
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
    for (const caseId of fs.readdirSync(casesRoot)) {
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
