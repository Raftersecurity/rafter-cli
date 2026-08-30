import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../src/core/surface/serialize.js";
import {
  loadYamlStringOnly,
  parseScalar,
  YamlAdapterError,
} from "../src/core/surface/yaml-safe.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const DIVERGENCE_EXPECTED = {
  a: "yes",
  b: "no",
  c: "on",
  d: "0o17",
  e: "017",
  f: "0x1F",
  g: "1_000",
  h: "27017:27017",
  i: "27017:27017",
  j: "3.0",
  k: "08",
};

function expectYamlError(
  source: string,
  reason: "parse_error" | "unsupported_syntax",
  detail: string,
): void {
  try {
    loadYamlStringOnly(source);
    throw new Error("expected YAML adapter to reject source");
  } catch (error) {
    expect(error).toBeInstanceOf(YamlAdapterError);
    expect((error as YamlAdapterError).reason).toBe(reason);
    expect((error as YamlAdapterError).detail).toBe(detail);
  }
}

describe("surface YAML string-only adapter", () => {
  it("matches the hand-written divergence fixture byte for byte", () => {
    const source = fs.readFileSync(
      path.join(REPO_ROOT, "fixtures/surface/yaml-divergence.yml"),
      "utf8",
    );

    expect(canonicalJson(loadYamlStringOnly(source))).toBe(canonicalJson(DIVERGENCE_EXPECTED));
  });

  it("rejects a duplicate mapping key with a typed parse_error", () => {
    expectYamlError("value: one\nvalue: two\n", "parse_error", "YAML could not be parsed");
  });

  it("normalizes empty nodes and empty documents to empty strings", () => {
    expect(canonicalJson(loadYamlStringOnly("mapping:\nsequence:\n  -\n"))).toBe(
      canonicalJson({ mapping: "", sequence: [""] }),
    );
    expect(loadYamlStringOnly("")).toBe("");
    expect(loadYamlStringOnly("---\n")).toBe("");
  });

  it("retains a merge key as a literal mapping key", () => {
    const source = [
      "base: &base",
      "  enabled: yes",
      "derived:",
      "  <<: *base",
      "  port: 017",
      "",
    ].join("\n");

    expect(canonicalJson(loadYamlStringOnly(source))).toBe(canonicalJson({
      base: { enabled: "yes" },
      derived: { "<<": { enabled: "yes" }, port: "017" },
    }));
  });

  it("resolves ordinary anchors and aliases without scalar coercion", () => {
    const source = [
      "base: &base",
      "  enabled: yes",
      "  port: 017",
      "copy: *base",
      "",
    ].join("\n");
    const expected = {
      base: { enabled: "yes", port: "017" },
      copy: { enabled: "yes", port: "017" },
    };

    expect(canonicalJson(loadYamlStringOnly(source))).toBe(canonicalJson(expected));
  });

  it("keeps additional divergent scalar forms as strings", () => {
    const source = [
      "sexagesimal: 12:34:56",
      "scientific: 1e3",
      "timestamp: 2025-01-02",
      "huge: 9007199254740993",
      "infinity: .inf",
      "null_word: null",
      "null_tilde: ~",
      "",
    ].join("\n");

    expect(canonicalJson(loadYamlStringOnly(source))).toBe(canonicalJson({
      sexagesimal: "12:34:56",
      scientific: "1e3",
      timestamp: "2025-01-02",
      huge: "9007199254740993",
      infinity: ".inf",
      null_word: "null",
      null_tilde: "~",
    }));
  });

  it("rejects tags, unsafe keys, cyclic aliases, and tabs as unsupported", () => {
    expectYamlError(
      "value: !!int 17\n",
      "unsupported_syntax",
      "YAML uses an unsupported tag",
    );
    expectYamlError(
      "[a, b]: value\n",
      "unsupported_syntax",
      "YAML mapping keys must be scalar strings",
    );
    expectYamlError(
      '"": value\n',
      "unsupported_syntax",
      "Empty YAML mapping keys are unsupported",
    );
    expectYamlError(
      "value: &value\n  self: *value\n",
      "unsupported_syntax",
      "Cyclic YAML aliases are unsupported",
    );
    expectYamlError(
      "value: plain\ttext\n",
      "unsupported_syntax",
      "YAML containing tab characters is unsupported",
    );
    expectYamlError(
      "block: |\n\t\nend: value\n",
      "unsupported_syntax",
      "YAML containing tab characters is unsupported",
    );
    expectYamlError(
      "- block: |\n    content\n  value: plain\ttext\n",
      "unsupported_syntax",
      "YAML containing tab characters is unsupported",
    );
    expectYamlError(
      "key: &key value\n*key: other\n",
      "parse_error",
      "YAML could not be parsed",
    );
  });

  it("accepts flow mappings and Unicode input keys", () => {
    expect(loadYamlStringOnly("{a: b, c: [d, e]}\n")).toEqual({
      a: "b",
      c: ["d", "e"],
    });
    expect(loadYamlStringOnly("a:\n  - {b: c}\n")).toEqual({ a: [{ b: "c" }] });
    expect(loadYamlStringOnly("café: value\n")).toEqual({ café: "value" });
    expect(loadYamlStringOnly("key: &key value\n? *key\n: other\n")).toEqual({
      key: "value",
      value: "other",
    });
  });

  it("allows tabs inside quoted strings, comments, and block scalars", () => {
    const source = [
      'double: "left\tright"',
      "single: 'left\tright'",
      "comment: value # left\tright",
      "block: |",
      "  left\tright",
      "explicit: |2",
      "    first",
      "  left\tright",
      "sequence:",
      "  - |",
      "    left\tright",
      "nested:",
      "  -   - |",
      "        left\tright",
      "",
    ].join("\n");

    expect(canonicalJson(loadYamlStringOnly(source))).toBe(canonicalJson({
      double: "left\tright",
      single: "left\tright",
      comment: "value",
      block: "left\tright\n",
      explicit: "  first\nleft\tright\n",
      sequence: ["left\tright\n"],
      nested: [["left\tright\n"]],
    }));
  });

  it("rejects structures beyond the shared nesting budget", () => {
    const source = `value: ${"[".repeat(65)}leaf${"]".repeat(65)}\n`;

    expectYamlError(source, "parse_error", "YAML could not be parsed");
  });

  it("copies prototype-shaped keys into inert mappings", () => {
    const loaded = loadYamlStringOnly("__proto__:\n  polluted: yes\nconstructor: safe\n");

    expect(canonicalJson(loaded)).toBe(
      canonicalJson(JSON.parse('{"__proto__":{"polluted":"yes"},"constructor":"safe"}')),
    );
    expect(({} as { polluted?: string }).polluted).toBeUndefined();
  });
});

describe("surface YAML scalar parsing", () => {
  it("coerces only the shared null, boolean, and safe-decimal lists", () => {
    const cases: Array<[string, string | number | boolean | null]> = [
      ["~", null],
      ["null", null],
      ["Null", null],
      ["NULL", null],
      ["true", true],
      ["True", true],
      ["TRUE", true],
      ["false", false],
      ["False", false],
      ["FALSE", false],
      ["0", 0],
      ["+0", 0],
      ["-0", 0],
      ["+17", 17],
      ["-17", -17],
      ["9007199254740991", 9007199254740991],
    ];

    for (const [source, expected] of cases) expect(parseScalar(source)).toBe(expected);
  });

  it("preserves ambiguous and unsupported scalar forms", () => {
    const values = [
      "",
      "yes",
      "no",
      "on",
      "off",
      "017",
      "08",
      "0o17",
      "0x1F",
      "1_000",
      "3.0",
      "1e3",
      "12:34:56",
      "2025-01-02",
      "9007199254740992",
      "-9007199254740992",
      "9".repeat(4_301),
    ];

    for (const value of values) expect(parseScalar(value)).toBe(value);
  });
});
