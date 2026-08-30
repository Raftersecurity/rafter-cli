import type { ExtractResult, Extractor, Property, PropertyKind } from "./model.js";
import { KIND_SPEC_BY_KIND } from "./kind-specs.js";

/**
 * TEMPORARY — W4 scaffolding.
 *
 * The CLI shell, renderers, and exit codes (W4) ship before the real extractors
 * (W6 `container.port`, W7 `iam.allow`/`iam.deny`, W8 `pkg.lifecycle_script`).
 * This extractor reads `*.surface-stub.json` files that state their properties
 * directly, so the whole pipeline — tree reads, differ, coverage, exit codes —
 * can be exercised end to end without waiting on Wave 2.
 *
 * To retire it: delete this file and drop it from `EXTRACTORS` in `registry.ts`.
 * Nothing else references it.
 */

const STUB_SUFFIX = ".surface-stub.json";

interface StubProperty {
  kind: PropertyKind;
  key: string;
  discriminator?: string;
  subject: string;
  label: string;
  levels: Record<string, string | null>;
  attrs?: Record<string, string | number | boolean | null>;
  line?: number | null;
  pairingScope?: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toProperty(file: string, raw: unknown): Property {
  if (!isRecord(raw)) throw new Error("property entry is not an object");
  const stub = raw as unknown as StubProperty;
  if (!KIND_SPEC_BY_KIND.has(stub.kind)) throw new Error(`unknown kind '${stub.kind}'`);
  return {
    kind: stub.kind,
    key: stub.key,
    discriminator: stub.discriminator ?? "",
    subject: stub.subject,
    levels: { ...stub.levels },
    label: stub.label,
    attrs: { ...(stub.attrs ?? {}) },
    evidence: { file, line: stub.line ?? null },
    confidence: "certain",
    pairingScope: stub.pairingScope ?? null,
  };
}

export const stubExtractor: Extractor = {
  id: "stub",
  version: 1,
  kinds: ["container.port", "iam.allow", "iam.deny", "pkg.lifecycle_script"],

  candidate(path: string): boolean {
    return path.endsWith(STUB_SUFFIX);
  },

  extract(files: ReadonlyMap<string, string>): ExtractResult {
    const result: ExtractResult = { properties: [], unanalyzed: [] };
    for (const file of [...files.keys()].sort()) {
      let document: unknown;
      try {
        document = JSON.parse(files.get(file)!);
      } catch {
        // The caller overwrites `side` and `changed`; both are its business.
        result.unanalyzed.push({
          file,
          side: "base",
          reason: "parse_error",
          detail: "stub document is not valid JSON",
          changed: false,
        });
        continue;
      }
      if (!isRecord(document)) {
        result.unanalyzed.push({
          file,
          side: "base",
          reason: "parse_error",
          detail: "stub document is not an object",
          changed: false,
        });
        continue;
      }
      for (const entry of (document.unanalyzed as unknown[] | undefined) ?? []) {
        if (!isRecord(entry)) continue;
        result.unanalyzed.push({
          file,
          side: "base",
          reason: (entry.reason as ExtractResult["unanalyzed"][number]["reason"]) ?? "parse_error",
          detail: (entry.detail as string) ?? "",
          changed: false,
        });
      }
      for (const entry of (document.properties as unknown[] | undefined) ?? []) {
        result.properties.push(toProperty(file, entry));
      }
    }
    return result;
  },
};
