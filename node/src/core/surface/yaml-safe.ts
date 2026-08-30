import yaml from "js-yaml";

import type { UnanalyzedReason } from "./model.js";

export const MAX_YAML_DEPTH = 64;
export const MAX_YAML_NODES = 100_000;

export type YamlStringValue =
  | string
  | YamlStringValue[]
  | { [key: string]: YamlStringValue };

export type ParsedScalar = string | number | boolean | null;
export type YamlAdapterReason = Extract<
  UnanalyzedReason,
  "parse_error" | "unsupported_syntax"
>;

/**
 * A parser-boundary failure that an extractor can turn into an Unanalyzed record.
 * The adapter does not know the file, side, or changed status, so it carries only
 * the W1 reason and a content-free detail.
 */
export class YamlAdapterError extends Error {
  constructor(
    readonly reason: YamlAdapterReason,
    readonly detail: string,
  ) {
    super(detail);
    this.name = "YamlAdapterError";
  }
}

interface SyntaxNode {
  kind: string | null;
  result: unknown;
  children: SyntaxNode[];
}

interface NormalizationState {
  active: Set<object>;
  nodes: number;
}

const NULL_SCALARS = new Set(["~", "null", "Null", "NULL"]);
const TRUE_SCALARS = new Set(["true", "True", "TRUE"]);
const FALSE_SCALARS = new Set(["false", "False", "FALSE"]);
const DECIMAL_INTEGER = /^[+-]?(?:0|[1-9][0-9]*)$/;
const PARSE_ERROR_DETAIL = "YAML could not be parsed";
const UNSUPPORTED_TAG_DETAIL = "YAML uses an unsupported tag";
const UNSUPPORTED_KEY_DETAIL = "YAML mapping keys must be scalar strings";
const UNSUPPORTED_EMPTY_KEY_DETAIL = "Empty YAML mapping keys are unsupported";
const BLOCK_SCALAR_HEADER =
  /(?:^|:\s*|-\s*)[|>](?:(?:[+-]([1-9])?)|(?:([1-9])[+-]?))?\s*$/;

/**
 * Apply Rafter's scalar rules after string-only loading.
 *
 * Deliberately excluded: floats, timestamps, base-prefixed integers, digit
 * separators, and leading-zero integers. Keeping ambiguous forms as strings
 * prevents either runtime's YAML resolver from deciding their meaning.
 */
export function parseScalar(value: string): ParsedScalar {
  if (NULL_SCALARS.has(value)) return null;
  if (TRUE_SCALARS.has(value)) return true;
  if (FALSE_SCALARS.has(value)) return false;
  if (DECIMAL_INTEGER.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) return parsed === 0 ? 0 : parsed;
  }
  return value;
}

/**
 * Parse untrusted YAML without native scalar coercion.
 *
 * The trust boundary is: source text -> FAILSAFE parser -> syntax/shape checks
 * -> null-prototype string tree. Alias occurrences are copied under shared
 * depth/node budgets, which rejects cycles and expansion bombs before callers
 * serialize or inspect the result.
 */
export function loadYamlStringOnly(source: string): YamlStringValue {
  if (hasUnsupportedTab(source)) {
    throw new YamlAdapterError(
      "unsupported_syntax",
      "YAML containing tab characters is unsupported",
    );
  }

  const syntaxStack: SyntaxNode[] = [];
  let syntaxRoot: SyntaxNode | undefined;
  let loaded: unknown;
  try {
    loaded = yaml.load(source, {
      schema: yaml.FAILSAFE_SCHEMA,
      listener(event, parserState) {
        if (event === "open") {
          syntaxStack.push({ kind: null, result: null, children: [] });
          return;
        }
        const node = syntaxStack.pop();
        if (!node) {
          throw new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
        }
        node.kind = parserState.kind;
        node.result = parserState.result;
        const parent = syntaxStack[syntaxStack.length - 1];
        if (parent) parent.children.push(node);
        else syntaxRoot = node;
      },
      // js-yaml 4.3 supports these parser limits, though @types/js-yaml does
      // not yet expose them. The mirrored post-parse limits remain authoritative.
      maxDepth: MAX_YAML_DEPTH + 8,
      maxTotalMergeKeys: MAX_YAML_NODES,
    } as yaml.LoadOptions & { maxDepth: number; maxTotalMergeKeys: number });
  } catch (error) {
    throw adaptParserError(error);
  }

  try {
    if (syntaxStack.length !== 0) {
      throw new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
    }
    if (syntaxRoot) assertScalarMappingKeys(syntaxRoot);

    return normalizeValue(loaded, 0, { active: new Set(), nodes: 0 });
  } catch (error) {
    throw adaptParserError(error);
  }
}

function hasUnsupportedTab(source: string): boolean {
  let blockParentIndent: number | null = null;
  let blockContentIndent: number | null = null;
  let quote: "'" | '"' | null = null;

  for (const line of source.split(/\r?\n/)) {
    const indent = /^ */.exec(line)?.[0].length ?? 0;
    if (blockParentIndent !== null) {
      if (line.trim().length === 0 && !line.includes("\t")) continue;
      if (blockContentIndent === null && indent > blockParentIndent) {
        blockContentIndent = indent;
        continue;
      }
      if (blockContentIndent !== null && indent >= blockContentIndent) continue;
      blockParentIndent = null;
      blockContentIndent = null;
    }

    let structural = "";
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (quote === "'") {
        if (character === "'" && line[index + 1] === "'") index += 1;
        else if (character === "'") quote = null;
        continue;
      }
      if (quote === '"') {
        if (character === "\\") index += 1;
        else if (character === '"') quote = null;
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }
      if (character === "#" && (index === 0 || /\s/.test(line[index - 1]))) break;
      if (character === "\t") return true;
      structural += character;
    }
    const blockHeader = quote === null
      ? BLOCK_SCALAR_HEADER.exec(structural.trimEnd())
      : null;
    if (blockHeader) {
      const sequencePrefix = /^ *(?:- +)+/.exec(structural)?.[0];
      const explicitIndent = blockHeader[1] ?? blockHeader[2];
      const directSequenceScalar = sequencePrefix !== undefined
        && /^[|>]/.test(structural.slice(sequencePrefix.length));
      if (directSequenceScalar) {
        blockParentIndent = sequencePrefix.lastIndexOf("-");
        blockContentIndent = blockParentIndent + Number(explicitIndent ?? 2);
      } else {
        blockParentIndent = sequencePrefix?.length ?? indent;
        blockContentIndent = explicitIndent
          ? blockParentIndent + Number(explicitIndent)
          : null;
      }
    }
  }
  return false;
}

/** Public adapter name; the longer alias states the string-only contract. */
export const loadYamlSafe = loadYamlStringOnly;

function adaptParserError(error: unknown): YamlAdapterError {
  if (error instanceof YamlAdapterError) return error;
  if (error instanceof yaml.YAMLException) {
    const reason = error.reason ?? "";
    if (
      reason.includes("unknown tag")
      || reason.includes("unacceptable node kind")
      || reason.includes("cannot resolve a node")
    ) {
      return new YamlAdapterError("unsupported_syntax", UNSUPPORTED_TAG_DETAIL);
    }
    return new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
  }
  if (error instanceof RangeError) {
    return new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
  }
  return new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
}

function assertScalarMappingKeys(node: SyntaxNode): void {
  const wrapped = node.children.length === 1 ? node.children[0] : undefined;
  if (wrapped && wrapped.kind === node.kind && wrapped.result === node.result) {
    assertScalarMappingKeys(wrapped);
    return;
  }
  if (node.kind === "mapping") {
    if (node.children.length % 2 !== 0) {
      throw new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
    }
    for (let index = 0; index < node.children.length; index += 2) {
      const key = node.children[index];
      if (
        !((key.kind === "scalar" || key.kind === null) && typeof key.result === "string")
      ) {
        throw new YamlAdapterError(
          "unsupported_syntax",
          UNSUPPORTED_KEY_DETAIL,
        );
      }
      if (key.result.length === 0) {
        throw new YamlAdapterError(
          "unsupported_syntax",
          UNSUPPORTED_EMPTY_KEY_DETAIL,
        );
      }
    }
  }
  for (const child of node.children) assertScalarMappingKeys(child);
}

function normalizeValue(
  value: unknown,
  depth: number,
  state: NormalizationState,
): YamlStringValue {
  state.nodes += 1;
  if (state.nodes > MAX_YAML_NODES) {
    throw new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
  }
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value !== "object") {
    throw new YamlAdapterError(
      "unsupported_syntax",
      "YAML parser produced an unsupported scalar",
    );
  }
  if (depth >= MAX_YAML_DEPTH) {
    throw new YamlAdapterError("parse_error", PARSE_ERROR_DETAIL);
  }
  if (state.active.has(value)) {
    throw new YamlAdapterError("unsupported_syntax", "Cyclic YAML aliases are unsupported");
  }

  state.active.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizeValue(item, depth + 1, state));
    }
    const output = Object.create(null) as Record<string, YamlStringValue>;
    for (const key of Object.keys(value)) {
      if (key.length === 0) {
        throw new YamlAdapterError(
          "unsupported_syntax",
          UNSUPPORTED_EMPTY_KEY_DETAIL,
        );
      }
      output[key] = normalizeValue((value as Record<string, unknown>)[key], depth + 1, state);
    }
    return output;
  } finally {
    state.active.delete(value);
  }
}
