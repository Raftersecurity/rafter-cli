import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import type { Unanalyzed, UnanalyzedReason } from "../core/surface/model.js";

export const EMPTY_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_CANDIDATES = 2000;
export const BINARY_SNIFF_BYTES = 8 * 1024;
export const EXTRACTION_TIMEOUT_MS = 20_000;
export const MAX_BATCH_BYTES = 32 * 1024 * 1024;

const OID_RE = /^[0-9a-f]{40}$/;
const MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024;

export interface GitRunOptions {
  cwd: string;
  input?: Buffer;
  timeoutMs?: number;
}

export type GitRunner = (args: readonly string[], options: GitRunOptions) => Buffer;

export interface BaseTreeReaderOptions {
  runner?: GitRunner;
  maxFileBytes?: number;
  maxCandidates?: number;
  timeoutMs?: number;
  maxBatchBytes?: number;
  clock?: () => number;
}

export interface TreeEntry {
  /** Repo-relative, forward slashes, NFC-normalized. */
  path: string;
  /** Original Git path used for filesystem access; consumers should use path. */
  rawPath: string;
  mode: string;
  type: "blob" | "commit";
  /** Empty only for a working-tree entry. */
  oid: string;
  sizeBytes: number;
}

export interface CandidateReadResult {
  files: Map<string, string>;
  unanalyzed: Unanalyzed[];
}

export class InvalidRefError extends Error {
  readonly code = "invalid_ref";
  readonly exitCode = 2;

  constructor(ref: string) {
    super(`Invalid git ref: ${JSON.stringify(ref)}`);
    this.name = "InvalidRefError";
  }
}

export class RefResolutionError extends Error {
  readonly code = "base_unresolved";
  readonly exitCode = 3;

  constructor(ref: string) {
    super(`Could not resolve git ref to a commit: ${JSON.stringify(ref)}`);
    this.name = "RefResolutionError";
  }
}

function defaultGitRunner(args: readonly string[], options: GitRunOptions): Buffer {
  return execFileSync("git", args, {
    cwd: options.cwd,
    input: options.input,
    encoding: "buffer",
    stdio: ["pipe", "pipe", "pipe"],
    timeout: options.timeoutMs,
    maxBuffer: MAX_GIT_OUTPUT_BYTES,
  });
}

export function validateRef(ref: string): void {
  if (!ref || ref.startsWith("-") || ref.includes("\0")) {
    throw new InvalidRefError(ref);
  }
}

function assertOid(oid: string): void {
  if (!OID_RE.test(oid)) {
    throw new Error(`Expected a resolved 40-hex git object ID, got ${JSON.stringify(oid)}`);
  }
}

function decodePath(value: Buffer): string {
  return value.toString("utf8");
}

function splitNul(output: Buffer): Buffer[] {
  const fields: Buffer[] = [];
  let start = 0;
  for (let index = 0; index < output.length; index++) {
    if (output[index] !== 0) continue;
    fields.push(output.subarray(start, index));
    start = index + 1;
  }
  if (start < output.length) {
    throw new Error("Malformed git output: missing NUL terminator");
  }
  return fields;
}

function isTimeoutError(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
}

function isMissingRefError(error: unknown): boolean {
  return (error as { status?: unknown } | undefined)?.status === 1;
}

export class BaseTreeReader {
  private readonly runner: GitRunner;
  private readonly maxFileBytes: number;
  private readonly maxCandidates: number;
  private readonly timeoutMs: number;
  private readonly maxBatchBytes: number;
  private readonly clock: () => number;

  constructor(
    private readonly repoPath: string,
    options: BaseTreeReaderOptions = {},
  ) {
    this.runner = options.runner ?? defaultGitRunner;
    this.maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
    this.maxCandidates = options.maxCandidates ?? MAX_CANDIDATES;
    this.timeoutMs = options.timeoutMs ?? EXTRACTION_TIMEOUT_MS;
    this.maxBatchBytes = options.maxBatchBytes ?? MAX_BATCH_BYTES;
    this.clock = options.clock ?? Date.now;
  }

  static validateRef(ref: string): void {
    validateRef(ref);
  }

  resolveRef(ref: string): string {
    validateRef(ref);
    const resolved = this.tryResolveCommit(ref);
    if (resolved) return resolved;

    const parent = this.parentRequestTarget(ref);
    if (parent) {
      const parentOid = this.tryResolveCommit(parent);
      if (parentOid && this.isRootCommit(parentOid)) return EMPTY_TREE_OID;
    }

    if (!this.tryResolveCommit("HEAD")) {
      this.run(["rev-parse", "--git-dir"]);
      return EMPTY_TREE_OID;
    }
    throw new RefResolutionError(ref);
  }

  listTree(oid: string, timeoutMs?: number): TreeEntry[] {
    assertOid(oid);
    const output = this.run(["ls-tree", "-r", "-z", "--long", oid], undefined, timeoutMs);
    return splitNul(output)
      .filter((record) => record.length > 0)
      .map((record) => this.parseTreeEntry(record));
  }

  listWorkTree(timeoutMs?: number): TreeEntry[] {
    const output = this.run(
      ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
      undefined,
      timeoutMs,
    );
    const entries: TreeEntry[] = [];
    for (const field of splitNul(output)) {
      if (field.length === 0) continue;
      const rawPath = decodePath(field);
      const inspected = this.inspectWorkTreePath(rawPath);
      if (inspected) entries.push(inspected);
    }
    return entries;
  }

  changedPaths(baseOid: string, headOid?: string): Set<string> {
    assertOid(baseOid);
    if (headOid !== undefined) assertOid(headOid);
    const args = ["diff", "--name-status", "-z", "--no-renames", "--end-of-options", baseOid];
    if (headOid !== undefined) args.push(headOid);
    const changed = this.parseNameStatus(this.run(args));
    if (headOid === undefined) {
      const untracked = this.run(["ls-files", "--others", "--exclude-standard", "-z"]);
      for (const field of splitNul(untracked)) {
        if (field.length > 0) changed.add(decodePath(field).normalize("NFC"));
      }
    }
    return changed;
  }

  readBlob(oid: string, timeoutMs?: number): Buffer {
    assertOid(oid);
    return this.run(["cat-file", "blob", oid], undefined, timeoutMs);
  }

  readAt(oid: string, requestedPath: string, timeoutMs?: number): Buffer {
    assertOid(oid);
    const normalizedPath = requestedPath.normalize("NFC");
    const matches = this.listTree(oid, timeoutMs).filter((entry) => entry.path === normalizedPath);
    if (matches.length !== 1) {
      throw new Error(
        matches.length === 0
          ? `Path is absent from tree: ${JSON.stringify(requestedPath)}`
          : `Multiple tree paths normalize to: ${JSON.stringify(normalizedPath)}`,
      );
    }
    const entry = matches[0];
    if (entry.mode === "120000" || entry.mode === "160000" || entry.type === "commit") {
      throw new Error(`Refusing to read symlink or submodule: ${JSON.stringify(normalizedPath)}`);
    }
    return this.readBlob(entry.oid, timeoutMs);
  }

  readBlobs(
    oids: readonly string[],
    timeoutMs?: number,
    deadline?: number,
  ): Map<string, Buffer> {
    for (const oid of oids) assertOid(oid);
    if (oids.length === 0) return new Map();
    try {
      const input = Buffer.from(`${oids.join("\n")}\n`, "ascii");
      const output = this.run(["cat-file", "--batch"], input, timeoutMs);
      if (deadline !== undefined && this.expired(deadline)) throw this.timeoutError();
      return this.parseBatchBlobs(oids, output);
    } catch (error) {
      if (isTimeoutError(error)) throw error;
      const blobs = new Map<string, Buffer>();
      for (const oid of oids) {
        const remaining = deadline === undefined ? timeoutMs : this.remaining(deadline);
        blobs.set(oid, this.readBlob(oid, remaining));
      }
      return blobs;
    }
  }

  readTreeCandidates(
    oid: string,
    candidate: (path: string, sizeBytes: number) => boolean,
    changedPaths: ReadonlySet<string> = new Set(),
    side: "base" | "head" = "base",
  ): CandidateReadResult {
    const started = this.clock();
    const deadline = started + this.timeoutMs;
    let entries: TreeEntry[];
    try {
      entries = this.listTree(oid, this.remaining(deadline));
    } catch (error) {
      if (isTimeoutError(error)) return this.timeoutResult(side, changedPaths);
      throw error;
    }
    const candidates = entries.filter((entry) => candidate(entry.path, entry.sizeBytes));
    const limited = this.enforceCandidateLimit(candidates, side, changedPaths);
    if (limited) return limited;

    const result: CandidateReadResult = { files: new Map(), unanalyzed: [] };
    const readable: TreeEntry[] = [];
    const collisionPaths = this.canonicalCollisionPaths(candidates);
    for (let index = 0; index < candidates.length; index++) {
      const entry = candidates[index];
      if (this.expired(deadline)) {
        this.markRemaining(result, candidates.slice(index), side, "timeout", changedPaths);
        break;
      }
      if (collisionPaths.has(entry.path)) {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "parse_error",
            "multiple repository paths normalize to the same NFC path",
            changedPaths,
          ),
        );
      } else if (entry.mode === "120000" || entry.mode === "160000" || entry.type === "commit") {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "symlink",
            "symlinks, submodules, and nonregular files are not read",
            changedPaths,
          ),
        );
      } else if (entry.sizeBytes > this.maxFileBytes) {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "too_large",
            `file is ${entry.sizeBytes} bytes; limit is ${this.maxFileBytes}`,
            changedPaths,
          ),
        );
      } else {
        readable.push(entry);
      }
    }

    if (readable.length === 0 || result.unanalyzed.some((item) => item.reason === "timeout")) {
      return result;
    }
    for (let cursor = 0; cursor < readable.length; ) {
      const batch: TreeEntry[] = [];
      let batchBytes = 0;
      while (cursor + batch.length < readable.length) {
        const entry = readable[cursor + batch.length];
        if (batch.length > 0 && batchBytes + entry.sizeBytes > this.maxBatchBytes) break;
        batch.push(entry);
        batchBytes += entry.sizeBytes;
      }
      try {
        const blobs = this.readBlobs(
          [...new Set(batch.map((entry) => entry.oid))],
          this.remaining(deadline),
          deadline,
        );
        for (const entry of batch) {
          const content = blobs.get(entry.oid);
          if (!content) throw new Error(`git cat-file omitted ${entry.oid}`);
          this.acceptContent(result, entry.path, side, content, changedPaths);
        }
        cursor += batch.length;
      } catch (error) {
        const reason: UnanalyzedReason = isTimeoutError(error) ? "timeout" : "parse_error";
        const detail =
          reason === "timeout" ? "20-second extraction budget expired" : "could not read git blob";
        this.markRemaining(result, readable.slice(cursor), side, reason, changedPaths, detail);
        break;
      }
    }
    return result;
  }

  readWorkTreeCandidates(
    candidate: (path: string, sizeBytes: number) => boolean,
    changedPaths: ReadonlySet<string> = new Set(),
  ): CandidateReadResult {
    const side = "head" as const;
    const deadline = this.clock() + this.timeoutMs;
    let entries: TreeEntry[];
    try {
      entries = this.listWorkTree(this.remaining(deadline));
    } catch (error) {
      if (isTimeoutError(error)) return this.timeoutResult(side, changedPaths);
      throw error;
    }
    const candidates = entries.filter((entry) => candidate(entry.path, entry.sizeBytes));
    const limited = this.enforceCandidateLimit(candidates, side, changedPaths);
    if (limited) return limited;

    const result: CandidateReadResult = { files: new Map(), unanalyzed: [] };
    const collisionPaths = this.canonicalCollisionPaths(candidates);
    for (let index = 0; index < candidates.length; index++) {
      const entry = candidates[index];
      if (this.expired(deadline)) {
        this.markRemaining(result, candidates.slice(index), side, "timeout", changedPaths);
        break;
      }
      if (collisionPaths.has(entry.path)) {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "parse_error",
            "multiple repository paths normalize to the same NFC path",
            changedPaths,
          ),
        );
        continue;
      }
      if (entry.mode === "120000" || entry.mode === "160000" || entry.type === "commit") {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "symlink",
            "symlinks, submodules, and nonregular files are not read",
            changedPaths,
          ),
        );
        continue;
      }
      if (entry.sizeBytes > this.maxFileBytes) {
        result.unanalyzed.push(
          this.unanalyzed(
            entry.path,
            side,
            "too_large",
            `file is ${entry.sizeBytes} bytes; limit is ${this.maxFileBytes}`,
            changedPaths,
          ),
        );
        continue;
      }
      try {
        const content = this.readContainedFile(entry.rawPath);
        if (this.expired(deadline)) {
          this.markRemaining(result, candidates.slice(index), side, "timeout", changedPaths);
          break;
        }
        if (content.length > this.maxFileBytes) {
          result.unanalyzed.push(
            this.unanalyzed(
              entry.path,
              side,
              "too_large",
              `file grew beyond the ${this.maxFileBytes}-byte limit while reading`,
              changedPaths,
            ),
          );
        } else {
          this.acceptContent(result, entry.path, side, content, changedPaths);
        }
      } catch (error) {
        const reason = this.pathContainsSymlink(entry.rawPath) ? "symlink" : "parse_error";
        const detail =
          reason === "symlink"
            ? "path contains a symlink"
            : "could not safely read working-tree file";
        result.unanalyzed.push(
          this.unanalyzed(entry.path, side, reason, detail, changedPaths),
        );
      }
    }
    return result;
  }

  isShallow(): boolean {
    return this.run(["rev-parse", "--is-shallow-repository"]).toString("utf8").trim() === "true";
  }

  private tryResolveCommit(ref: string): string | null {
    try {
      const oid = this.run([
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        `${ref}^{commit}`,
      ])
        .toString("ascii")
        .trim();
      assertOid(oid);
      return oid;
    } catch (error) {
      if (isMissingRefError(error)) return null;
      throw error;
    }
  }

  private parentRequestTarget(ref: string): string | null {
    if (ref.endsWith("^1") || ref.endsWith("~1")) return ref.slice(0, -2);
    if (ref.endsWith("^")) return ref.slice(0, -1);
    return null;
  }

  private isRootCommit(oid: string): boolean {
    const fields = this.run(["rev-list", "--parents", "-n", "1", oid])
      .toString("ascii")
      .trim()
      .split(/\s+/);
    return fields.length === 1 && fields[0] === oid;
  }

  private parseTreeEntry(record: Buffer): TreeEntry {
    const separator = record.indexOf(9);
    if (separator < 0) throw new Error("Malformed git ls-tree record: missing path separator");
    const metadata = record.subarray(0, separator).toString("ascii").trim().split(/\s+/);
    if (metadata.length !== 4) throw new Error("Malformed git ls-tree record metadata");
    const [mode, objectType, oid, size] = metadata;
    if (objectType !== "blob" && objectType !== "commit") {
      throw new Error(`Unsupported git object type in tree: ${objectType}`);
    }
    assertOid(oid);
    const rawPath = decodePath(record.subarray(separator + 1));
    return {
      mode,
      type: objectType,
      oid,
      sizeBytes: size === "-" ? 0 : Number(size),
      path: rawPath.normalize("NFC"),
      rawPath,
    };
  }

  private parseNameStatus(output: Buffer): Set<string> {
    const fields = splitNul(output).filter((field) => field.length > 0);
    const changed = new Set<string>();
    for (let index = 0; index < fields.length; ) {
      const token = fields[index].toString("utf8");
      const tab = token.indexOf("\t");
      if (tab >= 0) {
        changed.add(decodePath(fields[index].subarray(tab + 1)).normalize("NFC"));
        index++;
        continue;
      }
      if (index + 1 >= fields.length) throw new Error("Malformed git --name-status -z output");
      changed.add(decodePath(fields[index + 1]).normalize("NFC"));
      index += 2;
    }
    return changed;
  }

  private inspectWorkTreePath(rawPath: string): TreeEntry | null {
    const absolutePath = this.containedPath(rawPath);
    const normalizedPath = rawPath.normalize("NFC");
    const parts = rawPath.split("/");
    let current = path.resolve(this.repoPath);
    for (let index = 0; index < parts.length; index++) {
      current = path.join(current, parts[index]);
      try {
        const stat = fs.lstatSync(current);
        if (stat.isSymbolicLink()) {
          return {
            path: normalizedPath,
            rawPath,
            mode: "120000",
            type: "blob",
            oid: "",
            sizeBytes: stat.size,
          };
        }
        if (index === parts.length - 1) {
          if (stat.isDirectory()) {
            return {
              path: normalizedPath,
              rawPath,
              mode: "160000",
              type: "commit",
              oid: "",
              sizeBytes: 0,
            };
          }
          if (!stat.isFile()) {
            return {
              path: normalizedPath,
              rawPath,
              mode: "120000",
              type: "blob",
              oid: "",
              sizeBytes: stat.size,
            };
          }
          return {
            path: normalizedPath,
            rawPath,
            mode: stat.mode & 0o111 ? "100755" : "100644",
            type: "blob",
            oid: "",
            sizeBytes: stat.size,
          };
        }
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") return null;
        throw error;
      }
    }
    void absolutePath;
    return null;
  }

  private containedPath(relativePath: string): string {
    if (!relativePath || path.posix.isAbsolute(relativePath)) {
      throw new Error(`Git returned a non-relative path: ${JSON.stringify(relativePath)}`);
    }
    const parts = relativePath.split("/");
    if (path.sep === "\\" && relativePath.includes("\\")) {
      throw new Error(`Git returned an unsafe path: ${JSON.stringify(relativePath)}`);
    }
    if (parts.some((part) => part === "" || part === "." || part === "..")) {
      throw new Error(`Git returned an unsafe path: ${JSON.stringify(relativePath)}`);
    }
    const root = path.resolve(this.repoPath);
    const target = path.resolve(root, ...parts);
    const relative = path.relative(root, target);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`Git path escapes the repository: ${JSON.stringify(relativePath)}`);
    }
    return target;
  }

  private pathContainsSymlink(relativePath: string): boolean {
    const parts = relativePath.split("/");
    let current = path.resolve(this.repoPath);
    for (const part of parts) {
      current = path.join(current, part);
      try {
        if (fs.lstatSync(current).isSymbolicLink()) return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  private readContainedFile(relativePath: string): Buffer {
    const absolutePath = this.containedPath(relativePath);
    const repositoryRoot = fs.realpathSync(this.repoPath);
    if (this.pathContainsSymlink(relativePath)) throw new Error("path contains a symlink");
    const noFollow = fs.constants.O_NOFOLLOW ?? 0;
    const nonblock = fs.constants.O_NONBLOCK ?? 0;
    const fd = fs.openSync(absolutePath, fs.constants.O_RDONLY | noFollow | nonblock);
    try {
      if (!fs.fstatSync(fd).isFile()) throw new Error("candidate is not a regular file");
      this.assertDescriptorContained(fd, repositoryRoot);
      const content = Buffer.allocUnsafe(this.maxFileBytes + 1);
      let bytesRead = 0;
      while (bytesRead < content.length) {
        const count = fs.readSync(fd, content, bytesRead, content.length - bytesRead, null);
        if (count === 0) break;
        bytesRead += count;
      }
      return content.subarray(0, bytesRead);
    } finally {
      fs.closeSync(fd);
    }
  }

  private assertDescriptorContained(fd: number, repositoryRoot: string): void {
    if (process.platform !== "linux") return;
    const openedPath = fs.realpathSync(`/proc/self/fd/${fd}`);
    const relative = path.relative(repositoryRoot, openedPath);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("opened file escapes the repository");
    }
  }

  private canonicalCollisionPaths(entries: readonly TreeEntry[]): Set<string> {
    const counts = new Map<string, number>();
    for (const entry of entries) counts.set(entry.path, (counts.get(entry.path) ?? 0) + 1);
    return new Set([...counts].filter(([, count]) => count > 1).map(([entryPath]) => entryPath));
  }

  private parseBatchBlobs(oids: readonly string[], output: Buffer): Map<string, Buffer> {
    const blobs = new Map<string, Buffer>();
    let offset = 0;
    for (const expectedOid of oids) {
      const lineEnd = output.indexOf(10, offset);
      if (lineEnd < 0) throw new Error("Malformed git cat-file --batch header");
      const [oid, objectType, rawSize] = output
        .subarray(offset, lineEnd)
        .toString("ascii")
        .split(" ");
      const size = Number(rawSize);
      if (oid !== expectedOid || objectType !== "blob" || !Number.isSafeInteger(size) || size < 0) {
        throw new Error("Unexpected git cat-file --batch header");
      }
      const contentStart = lineEnd + 1;
      const contentEnd = contentStart + size;
      if (contentEnd >= output.length || output[contentEnd] !== 10) {
        throw new Error("Malformed git cat-file --batch payload");
      }
      blobs.set(oid, Buffer.from(output.subarray(contentStart, contentEnd)));
      offset = contentEnd + 1;
    }
    if (offset !== output.length) throw new Error("Unexpected trailing git cat-file output");
    return blobs;
  }

  private enforceCandidateLimit(
    candidates: readonly TreeEntry[],
    side: "base" | "head",
    changedPaths: ReadonlySet<string>,
  ): CandidateReadResult | null {
    if (candidates.length <= this.maxCandidates) return null;
    const detail = `side has ${candidates.length} candidates; limit is ${this.maxCandidates}`;
    return {
      files: new Map(),
      unanalyzed: candidates.map((entry) =>
        this.unanalyzed(entry.path, side, "too_many_candidates", detail, changedPaths),
      ),
    };
  }

  private acceptContent(
    result: CandidateReadResult,
    file: string,
    side: "base" | "head",
    content: Buffer,
    changedPaths: ReadonlySet<string>,
  ): void {
    if (content.subarray(0, BINARY_SNIFF_BYTES).includes(0)) {
      result.unanalyzed.push(
        this.unanalyzed(
          file,
          side,
          "binary",
          "NUL byte found in the first 8192 bytes",
          changedPaths,
        ),
      );
    } else {
      result.files.set(file, content.toString("utf8"));
    }
  }

  private markRemaining(
    result: CandidateReadResult,
    entries: readonly TreeEntry[],
    side: "base" | "head",
    reason: UnanalyzedReason,
    changedPaths: ReadonlySet<string>,
    detail = "20-second extraction budget expired",
  ): void {
    for (const entry of entries) {
      result.unanalyzed.push(this.unanalyzed(entry.path, side, reason, detail, changedPaths));
    }
  }

  private timeoutResult(
    side: "base" | "head",
    changedPaths: ReadonlySet<string>,
  ): CandidateReadResult {
    return {
      files: new Map(),
      unanalyzed: [
        this.unanalyzed(".", side, "timeout", "20-second extraction budget expired", changedPaths),
      ],
    };
  }

  private unanalyzed(
    file: string,
    side: "base" | "head",
    reason: UnanalyzedReason,
    detail: string,
    changedPaths: ReadonlySet<string>,
  ): Unanalyzed {
    return { file, side, reason, detail, changed: changedPaths.has(file) };
  }

  private expired(deadline: number): boolean {
    return this.clock() >= deadline;
  }

  private remaining(deadline: number): number {
    const remaining = deadline - this.clock();
    if (remaining <= 0) throw this.timeoutError();
    return Math.max(1, remaining);
  }

  private timeoutError(): Error {
    return Object.assign(new Error("20-second extraction budget expired"), { code: "ETIMEDOUT" });
  }

  private run(args: readonly string[], input?: Buffer, timeoutMs?: number): Buffer {
    return this.runner(args, { cwd: this.repoPath, input, timeoutMs });
  }
}
