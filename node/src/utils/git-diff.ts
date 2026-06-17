/**
 * Parse unified git diff output and extract added/modified lines (+ side only).
 * Dependency-free — expects `git diff -U0 --no-color` output (zero context lines).
 */

export interface AddedDiffLine {
  /** Repo-relative path (forward slashes). */
  file: string;
  /** 1-based line number in the post-change file. */
  line: number;
  /** Line content without the leading '+'. */
  text: string;
}

const HUNK_HEADER_RE = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
const NO_NEWLINE_RE = /^\\ No newline at end of file$/;

/**
 * Strip the `b/` prefix git adds to paths in `+++ b/path` headers.
 */
export function normalizeDiffPath(raw: string): string {
  let p = raw.trim().replace(/\\/g, "/");
  if (p.startsWith("b/")) p = p.slice(2);
  else if (p.startsWith("a/")) p = p.slice(2);
  return p;
}

/**
 * Extract added lines from a unified diff patch. Context lines (leading space)
 * and deletions (leading '-') are ignored. Modifications appear as `-` then `+`;
 * only the `+` side is returned.
 */
export function parseUnifiedDiffAddedLines(patch: string): AddedDiffLine[] {
  const results: AddedDiffLine[] = [];
  let currentFile: string | null = null;
  let newLine = 0;

  for (const rawLine of patch.split(/\r?\n/)) {
    if (NO_NEWLINE_RE.test(rawLine)) continue;

    if (rawLine.startsWith("diff --git ")) {
      currentFile = null;
      newLine = 0;
      continue;
    }

    if (rawLine.startsWith("Binary files ") && rawLine.endsWith(" differ")) {
      currentFile = null;
      newLine = 0;
      continue;
    }

    // `+++ `/`--- ` are file headers ONLY in the file-header region (before the
    // first `@@`, where newLine is still 0). Inside a hunk body (newLine > 0) a
    // line like `++ x` serializes as `+++ x` and is ADDED CONTENT, not a header
    // — guarding on newLine keeps it from corrupting currentFile.
    if (newLine <= 0 && rawLine.startsWith("+++ ")) {
      const pathPart = rawLine.slice(4).trim();
      if (pathPart === "/dev/null") {
        currentFile = null;
      } else {
        currentFile = normalizeDiffPath(pathPart);
      }
      newLine = 0;
      continue;
    }

    if (newLine <= 0 && rawLine.startsWith("--- ")) {
      continue;
    }

    const hunk = HUNK_HEADER_RE.exec(rawLine);
    if (hunk) {
      newLine = parseInt(hunk[1], 10);
      continue;
    }

    if (!currentFile || newLine <= 0) continue;

    // Any '+' line here is added content (real headers were consumed above
    // while newLine <= 0). Do NOT exclude '+++...': an added line whose content
    // starts with '++' would otherwise be dropped, missing a secret.
    if (rawLine.startsWith("+")) {
      results.push({
        file: currentFile,
        line: newLine,
        text: rawLine.slice(1),
      });
      newLine++;
      continue;
    }

    if (rawLine.startsWith("-")) {
      continue;
    }

    if (rawLine.startsWith(" ")) {
      newLine++;
    }
  }

  return results;
}
