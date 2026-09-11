/**
 * Centralized risk assessment rules.
 * Single source of truth — imported by command-interceptor, audit-logger, and config-defaults.
 *
 * Risk patterns are matched against a *sanitized* view of the command line
 * (see `sanitizeCommandForMatching`), not the raw string: quoted text that a
 * command consumes as DATA (a commit message, a PR body, an `echo` argument)
 * must not be mistaken for a command, while quoted text that a shell or eval
 * wrapper EXECUTES (`bash -c "…"`, `eval "…"`) must still be scanned.
 */

export type CommandRiskLevel = "low" | "medium" | "high" | "critical";

/** Directories where `rm -rf /<dir>` is catastrophic (data loss / unbootable). */
const CRITICAL_DIRS = "home|etc|usr|boot|root|sys|proc|lib|lib64|bin|sbin|opt";

/**
 * Catastrophic, irreversible commands. These are hard-blocked unconditionally —
 * no policy, mode, or deny-list can opt out of them. Kept as pattern *sources*
 * so the default policy deny-list (`DEFAULT_BLOCKED_PATTERNS`) is exactly this
 * set, byte for byte, and can never drift from it.
 */
const CRITICAL_PATTERN_SOURCES: string[] = [
  // rm -rf / (root only, any flag order)
  `rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+/(\\s|$)`,
  `rm\\s+(-[a-z]*f[a-z]*\\s+)*-[a-z]*r[a-z]*\\s+/(\\s|$)`,
  // rm -rf on critical top-level directories
  `rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+/(${CRITICAL_DIRS})(/|\\s|$)`,
  `rm\\s+(-[a-z]*f[a-z]*\\s+)*-[a-z]*r[a-z]*\\s+/(${CRITICAL_DIRS})(/|\\s|$)`,
  `:\\(\\)\\{\\s*:\\|:&\\s*\\};:`,   // fork bomb
  `dd\\s+if=.*of=/dev/sd`,
  `>\\s*/dev/sd`,
  `mkfs`,
  `fdisk`,
  `parted`,
];

export const CRITICAL_PATTERNS: RegExp[] = CRITICAL_PATTERN_SOURCES.map((s) => new RegExp(s));

export const HIGH_PATTERNS: RegExp[] = [
  /rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*/,  // rm -rf, -fr, -r -f, -f -r (any path)
  /rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*/,  // rm -fr, reversed
  /sudo\s+rm/,
  /chmod\s+777/,
  /curl.*\|\s*(bash|sh|zsh|dash)\b/,
  /wget.*\|\s*(bash|sh|zsh|dash)\b/,
  /git\s+push\b.*\s--force\b/,                           // --force anywhere after push
  /git\s+push\b.*\s-[a-zA-Z]*f\b/,                      // -f or combined flags like -vf
  /git\s+push\b.*\s--force-(with-lease|if-includes)\b/,  // specific force variants
  /git\s+push\s+\S*\s+\+/,                               // refspec force: git push origin +main
  /docker\s+system\s+prune/,
  /npm\s+publish/,
  /pypi.*upload/,
];

export const MEDIUM_PATTERNS: RegExp[] = [
  /sudo/,
  /chmod/,
  /chown/,
  /systemctl/,
  /service/,
  /kill\s+-9/,
  /pkill/,
  /killall/,
];

/**
 * Default policy deny-list. Identical to the built-in unconditional hard-block
 * set: a deny-list entry hard-denies, so the *defaults* must never match a
 * merely approval-grade command. (The old literals — e.g. the substring
 * "rm -rf /" — hard-denied `rm -rf /tmp/build`, which is HIGH and belongs in
 * DEFAULT_REQUIRE_APPROVAL, not in a deny-list.)
 */
export const DEFAULT_BLOCKED_PATTERNS: string[] = [...CRITICAL_PATTERN_SOURCES];

export const DEFAULT_REQUIRE_APPROVAL: string[] = [
  "rm -rf",
  "sudo rm",
  "curl.*\\|\\s*(bash|sh|zsh|dash)\\b",
  "wget.*\\|\\s*(bash|sh|zsh|dash)\\b",
  "chmod 777",
  "git push --force",
  "git push -f",
  "git push --force-with-lease",
  "git push --force-if-includes",
  "git push .* \\+",
];

// ---------------------------------------------------------------------------
// Argument-aware command sanitizer
// ---------------------------------------------------------------------------
//
// The risk patterns above describe *shell commands*. Matching them against the
// raw command line treats quoted argument text as if it were a command, so
//
//     gh pr create --body "…don't git push --force…"
//     git commit -m "don't git push --force"
//
// were flagged as force-pushes. Simply ignoring quoted text is NOT a fix: a
// shell or eval wrapper *executes* its quoted argument, so `bash -c "rm -rf /"`
// must still hard-block. The sanitizer is therefore argument-aware:
//
//   * tokenize respecting quotes, escapes, command substitution and redirects;
//   * split on chain operators (`;` `&&` `||` `|` `&`), keeping them in place so
//     pipeline rules (`curl … | bash`) still match;
//   * a shell's `-c` argument IS a command → recursively sanitize and inline it;
//   * `$(…)` / backticks (outside single quotes) ARE commands → same;
//   * arguments a command consumes as text (`echo`/`grep` operands, `-m`,
//     `--body`, …) and prose-shaped quoted arguments are DATA → redacted;
//   * everything else is preserved byte for byte.
//
// Known limitation: an *unrecognized* evaluator that takes a bare quoted command
// string with no `-c`/`-e`-style flag (e.g. a bespoke `myrunner "rm -rf /"`) has
// its argument treated as data. Anything reached through a real shell, an eval
// flag, a substitution, or an unquoted argument is still scanned.

/** Shells whose `-c` argument is a command string to execute. */
const SHELL_EXECS = new Set(["bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "su"]);

/** Execs whose arguments are executable text (a remote command, a script). */
const EVAL_EXECS = new Set(["eval", "exec", "ssh", "sshpass", "xargs"]);

/** Flags carrying an executable string (`bash -c`, `python -c`, `mysql -e`, `find -exec`). */
const EVAL_FLAGS = new Set(["-c", "-e", "--command", "--execute", "--eval", "-exec", "--exec"]);

/** Prefix wrappers that delegate to the command that follows them. */
const TAIL_WRAPPERS = new Set([
  "sudo", "doas", "env", "nohup", "timeout", "nice", "ionice",
  "time", "watch", "setsid", "stdbuf", "chrt", "command",
]);

/** Commands whose operands are pure text data — searching or printing, never executing. */
const TEXT_EXECS = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack"]);

/** Flags whose value is human prose (a message, a body, a title) — never a command. */
const TEXT_FLAGS = new Set([
  "-m", "--message", "--body", "--body-text", "--title", "--description",
  "--reason", "--notes", "--subject", "--comment", "--annotation",
]);

/** Operators that chain independent commands. */
const CHAIN_OPS = new Set([";", "&&", "||", "|", "&"]);

/** Operators whose following token is a redirect target (a path — never data). */
const REDIRECT_OPS = new Set([">", ">>", "<", "<<"]);

/** Bound on recursion through nested shell wrappers / substitutions. */
const MAX_SANITIZE_DEPTH = 8;

interface Piece {
  /** Span in the source string. */
  start: number;
  end: number;
  /** Operator text, or null for a word. */
  op: string | null;
  /** Unquoted, unescaped word content (empty for operators). */
  text: string;
  /** Whether any part of the word was quoted. */
  quoted: boolean;
  /** Contents of any command substitutions that the shell would execute. */
  substs: string[];
}

function isOpChar(c: string): boolean {
  // \n and \r are statement separators (rf-6pqx): a newline ends a command
  // exactly as ";" does, so a payload on a later line is classified on its own.
  return c === ";" || c === "&" || c === "|" || c === ">" || c === "<" || c === "\n" || c === "\r";
}

/** Read a `$(…)` substitution starting at `i`; returns its contents and the next index. */
function readSubst(s: string, i: number): { inner: string; next: number } {
  let j = i + 2;
  let depth = 1;
  let inner = "";
  while (j < s.length && depth > 0) {
    const ch = s[j];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) { j++; break; }
    }
    inner += ch;
    j++;
  }
  return { inner, next: j };
}

/** Read a backtick substitution starting at `i`. */
function readBacktick(s: string, i: number): { inner: string; next: number } {
  let j = i + 1;
  let inner = "";
  while (j < s.length && s[j] !== "`") { inner += s[j]; j++; }
  return { inner, next: Math.min(j + 1, s.length) };
}

/**
 * Split a command line into words and operators, respecting quotes and substitutions.
 * `unterminated` is set when a quote is never closed — the parse is then unreliable
 * and the caller must FAIL CLOSED (match the raw string) rather than trust a
 * desynchronized sanitization (se-y6vo: `$'a\'b'` swallows a trailing payload).
 */
function tokenize(s: string): { pieces: Piece[]; unterminated: boolean } {
  const pieces: Piece[] = [];
  let unterminated = false;
  let i = 0;

  while (i < s.length) {
    const c = s[i];

    // Whitespace EXCEPT newlines is skipped; a newline falls through to the
    // operator branch below so it becomes a statement separator (rf-6pqx).
    if (/\s/.test(c) && c !== "\n" && c !== "\r") { i++; continue; }

    if (isOpChar(c)) {
      const start = i;
      if (c === "\n" || c === "\r") {
        // Normalize a line break (incl. CRLF) to a ";" separator piece.
        i += 1;
        pieces.push({ start, end: i, op: ";", text: ";", quoted: false, substs: [] });
        continue;
      }
      const two = s.slice(i, i + 2);
      const op = (two === "&&" || two === "||" || two === ">>" || two === "<<") ? two : c;
      i += op.length;
      pieces.push({ start, end: i, op, text: op, quoted: false, substs: [] });
      continue;
    }

    const start = i;
    let text = "";
    let quoted = false;
    const substs: string[] = [];

    while (i < s.length) {
      const ch = s[i];
      if (/\s/.test(ch) || isOpChar(ch)) break;

      if (ch === "\\") {
        // Line continuation: `\` immediately before a newline (incl. CRLF) is
        // deleted by the shell — `r\<NL>m` is `rm`, so the newline must not be
        // absorbed into the word (rf-6pqx/se-y6vo).
        const nxt = s[i + 1] ?? "";
        if (nxt === "\n") { i += 2; continue; }
        if (nxt === "\r") { i += 2; if (s[i] === "\n") i++; continue; }
        i++;
        if (i < s.length) { text += s[i]; i++; }
        continue;
      }

      // Single quotes are inert: no expansion, no substitution.
      if (ch === "'") {
        i++;
        quoted = true;
        let closed = false;
        while (i < s.length) {
          if (s[i] === "'") { closed = true; i++; break; }
          text += s[i]; i++;
        }
        if (!closed) unterminated = true;
        continue;
      }

      // Double quotes are data, but `$( )` / backticks inside them DO execute.
      if (ch === '"') {
        i++;
        quoted = true;
        let closed = false;
        while (i < s.length) {
          if (s[i] === '"') { closed = true; i++; break; }
          if (s[i] === "\\") {
            const nxt = s[i + 1] ?? "";
            if (nxt === "\n") { i += 2; continue; }
            if (nxt === "\r") { i += 2; if (s[i] === "\n") i++; continue; }
            i++;
            if (i < s.length) { text += s[i]; i++; }
            continue;
          }
          if (s[i] === "$" && s[i + 1] === "(") {
            const r = readSubst(s, i); substs.push(r.inner); i = r.next; continue;
          }
          if (s[i] === "`") {
            const r = readBacktick(s, i); substs.push(r.inner); i = r.next; continue;
          }
          text += s[i];
          i++;
        }
        if (!closed) unterminated = true;
        continue;
      }

      if (ch === "$" && s[i + 1] === "(") {
        const r = readSubst(s, i); substs.push(r.inner); i = r.next; continue;
      }
      if (ch === "`") {
        const r = readBacktick(s, i); substs.push(r.inner); i = r.next; continue;
      }

      text += ch;
      i++;
    }

    pieces.push({ start, end: i, op: null, text, quoted, substs });
  }

  return { pieces, unterminated };
}

/** `/usr/bin/rm` → `rm`; used to classify the executable of a segment. */
function execName(text: string): string {
  const base = text.slice(text.lastIndexOf("/") + 1);
  return base.toLowerCase();
}

const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_C_FLAG = /^-[a-z]*c$/;
const LONG_FLAG_WITH_VALUE = /^(--[a-z][a-z-]*)=/;
const NUMERIC_ARG = /^\d+[a-z]*$/i;

/**
 * A heredoc introducer: `<<`, optional `-`/`~` (indented-terminator forms), an
 * optional quote around the delimiter, and the delimiter word. Group 1 is the
 * dash/tilde, group 3 is the delimiter name. `g` so we can find all on a line.
 */
const HEREDOC_START = /(?<!<)<<(?!<)([-~]?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g;
/** Chain/pipe operators, used to find the statement that owns a heredoc. */
const CHAIN_SPLIT = /\|\||&&|[;|&]/;

interface Replacement { start: number; end: number; with: string; }

/**
 * Decide, for one segment (a single command in a chain), which spans are DATA
 * and which are code, appending the resulting replacements.
 */
/**
 * The effective executable of a segment (`sudo rm -rf /` -> `rm`), used to ask
 * what the NEXT stage of a pipeline does with this stage's output.
 */
function segmentExec(pieces: Piece[]): string {
  const isRedirectTarget = new Array<boolean>(pieces.length).fill(false);
  for (let i = 1; i < pieces.length; i++) {
    const prev = pieces[i - 1];
    if (prev.op && REDIRECT_OPS.has(prev.op) && !pieces[i].op) isRedirectTarget[i] = true;
  }
  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op || isRedirectTarget[i]) continue;
    if (!p.quoted && ENV_ASSIGNMENT.test(p.text)) continue;
    if (!p.quoted && TAIL_WRAPPERS.has(execName(p.text))) {
      let j = i + 1;
      while (j < pieces.length) {
        const q = pieces[j];
        if (q.op || isRedirectTarget[j]) { j++; continue; }
        if (q.text.startsWith("-") || /^\d+[a-z]*$/i.test(q.text)) { j++; continue; }
        break;
      }
      i = j - 1;
      continue;
    }
    return execName(p.text);
  }
  return "";
}

function processSegment(
  pieces: Piece[],
  depth: number,
  out: Replacement[],
  pipedIntoShell = false,
  outputExecuted = false
): void {
  // A word is a redirect target when the piece before it is `>`/`>>`/`<`.
  const isRedirectTarget = new Array<boolean>(pieces.length).fill(false);
  for (let i = 1; i < pieces.length; i++) {
    const prev = pieces[i - 1];
    if (prev.op && REDIRECT_OPS.has(prev.op) && !pieces[i].op) isRedirectTarget[i] = true;
  }

  // Effective executable: skip env assignments and prefix wrappers (`sudo`,
  // `env`, `timeout 5`, `nice -n 15`, …) to reach the command they delegate to.
  let execIdx = -1;
  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op || isRedirectTarget[i]) continue;
    if (!p.quoted && ENV_ASSIGNMENT.test(p.text)) continue;
    if (execIdx === -1 && !p.quoted && TAIL_WRAPPERS.has(execName(p.text))) {
      // Skip the wrapper's own flags and their numeric/duration values.
      let j = i + 1;
      while (j < pieces.length) {
        const q = pieces[j];
        if (q.op || isRedirectTarget[j]) { j++; continue; }
        if (q.text.startsWith("-") || /^\d+[a-z]*$/i.test(q.text)) { j++; continue; }
        break;
      }
      i = j - 1;
      continue;
    }
    execIdx = i;
    break;
  }

  const exec = execIdx === -1 ? "" : execName(pieces[execIdx].text);
  const isTextExec = TEXT_EXECS.has(exec);

  // A segment is code-carrying when some part of it is a command string the
  // segment will execute: a shell, an eval-style flag, or an eval-style exec.
  // Its quoted arguments are NOT prose and must stay visible to the patterns.
  let hasShellExec = false;
  let hasEvalFlag = false;
  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op || isRedirectTarget[i]) continue;
    if (!p.quoted && SHELL_EXECS.has(execName(p.text))) hasShellExec = true;
    if (!p.quoted && EVAL_FLAGS.has(p.text.toLowerCase())) hasEvalFlag = true;
  }
  const codeCarrying = hasShellExec || hasEvalFlag || EVAL_EXECS.has(exec);

  // sable-c6an. Two questions the code conflated, and conflating them gets one
  // of them wrong:
  //   codeCarrying   — this segment RUNS a command string it was handed
  //   executesOutput — this segment's STDOUT becomes code somewhere else
  //                    (`… | bash`, or a substitution used as a -c script)
  // `bash -c "echo 'rm -rf /'"` is the first and not the second, so its operand
  // stays data; `bash -c "$(echo rm -rf /)"` is the second, so it is code.
  const executesOutput = pipedIntoShell || outputExecuted;

  let seenShell = false;
  let pendingScript = false;
  let prevTextFlag = false;

  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op) { prevTextFlag = false; continue; }

    const isExecTok = i === execIdx;
    const flagName = p.text.toLowerCase();

    if (!p.quoted && SHELL_EXECS.has(execName(p.text))) seenShell = true;

    // `bash -c <script>` — the next word is a command string, not data.
    if (pendingScript && !p.text.startsWith("-")) {
      // The script can be entirely a substitution — `bash -c "$(…)"` — where
      // `text` is EMPTY and the substitution IS the script. Reading only `text`
      // dropped it, so `bash -c "$(echo rm -rf /)"` classified low: a bypass of
      // the hard block needing no policy file (sable-c6an). The substitution's
      // OUTPUT is the script, so it sanitizes as output-executed.
      const parts: string[] = [];
      if (p.text !== "") parts.push(sanitize(p.text, depth + 1));
      for (const sub of p.substs) parts.push(sanitize(sub, depth + 1, true));
      out.push({ start: p.start, end: p.end, with: parts.join(" ") });
      pendingScript = false;
      prevTextFlag = false;
      continue;
    }

    if (seenShell && !p.quoted && SHELL_C_FLAG.test(flagName)) {
      pendingScript = true;
      prevTextFlag = false;
      continue;
    }

    // `$(…)` / backticks execute — scan their contents, drop the literal wrapper.
    if (p.substs.length > 0) {
      const inner = p.substs
        .map((s) => sanitize(s, depth + 1, codeCarrying || executesOutput))
        .join(" ");
      out.push({ start: p.start, end: p.end, with: inner });
      prevTextFlag = false;
      continue;
    }

    if (isRedirectTarget[i]) { prevTextFlag = false; continue; }
    if (isExecTok) {
      // Unquote a quoted executable so quoting the *command name* cannot break
      // the pattern anchors (`"rm" -rf /`, `r"m" -rf /`, `watch "rm -rf /"`).
      // Unquoting only ever exposes more to the patterns — the safe direction.
      if (p.quoted) out.push({ start: p.start, end: p.end, with: p.text });
      prevTextFlag = false;
      continue;
    }

    // Value of a prose flag (`-m "…"`, `--body "…"`) — always data, even inside
    // a code-carrying segment (`git commit -e -m "don't git push --force"`).
    if (prevTextFlag) {
      out.push({ start: p.start, end: p.end, with: " " });
      prevTextFlag = false;
      continue;
    }

    const longFlag = LONG_FLAG_WITH_VALUE.exec(p.text);
    if (!p.quoted && longFlag && TEXT_FLAGS.has(longFlag[1])) {
      out.push({ start: p.start, end: p.end, with: longFlag[1] });
      continue;
    }

    if (TEXT_FLAGS.has(flagName)) { prevTextFlag = true; continue; }
    prevTextFlag = false;

    // Operands of a text command (`echo`, `grep`, `printf`) are never executed.
    if (isTextExec && i > execIdx && !executesOutput) {
      out.push({ start: p.start, end: p.end, with: " " });
      continue;
    }

    if (p.quoted) {
      const isProse = /\s/.test(p.text);
      if (!isProse) {
        // Single-word quoted operand: unquote it so quoting cannot be used to
        // hide a flag or a path from the patterns (`rm "-rf" "/"`).
        out.push({ start: p.start, end: p.end, with: p.text });
      } else if (codeCarrying || executesOutput) {
        // This segment executes a command string (`ssh host "…"`, `mysql -e "…"`).
        // The quoted argument is code — unquote and scan it, recursively.
        out.push({ start: p.start, end: p.end, with: sanitize(p.text, depth + 1) });
      } else {
        // A quoted, multi-word argument to an ordinary command is prose data.
        out.push({ start: p.start, end: p.end, with: " " });
      }
    }
  }
}

/**
 * Remove `\<newline>` line continuations the way a shell does BEFORE parsing.
 * `r\<NL>m -rf /` is `rm -rf /` to bash, so the backslash-newline must be deleted
 * or the token `rm` never forms and the pattern misses it (se-y6vo). Removed when
 * unquoted or inside double quotes; PRESERVED inside single quotes.
 */
function stripLineContinuations(s: string): string {
  if (!s.includes("\\")) return s;
  let out = "";
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" && !inDouble) { inSingle = !inSingle; out += c; i++; continue; }
    if (c === '"' && !inSingle) { inDouble = !inDouble; out += c; i++; continue; }
    if (c === "\\" && !inSingle) {
      const nxt = s[i + 1] ?? "";
      if (nxt === "\n") { i += 2; continue; }
      if (nxt === "\r") { i += 2; if (s[i] === "\n") i++; continue; }
      // Normal escape (`\"`, `\$`, …): keep both chars so an escaped quote does
      // not flip the quote state above.
      out += c;
      if (i + 1 < s.length) { out += s[i + 1]; i += 2; } else { i++; }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function sanitize(command: string, depth: number, outputExecuted = false): string {
  if (!command || depth > MAX_SANITIZE_DEPTH) return command;

  command = stripLineContinuations(command);
  const { pieces, unterminated } = tokenize(command);
  // Fail closed: an unterminated quote means the parse desynchronized from the
  // shell, so a sanitized view could hide an executable payload. Match the raw
  // command instead (se-y6vo).
  if (unterminated) return command;
  const replacements: Replacement[] = [];

  // Segments keep the operator that ends them, so a segment can be asked
  // whether its output feeds a shell (`echo "rm -rf /" | bash`).
  const segments: { pieces: Piece[]; endOp: string | null }[] = [];
  let segment: Piece[] = [];
  for (const p of pieces) {
    if (p.op && CHAIN_OPS.has(p.op)) {
      segments.push({ pieces: segment, endOp: p.op });
      segment = [];
      continue;
    }
    segment.push(p);
  }
  segments.push({ pieces: segment, endOp: null });

  for (let k = 0; k < segments.length; k++) {
    const next = segments[k + 1];
    const pipedIntoShell =
      segments[k].endOp === "|" &&
      next !== undefined &&
      SHELL_EXECS.has(segmentExec(next.pieces));
    processSegment(
      segments[k].pieces, depth, replacements, pipedIntoShell, outputExecuted
    );
  }

  if (replacements.length === 0) return command;

  replacements.sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const r of replacements) {
    if (r.start < cursor) continue;
    out += command.slice(cursor, r.start) + r.with;
    cursor = r.end;
  }
  out += command.slice(cursor);
  return out;
}

/**
 * Normalize a command line for risk/policy pattern matching: quoted text the
 * command consumes as DATA is redacted; text a shell or eval wrapper EXECUTES
 * is preserved (and recursively sanitized). Everything else is untouched.
 */
/**
 * Does the command that owns a heredoc EXECUTE its body? `cat > f <<EOF` /
 * `grep -q x <<EOF` consume the body as DATA; `bash <<EOF` / `sh <<'EOF'` /
 * `ssh host <<EOF` EXECUTE it. Only a data body may be stripped; an executed
 * body must stay visible to the patterns (else the newline fix opens a fresh
 * bypass — se-y6vo).
 */
function heredocOwnerExecutes(line: string, ltPos: number): boolean {
  const head = line.slice(0, ltPos);
  const segments = head.split(CHAIN_SPLIT);
  const seg = segments.length ? segments[segments.length - 1] : head;
  const tokens = seg.split(/\s+/).filter((t) => t.length > 0);
  let idx = 0;
  while (idx < tokens.length) {
    const tok = tokens[idx];
    if (ENV_ASSIGNMENT.test(tok)) { idx++; continue; }
    const name = execName(tok);
    if (TAIL_WRAPPERS.has(name)) {
      idx++;
      while (idx < tokens.length && (tokens[idx].startsWith("-") || NUMERIC_ARG.test(tokens[idx]))) idx++;
      continue;
    }
    return SHELL_EXECS.has(name) || EVAL_EXECS.has(name);
  }
  return false;
}

/**
 * Blank heredoc BODIES that a command consumes as DATA, before tokenizing.
 * A body written to a file (`cat > doc.md <<EOF … EOF`) or searched
 * (`grep <<EOF … EOF`) is data, never executed. Leaving it in place makes the
 * newline-as-separator fix (rf-6pqx) classify ordinary documentation writes as
 * CRITICAL (rf-3rsj) — the same over-block public #230 reported. Stripping it
 * fixes both. A body EXECUTED by a shell/eval owner is KEPT so it is still
 * scanned. Co-designed with kerckhoffs (se-ijzs) and achebe (#230).
 */
/**
 * `cat <<EOF | bash` — the body is data to `cat`, but `cat`'s OUTPUT is the
 * script, so the body is executed after all. The owner check above only reads
 * the text BEFORE the introducer and never sees the pipe, so without this a
 * heredoc piped into a shell is stripped and the hard block is silently lost.
 * Keeping a body is the safe direction: it can only over-block, and only for a
 * shape that should block anyway.
 */
function heredocOutputPipedToShell(line: string, ltPos: number): boolean {
  const stages = line.slice(ltPos).split("|").slice(1);
  for (const stage of stages) {
    const tokens = stage.trim().split(/\s+/).filter((t) => t.length > 0);
    let idx = 0;
    while (idx < tokens.length) {
      const tok = tokens[idx];
      if (ENV_ASSIGNMENT.test(tok)) { idx++; continue; }
      const name = execName(tok);
      if (TAIL_WRAPPERS.has(name)) {
        idx++;
        while (idx < tokens.length && (tokens[idx].startsWith("-") || NUMERIC_ARG.test(tokens[idx]))) idx++;
        continue;
      }
      if (SHELL_EXECS.has(name) || EVAL_EXECS.has(name)) return true;
      break;
    }
  }
  return false;
}

function stripHeredocBodies(command: string): string {
  if (!command.includes("<<")) return command;
  const lines = command.split("\n");
  const out: string[] = [];
  let k = 0;
  while (k < lines.length) {
    const line = lines[k];
    out.push(line);
    HEREDOC_START.lastIndex = 0;
    const matches = [...line.matchAll(HEREDOC_START)];
    k += 1;
    if (matches.length === 0) continue;
    const ltPos = matches[0].index ?? 0;
    const keep =
      heredocOwnerExecutes(line, ltPos) || heredocOutputPipedToShell(line, ltPos);
    for (const m of matches) {
      const delim = m[3];
      const dash = m[1]; // '-'/'~': a tab-indented terminator is allowed
      while (k < lines.length) {
        // bash terminates only on a line EXACTLY equal to the delimiter — for
        // plain `<<` an indented delimiter is body; `<<-` strips leading TABS.
        let cand = lines[k].replace(/\r$/, "");
        if (dash) cand = cand.replace(/^\t+/, "");
        if (cand === delim) { k += 1; break; }
        if (keep) out.push(lines[k]);
        k += 1;
      }
    }
  }
  return out.join("\n");
}

export function sanitizeCommandForMatching(command: string): string {
  return sanitize(stripHeredocBodies(command), 0);
}

/**
 * Assess risk level of a command string.
 */
/**
 * rf-vnxs — reconfiguring rafter's OWN security controls is a PROTECTED CLASS.
 *
 * The gate must never approve its own disarming. On 0.10.1 it did: the hook
 * rated `rafter agent config set agent.hooks.enabled false` as `low`, allowed
 * it, and every later command — including the CRITICAL tier that no policy,
 * mode or deny-list can override — was then permitted. Three steps, no
 * malformed command, and it persists to config.json.
 *
 * This is matched STRUCTURALLY — resolved exec plus an argv walk — and not by
 * string, because the spellings are unbounded and were all observed allowed on
 * the published artifact: extra whitespace, `FALSE`, `npx @rafter-security/cli
 * …`, `sudo -E rafter …`, the `agent disable` component route, and three
 * different self-disabling keys (hooks.enabled, hooks.secretScan,
 * hooks.commandPolicy). A blacklist of one string is one alias away from being
 * a no-op — the same shape as the CHAIN_OPS one-liner that was proven inert
 * only by running the shipped module.
 */
const RAFTER_EXECS = new Set(["rafter", "rafter-cli"]);
const PACKAGE_RUNNERS = new Set(["npx", "bunx", "pnpx", "dlx", "pnpm", "yarn", "bun"]);
const RAFTER_PACKAGE = /^(?:@rafter-security\/cli|rafter-cli|rafter)(?:@[\w.^~*-]+)?$/;

/** Config keys that gate the hook. Namespace, not a leaf — see hook-control. */
const PROTECTED_CONFIG_KEY = /^(?:agent\.)?(?:hooks|commandpolicy)\b|^agent\.risklevel$/;

/**
 * True if this statement's argv reconfigures or removes a rafter security
 * control.
 *
 * The rafter invocation is looked for at ANY position, not just as the
 * statement's own exec, because a shell that carries a command string puts it
 * in the operand: `bash -c "rafter agent config set agent.hooks.enabled false"`
 * and `bash -c "$(echo rafter …)"` both sanitize to a statement whose exec is
 * `bash`, and an exec-only walk reads them — wrongly — as not-rafter. A quoted
 * word is skipped on the raw pass so that `echo 'rafter agent config set …'`
 * stays prose; the sanitized pass is where an actually-executed operand has
 * already been unwrapped for us.
 */
function statementDisarmsRafter(words: Piece[]): boolean {
  for (let j = 0; j < words.length; j++) {
    if (words[j].quoted) continue;
    let k = j;
    let exec = execName(words[k].text);
    k++;

    // `npx [-y] @rafter-security/cli …`, `pnpm dlx rafter-cli …`, `bunx rafter …`
    if (PACKAGE_RUNNERS.has(exec)) {
      while (k < words.length && (words[k].text.startsWith("-") || ["dlx", "exec"].includes(words[k].text.toLowerCase()))) k++;
      if (k >= words.length || !RAFTER_PACKAGE.test(words[k].text.toLowerCase())) continue;
      k++;
      exec = "rafter";
    }
    if (!RAFTER_EXECS.has(exec)) continue;

    const args = words.slice(k).map((w) => w.text.toLowerCase()).filter((a) => !a.startsWith("-"));
    for (let n = 0; n + 1 < args.length; n++) {
      // `… config set <protected key>` — the key is the next non-flag operand.
      if (args[n] === "config" && args[n + 1] === "set") {
        const key = args[n + 2];
        if (key && PROTECTED_CONFIG_KEY.test(key)) return true;
      }
      // `… agent disable <component>` — uninstalls a control outright.
      if (args[n] === "agent" && args[n + 1] === "disable") return true;
    }
  }
  return false;
}

/**
 * True if the command disarms rafter, checked on BOTH the raw text and the
 * sanitized text. Raw catches the ordinary invocation; sanitized catches the
 * case where a shell runs the OUTPUT of something else — `bash -c "$(echo
 * rafter agent config set …)"`, whose own exec is `echo` and which a walk over
 * the raw argv therefore reads, correctly, as a print. That is the same
 * executes-output distinction sable-c6an turned on.
 */
export function modifiesRafterSecurityConfig(command: string): boolean {
  if (disarmsRafter(command, 0)) return true;
  const sanitized = sanitizeCommandForMatching(command);
  return sanitized !== command && disarmsRafter(sanitized, 0);
}

/** True if any statement (or any command substitution) disarms rafter. */
function disarmsRafter(command: string, depth = 0): boolean {
  if (depth > MAX_SANITIZE_DEPTH) return false;
  const { pieces } = tokenize(command);
  let stmt: Piece[] = [];
  const statements: Piece[][] = [];
  for (const p of pieces) {
    if (p.op !== null) {
      if (CHAIN_OPS.has(p.op) || p.op === "\n" || p.op === "\r") { statements.push(stmt); stmt = []; }
      continue;
    }
    stmt.push(p);
    for (const sub of p.substs ?? []) {
      if (disarmsRafter(sub, depth + 1)) return true;
    }
  }
  statements.push(stmt);
  return statements.some(statementDisarmsRafter);
}

export function assessCommandRisk(command: string): CommandRiskLevel {
  // rf-vnxs: checked on the RAW command, before sanitization, because the
  // disarm is an ordinary well-formed invocation — there is nothing malformed
  // for the sanitizer to normalise, and redaction could hide the operand.
  if (modifiesRafterSecurityConfig(command)) return "critical";

  const cmd = sanitizeCommandForMatching(command).toLowerCase().trim();
  if (!cmd) return "low";

  for (const pattern of CRITICAL_PATTERNS) {
    if (pattern.test(cmd)) return "critical";
  }
  for (const pattern of HIGH_PATTERNS) {
    if (pattern.test(cmd)) return "high";
  }
  for (const pattern of MEDIUM_PATTERNS) {
    if (pattern.test(cmd)) return "medium";
  }
  return "low";
}

/**
 * Return the source of the first CRITICAL pattern matching the command, or null.
 * Mirrors assessCommandRisk's sanitization + lowercasing. Intended to be called
 * only once a command is already classified "critical", to surface *which*
 * built-in rule matched.
 */
export function matchedCriticalPattern(command: string): string | null {
  if (modifiesRafterSecurityConfig(command)) {
    return "rafter security configuration is protected (rf-vnxs)";
  }
  const cmd = sanitizeCommandForMatching(command).toLowerCase().trim();
  for (const pattern of CRITICAL_PATTERNS) {
    if (pattern.test(cmd)) return pattern.source;
  }
  return null;
}
