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
// HEREDOC (sable-5ogx / issue #230). `cat > notes.md <<'EOF' … EOF` WRITES its
// body to a file; it does not run it. Without heredoc handling the body reaches
// the matcher as bare words, so documentation that quotes a dangerous command
// scored identically to running it — a prose line mentioning `rm -rf /` in a
// markdown file classified CRITICAL, the tier no policy, mode or deny-list can
// override. So a heredoc body is DATA, with one exception below.
//
// The exception is the case where the body really is executed: a shell or
// eval-style exec consuming it (`bash <<EOF`, `ssh host <<EOF`), or a segment
// whose output is piped into a shell (`cat <<EOF | bash`). Those reuse the same
// SHELL_EXECS / EVAL_EXECS machinery that already governs quoted arguments,
// rather than adding a second rule beside it.
//
// This has to happen in the TOKENIZER, not as a filter afterward: once the
// input has been split into statements, the fact that a line was heredoc body
// is gone. rf-6pqx splits statements on newlines, and a body line promoted to
// its own statement is exactly the #230 regression.
//
// Known limitation: an *unrecognized* evaluator that takes a bare quoted command
// string with no `-c`/`-e`-style flag (e.g. a bespoke `myrunner "rm -rf /"`) has
// its argument treated as data. Anything reached through a real shell, an eval
// flag, a substitution, or an unquoted argument is still scanned. The same gap
// applies to a heredoc fed to such an evaluator.

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
const REDIRECT_OPS = new Set([">", ">>", "<", "<<", "<<-", "<<<"]);

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
  /** True for the body of a heredoc — see HEREDOC below. */
  heredocBody?: boolean;
  /** True for the word naming a heredoc's terminator (`<<EOF` → `EOF`). */
  heredocDelim?: boolean;
}

function isOpChar(c: string): boolean {
  return c === ";" || c === "&" || c === "|" || c === ">" || c === "<";
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

interface PendingHeredoc { delim: string; stripTabs: boolean; }

/**
 * Consume heredoc bodies queued on this line, starting at the newline index
 * `i`. Returns the index just past the last terminator consumed.
 *
 * An UNTERMINATED heredoc runs to end of input. That is the fail-safe
 * direction: the alternative is scanning documentation as commands, which is
 * the bug this exists to fix.
 */
function readHeredocBodies(s: string, i: number, queued: PendingHeredoc[]): number {
  let j = i + 1;
  for (const h of queued) {
    for (;;) {
      if (j >= s.length) { j = s.length; break; }
      const nl = s.indexOf("\n", j);
      const lineEnd = nl === -1 ? s.length : nl;
      // `<<-` strips leading TABS from the terminator — tabs only, not spaces.
      const line = h.stripTabs ? s.slice(j, lineEnd).replace(/^\t+/, "") : s.slice(j, lineEnd);
      if (line === h.delim) { j = nl === -1 ? s.length : nl + 1; break; }
      if (nl === -1) { j = s.length; break; }
      j = nl + 1;
    }
  }
  return j;
}

/** Split a command line into words and operators, respecting quotes and substitutions. */
function tokenize(s: string): Piece[] {
  const pieces: Piece[] = [];
  let i = 0;
  /** Heredocs introduced on the current line, in the order the shell reads them. */
  let queued: PendingHeredoc[] = [];
  /** Set after `<<`/`<<-`: the next word names the terminator, it is not a path. */
  let expectDelim: { stripTabs: boolean } | null = null;

  while (i < s.length) {
    const c = s[i];

    // A newline with heredocs queued: everything through the terminators is
    // body text, and body text is data. This must precede the whitespace skip
    // below, which would otherwise step over the newline and let the body
    // tokenize as ordinary words.
    if (c === "\n" && queued.length > 0) {
      const bodyStart = i + 1;
      const end = readHeredocBodies(s, i, queued);
      queued = [];
      if (end > bodyStart) {
        pieces.push({
          start: bodyStart, end, op: null, text: s.slice(bodyStart, end),
          quoted: true, substs: [], heredocBody: true,
        });
      }
      i = end;
      continue;
    }

    if (/\s/.test(c)) { i++; continue; }

    if (isOpChar(c)) {
      const start = i;
      const three = s.slice(i, i + 3);
      const two = s.slice(i, i + 2);
      let op: string;
      if (three === "<<<") {
        // A here-STRING, not a heredoc: its operand is one word, there is no
        // body, and mistaking it for `<<` would swallow the rest of the input.
        op = three;
      } else if (three === "<<-") {
        op = three;
      } else if (two === "&&" || two === "||" || two === ">>" || two === "<<") {
        op = two;
      } else {
        op = c;
      }
      i += op.length;
      pieces.push({ start, end: i, op, text: op, quoted: false, substs: [] });
      if (op === "<<" || op === "<<-") expectDelim = { stripTabs: op === "<<-" };
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
        i++;
        if (i < s.length) { text += s[i]; i++; }
        continue;
      }

      // Single quotes are inert: no expansion, no substitution.
      if (ch === "'") {
        i++;
        quoted = true;
        while (i < s.length && s[i] !== "'") { text += s[i]; i++; }
        i++;
        continue;
      }

      // Double quotes are data, but `$( )` / backticks inside them DO execute.
      if (ch === '"') {
        i++;
        quoted = true;
        while (i < s.length && s[i] !== '"') {
          if (s[i] === "\\") {
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
        i++;
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

    if (expectDelim) {
      // `<<'EOF'` / `<<"EOF"` — quoting changes expansion inside the body, not
      // where the body ends, so both forms terminate identically.
      queued.push({ delim: text, stripTabs: expectDelim.stripTabs });
      expectDelim = null;
      pieces.push({ start, end: i, op: null, text, quoted, substs, heredocDelim: true });
      continue;
    }

    pieces.push({ start, end: i, op: null, text, quoted, substs });
  }

  // Input that ends while a heredoc is still open: the body never arrived.
  return pieces;
}

/** `/usr/bin/rm` → `rm`; used to classify the executable of a segment. */
function execName(text: string): string {
  const base = text.slice(text.lastIndexOf("/") + 1);
  return base.toLowerCase();
}

const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_C_FLAG = /^-[a-z]*c$/;
const LONG_FLAG_WITH_VALUE = /^(--[a-z][a-z-]*)=/;

interface Replacement { start: number; end: number; with: string; }

/**
 * Decide, for one segment (a single command in a chain), which spans are DATA
 * and which are code, appending the resulting replacements.
 */
function redirectTargets(pieces: Piece[]): boolean[] {
  // A word is a redirect target when the piece before it is `>`/`>>`/`<`/`<<`.
  const isRedirectTarget = new Array<boolean>(pieces.length).fill(false);
  for (let i = 1; i < pieces.length; i++) {
    const prev = pieces[i - 1];
    if (prev.op && REDIRECT_OPS.has(prev.op) && !pieces[i].op) isRedirectTarget[i] = true;
  }
  return isRedirectTarget;
}

/**
 * Index of the word that actually runs: env assignments and prefix wrappers
 * (`sudo`, `env`, `timeout 5`, `nice -n 15`, …) are skipped to reach the
 * command they delegate to. -1 when the segment runs nothing.
 */
function findExecIdx(pieces: Piece[], isRedirectTarget: boolean[]): number {
  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op || isRedirectTarget[i] || p.heredocBody) continue;
    if (!p.quoted && ENV_ASSIGNMENT.test(p.text)) continue;
    if (!p.quoted && TAIL_WRAPPERS.has(execName(p.text))) {
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
    return i;
  }
  return -1;
}

/** The effective executable of a segment (`sudo rm -rf /` → `rm`). */
function segmentExec(pieces: Piece[]): string {
  const idx = findExecIdx(pieces, redirectTargets(pieces));
  return idx === -1 ? "" : execName(pieces[idx].text);
}

function processSegment(
  pieces: Piece[],
  depth: number,
  out: Replacement[],
  pipedIntoShell = false,
  outputExecuted = false
): void {
  const isRedirectTarget = redirectTargets(pieces);

  const execIdx = findExecIdx(pieces, isRedirectTarget);
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

  // A heredoc body is executed when a shell or eval-style exec consumes it
  // (`bash <<EOF`, `ssh host <<EOF`) or when this segment's output is piped
  // into a shell (`cat <<EOF | bash`). Otherwise the body is written, printed
  // or searched — data. Same question the quoted-argument rules already ask,
  // asked of the body.
  // Two different questions, and conflating them gets one of them wrong.
  //
  //   codeCarrying   — this segment RUNS a command string it was handed
  //                    (`bash -c …`, `ssh host …`).
  //   outputExecuted — this segment's STDOUT becomes code somewhere else
  //                    (`… | bash`, or a substitution whose result is a script).
  //
  // `bash -c "echo 'rm -rf /'"` is codeCarrying but its echo merely prints, so
  // the operand stays data. `bash -c "$(echo rm -rf /)"` is the same words with
  // the echo's OUTPUT as the script, so there the operand is code.
  const executesOutput = pipedIntoShell || outputExecuted;
  const heredocExecuted = codeCarrying || executesOutput;

  let seenShell = false;
  let pendingScript = false;
  let prevTextFlag = false;

  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.op) { prevTextFlag = false; continue; }

    if (p.heredocBody) {
      // Recursing on an executed body keeps `bash <<EOF … rm -rf / … EOF`
      // hard-blocking; redacting an unexecuted one is issue #230's fix.
      out.push({
        start: p.start, end: p.end,
        with: heredocExecuted ? sanitize(p.text, depth + 1) : " ",
      });
      prevTextFlag = false;
      continue;
    }
    if (p.heredocDelim) { prevTextFlag = false; continue; }

    const isExecTok = i === execIdx;
    const flagName = p.text.toLowerCase();

    if (!p.quoted && SHELL_EXECS.has(execName(p.text))) seenShell = true;

    // `bash -c <script>` — the next word is a command string, not data.
    if (pendingScript && !p.text.startsWith("-")) {
      // The script can be entirely a substitution — `bash -c "$(…)"` — where
      // `text` is empty and the substitution IS the script. Reading only `text`
      // dropped it, so every `bash -c "$(echo rm -rf /)"` classified low: a
      // silent bypass of the hard block (sable-c6an). The substitution's OUTPUT
      // is the script, so it is sanitized as output-executed; the literal part
      // of the script is not.
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

    // Operands of a text command (`echo`, `grep`, `printf`) are never executed
    // — unless this segment's OUTPUT is what gets executed, in which case they
    // are the script. `bash -c "$(echo rm -rf /)"` and `echo "rm -rf /" | bash`
    // both run it; redacting the operand there hid a hard-block bypass.
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
        // This segment executes a command string (`ssh host "…"`, `mysql -e "…"`),
        // or its output is executed by whoever asked for it. Either way the
        // quoted argument is code — unquote and scan it, recursively.
        out.push({ start: p.start, end: p.end, with: sanitize(p.text, depth + 1) });
      } else {
        // A quoted, multi-word argument to an ordinary command is prose data.
        out.push({ start: p.start, end: p.end, with: " " });
      }
    }
  }
}

function sanitize(command: string, depth: number, outputExecuted = false): string {
  if (!command || depth > MAX_SANITIZE_DEPTH) return command;

  const pieces = tokenize(command);
  const replacements: Replacement[] = [];

  // Collect segments with the operator that ends each, so a segment can be
  // asked whether its output feeds a shell.
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
export function sanitizeCommandForMatching(command: string): string {
  return sanitize(command, 0);
}

/**
 * Assess risk level of a command string.
 */
export function assessCommandRisk(command: string): CommandRiskLevel {
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
  const cmd = sanitizeCommandForMatching(command).toLowerCase().trim();
  for (const pattern of CRITICAL_PATTERNS) {
    if (pattern.test(cmd)) return pattern.source;
  }
  return null;
}
