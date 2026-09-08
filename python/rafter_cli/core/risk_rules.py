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
_EVAL_EXECS = {"eval", "exec", "ssh", "sshpass", "xargs"}

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


def assess_command_risk(command: str) -> str:
    """Assess risk level of a command string."""
    cmd = sanitize_command_for_matching(command).strip()
    if not cmd:
        return "low"
    for p in CRITICAL_PATTERNS:
        if re.search(p, cmd, re.IGNORECASE):
            return "critical"
    for p in HIGH_PATTERNS:
        if re.search(p, cmd, re.IGNORECASE):
            return "high"
    for p in MEDIUM_PATTERNS:
        if re.search(p, cmd, re.IGNORECASE):
            return "medium"
    return "low"


def match_critical_pattern(command: str) -> str | None:
    """Return the first CRITICAL pattern matching the command, or None.

    Mirrors assess_command_risk's sanitization. Intended to be called only once a
    command is already classified "critical", to surface *which* built-in rule
    matched.
    """
    cmd = sanitize_command_for_matching(command).strip()
    for p in CRITICAL_PATTERNS:
        if re.search(p, cmd, re.IGNORECASE):
            return p
    return None
