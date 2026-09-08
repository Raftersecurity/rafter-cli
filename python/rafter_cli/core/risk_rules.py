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
# HEREDOC (sable-5ogx / issue #230). `cat > notes.md <<'EOF' … EOF` WRITES its
# body to a file; it does not run it. Without heredoc handling the body reached
# the matcher as bare words, so documentation that quotes a dangerous command
# scored identically to running it -- a prose line mentioning `rm -rf /` in a
# markdown file classified CRITICAL, the tier no policy, mode or deny-list can
# override. So a heredoc body is DATA, with one exception.
#
# The exception is the case where the body really is executed: a shell or
# eval-style exec consuming it (`bash <<EOF`, `ssh host <<EOF`), or a segment
# whose output is piped into a shell (`cat <<EOF | bash`). Those reuse the same
# _SHELL_EXECS / _EVAL_EXECS machinery that already governs quoted arguments,
# rather than adding a second rule beside it.
#
# This has to happen in the TOKENIZER, not as a filter afterward: once the input
# has been split into statements, the fact that a line was heredoc body is gone.
# rf-6pqx splits statements on newlines, and a body line promoted to its own
# statement is exactly the #230 regression.
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
_REDIRECT_OPS = {">", ">>", "<", "<<", "<<-", "<<<"}

# Bound on recursion through nested shell wrappers / substitutions.
_MAX_SANITIZE_DEPTH = 8

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_C_FLAG = re.compile(r"^-[a-z]*c$")
_LONG_FLAG_WITH_VALUE = re.compile(r"^(--[a-z][a-z-]*)=")
_NUMERIC_ARG = re.compile(r"^\d+[a-z]*$", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s")


class _Piece:
    """A word or an operator, with its span in the source string."""

    __slots__ = (
        "start", "end", "op", "text", "quoted", "substs",
        "heredoc_body", "heredoc_delim",
    )

    def __init__(
        self,
        start: int,
        end: int,
        op: str | None,
        text: str,
        quoted: bool,
        substs: list[str],
        heredoc_body: bool = False,
        heredoc_delim: bool = False,
    ) -> None:
        self.start = start
        self.end = end
        self.op = op
        self.text = text
        self.quoted = quoted
        self.substs = substs
        #: True for the body of a heredoc — see HEREDOC in the module notes.
        self.heredoc_body = heredoc_body
        #: True for the word naming a heredoc's terminator (`<<EOF` -> `EOF`).
        self.heredoc_delim = heredoc_delim


def _is_op_char(c: str) -> bool:
    return c in (";", "&", "|", ">", "<")


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


def _read_heredoc_bodies(s: str, i: int, queued: list[tuple[str, bool]]) -> int:
    """Consume the heredoc bodies queued on this line, starting at newline ``i``.

    Returns the index just past the last terminator consumed. An UNTERMINATED
    heredoc runs to end of input: that is the fail-safe direction, because the
    alternative is scanning documentation as commands.
    """
    j = i + 1
    n = len(s)
    for delim, strip_tabs in queued:
        while True:
            if j >= n:
                j = n
                break
            nl = s.find("\n", j)
            line_end = n if nl == -1 else nl
            line = s[j:line_end]
            if strip_tabs:
                # `<<-` strips leading TABS from the terminator — tabs only.
                line = line.lstrip("\t")
            if line == delim:
                j = n if nl == -1 else nl + 1
                break
            if nl == -1:
                j = n
                break
            j = nl + 1
    return j


def _tokenize(s: str) -> list[_Piece]:
    """Split a command line into words and operators, respecting quotes/substitutions."""
    pieces: list[_Piece] = []
    i = 0
    n = len(s)
    #: Heredocs introduced on the current line, in the order the shell reads them.
    queued: list[tuple[str, bool]] = []
    #: Set after `<<`/`<<-`: the next word names the terminator, not a path.
    expect_delim: bool | None = None

    while i < n:
        c = s[i]

        # A newline with heredocs queued: everything through the terminators is
        # body text, and body text is data. This must precede the whitespace
        # skip below, which would otherwise step over the newline and let the
        # body tokenize as ordinary words.
        if c == "\n" and queued:
            body_start = i + 1
            end = _read_heredoc_bodies(s, i, queued)
            queued = []
            if end > body_start:
                pieces.append(
                    _Piece(
                        body_start, end, None, s[body_start:end], True, [],
                        heredoc_body=True,
                    )
                )
            i = end
            continue

        if c.isspace():
            i += 1
            continue

        if _is_op_char(c):
            start = i
            three = s[i:i + 3]
            two = s[i:i + 2]
            if three == "<<<":
                # A here-STRING, not a heredoc: one word operand, no body.
                # Mistaking it for `<<` would swallow the rest of the input.
                op = three
            elif three == "<<-":
                op = three
            elif two in ("&&", "||", ">>", "<<"):
                op = two
            else:
                op = c
            i += len(op)
            pieces.append(_Piece(start, i, op, op, False, []))
            if op in ("<<", "<<-"):
                expect_delim = op == "<<-"
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
                i += 1
                if i < n:
                    text.append(s[i])
                    i += 1
                continue

            # Single quotes are inert: no expansion, no substitution.
            if ch == "'":
                i += 1
                quoted = True
                while i < n and s[i] != "'":
                    text.append(s[i])
                    i += 1
                i += 1
                continue

            # Double quotes are data, but `$( )` / backticks inside them DO execute.
            if ch == '"':
                i += 1
                quoted = True
                while i < n and s[i] != '"':
                    if s[i] == "\\":
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
                i += 1
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

        word = "".join(text)
        if expect_delim is not None:
            # `<<'EOF'` / `<<"EOF"` — quoting changes expansion inside the body,
            # not where the body ends, so both forms terminate identically.
            queued.append((word, expect_delim))
            expect_delim = None
            pieces.append(
                _Piece(start, i, None, word, quoted, substs, heredoc_delim=True)
            )
            continue

        pieces.append(_Piece(start, i, None, word, quoted, substs))

    return pieces


def _exec_name(text: str) -> str:
    """`/usr/bin/rm` -> `rm`; used to classify the executable of a segment."""
    return text[text.rfind("/") + 1:].lower()


def _redirect_targets(pieces: list[_Piece]) -> list[bool]:
    """A word is a redirect target when the piece before it is `>`/`>>`/`<`/`<<`."""
    is_redirect_target = [False] * len(pieces)
    for i in range(1, len(pieces)):
        prev = pieces[i - 1]
        if prev.op in _REDIRECT_OPS and pieces[i].op is None:
            is_redirect_target[i] = True
    return is_redirect_target


def _find_exec_idx(pieces: list[_Piece], is_redirect_target: list[bool]) -> int:
    """Index of the word that actually runs.

    Env assignments and prefix wrappers (`sudo`, `env`, `timeout 5`,
    `nice -n 15`, …) are skipped to reach the command they delegate to.
    -1 when the segment runs nothing.
    """
    i = 0
    while i < len(pieces):
        p = pieces[i]
        if p.op is not None or is_redirect_target[i] or p.heredoc_body:
            i += 1
            continue
        if not p.quoted and _ENV_ASSIGNMENT.match(p.text):
            i += 1
            continue
        if not p.quoted and _exec_name(p.text) in _TAIL_WRAPPERS:
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
        return i
    return -1


def _segment_exec(pieces: list[_Piece]) -> str:
    """The effective executable of a segment (`sudo rm -rf /` -> `rm`)."""
    idx = _find_exec_idx(pieces, _redirect_targets(pieces))
    return "" if idx == -1 else _exec_name(pieces[idx].text)


def _process_segment(
    pieces: list[_Piece],
    depth: int,
    out: list[tuple[int, int, str]],
    piped_into_shell: bool = False,
    output_executed: bool = False,
) -> None:
    """Decide which spans of one segment are DATA and which are code."""
    is_redirect_target = _redirect_targets(pieces)
    exec_idx = _find_exec_idx(pieces, is_redirect_target)
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

    # Two different questions, and conflating them gets one of them wrong.
    #
    #   code_carrying   -- this segment RUNS a command string it was handed
    #                      (`bash -c …`, `ssh host …`).
    #   executes_output -- this segment's STDOUT becomes code somewhere else
    #                      (`… | bash`, or a substitution whose result is a
    #                      script).
    #
    # `bash -c "echo 'rm -rf /'"` is code-carrying but its echo merely prints,
    # so the operand stays data. `bash -c "$(echo rm -rf /)"` is the same words
    # with the echo's OUTPUT as the script, so there the operand is code.
    executes_output = piped_into_shell or output_executed
    heredoc_executed = code_carrying or executes_output

    seen_shell = False
    pending_script = False
    prev_text_flag = False

    for i, p in enumerate(pieces):
        if p.op is not None:
            prev_text_flag = False
            continue

        if p.heredoc_body:
            # Recursing on an executed body keeps `bash <<EOF … rm -rf / … EOF`
            # hard-blocking; redacting an unexecuted one is issue #230's fix.
            out.append(
                (
                    p.start,
                    p.end,
                    _sanitize(p.text, depth + 1) if heredoc_executed else " ",
                )
            )
            prev_text_flag = False
            continue
        if p.heredoc_delim:
            prev_text_flag = False
            continue

        is_exec_tok = i == exec_idx
        flag_name = p.text.lower()

        if not p.quoted and _exec_name(p.text) in _SHELL_EXECS:
            seen_shell = True

        # `bash -c <script>` — the next word is a command string, not data.
        if pending_script and not p.text.startswith("-"):
            # The script can be entirely a substitution -- `bash -c "$(…)"` --
            # where `text` is empty and the substitution IS the script. Reading
            # only `text` dropped it, so every `bash -c "$(echo rm -rf /)"`
            # classified low: a silent bypass of the hard block (sable-c6an).
            # The substitution's OUTPUT is the script, so it is sanitized as
            # output-executed; the literal part of the script is not.
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


def _sanitize(command: str, depth: int, output_executed: bool = False) -> str:
    if not command or depth > _MAX_SANITIZE_DEPTH:
        return command

    pieces = _tokenize(command)
    replacements: list[tuple[int, int, str]] = []

    # Collect segments with the operator that ends each, so a segment can be
    # asked whether its output feeds a shell.
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


def sanitize_command_for_matching(command: str) -> str:
    """Normalize a command line for risk/policy pattern matching.

    Quoted text the command consumes as DATA is redacted; text a shell or eval
    wrapper EXECUTES is preserved (and recursively sanitized). Everything else is
    untouched.
    """
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
