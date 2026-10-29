#!/usr/bin/env python3
"""rf-6pqx DIFFERENTIAL gate (python). The lesson of db9a809: a battery that goes
red-on-unpatched is still only as good as its cases, and a single-line here-string
case never exercised the multi-line path where <<< is misread as << and the next
line is swallowed. So this gate does NOT trust hand-picked expectations alone: it
runs a GENERATED corpus of shell-argument constructs on BOTH main and the
candidate and asserts the candidate is NEVER more permissive than main — except a
construct whose owner does not execute it (a pure data-heredoc body, #230; a here-
string with a non-executing owner, rf-gn0h). Both exemptions are keyed on the exec
name computed in THIS file, never on an answer from the code under test.

Usage: rf-6pqx-differential.py <main risk_rules.py> <candidate risk_rules.py>
Exit 0 iff no non-allowlisted row moved toward permissive AND every explicit
regression case is critical on the candidate."""
import sys, importlib.util
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
def load(p):
    s = importlib.util.spec_from_file_location("rr" + str(id(p)), p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
main = load(sys.argv[1]); cand = load(sys.argv[2])
P = "rm -rf /"
DATA_EXECS = ["cat", "grep -q x", "tee /tmp/z", "head", "tac"]
SHELL_EXECS = ["bash", "sh", "sudo bash", "env FOO=1 bash", "zsh"]
corpus = []  # (label, cmd, perm_ok)  perm_ok=True => allowed to be more-permissive than main (data heredoc)
def add(label, cmd, perm_ok): corpus.append((label, cmd, perm_ok))
for E in DATA_EXECS + SHELL_EXECS:
    is_shell = any(E == s or E.endswith(" bash") or E.split()[-1] in ("bash","sh","zsh") for s in SHELL_EXECS)
    # pure data-heredoc: intentional strip ONLY when the owner does not execute
    add(f"heredoc-data [{E}]", f"{E} <<EOF\n{P}\nEOF", perm_ok=not is_shell)
    # here-string, single line. A here-string whose owner does NOT execute it is data,
    # exactly as a data-heredoc body is (#230) — same construct, same rule, other syntax.
    # The exemption is keyed on the EXEC NAME, computed here and not by the classifier
    # under test, so a broken candidate cannot grant itself this row. (rf-gn0h)
    add(f"herestring-1 [{E}]", f'{E} <<< "{P}"', perm_ok=not is_shell)
    # ...and the composition that exemption must never mask: the owner is data, but its
    # OUTPUT is executed. Stays perm_ok=False for EVERY exec, shell or not.
    add(f"herestring-pipe-bash [{E}]", f'{E} <<< "{P}" | bash', perm_ok=False)
    add(f"herestring-pipe-sh [{E}]", f'{E} <<< "{P}" | sudo sh', perm_ok=False)
    # here-string, MULTI-LINE (the regression: <<< misread as << swallows next line)
    add(f"herestring-multi [{E}]", f'{E} <<< "marker" > /tmp/x\n{P}', perm_ok=False)
    # heredoc piped to a shell (the other regression: owner is data but output is executed)
    add(f"heredoc-pipe-bash [{E}]", f"{E} <<EOF | bash\n{P}\nEOF", perm_ok=False)
    add(f"heredoc-pipe-sh [{E}]", f"{E} <<DATA | sudo sh\n{P}\nDATA", perm_ok=False)
    # process substitution & command substitution feeding the exec
    add(f"cmdsubst [{E}]", f'{E} "$({P})"', perm_ok=False)
    add(f"newline [{E}]", f"{E} foo\n{P}", perm_ok=False)
fails = 0
perm_regressions = []
for label, cmd, perm_ok in corpus:
    a = main.assess_command_risk(cmd); b = cand.assess_command_risk(cmd)
    more_perm = RANK.get(b, 9) < RANK.get(a, 9)
    if more_perm and not perm_ok:
        perm_regressions.append((label, a, b, cmd))
        fails += 1
print(f"=== DIFFERENTIAL: {len(corpus)} generated rows, candidate vs main ===")
if perm_regressions:
    print(f"\n{len(perm_regressions)} PERMISSIVE REGRESSION(S) — candidate weaker than main on a non-data-heredoc construct:")
    for label, a, b, cmd in perm_regressions:
        print(f"  [REGRESSION] {label:26s} main={a:8s} cand={b:8s}  {cmd!r}")
else:
    print("  no non-allowlisted permissive move (candidate never weaker than main except data heredocs)")
print(f"\n{'DIFFERENTIAL CLEAN' if not fails else str(fails)+' PERMISSIVE REGRESSIONS'}")
sys.exit(1 if fails else 0)
