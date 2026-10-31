#!/usr/bin/env python3
"""rf-zvll: generate the space of "an argument reaches a shell".

SEEDED FROM FOUR SOURCES, NONE OF THEM A LIST OF KNOWN BUGS:
  1. the shell grammar   -- productions that introduce a command word / pipe into one
  2. the classifier's own tables -- parsed out of risk_rules.py at runtime
  3. the environment     -- exec-capable binaries actually on PATH
  4. flag mining         -- --help scanned for flags whose value is a command

If this file ever grows a hard-coded `echo hi\\nrm -rf /`, the generator has
become a hand-list with extra steps and Measure B below is meaningless.
"""
import itertools, json, re, shutil, subprocess, sys, pathlib

PAYLOAD = "__PAYLOAD__"          # replaced later by a canary or by `rm -rf /`

# ---------------------------------------------------------------- 1. GRAMMAR
# Statement separators, from the shell grammar. NOTE newline is a separator
# here because the grammar says so, not because we know about rf-6pqx.
SEPARATORS = [";", "&&", "||", "|", "&", "\n"]

# Productions that take a command and place it somewhere it may be executed.
# {C} is a command; the production yields a full command line.
PRODUCTIONS = {
    "cmdsubst-dollar":   '{HOST} "$({C})"',
    "cmdsubst-backtick": '{HOST} "`{C}`"',
    "procsubst-in":      '{HOST} <({C})',
    "procsubst-out":     '{HOST} >({C})',
    "subshell":          '( {C} )',
    "bracegroup":        '{{ {C} ; }}',
    "background":        '{C} &',
    "heredoc":           '{HOST} <<EOF\n{C}\nEOF',
    "heredoc-quoted":    "{HOST} <<'EOF'\n{C}\nEOF",
    "heredoc-dash":      '{HOST} <<-EOF\n{C}\nEOF',
    "herestring":        '{HOST} <<< "{C}"',
    "redirect-in":       '{HOST} < {FILE}',
    "funcdef-call":      'f() {{ {C} ; }}; f',
    "trap-exit":         "trap '{C}' EXIT; true",
    "alias-call":        "alias a='{C}'; a",
}

# ------------------------------------------------- 2. THE CLASSIFIER'S TABLES
def parse_tables(risk_rules_py: pathlib.Path) -> dict:
    """Read the sets the classifier itself reasons with. Gaps in these tables
    are exactly where we expect findings, so they are an input, not an oracle."""
    src = risk_rules_py.read_text()
    out = {}
    for name in ("_SHELL_EXECS", "_EVAL_EXECS", "_EVAL_FLAGS", "_TAIL_WRAPPERS", "_TEXT_EXECS"):
        m = re.search(name + r"\s*[:=].*?\{(.*?)\}", src, re.S)
        out[name] = sorted(set(re.findall(r'"([^"]+)"', m.group(1)))) if m else []
    return out

# ------------------------------------------------------------ 3. ENVIRONMENT
# Binaries on PATH that can execute an argument. The NAMES are enumerated from
# the machine; the flag for each is discovered by mining --help (source 4).
EXEC_CANDIDATES = [
    "bash", "sh", "zsh", "dash", "ksh", "env", "sudo", "nohup", "timeout", "nice",
    "setsid", "stdbuf", "xargs", "find", "parallel", "ssh", "script", "expect",
    "unbuffer", "socat", "watch", "make", "awk", "perl", "python3", "node", "ruby",
    "php", "sed", "git", "docker", "kubectl", "flock", "chroot", "runuser", "su",
]
def on_path(names): return [n for n in names if shutil.which(n)]

# ----------------------------------------------------------- 4. FLAG MINING
CMD_FLAG = re.compile(r"(?<![\w-])(-c|-e|-r|--exec|-exec|--eval|--command|--run)(?![\w-])")
def mine_flags(binary: str) -> list:
    """Scan --help for flags whose value is a command. Environment-derived."""
    for probe in (["--help"], ["-h"], ["--usage"]):
        try:
            p = subprocess.run([binary] + probe, capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        txt = (p.stdout or "") + (p.stderr or "")
        if not txt.strip():
            continue
        hits = []
        for line in txt.splitlines():
            if not CMD_FLAG.search(line):
                continue
            if re.search(r"\b(command|program|script|expression|code|exec)\b", line, re.I):
                for f in CMD_FLAG.findall(line):
                    if f not in hits:
                        hits.append(f)
        if hits:
            return hits[:3]
    return []

# --------------------------------------------- DELIVERY: how bytes arrive
# Orthogonal axis: the payload may be inline, or arrive through a channel the
# classifier cannot read. Derived from "what can produce bytes on a stream",
# not from any particular known bug.
DELIVERY = {
    "inline":   lambda p: p,
    "echo":     lambda p: f"echo '{p}'",
    "printf":   lambda p: f"printf '%s' '{p}'",
    "file":     lambda p: "cat {FILE}",
    "base64":   lambda p: "echo {B64} | base64 -d",
    "xxd":      lambda p: "echo {HEX} | xxd -r -p",
    "variable": lambda p: f"P='{p}'; printf '%s' \"$P\"",
}

def build(tables: dict, execs: list, flags: dict) -> list:
    rows = []
    shells = [e for e in execs if e in ("bash", "sh", "zsh", "dash", "ksh")] or ["sh"]
    hosts  = (tables.get("_TEXT_EXECS") or ["cat", "grep"])[:4]

    # A. separator compositions: a benign statement then the payload
    for sep in SEPARATORS:
        rows.append(("separator/" + repr(sep), f"echo ok{sep}{PAYLOAD}"))
        for sh in shells[:2]:
            rows.append(("separator-into-shell/" + repr(sep), f"echo ok{sep}{sh} -c '{PAYLOAD}'"))

    # B. grammar productions hosting the payload
    for pname, tpl in PRODUCTIONS.items():
        for host in hosts[:3]:
            rows.append(("production/" + pname,
                         tpl.replace("{HOST}", host).replace("{C}", PAYLOAD)))
        for sh in shells[:2]:
            rows.append(("production-shell/" + pname,
                         tpl.replace("{HOST}", sh).replace("{C}", PAYLOAD)))

    # C. delivery x carrier: bytes reach a shell through every channel
    for dname, dfn in DELIVERY.items():
        producer = dfn(PAYLOAD)
        for sh in shells:
            rows.append((f"delivery/{dname}|{sh}", f"{producer} | {sh}"))
            rows.append((f"delivery/{dname}|{sh}-s", f"{producer} | {sh} -s"))
        for carrier in [e for e in execs if e in ("xargs", "parallel")]:
            for sh in shells[:2]:
                rows.append((f"delivery/{dname}|{carrier}-{sh}", f"{producer} | {carrier} {sh} -c"))
        rows.append((f"delivery/{dname}|eval", f'eval "$({producer})"'))

    # D. exec carriers x their mined command-flags
    for b, fs in flags.items():
        for f in fs:
            rows.append((f"carrier/{b}{f}", f"{b} {f} '{PAYLOAD}'"))
    for w in [e for e in execs if e in tables.get("_TAIL_WRAPPERS", [])]:
        for sh in shells[:2]:
            rows.append((f"wrapper/{w}-{sh}", f"{w} {sh} -c '{PAYLOAD}'"))
    if "find" in execs:
        rows.append(("carrier/find-exec", f"find . -maxdepth 0 -exec {PAYLOAD} \;"))
    if "xargs" in execs:
        rows.append(("carrier/xargs-I", f"echo x | xargs -I{{}} {PAYLOAD}"))

    seen, uniq = set(), []
    for tag, c in rows:
        if c not in seen:
            seen.add(c); uniq.append({"tag": tag, "cmd": c})
    return uniq

if __name__ == "__main__":
    rr = pathlib.Path(sys.argv[1])
    tables = parse_tables(rr)
    execs = on_path(EXEC_CANDIDATES)
    flags = {b: mine_flags(b) for b in execs}
    flags = {b: f for b, f in flags.items() if f}
    rows = build(tables, execs, flags)
    json.dump({"tables": {k: len(v) for k, v in tables.items()},
               "execs_on_path": execs, "mined_flags": flags, "rows": rows},
              open(sys.argv[2], "w"), indent=1)
    print(f"tables parsed: { {k: len(v) for k, v in tables.items()} }")
    print(f"execs on PATH: {len(execs)}  flag-mined binaries: {len(flags)}")
    print(f"GENERATED ROWS: {len(rows)}")
