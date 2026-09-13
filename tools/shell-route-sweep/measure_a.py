#!/usr/bin/env python3
"""Measure A — rule-kill coverage, with payloads DERIVED FROM THE RULES.

Answers the one question B, C and D cannot: is the corpus's coverage of
code-bearing positions COMPLETE, or merely plausible?

THREE EARLIER VERSIONS WERE WRONG, and each was wrong in a way that produced a
confident number:
  v1  extracted the wrong bracket -- `list[str]` ate a lazy match -- so the
      mutation deleted nothing and every rule reported "not killed". 0%.
  v2  fixed that and still said 0%, because the two `rm` rules are REDUNDANT
      (each matches what the other does, so deleting either alone changes no
      verdict) and because every row used ONE hand-written payload, leaving the
      mkfs/dd/fdisk rules with nothing to exercise them.
  v3  varied the payload across NINE HAND-PICKED shapes -- and that hand-list
      was the last hand-written component of the whole sweep. It is what
      Measure A exists to catch, sitting inside Measure A.

This version generates a matching example FOR EACH RULE from the rule's own
compiled parse tree, so coverage is complete by construction rather than by my
imagination. The generator is self-checked: an example that does not match the
rule it came from is reported, never counted.
"""
import importlib.util, json, pathlib, re, sys, tempfile

try:
    import re._parser as sre_parse          # 3.11+
except ImportError:                          # pragma: no cover
    import sre_parse                         # type: ignore

SAFE = {"\\s": " ", "\\w": "x", "\\d": "7", "any": "x"}


def _from_in(items) -> str:
    """Pick one member of a character class."""
    for op, arg in items:
        name = str(op)
        if name == "LITERAL":
            return chr(arg)
        if name == "RANGE":
            return chr(arg[0])
        if name == "CATEGORY":
            c = str(arg)
            if "SPACE" in c:
                return " "
            if "DIGIT" in c:
                return "7"
            return "x"
    return "x"


def example(seq) -> str:
    out = []
    for op, arg in seq:
        name = str(op)
        if name == "LITERAL":
            out.append(chr(arg))
        elif name == "NOT_LITERAL":
            out.append("x" if chr(arg) != "x" else "y")
        elif name == "ANY":
            out.append("x")
        elif name == "IN":
            neg = any(str(o) == "NEGATE" for o, _ in arg)
            out.append("x" if neg else _from_in(arg))
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            lo, _hi, sub = arg
            out.append(example(sub) * max(lo, 0))
        elif name == "SUBPATTERN":
            out.append(example(arg[3] if len(arg) > 3 else arg[1]))
        elif name == "BRANCH":
            out.append(example(arg[1][0]))
        elif name in ("AT", "NEGATE"):
            pass
        elif name == "GROUPREF":
            pass
        else:
            out.append("")
    return "".join(out)


def derive(patterns):
    """(pattern, example, ok) per rule; ok=False when the generator failed it."""
    rows = []
    for p in patterns:
        try:
            ex = example(sre_parse.parse(p))
            ok = re.search(p, ex, re.IGNORECASE) is not None
        except Exception:
            ex, ok = "", False
        rows.append((p, ex, ok))
    return rows


def load(src: str):
    f = pathlib.Path(tempfile.mkdtemp()) / "rr.py"
    f.write_text(src)
    s = importlib.util.spec_from_file_location("m", f)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def main():
    rr_path = pathlib.Path(sys.argv[1])
    corpus = json.loads(pathlib.Path(sys.argv[2]).read_text())["rows"]
    src = rr_path.read_text()
    base = load(src)

    derived = derive(list(base.CRITICAL_PATTERNS) + list(base.HIGH_PATTERNS))
    ungenerable = [p for p, _e, ok in derived if not ok]
    payloads = [e for _p, e, ok in derived if ok]

    # Each rule's own example, bare AND embedded in every corpus construct, so a
    # rule is exercised through the real shell shapes rather than in isolation.
    cmds = list(payloads)
    for r in corpus:
        for pay in payloads:
            cmds.append(r["cmd"].replace("__PAYLOAD__", pay)
                                .replace("{FILE}", "/tmp/p.txt")
                                .replace("{B64}", "Y21k").replace("{HEX}", "636d64"))
    base_v = [base.assess_command_risk(c) for c in cmds]

    killed, redundant, uncovered_rules = [], [], []
    # Mutate the LOADED pattern lists by index rather than editing source text.
    # assess_command_risk iterates the module-level lists at call time, so
    # removing an element is a real mutation -- and unlike source matching it
    # works for f-string rules, whose compiled text never appears verbatim in
    # the file. The earlier text-matching version silently could not touch two
    # rules and dropped them from the denominator entirely.
    for pat, ex, ok in derived:
        if not ok:
            continue
        for lst in (base.CRITICAL_PATTERNS, base.HIGH_PATTERNS):
            if pat in lst:
                idx = lst.index(pat)
                lst.pop(idx)
                try:
                    v = [base.assess_command_risk(c) for c in cmds]
                finally:
                    lst.insert(idx, pat)          # always restore
                if v != base_v:
                    killed.append(pat)
                else:
                    sibs = [q for q, _e, _o in derived
                            if q != pat and re.search(q, ex, re.IGNORECASE)]
                    (redundant if sibs else uncovered_rules).append(pat)
                break

    total = len([1 for _p, _e, ok in derived if ok])
    print("=== MEASURE A — rule-kill coverage (payloads derived from the rules) ===")
    print(f"  rules: {len(derived)}   examples generated and self-verified: {total}")
    if ungenerable:
        print(f"  GENERATOR FAILED on {len(ungenerable)} rule(s) — reported, not counted:")
        for p in ungenerable[:6]:
            print(f"    {p[:64]}")
    print(f"  classifications run: {len(cmds)}")
    print(f"  KILLED    (corpus isolates the rule): {len(killed)}/{total}")
    print(f"  REDUNDANT (a sibling matches it too): {len(redundant)}/{total}")
    covered = len(killed) + len(redundant)
    print(f"  COVERAGE  (killed + redundant)      : {covered}/{total}"
          + (f" = {100*covered//total}%" if total else ""))
    print(f"  UNCOVERED (no row exercises it)     : {len(uncovered_rules)}")
    for p in uncovered_rules[:6]:
        print(f"    uncovered: {p[:62]}")
    ok = not uncovered_rules and not ungenerable
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
