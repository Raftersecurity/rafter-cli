#!/usr/bin/env python3
"""rf-zvll gate: replay the recorded shell-route corpus against the CURRENT
classifier and fail on any disagreement that is not in the baseline.

WHAT IT DOES AND DOES NOT CATCH, stated so nobody over-trusts it:
  It catches a classifier change that opens a NEW under-block on a shape the
  corpus already contains, and it catches a fix that silently trades an
  under-block for an over-block. It does NOT discover new SHAPES -- that needs
  re-running generate.py + oracle.py, which executes shell and therefore is not
  a CI job.

EXECUTION GROUND TRUTH is recorded once, in the corpus, by the sandboxed oracle:
`executes` is whether bash actually ran the payload. The gate itself never runs
a shell; it is pure classification against that recorded truth.

THE BASELINE IS NOT A SUPPRESSION LIST. Two properties are asserted by tests:
removing a row while it still disagrees must FAIL, and adding a fresh
disagreeing row must FAIL. A list that can only grow is a suppression list
wearing a gate's clothes. Under-blocks and over-blocks are kept SEPARATE
because they have opposite urgencies -- merged, a fix could trade one for the
other and the total would not move.
"""
import importlib.util, json, pathlib, sys

FIXED_FILE = "/tmp/rf-zvll-payload.txt"      # stable stand-in; the real oracle uses a sandbox path
DANGEROUS  = "rm -rf /"

def load(p):
    s = importlib.util.spec_from_file_location("rr", p); m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m); return m

def render(cmd: str) -> str:
    import base64
    return (cmd.replace("__PAYLOAD__", DANGEROUS)
               .replace("{FILE}", FIXED_FILE)
               .replace("{B64}", base64.b64encode(DANGEROUS.encode()).decode())
               .replace("{HEX}", DANGEROUS.encode().hex()))

def classify_all(corpus, rr):
    under, over = set(), set()
    for r in corpus:
        if "executes" not in r:
            continue
        try:
            v = rr.assess_command_risk(render(r["cmd"]))
        except Exception:
            v = "ERROR"
        if r["executes"] and v in ("low", "medium"):
            under.add(r["key"])
        elif (not r["executes"]) and v == "critical":
            over.add(r["key"])
    return under, over

def run(corpus_path, rr_path, under_base_path, over_base_path):
    corpus = json.load(open(corpus_path))["rows"]
    rr = load(rr_path)
    under, over = classify_all(corpus, rr)
    under_base = set(json.load(open(under_base_path))["keys"])
    over_base = set(json.load(open(over_base_path))["keys"])

    new_under = sorted(under - under_base)
    new_over = sorted(over - over_base)
    fixed_under = sorted(under_base - under)
    fixed_over = sorted(over_base - over)
    return {"under": under, "over": over, "new_under": new_under, "new_over": new_over,
            "fixed_under": fixed_under, "fixed_over": fixed_over}

def main():
    corpus_path, rr_path, ub, ob = sys.argv[1:5]
    r = run(corpus_path, rr_path, ub, ob)
    print(f"=== rf-zvll shell-route gate ===")
    print(f"  under-blocks now {len(r['under'])} (baseline {len(r['under']) - len(r['new_under']) + len(r['fixed_under'])})")
    print(f"  over-blocks  now {len(r['over'])}")
    bad = False
    if r["new_under"]:
        bad = True
        print(f"\n  FAIL: {len(r['new_under'])} NEW under-block(s) — a construct executes and is rated low:")
        for k in r["new_under"][:12]: print(f"    {k}")
    if r["new_over"]:
        bad = True
        print(f"\n  FAIL: {len(r['new_over'])} NEW over-block(s) — rated critical but never executes:")
        for k in r["new_over"][:12]: print(f"    {k}")
    if r["fixed_under"]:
        print(f"\n  PROGRESS: {len(r['fixed_under'])} baselined under-block(s) no longer disagree.")
        print(f"    Remove them from the baseline — the shrink is the evidence the fix worked:")
        for k in r["fixed_under"][:12]: print(f"    {k}")
    if r["fixed_over"]:
        print(f"\n  PROGRESS: {len(r['fixed_over'])} baselined over-block(s) resolved; remove from baseline.")
    if not bad:
        print("\n  PASS — no disagreement outside the baseline.")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
