#!/usr/bin/env python3
"""rf-zvll oracle: let bash adjudicate.

Each generated row is instantiated TWICE:
  cmd_exec     payload -> `touch $CANARY`   ... actually RUN, in a sandbox
  cmd_classify payload -> a dangerous cmd   ... only ever passed to the classifier

If the canary fires, the construct really does execute its payload — bash said
so, not us. If the classifier then rates the dangerous instantiation `low`,
that is a real execution route the classifier cannot see. Measure D.

SAFETY: the executed string is asserted to contain no destructive token before
it is allowed anywhere near a shell. The dangerous text exists only as an
argument to a pure Python function.
"""
import importlib.util, json, os, pathlib, re, shutil, subprocess, sys, tempfile

DANGEROUS = "rm -rf /"
FORBIDDEN = re.compile(r"\brm\s+-[rf]|\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b|:\(\)\{|>\s*/dev/sd")

def load(p, n):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

def instantiate(cmd, payload, sandbox, canary):
    c = cmd.replace("__PAYLOAD__", payload)
    pf = sandbox / "payload.txt"
    c = c.replace("{FILE}", str(pf))
    import base64 as b64
    c = c.replace("{B64}", b64.b64encode(payload.encode()).decode())
    c = c.replace("{HEX}", payload.encode().hex())
    return c

def main():
    corpus = json.load(open(sys.argv[1]))["rows"]
    rr = load(sys.argv[2], "rr")
    sandbox = pathlib.Path(tempfile.mkdtemp(prefix="rf-zvll-"))
    results = []
    try:
        for i, row in enumerate(corpus):
            canary = sandbox / f"canary_{i}"
            exec_payload = f"touch {canary}"
            cmd_exec = instantiate(row["cmd"], exec_payload, sandbox, canary)
            (sandbox / "payload.txt").write_text(exec_payload + "\n")

            # SAFETY GATE — never run anything matching a destructive shape.
            if FORBIDDEN.search(cmd_exec):
                results.append({**row, "skipped": "failed safety gate"}); continue

            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(sandbox), "SHELL": "/bin/sh"}
            fired = False
            try:
                subprocess.run(["bash", "-c", cmd_exec], cwd=sandbox, env=env,
                               timeout=5, capture_output=True)
                fired = canary.exists()
            except Exception:
                fired = canary.exists()

            cmd_classify = instantiate(row["cmd"], DANGEROUS, sandbox, canary)
            try:
                verdict = rr.assess_command_risk(cmd_classify)
            except Exception:
                verdict = "ERROR"
            results.append({**row, "executes": fired, "verdict": verdict,
                            "cmd_classify": cmd_classify})
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    ran = [r for r in results if "executes" in r]
    findings = [r for r in ran if r["executes"] and r["verdict"] in ("low", "medium")]
    overblock = [r for r in ran if not r["executes"] and r["verdict"] == "critical"]
    json.dump(results, open(sys.argv[3], "w"), indent=1)

    print(f"=== MEASURE D — oracle disagreement (the yield) ===")
    print(f"  rows executed in sandbox: {len(ran)}  (skipped by safety gate: {len(results)-len(ran)})")
    print(f"  payload actually RAN: {sum(1 for r in ran if r['executes'])}")
    print(f"  FINDINGS — executes but classifier says low/medium: {len(findings)}")
    seen = set()
    for r in sorted(findings, key=lambda x: x["tag"]):
        fam = r["tag"].split("/")[0] + "/" + r["tag"].split("/")[1].split("|")[0]
        if fam in seen: continue
        seen.add(fam)
        print(f"    [{r['verdict']:6}] {r['tag'][:34]:34} {r['cmd_classify'][:58]!r}")
    print(f"  (families shown: {len(seen)}; total findings {len(findings)})")
    print(f"  over-block candidates — never executes but rated critical: {len(overblock)}")

main()
