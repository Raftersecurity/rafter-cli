// rf-6pqx DIFFERENTIAL gate (node) — mirror of rf-6pqx-differential.py. Same
// generated corpus; asserts the candidate is never more permissive than main
// except a pure data-heredoc body (#230). Run:
//   bun run rf-6pqx-differential.node.ts <main risk-rules.ts> <candidate risk-rules.ts>
const RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const mainMod = await import(process.argv[2]);
const candMod = await import(process.argv[3]);
const A = (m: any) => m.assessCommandRisk as (c: string) => string;
const P = "rm -rf /";
const DATA_EXECS = ["cat", "grep -q x", "tee /tmp/z", "head", "tac"];
const SHELL_EXECS = ["bash", "sh", "sudo bash", "env FOO=1 bash", "zsh"];
const isShell = (E: string) => { const last = E.split(" ").pop()!; return ["bash", "sh", "zsh"].includes(last); };
const corpus: [string, string, boolean][] = [];
for (const E of [...DATA_EXECS, ...SHELL_EXECS]) {
  const sh = isShell(E);
  corpus.push([`heredoc-data [${E}]`, `${E} <<EOF\n${P}\nEOF`, !sh]);
  corpus.push([`herestring-1 [${E}]`, `${E} <<< "${P}"`, false]);
  corpus.push([`herestring-multi [${E}]`, `${E} <<< "marker" > /tmp/x\n${P}`, false]);
  corpus.push([`heredoc-pipe-bash [${E}]`, `${E} <<EOF | bash\n${P}\nEOF`, false]);
  corpus.push([`heredoc-pipe-sh [${E}]`, `${E} <<DATA | sudo sh\n${P}\nDATA`, false]);
  corpus.push([`cmdsubst [${E}]`, `${E} "$(${P})"`, false]);
  corpus.push([`newline [${E}]`, `${E} foo\n${P}`, false]);
}
const regs: [string, string, string, string][] = [];
for (const [label, cmd, permOk] of corpus) {
  const a = A(mainMod)(cmd), b = A(candMod)(cmd);
  if ((RANK[b] ?? 9) < (RANK[a] ?? 9) && !permOk) regs.push([label, a, b, cmd]);
}
console.log(`=== DIFFERENTIAL (node): ${corpus.length} rows, candidate vs main ===`);
if (regs.length) {
  console.log(`\n${regs.length} PERMISSIVE REGRESSION(S):`);
  for (const [label, a, b, cmd] of regs) console.log(`  [REGRESSION] ${label.padEnd(26)} main=${a.padEnd(8)} cand=${b.padEnd(8)} ${JSON.stringify(cmd)}`);
} else console.log("  no non-allowlisted permissive move");
console.log(`\n${regs.length ? regs.length + " PERMISSIVE REGRESSIONS" : "DIFFERENTIAL CLEAN"}`);
process.exit(regs.length ? 1 : 0);
