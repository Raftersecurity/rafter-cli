// Node 18 smoke test of the BUILT artifact — deliberately not a vitest test.
//
// vitest 4 declares engines ^20 || ^22 || >=24, so it cannot run on Node 18 at
// all; the old cross-platform matrix leg was therefore exercising the runner's
// unsupported path rather than the product, and said nothing about either. But
// package.json still declares engines >=18, and a support claim nothing checks
// is a claim, not a guarantee.
//
// So this runs what a Node 18 USER runs: the compiled dist, under Node 18, with
// no test framework in the way. It asserts the rf-fuwy liveness probe both ways
// — a live gate yields its decision, an inert one yields none — because that is
// the property the release exists to establish, and the one place Node 18
// coverage would actually matter.
import { runConfiguredHook } from "../dist/commands/agent/verify.js";
const cmd = `printf '%s' '{"hookSpecificOutput":{"permissionDecision":"deny"}}'`;
const r = runConfiguredHook(cmd, "rm -rf / --no-preserve-root");
if (r.decision !== "deny") {
  console.error(`FAIL: probe read ${JSON.stringify(r.decision)}, expected "deny"`);
  console.error(JSON.stringify(r));
  process.exit(1);
}
const dead = runConfiguredHook("rafter-does-not-exist-9c1f hook pretool", "rm -rf /");
if (dead.decision !== null || dead.status === 0) {
  console.error(`FAIL: an inert gate was not reported inert: ${JSON.stringify(dead)}`);
  process.exit(1);
}
console.log(`OK on ${process.version}: live gate -> "deny", inert gate -> no decision, status ${dead.status}`);
