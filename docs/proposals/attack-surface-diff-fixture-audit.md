# Independent audit of the 10 fixture oracles (fresh context, read-only)

Ranked findings. Verified items are marked where I (poe) confirmed them separately.

## F1 — `compose-file-renamed` expects `transitions: []`, but both documents imply TWO `unchanged` transitions. CORRUPTS (spec/oracle divergence)

Base keys under `infra/docker-compose.yml`, head under `infra/compose.prod.yml`, so Phase 1 matches nothing. `pairingScope` is `infra`; discriminators `redis|6379/tcp` and `web|8080/tcp` are equal and unique on both sides, so Phase 1c matches both pairs and — in A1's own words — "Emit through `classify(..., paired=true)`." §2.8's rule is `if danger == "unchanged" and not paired: return []`. With `paired=true` the no-op guard does not fire; that is exactly why `compose-service-renamed` emits its one `unchanged` line. Same mechanism, same flag, opposite oracle.

The committed `[]` is reachable only via a third `classify` parameter documented nowhere: `differ.ts:127` `classify(base, head, specs, paired = false, emitUnchanged = paired)`, called at line 300 as `classify(b, h, byKind, true, false)` for relocation and line 304 as `classify(b, h, byKind, true)` for Phase 2. Python mirrors it. A1.1 mentions "`emitUnchanged` stays false" once, in the *bucket-residue* paragraph, as an observation — never as a specification for Phase 1c.

The oracle's verdict is probably the better product behavior (a 2-service file rename producing two "unchanged" lines is noise; §3.4's "show the human the tool understood the rename" is served once, not per-property) — but it is currently code-only law. An extractor author reading only the docs will conclude the differ is broken and "fix" it.

Not vacuous: 2-vs-2 residual defeats Phase 2, so without Phase 1c the differ emits four add/removes.

## F2 — Lattice severity makes EVERY added `Allow` and EVERY removed `Deny` `critical`. CORRUPTS the feature

[VERIFIED EMPIRICALLY BY POE: the narrowest possible Allow — literal action, literal resource, no wildcard principal, plus a Condition — comes back `added / increased / critical`.]

§2.3: "`max` over `severityByAxisTop[axis]` for every axis that **increased**". Every IAM axis has `absentRank: "below"`, so absent→present moves all four axes to `greater`. The `principal` axis carries `severityAtTop: "critical"`. So adding the narrowest imaginable statement is `critical`, because `principal` moved from "absent property" to `absent-or-literal` — an axis move that means nothing.

`compare.ts:130-140` / `compare.py` filter `increasingAxes` on `order === "greater"` with no check that the axis arrived anywhere dangerous; `severityAtTop` is contributed by any increase. The implementation is faithful; the spec is wrong.

Consequence: default `--fail-on high` breaks the build at `critical` on any PR that adds any IAM statement to any policy JSON. Defeats §5's "empty report on the median PR" and R5's noise budget. A1 Defect 2's residual-risk paragraph leans on this path and calls it acceptable over-reporting — at `critical`, it is not.

`iam-deny-removed` is the only fixture on this path and uses `Deny * on *`, the one Deny where `critical` is right for the wrong reason. A narrow-Deny-removed or narrow-Allow-added fixture would have exposed it. Fix before E2 is written, since it changes what a correct `iam-deny-removed` severity is.

## F3 — `iam-deny-removed`'s head is not an IAM candidate at all. CORRUPTS

Head is `{"Version": ..., "Statement": []}`. §4.3 stage 2 requires the file parse as an object with a `Statement` array **whose first element has an `Effect` key**. An empty array has no first element, so the head file fails stage 2 and is "silently non-candidate — not `Unanalyzed`." It is never analyzed.

- `coverage.analyzed` should be **1**, not 2 (every other fixture's 2 = base file + head file both parsed).
- Worse, the case asserts "a whole policy file stopped being an IAM policy," not "a `Deny` statement was deleted." An extractor that never reaches the head document passes it.
- `"Statement": []` is also rejected by AWS as `MalformedPolicyDocument`, so it is not a shape worth encoding as an oracle.

Replace the head with a policy retaining a benign statement and dropping only the `Deny`.

The pre-inversion direction IS correct, though: all axes `order:"less"`, aggregate `less`, `invertDanger` flips to `greater` → `danger:"increased"`, `change:"removed"`. Matches §9.1. Do not re-litigate.

## F4 — `pkg.lifecycle_script` (E3) has ZERO fixtures. CORRUPTS by omission

Four Compose cases, six IAM, none for the third extractor. Nothing pins the `fetch` ladder (`local` / `fetches-remote` / `pipes-remote-to-interpreter`), `severityByLevel: [null, "medium", "critical"]`, `allowResidualPairing: false` (the only kind where it is false — so residual pairing must NOT happen and nothing asserts that), or the `npm run` indirection → `unsupported_syntax` refusal.

Minimum: `postinstall` added as `curl … | sh` (added/increased/critical); a `local` script added (added/increased/**severity: null**, which also covers F7.3); a script body edited `local` → `fetches-remote`.

## F5 — The `key` on a paired transition is unspecified. Oracle weakness

`differ.ts:143` emits `key = [base.key, head.key].sort(compareUtf8)[0]` — lexicographically smaller — while `subject`, `label`, `attrs`, `confidence` come from `endpoint = head ?? base`. Neither document states a rule.

In `compose-service-renamed`, `cache` < `redis`, so min-of-two and head-key coincide and the committed value passes under either rule. Rename the other direction (`cache` → `redis`) and `key` names the base service while `subject`/`attrs` name the head's. Pick a rule (head's key, matching `label = (head ?? base).label`), write it into §2.8, add a reverse-alphabetical rename fixture.

## F6 — §7.1's `not-published` rank is wrong about Compose. Domain error, currently unexercised

[VERIFIED BY POE against docs.docker.com/reference/compose-file/services/: with long syntax, omitting `published` yields an automatically allocated ephemeral host port; short-syntax bare `- "6379"` likewise "the container runtime automatically allocates any unassigned port of the host". Both ARE published.]

§7.1 says `not-published` = "`expose:` entry, or a long-syntax entry with `mode: host` absent and no host port". Anything under `ports:` publishes. Classifying that `not-published` maps it to `severityByLevel[0] = null` — a genuinely host-reachable port scored as a non-reported line. False negative in the dangerous direction. Short-syntax bare container port is not covered by the rank table at all.

`expose:` → `not-published` is correct (it publishes nothing) — do not touch that half.

## F7 — Behaviors the spec promises that no case covers. Oracle gap

1. **`danger: "unknown"`** — zero fixtures, two producers: §7.2's textually-different `Condition`s → axis `unknown`, and §5 R3's asymmetric-unanalyzability suppression, which the spec calls "the single most important anti-cry-wolf rule." `differ.ts:284` implements the latter and nothing asserts it.
2. **`coverage.degraded` / `inconclusive` / non-empty `unanalyzed[]`** — all ten cases are `{false, false, []}`. Exit 4 and the whole §5 R4 fail-open fix have no oracle. Nor does any refused construct (`extends`, `include`, `<<`, `${…}`, port ranges, `profiles`, `NotAction`, policy variables).
3. **`severity: null` on an `added` property** — §7.1's `expose:`-only port.
4. **The `principal` axis moving** — the `critical` axis; a resource policy gaining `Principal: "*"` is the highest-value thing E2 can find. Nothing moves it.
5. **§2.3's ≥2-axes-at-top → `critical` promotion** — never reached on its own merits.
6. **`iam.deny` `added` and `modified`** — §2.1's table advertises a new `Deny` as added/decreased; a narrowed Deny is modified/increased. Only removal is covered.
7. **A1.1's cancellation tiebreak** — the multiplicity-mismatch case `contentSignature` exists for. A1.1 delegates it to a unit test, but the fixtures are also the §8.2 cross-runtime parity corpus, so a survivor-choice divergence is invisible to all ten cases.

## F8 — Positional `subject` and evidence undercut A1.1's stated reorder-invariance. Cosmetic-to-medium

`iam-two-nosid-statements-changed` commits `subject: "statement 2"` and evidence `line: 10`, both functions of position in `Statement[]`. A1.1 establishes that reordering a `Statement[]` must not change output, then fixes only the cancellation survivor. Swap the two statements and `subject` becomes `"statement 1"`, evidence line 5. M1 only asserts "zero increased transitions" so it will not catch it. Either scope A1.1's claim explicitly to the verdict, or derive `subject` for no-Sid statements from content.

## F9 — Evidence line convention is unstated but locked. Cosmetic

All six IAM fixtures put evidence on the statement's first key line, not its opening `{` (`iam-condition-removed` base line 5 is `"Sid"`, the `{` is line 4). Consistent across all six; §2.6 says only "1-based". Arbitrary but now binding on E2 in both runtimes. Write it into §7.2.

## F10 — `pairingScope` for a repo-root file is unspecified. Cosmetic, parity risk

A1 widens `container.port`'s scope to "its parent directory." For root-level `compose.yml` (three of four Compose fixtures) that is `""` or `"."` depending on implementation. Both pairing phases gate on `pairingScope !== null`, so `""` works — but a runtime emitting `"."` and one emitting `""` both pass all ten fixtures with different internal state. Pin it.

## Cases confirmed correct (do not re-open)

- `iam-resource-widened-sid` — `|sid=` key, `resource` sole `greater`, `high`, one top so no promotion.
- `iam-resource-widened-no-sid` — `|nosid` per A1 Defect 2; `paired: false` per A1.1's 1:1-bucket rule (`differ.ts:272` exact-match branch).
- `iam-incomparable` — `paired: false` right (1:1 bucket); `s3:*` on one bucket vs `s3:GetObject` on `*` genuinely incomparable in AWS.
- `iam-condition-removed` — `present`→`absent` is `greater`, `medium`, one top. For an `Allow`, a Condition can only restrict, so `present < absent` is domain-sound.
- `compose-port-appears` — ordinal path, `severityByLevel[rank]` = high. Commits E1 to normalizing an absent host IP to literal `"0.0.0.0"` in attrs — intentional.
- `compose-port-narrowed` — `host_ip` is axis-derived not key-derived, so the key survives; `less` → `decreased` → null. The invariant-2 demo for E1.
- `iam-two-nosid-statements-changed` — the Phase 1b oracle, non-vacuous (without cancellation the 2-vs-2 bucket yields four add/removes). `paired: true` per A1.1.
- All ten `summary` blocks reconcile with `transitions`; `reportable` = count of non-null severities; severity non-null only under increased/incomparable; `from`/`to` populated on exactly the two single-axis kinds; no key contains a line number, formatting artifact, or compared-axis value.

## Structural note that shaped the audit

`node/tests/surface-differ.test.ts` feeds **hand-constructed `Property` objects** into `diffProperties` and compares against `expected.transitions[0]`. The `base/` and `head/` **trees are read by nothing today.** Every tree→property mapping the fixtures assert — levels, keys, subject, attrs, evidence lines, candidate eligibility — is unexercised oracle. That is why F3 (a head file that is not even a candidate) slipped through review.

## Verdict

**Safe to build against now:** `iam-resource-widened-sid`, `iam-resource-widened-no-sid`, `iam-incomparable`, `iam-condition-removed`, `iam-two-nosid-statements-changed`, `compose-port-appears`, `compose-port-narrowed`.

**Fix before building:** `compose-file-renamed` (F1), `iam-deny-removed` (F3), `compose-service-renamed` (F5 — correct as committed but certifies nothing about paired-key provenance).

**Blocking work that is not a fixture edit:** F2 (settle before E2 is written), F4 (E3 has no oracle), F6 (false negative in the dangerous direction).
