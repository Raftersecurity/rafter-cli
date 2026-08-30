# Amendment A1 — Attack-Surface Diff

**Amends:** `attack-surface-diff.md` · **Bead:** sable-8sti (W1) · **Status:** accepted

Three defects surfaced by implementing W1. All three type changes are **additive**.
**No `schema_version` bump** — every wire change is to a field §9.1 already documents.

---

## Defect 1 — `label` is missing from `Transition` and from both serializers

`Property` has `label` (`node/src/core/surface/model.ts:38`), but `Transition` does not, and
neither serializer emits it. All 8 fixtures carry `transitions[].label`, so **the wire output
cannot match its own oracles.** W1's tests missed this because nothing yet produces properties
from a fixture tree end-to-end; the fixture test only checks internal schema consistency.

**Decision.** Add `label: string` to `Transition` in §2.6/§2.7 and emit it between `subject` and
`change`. Define `label = (head ?? base).label` — the endpoint property's own description. The
differ does **not** compose delta prose.

**Why not compose the delta phrase.** §9.1's example labels ("— resource widened to `*`") imply
the differ builds a phrase from axis orders. That needs per-kind verb tables in the core
("widened" fits `resource`, not `binding`) — danger-flavored prose in the one module §2.4 keeps
prose-free. It is also unnecessary: §9.2's renderer already composes its own lines rather than
printing `label` verbatim.

**Changes.** `model.{ts,py}` (add field), `differ.{ts,py}` `classify()` (set from endpoint),
`serialize.{ts,py}` (emit it). §9.1: restate the three example labels as property descriptions.
Rewrite delta-flavored labels in 4 fixtures: `iam-resource-widened-sid`,
`iam-resource-widened-no-sid`, `iam-condition-removed`, `iam-incomparable`. §10 W4 gains a note
that delta phrasing is `render.ts`'s job.

**Test that fails today.** A serializer test asserting `transitionToWire`'s key set equals the
§9.1 `transitions[]` key set exactly.

---

## Defect 2 — the no-Sid IAM key is built from compared axes

§3.2 invariant 2 forbids a key component that is also a compared axis. It exists because v1
hashed `Resource` into the IAM key while comparing resource breadth, making the flagship
transition structurally impossible. As implemented, the no-Sid key is
`path|effect|action_hash|principal_hash` (`kind-specs.ts:88`) — and `action` and `principal`
**are compared axes**. An action widening on a no-Sid statement changes the key, degrading a
`modified`/`increased` into an unpaired add/remove whenever the residual is not 1:1.

**There is no non-compared discriminator available.** A statement's fields are `Sid`, `Effect`,
`Action`/`NotAction`, `Resource`/`NotResource`, `Principal`/`NotPrincipal`, `Condition`. `Sid` is
the only non-axis discriminator and it is optional. `Effect` is the kind discriminator. The other
four are the lattice axes. Partial invariants do not rescue it: an action set's service prefix
survives `s3:GetObject → s3:*` but not `s3:GetObject → *`, and a discriminator that holds for
some rank moves and not others fails unpredictably.

**Decision. The no-Sid key stops discriminating.**

- `Sid` present: `iam.<effect>:iam-json:<path>|sid=<sid>` — unchanged.
- `Sid` absent: `iam.<effect>:iam-json:<path>|nosid`.

Invariant 2 then holds by construction. This makes keys non-unique within a document, so:

**New `KindSpec` field `keyMayRepeat: boolean`** (default `false`; `true` for `iam.allow` /
`iam.deny`). §2.8 Phase 0's duplicate-key `parse_error` is retained verbatim for
`keyMayRepeat: false` kinds — `container.port` and `pkg.lifecycle_script` keep fail-loud.

**New §2.8 Phase 1b — content cancellation.** For `keyMayRepeat` kinds a repeated key forms a
bucket, not a defect. Within a bucket: compute each property's compared level vector (the
`levels[axis]` tuple in declared axis order); cancel base/head pairs with identical vectors,
greedily in canonical vector order; run the existing Phase 2 rule on the residue; whatever
remains falls to Phase 3 add/remove.

**Safety argument, replacing uniqueness.** §3.3's argument was uniqueness, which Phase 1b weakens
inside a bucket. Its replacement is stronger: **cancellation is output-invariant.** A cancelled
pair has identical compared vectors, so `classify()` returns `order:"equal"` → `danger:"unchanged"`
→ the never-emit-no-ops rule drops it. Every bijection between two equal-vector sets yields
byte-identical output, so the choice among them is unobservable. Phase 2 pairing still runs only
on a 1:1 residual, so §3.3's original argument survives intact for every emitted transition.

**Correction (A1.1) — invariance holds for the verdict, not automatically for the survivor.**
The paragraph above is true of `danger` and `severity` but not of the whole wire record when
equal-vector *multiplicities* differ between the sides. With base `{X, Y}` sharing vector `V` and
head `{Z}` at `V`, one of `X`/`Y` survives as `removed`, and *which* one determines the emitted
`label`, `subject`, and `evidence`. Ordering cancellation by input position makes that depend on
emission order, so reordering an IAM `Statement[]` — semantically meaningless in AWS — changes the
output. That is exactly the mutation W7's M1 suite asserts against.

**Resolution.** Cancellation orders by `(levelVector, contentSignature)`, where `contentSignature`
is `canonicalJson([label, attrs])` — content only, never evidence (line numbers move under
reorder) and never input position. The survivor is then a function of content alone. Enforced by
`picks the same cancellation survivor regardless of input order` in both runtimes, which fails
without the content tiebreak.

**`paired` within a bucket (A1.1).** A1 was contradictory here: it said to run the Phase 2 rule on
the residue (which implies `paired: true`) while specifying `paired: false` in the fixture.
Resolved by bucket size, because the two cases differ epistemically:

- **1:1 bucket** — one property per side under an equal key, exactly one possible correspondence.
  This is a true exact match: `paired: false`. Covers `iam-resource-widened-no-sid` and
  `iam-incomparable`.
- **Multi-property bucket** — the key matched but does not discriminate *within* the bucket, so
  which surviving statement corresponds to which is inferred, not proven. Same epistemic status as
  Phase 2 residual pairing, therefore `paired: true`. Covers
  `iam-two-nosid-statements-changed`, whose fixture is corrected accordingly.

Cancellation has already removed every equal-vector pair, so a residue pair never compares equal
and `emitUnchanged` stays false — the flag does not resurrect no-ops.

**Label consistency (A1.1).** A1 scoped label rewrites to four fixtures, but `iam-deny-removed`
also carried delta prose (`"Deny * on * removed"`). Under `label = (head ?? base).label` the
endpoint is the base property, whose own description is `"Deny * on *"`. Corrected; the rule
applies to all ten fixtures, not the four originally enumerated.

**What remains broken, and in which direction.** Two or more no-Sid statements whose action or
principal sets both changed still produce unpaired add/remove. The flagship-class line is **not**
lost: an unpaired head statement is classified against absence, every axis moves from
`absentRank:"below"` to its observed rank, giving `danger:"increased"` at
`max(severityAtTop)`. What is lost is framing — "a new Allow grant" where the truth is "an
existing grant widened," with the matching `removed` hidden as `decreased`/`severity: null`.
Across the direction matrix (pure widening, pure narrowing, mixed) this can only **over-report**;
it never suppresses a `danger:"increased"`. Correct direction for a CI gate. Goes in §11 as
residual risk #10, and is a `Sid` adoption incentive the remediation message should name.

**Rejected on the record.**
- *Positional index.* Reordering two statements would compare A's base against B's head and
  fabricate an `increased` on a set-identical document. IAM statement order is semantically
  meaningless; encoding it is a correctness regression, and it breaks M1's reorder mutation.
- *Bounded greedy matching on axis distance.* The only option that rescues the 2×2 case, and
  precisely where a wrong pairing can fabricate: base `{A: literal, B: global-wildcard}` → head
  `{A': global-wildcard, B': literal}` is a pure swap (semantically unchanged) that pairs A→A'
  and reports `resource widened`, `high`, on an unchanged document. The swap is
  distance-symmetric, so distance minimization does not prevent it, and there is no argument as
  concrete as cancellation's output-invariance.

### The invariant test — fixing the false assurance

`node/tests/surface-differ.test.ts:263` compares **names**: `action_hash` vs `action` are
textually disjoint, so it passes on a violating table. **Delete it.** Replace with a provenance
test, requiring one more additive field:

**New `AxisSpec` field `derivedFrom: readonly string[]`** — the artifact fields the axis reads.
**`KEY_COMPONENTS` reshapes** to `Array<{ component: string; derivedFrom: readonly string[]; locative: boolean }>`.

> **Invariant 2, restated semantically:** for every kind,
> `⋃ keyComponent.derivedFrom ∩ ⋃ axis.derivedFrom = ∅`. No key component may derive from any
> artifact field a comparator reads.

| kind | key components → derivedFrom | axes → derivedFrom |
|---|---|---|
| `container.port` | `path`→`file-path`, `service`→`service-name`, `container_port`→`ports[].target`, `protocol`→`ports[].protocol` | `binding`→`ports[].host_ip`, `ports[].published`, `ports[].mode`, `expose` |
| `iam.allow`/`iam.deny` | `path`→`file-path`, `effect`→`Effect`, `sid`→`Sid` | `action`→`Action`, `resource`→`Resource`, `principal`→`Principal`, `condition`→`Condition` |
| `pkg.lifecycle_script` | `path`→`file-path`, `script_name`→`scripts.<name>` | `fetch`→`scripts.<name>.body` |

**This test fails today** — `action_hash`→`Action` collides with the `action` axis. It passes only
once the key becomes `path|effect|sid`. This replaces item 5 in §2.4's list of five mechanisms.

**M6, deferred to W7** (add to §5 R2): *key-invariance under single-axis perturbation.* For every
kind and axis, mutate a corpus artifact so that axis moves exactly one rank, re-run the extractor,
assert the emitted `key` is byte-identical. This is the dynamic form of the invariant and catches
an extractor that satisfies the declared table but lies about it. It cannot run in W1 (no
extractors yet); the provenance test is W1's mechanically-checkable proxy.

---

## Defect 3 — a compose file rename fabricates a full set of appearances

§7.1 puts the path in the `container.port` key and §3.5 justifies it as "paid for by residual
pairing at file granularity." But `pairingScope` **is** the file, so renaming
`docker-compose.yml` → `compose.prod.yml` changes every key *and* the scope: nothing can pair.

**The assumption behind the path holds — verify before removing it, and it survives.** Two compose
files routinely define the same service name with different mappings (`docker-compose.yml` vs
`deploy/staging/compose.yml`; a base and its `.override.yml`). §4.1(b) makes each file an
independent descriptor, so dropping the path merges distinct subjects and, under Phase 0, turns a
monorepo with two `api` services on 8080 into a `parse_error` on both. **The path stays.**

**Rejected: git rename detection.** §4.2 uses `--no-renames` and treats the changed-file set as a
hint, never a filter. Wiring `-M` in makes identity depend on git's similarity threshold —
version- and content-sensitive, and undefined for the working-tree head where a rename is an
untracked add plus a tracked delete. Identity must not depend on VCS metadata.

**Decision. Split the key into locative and discriminative components, and add a relocation phase.**

**New `Property` field `discriminator: string`** (internal, not on the wire) — the key with its
locative components elided. `container.port`: `<service>|<containerPort>/<proto>`. IAM: `""` (a
no-Sid statement has no residual identity — see Defect 2). `pkg.lifecycle_script`: `<scriptName>`.
`path` is the only locative component in all three v1 kinds. A W1 test asserts `discriminator`
equals the key minus locative parts, so the two cannot drift.

**`container.port`'s `pairingScope` widens from the file to its parent directory** — file renames
are overwhelmingly within-directory. §7.1's "at file granularity" becomes "at directory granularity."

**New §2.8 Phase 1c — relocation matching**, after Phase 1b, before Phase 2:

> Within a `pairingScope`, among unmatched properties of the same kind, match a base and a head
> property whose `discriminator` is equal and non-empty — but only when that discriminator is
> unique on both sides. Emit through `classify(..., paired=true)`.

Uniqueness carries over verbatim from §3.3, so the safety argument is unchanged. Phase 1c runs
only on the residue, so an unrenamed repo never enters it.

**Why not just widen `pairingScope`.** Scope alone cannot resolve a renamed file defining three
services (3 base, 3 head — no 1:1 residual). The discriminator makes the residue resolvable, and
it is safe precisely because it derives from no compared axis.

**New false negative.** A compose file genuinely deleted while an unrelated file in the same
directory adds a service with identical name, port, protocol **and** binding rank is paired as
`unchanged` and disappears. Bounded: the sides are equal on every compared axis, so nothing
carrying a severity is suppressed — same class §3.4 already accepts. Differing `binding` still
reports. Accepted.

**Test that fails today.** Two base properties keyed under `a/docker-compose.yml`, two head
properties under `a/compose.prod.yml`, same services and bindings, `pairingScope: "a"` → assert
zero transitions. Today the differ emits four.

---

## A1.2 — W3 adapter contract (corrections to §8.1)

Implementing W3 exposed gaps in §8.1. Recorded here because W6 consumes the adapter.

- **The adapter raises; the caller converts.** The adapter cannot construct an `Unanalyzed` — that
  record needs `file`, `side`, and `changed`, which are the caller's context, not the parser's. It
  raises typed `parse_error` / `unsupported_syntax` errors and **the extractor** converts them,
  attaching context. W6/W7/W8 must do this uniformly; an extractor that swallows one of these and
  returns `[]` violates §5 R3 and is a review reject.
- **§8.1's "empty node is the only surviving difference" is false.** Confirmed divergence classes
  beyond those §8.1 lists: sexagesimal (`12:34:56` → `754`-style ints in PyYAML, string in
  js-yaml), scientific notation, timestamp coercion, huge-integer precision plus CPython's
  4300-digit int-conversion limit, `.inf` / `.nan` / underscored floats, explicit and custom tags,
  complex and empty mapping keys, boolean-like mapping-key collisions, empty documents, cyclic
  aliases and alias-expansion limits, plain-scalar tabs versus tabs legally inside quoted strings /
  comments / block scalars, compact alias mapping keys, and JS negative zero. String-only loading
  plus one shared `parseScalar` is what makes these agree; native library configuration alone does
  not.
- **`parseScalar`'s domain is now defined by the implementation**, since §8.1 gave no grammar,
  bounds, or return type: it coerces only the shared null forms, `true`/`false`, and safe decimal
  integers. Everything else — floats, timestamps, base-prefixed and leading-zero integers,
  separator forms, sexagesimal, oversized integers — stays a string. Widening this set is a
  parity-relevant change and needs both runtimes plus a divergence test.
- **"Every W3 test must fail against library defaults" was not literally achievable**, and the
  requirement is withdrawn. A plain-string alias test passes unadapted, and js-yaml already throws
  on duplicate keys where PyYAML silently takes the last value. The tests preserve the intent by
  asserting adapter-specific typed errors and coercion-sensitive aliases.
- `fixtures/surface/yaml-divergence.yml`'s `27017:27017` entries are **not** a sexagesimal probe
  (sexagesimal components must be ≤ 59, so PyYAML leaves it a string). They are retained
  deliberately: that is the Compose published-port shape E1 must keep as a string. Genuine
  sexagesimal is probed in both test suites via `12:34:56`.

## Fixture blast radius

Two `expected.json` keys become `iam.allow:iam-json:policy.json|nosid`:
`iam-resource-widened-no-sid` and `iam-incomparable`. `paired` stays `false` in the first (1:1
bucket, Phase 1 matches exactly). **Check `iam-incomparable`:** under the coarse key it now
matches exactly and should become `paired: false` if it was authored as `true` to model a
key-changing action narrow.

**Two new fixtures**, bringing the total to 10 — the human-review gate re-runs on all 10:
- `iam-two-nosid-statements-changed/` — two no-Sid statements per side, one unchanged, one
  resource-widened. Expected: exactly one `modified`/`increased`, `paired: false`. Oracle for
  Phase 1b; today this is a `parse_error` with zero transitions.
- `compose-file-renamed/` — `base/infra/docker-compose.yml`, `head/infra/compose.prod.yml`, two
  services, identical mappings. Expected: `transitions: []`, summary all zeros,
  `highest_severity: null`.

## Blast radius on the other work units

Four additive fields: `Transition.label`, `AxisSpec.derivedFrom`, `KindSpec.keyMayRepeat`,
`Property.discriminator`. Nothing removed or retyped. §9.1 wire schema unchanged.

| Unit | Impact |
|---|---|
| **W1** | model ×2, kind-specs ×2, differ Phases 1b/1c ×2, serializer `label` ×2, `KEY_COMPONENTS` reshape ×2; replace the name-disjointness test with the provenance test; add 3 tests (bucket cancellation, relocation, serializer key set); edit `kind-specs.json`, 4 fixture labels, 2 fixture keys; add 2 fixtures. |
| **W4** | Renderer owns delta phrasing. |
| **W6** | `pairingScope` = parent directory; populate `discriminator`; M1 file-rename gains a committed oracle. |
| **W7** | No-Sid key is `\|nosid`; `discriminator: ""`; gains M6. Its "two removals + two additions → four unpaired transitions" test is now documented behavior rather than an accident. |
| **W8** | Populate `discriminator`; `keyMayRepeat: false` preserves current behavior. |
| **W9** | Parity block covers 10 cases; M6 joins the metamorphic gate. |
| **W2, W3, W5, W10, W11** | Untouched. |

**Net direction of error.** Every choice trades toward over-reporting or abstention and away from
silence. Defect 2's residue over-reports a widened no-Sid statement as a new grant rather than
missing it; Defect 3's relocation matching can only suppress a pair equal on every compared axis.
Neither creates a path where a `danger:"increased"` disappears.
