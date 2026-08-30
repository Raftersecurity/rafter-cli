# Architecture Decision Document — Attack-Surface Diff (v2)

**Status:** proposed, implementable · **Target:** 0.11.0 (both runtimes) · **Bead:** sable-uoes
**Supersedes:** v1 ADR. This document is standalone; do not read v1 to implement it.
**Basis:** v1 + an adversarial review. §12 is the itemized changelog with attribution.

---

## 0. What this feature is, and four framing corrections

`rafter surface diff` answers one question: **what became more dangerous in this change?** It is a delta of security *properties* between two trees. It is not a findings list, not a linter, and not a count.

Four things in the original brief are wrong or unbuildable as stated.

**0.1 — "new package executes install scripts" is not computable offline.** Knowing that a newly *added dependency* runs `postinstall` requires the dependency's own manifest, which lives in the registry or in a `node_modules` tree that does not exist for the base commit. `shared-docs/CLI_SPEC.md:7` commits the CLI to working "without network access." What v1 computes at zero network is lifecycle scripts in the **repo's own** manifests. The registry-backed version is future work behind an explicit `--online` flag.

**0.2 — "new user-controlled value reaches shell" is deferred, with no v1 approximation.** That is an interprocedural taint query. This repo has no dataflow infrastructure: `node/src/core/pattern-engine.ts` is a regex list and `node/src/core/risk-rules.ts` classifies *shell command strings*, not source. A regex proxy ("`exec(` in a file that mentions `req.`") is precisely the cry-wolf failure §5 exists to prevent, and it is a finding, not a surface property — `rafter run` already owns findings. The property model in §2 accommodates it later as a kind with an ordinal ladder, at zero schema cost. That is a genuine argument for the model, not a promise to ship it.

**0.3 — "+2 unauthenticated endpoints" is a count, and counts are what this feature claims not to be.** JSON always carries identities. Text may collapse to a count line only when identities are one flag away.

**0.4 — "diff the property sets, report only transitions" underspecifies two independent things at once.** Naive set logic calls removing a CSP directive a `disappeared`, i.e. the safe direction. v1 patched this by mapping absent-protection to the top of the level ladder — and thereby produced objects reading `direction:"appeared", from:"strict", to:null`, contradicting its own schema. The real defect is that **membership change and danger direction are two axes and cannot share one enum.** §2 separates them. This is the single most important change from v1.

---

## 1. Scope of v1

Three extractors, all file-local, all reading fully-parsed declarative artifacts.

| # | Kind(s) | Source | Why it is in |
|---|---|---|---|
| E1 | `container.port` | Docker Compose `services.*.ports` and `services.*.expose` | Highest-confidence, cheapest, most demoable. One grammar. |
| E2 | `iam.allow`, `iam.deny` | IAM policy JSON documents | The flagship line. Pure JSON — zero parser risk. Forces the partial-order model to be right. |
| E3 | `pkg.lifecycle_script` | `package.json` install-time lifecycle scripts | Pure JSON, ~1 day, gives the supply-chain line. |

**Cut from v1's proposed set, with reasons:**

- **Dockerfile `EXPOSE`** — the reviewer is factually right: `EXPOSE` is image metadata and publishes nothing. Including it under `container.port` would have taught users that the tool does not know what a published port is.
- **Kubernetes Service/Deployment** — inherently cross-document (a Service's exposure depends on selector-matched workloads in other files). Correctly modeling it requires the dependency closure §4 refuses to build in v1. Deferred to v1.1 with a specified key: `(namespace, kind, name, port, protocol)`.
- **CSP / security headers** — `helmet({...})` and `next.config.js` are *executable JavaScript*. Claiming `certain` confidence over them means claiming to have evaluated JS, which is false. Reviewer right.
- **`net.egress` + vendor catalog** — a grab-bag of six unrelated grammars, and the classification was wrong in places (`uses:` is supply-chain provenance, not runtime egress). It also drags in a catalog data-file that must stay byte-identical across two package trees. Deferred whole.
- **`dep.added`** — *my* cut, not the reviewer's. It fires on nearly every dependency PR, `rafter run` already does SCA, and §5's "empty report on the median PR" target is worth more than this line.
- **`confidence: "probable"`** — cut as a *mechanism*, not just as content. v1 made everything speculative invisible-by-default, which meant shipping it bought nothing. Everything in v1 is `certain`. The field survives in the schema with the single value `"certain"` so reintroducing `probable` is not a `schema_version` bump.

**Where I push back on the reviewer's recommended cut.** The review proposed Compose `ports` + IAM `Allow`-with-a-required-`Sid`, and nothing else. I reject two parts of that:

1. **Requiring a stable `Sid` silently disables the flagship extractor.** I checked: `Sid` is documented as *optional* ([AWS: IAM JSON policy elements: Sid](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html)), and the single most-referenced AWS managed policy, `AmazonS3FullAccess`, ships with **no `Sid` on its only statement** ([AWS managed policy reference](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonS3FullAccess.html)). `Sid` is also alnum-only, so it is not even a natural slug. A design that requires `Sid` produces `unknown` on the modal real-world policy. §3.3 uses `Sid` when present and specifies a structural identity plus a provable unique-residual pairing when it is absent.
2. **Dropping `Deny` makes the tool wrong rather than narrow.** The reviewer's own strongest IAM counterexample was that v1 would score a new `Deny *` as `critical`. Cutting `Deny` from the parser does not fix that — it means a PR that *removes* a `Deny "*"` statement produces silence from a security gate. Removing a Deny is a real privilege widening. `iam.deny` is the same lattice with `invertDanger: true`; it costs a boolean in a table.

I keep **E3** against the reviewer's cut on cost: it is JSON-only, has no grammar risk, is roughly a day of work in both runtimes, and it is the only v1 line that speaks to supply chain. I do accept the reviewer's specific correction that `local-only` vs `network-or-shell` is incoherent — npm runs *all* lifecycle scripts through a shell. §7.3 replaces it with a ladder that is actually decidable.

---

## 2. The property and transition model

### 2.1 Two axes, never one

The v1 `Direction` enum conflated membership with danger and was internally contradictory. v2 splits them:

```
change:   "added" | "removed" | "modified"                       -- structural. Never carries severity.
danger:   "increased" | "decreased" | "unchanged"
        | "incomparable" | "unknown"                             -- semantic.
severity: non-null iff danger == "increased".
```

The two axes are independent, and every combination is meaningful:

| change | danger | Example |
|---|---|---|
| `added` | `increased` | A new published port. |
| `added` | `decreased` | A new `Deny` statement. |
| `removed` | `increased` | A `Deny` statement deleted; a `Condition` deleted. |
| `removed` | `decreased` | A published port deleted. |
| `modified` | `incomparable` | `s3:* on one-bucket` → `s3:GetObject on *`. |
| `modified` | `unchanged` | A Compose service renamed with identical mappings (§3.4). |
| any | `unknown` | Comparison could not be decided; see `coverage`. |

`from`/`to` now mean exactly what the JSON reference says they mean, in every case, because they describe the *change* axis only.

### 2.2 Danger is decided by a comparator, not an integer

v1 assumed every kind is a total order and compared level indices. IAM is a product partial order — `s3:*` on one bucket and `s3:GetObject` on `*` are genuinely incomparable — and forcing a total order both mislabels one direction and silently suppresses the other.

The core provides **two comparator families**. Extractors *select* one declaratively in the kind-spec table and never write comparator code. This preserves the property v1 was right to insist on — extractors cannot invent their own notion of "worse" — while dropping the totality assumption that was wrong.

**`ordinal`** — a named ladder, safest first. Absence has its own rank, controlled by `absentRank: "below" | "above"`. `absentRank: "above"` is the honest form of v1's "protection polarity": it says *the absence of this property is more dangerous than any of its present levels*. Because it now feeds only the `danger` axis, it can no longer contradict `change`.

**`lattice`** — a product of independent ordinal axes. Result:

```
all axes equal                              -> "equal"
≥1 axis greater, none less, none unknown    -> "greater"
≥1 axis less,    none greater, none unknown -> "less"
≥1 greater AND ≥1 less                      -> "incomparable"
any axis unknown                            -> "unknown"
```

`"greater"` always means *head is more dangerous.*

### 2.3 Severity assignment

Severity is a lookup in the kind-spec table, never a computation in an extractor.

- **`ordinal`:** `severityByLevel[rankOf(head)]`. A `null` entry means "this transition is real, record it, but it is not worth a reported line." A new `expose:`-only port is a real transition with `severity: null`; it appears only under `--all`.
- **`lattice`, `danger:"increased"`:** `max` over `severityByAxisTop[axis]` for every axis that increased; promoted to `critical` if two or more axes reached their top rank.
- **`lattice`, `danger:"incomparable"`:** `severityWhenIncomparable` from the table. This is deliberately reported — an incomparable IAM change is a change a human must look at.
- **Any other `danger` value:** `null`.

**No fifth severity value.** The repo-wide vocabulary is `low | medium | high | critical` (`node/src/core/risk-rules.ts:12`; Python's equivalents around `python/rafter_cli/core/risk_rules.py:485`; secret-pattern severities; `action.riskLevel` in the audit-log schema at `shared-docs/CLI_SPEC.md:790`). Adding `"info"` would force every existing consumer of that vocabulary to widen. Severity is simply undefined outside `danger:"increased"`, and `danger` is the discriminator. "How severe is it that a port got closed" is not a well-posed question.

### 2.4 How ad-hoc per-extractor severity is structurally prevented

Five mechanisms, all mechanically checkable in review:

1. `Property` has no severity field and no danger field. Extractors cannot express either.
2. `extract()` receives one side's files and has no parameter telling it which side. It cannot compute a direction.
3. All severity and all ordering live in one table per runtime: `node/src/core/surface/kind-specs.ts` / `python/rafter_cli/core/surface/kind_specs.py`.
4. A lint-grade unit test asserts no module under `core/surface/extractors/` contains the literals `"critical" | "high" | "medium" | "low" | "increased" | "decreased"` or imports the differ.
5. A structural test asserts, for every kind, that **no component of `key` is also a compared axis** (§3.2). This is the invariant that makes the flagship demo possible at all.

**Reviewer rejection criteria for an extractor PR:** it contains a severity literal; it imports the differ; it takes a `side` parameter; it puts a compared value in the key; it adds a level or axis without updating the kind-spec table in both runtimes.

### 2.5 Attributes are descriptive, never diffed

`attrs` exists for rendering. It is not part of identity and is not compared. If a value change matters for danger it belongs in a compared axis; if it distinguishes two things it belongs in the key. A free-floating "attrs changed" transition class would be an infinite noise source. `attrs` keys are ASCII identifiers (test-enforced, see §8.3) and `attrs` values are `string | int | bool | null` — **no floats**.

### 2.6 TypeScript

`node/src/core/surface/model.ts`:

```ts
import type { CommandRiskLevel } from "../risk-rules.js"; // "low"|"medium"|"high"|"critical"

export type SurfaceSeverity = CommandRiskLevel | null;
export type Confidence = "certain";                       // v1 has one value; field reserved.

export type PropertyKind =
  | "container.port"
  | "iam.allow"
  | "iam.deny"
  | "pkg.lifecycle_script";

export type Change = "added" | "removed" | "modified";
export type Danger =
  | "increased" | "decreased" | "unchanged" | "incomparable" | "unknown";

export type AxisOrder = "equal" | "greater" | "less" | "unknown";

export interface Evidence {
  /** Repo-relative, forward slashes, NFC-normalized. */
  file: string;
  /** 1-based; null when the artifact has no meaningful line. */
  line: number | null;
}

/** What an extractor produces. One observed security property on ONE side. */
export interface Property {
  kind: PropertyKind;
  /** Stable identity. See the §3.2 rules. */
  key: string;
  /** Human-facing name of the thing this property is about, e.g. "service redis". */
  subject: string;
  /**
   * Axis name -> level name. For an `ordinal` kind this has exactly one entry,
   * named "level". For a `lattice` kind it has one entry per declared axis.
   * A value of null on a lattice axis means "observed but not decidable"
   * and forces that axis to `"unknown"`.
   */
  levels: Readonly<Record<string, string | null>>;
  label: string;
  attrs: Readonly<Record<string, string | number | boolean | null>>;
  evidence: Evidence;
  confidence: Confidence;
  /**
   * Optional scope for residual pairing (§3.3). Two properties may only be
   * residually paired if their pairingScope is equal and non-null.
   */
  pairingScope: string | null;
}

export interface AxisSpec {
  name: string;
  /** Safest first. */
  ranks: readonly string[];
  /** Where absence of the whole property sits relative to `ranks`. */
  absentRank: "below" | "above";
  /** Severity contributed when this axis reaches its highest rank. */
  severityAtTop: SurfaceSeverity;
}

export interface KindSpec {
  kind: PropertyKind;
  comparator: "ordinal" | "lattice";
  axes: readonly AxisSpec[];               // length 1 for `ordinal`
  /** ordinal only: severity of ARRIVING at ranks[i]. Same length as axes[0].ranks. */
  severityByLevel?: readonly SurfaceSeverity[];
  /** ordinal only: severity when the property becomes absent and absentRank==="above". */
  severityWhenAbsent?: SurfaceSeverity;
  /** lattice only. */
  severityWhenIncomparable?: SurfaceSeverity;
  /** Danger direction is flipped wholesale. Used by `iam.deny`. */
  invertDanger: boolean;
  /** Extractor may residually pair unmatched add/remove within a pairingScope. */
  allowResidualPairing: boolean;
  /** Short noun phrase for text headers. */
  display: string;
}

export interface AxisTransition {
  axis: string;
  from: string | null;
  to: string | null;
  order: AxisOrder;      // direction of head relative to base, PRE-inversion
}

export interface Transition {
  kind: PropertyKind;
  key: string;
  subject: string;
  change: Change;
  danger: Danger;
  severity: SurfaceSeverity;
  /** Always present, always authoritative. */
  axes: AxisTransition[];
  /** Convenience mirrors of axes[0] when axes.length === 1; otherwise null. */
  from: string | null;
  to: string | null;
  confidence: Confidence;
  baseEvidence: Evidence | null;
  headEvidence: Evidence | null;
  attrs: Readonly<Record<string, string | number | boolean | null>>;
  /** True when this transition came from residual pairing, not key equality. */
  paired: boolean;
}

export type UnanalyzedReason =
  | "parse_error"
  | "unsupported_syntax"
  | "too_large"
  | "too_many_candidates"
  | "binary"
  | "symlink"
  | "timeout";

export interface Unanalyzed {
  file: string;
  side: "base" | "head";
  reason: UnanalyzedReason;
  detail: string;
  /** True when this file differs between base and head. Drives exit 4. */
  changed: boolean;
}

/** The ONLY thing an extractor returns. No severity, no change, no danger. */
export interface ExtractResult {
  properties: Property[];
  unanalyzed: Unanalyzed[];
}

export interface Extractor {
  id: string;
  version: number;
  kinds: readonly PropertyKind[];
  /**
   * Stage-1 candidate filter: cheap, path/size-only, applied to the FULL tree
   * on BOTH sides. There is no `contextGlobs` — see §4.
   */
  candidate(path: string, sizeBytes: number): boolean;
  extract(files: ReadonlyMap<string, string>): ExtractResult;
}
```

### 2.7 Python

`python/rafter_cli/core/surface/model.py`:

```python
from dataclasses import dataclass, field
from typing import Literal, Mapping, Optional, Sequence

SurfaceSeverity = Optional[Literal["low", "medium", "high", "critical"]]
Confidence = Literal["certain"]
Change = Literal["added", "removed", "modified"]
Danger = Literal["increased", "decreased", "unchanged", "incomparable", "unknown"]
AxisOrder = Literal["equal", "greater", "less", "unknown"]
UnanalyzedReason = Literal[
    "parse_error", "unsupported_syntax", "too_large",
    "too_many_candidates", "binary", "symlink", "timeout",
]
AttrValue = Optional[str | int | bool]   # no floats — see §2.5


@dataclass(frozen=True, slots=True)
class Evidence:
    file: str
    line: Optional[int]


@dataclass(frozen=True, slots=True)
class Property:
    kind: str
    key: str
    subject: str
    levels: Mapping[str, Optional[str]]
    label: str
    attrs: Mapping[str, AttrValue]
    evidence: Evidence
    confidence: Confidence = "certain"
    pairing_scope: Optional[str] = None


@dataclass(frozen=True, slots=True)
class AxisSpec:
    name: str
    ranks: Sequence[str]
    absent_rank: Literal["below", "above"]
    severity_at_top: SurfaceSeverity


@dataclass(frozen=True, slots=True)
class KindSpec:
    kind: str
    comparator: Literal["ordinal", "lattice"]
    axes: Sequence[AxisSpec]
    display: str
    invert_danger: bool = False
    allow_residual_pairing: bool = False
    severity_by_level: Optional[Sequence[SurfaceSeverity]] = None
    severity_when_absent: SurfaceSeverity = None
    severity_when_incomparable: SurfaceSeverity = None


@dataclass(frozen=True, slots=True)
class AxisTransition:
    axis: str
    from_rank: Optional[str]
    to_rank: Optional[str]
    order: AxisOrder


@dataclass(frozen=True, slots=True)
class Transition:
    kind: str
    key: str
    subject: str
    change: Change
    danger: Danger
    severity: SurfaceSeverity
    axes: Sequence[AxisTransition]
    from_level: Optional[str]
    to_level: Optional[str]
    confidence: Confidence
    base_evidence: Optional[Evidence]
    head_evidence: Optional[Evidence]
    attrs: Mapping[str, AttrValue]
    paired: bool


@dataclass(frozen=True, slots=True)
class Unanalyzed:
    file: str
    side: Literal["base", "head"]
    reason: UnanalyzedReason
    detail: str
    changed: bool


@dataclass(frozen=True, slots=True)
class ExtractResult:
    properties: list[Property] = field(default_factory=list)
    unanalyzed: list[Unanalyzed] = field(default_factory=list)
```

Field-name divergence is deliberate and confined: `from`/`to` are awkward in Python, so the dataclass uses `from_rank`/`from_level`/`to_*` and the **serializer**, not the dataclass, owns the wire names `"from"`/`"to"`. The cross-runtime agreement test in §8.2 makes any drift here a hard failure.

### 2.8 The differ

```
diff(baseProps, headProps, specs, coverage) -> Transition[]:

  # Phase 0 — duplicate keys are a bug, not a merge opportunity.
  # v1 collapsed duplicates to the max level. That silently merges distinct
  # subjects and can HIDE a widening. Instead: a duplicate key within one side
  # is an extractor defect -> emit Unanalyzed{reason:"parse_error"} for the
  # file and drop BOTH properties. Fails loud, never fabricates.
  B = indexUnique(baseProps); H = indexUnique(headProps)

  out = []
  # Phase 1 — exact key matches.
  for key in sorted(B.keys & H.keys):
      out += classify(B[key], H[key], specs)

  # Phase 2 — residual pairing, only for kinds that opt in (§3.3/§3.4).
  # Within one pairingScope, if exactly ONE unmatched base property and
  # exactly ONE unmatched head property of the same kind remain, pair them
  # and mark paired=true. More than one on either side: no pairing.
  pairs, leftB, leftH = residualPair(B \ H, H \ B, specs)
  for (b, h) in pairs: out += classify(b, h, specs, paired=True)

  # Phase 3 — genuine add/remove.
  for b in leftB: out += classify(b, None, specs)
  for h in leftH: out += classify(None, h, specs)

  # Phase 4 — coverage suppression (§5 R3).
  for t in out:
      if coverage.blocksAbsenceProof(t): t.danger, t.severity = "unknown", None

  sort by (severityRank desc, kind, key utf8-bytes asc)
  return out


classify(b, h, specs, paired=False):
  spec = specs[kindOf(b or h)]
  change = "added" if b is None else "removed" if h is None else "modified"
  order  = spec.comparator == "ordinal" ? ordinalCompare(spec, b, h)
                                        : latticeCompare(spec, b, h)
  if spec.invertDanger: order = flip(order)
  danger = {"equal":"unchanged", "greater":"increased",
            "less":"decreased", "incomparable":"incomparable",
            "unknown":"unknown"}[order]
  if danger == "unchanged" and not paired: return []   # never emit no-ops
  severity = severityFor(spec, b, h, danger)
  return [Transition(...)]
```

Two rules worth calling out because they are the anti-noise core:

- **Unchanged properties are never emitted.** The only exception is a residually-paired rename, which is emitted with `danger:"unchanged", severity:null` so the human can see that the tool understood the rename rather than silently ignoring something.
- **Duplicate keys within one side abort that file** rather than merging. v1's max-level merge was a correctness hole the reviewer correctly identified.

---

## 3. Identity

### 3.1 Identity is per-extractor and domain-specific

v1 had one generic key rule for all kinds. That is wrong: a Compose service, an IAM statement, and an npm lifecycle script have nothing in common as identities. Each extractor declares its own key construction, and each is bound by the following invariants.

### 3.2 The four invariants (all test-enforced)

1. **No formatting.** No line number, column, byte offset, or indentation-derived value. Reindenting a file must produce zero transitions.
2. **No compared value.** *No component of the key may also be a compared axis.* This is the invariant v1 violated: it hashed sorted `Resource` into the IAM key *and* made resource breadth a level, which is why v1's advertised flagship transition was structurally impossible to emit — a resource change changed the key and produced a disappear+appear pair. A machine test walks every kind spec and asserts `keyComponents(kind) ∩ axisNames(kind) = ∅`.
3. **Order-independent.** Sets are sorted before hashing.
4. **Namespaced:** `<kind>:<extractorId>:<part>|<part>|…`, parts NFC-normalized, lowercased where the domain is case-insensitive, and `|` / `\` escaped.

There is deliberately no general rule about file paths. Whether the path is part of identity is a domain question, answered per extractor in §7.

### 3.3 Residual pairing — the escape hatch for identity change

Keys cannot survive every legitimate rename. Rather than pretend otherwise, the differ has one narrow, provable fallback:

> Within a single `pairingScope`, if exactly one unmatched base property and exactly one unmatched head property of the same kind remain after exact-key matching, pair them.

Uniqueness is the whole safety argument. If two statements were removed and two added, nothing is paired and all four are emitted as add/remove. This is the reviewer's "conservative semantic matching only when unique," adopted as specified. `paired: true` is on the wire so a consumer can distinguish an inferred pairing from a proven one.

### 3.4 The rename case, and why pairing cannot manufacture a finding

The reviewer's sharpest identity example: renaming a Compose service `redis` → `cache` with an identical port mapping produces, under v1, a `high`-severity appearance. Under v2, residual pairing finds exactly one removal and one addition in the same file, pairs them, and the comparator returns `equal` on every axis → `change:"modified", danger:"unchanged", severity:null`, rendered as a rename.

The load-bearing property: **residual pairing can only be wrong in a direction that cannot create or hide a reported line, unless the paired pair genuinely differs on a compared axis** — in which case the transition it produces is exactly the transition a human would want. If pairing is *wrong* (two unrelated services swapped in one commit), the worst outcome is a `modified` transition instead of an add/remove pair, with the same danger verdict on the same axis values. It cannot invent a widening that no property exhibits.

### 3.5 What v1 identity claims survive, and on what argument

- **"Never contains a line number"** survives unchanged. The reviewer did not attack it and it is obviously right.
- **"Never contains the file path unless the path is itself the surface"** survives *as a per-extractor question, not a global rule.* The reviewer's "file-class rename" objection (renaming `docker-compose.yml` to `compose.prod.yml` fabricates an appearance) is real, and it is why v1's global `file class` component is gone. §7.1 puts the path back in the Compose key for a different, defensible reason and pays for it with residual pairing at file granularity.
- **"Unordered values are identity, not level"** survives. Destinations, hostnames, and bucket names cannot sit on a ladder; two of them are two keys. This is why `net.egress` was never going to work as a level-based kind and is one more reason it is cut.

---

## 4. Reading the two trees

### 4.1 Decision: read all candidates on both sides. Changed-files-only is not a correctness mechanism.

v1 scoped extraction to the changed-file set and offered `contextGlobs` to patch cross-file cases. The reviewer is right that this does not work, and I verified the load-bearing fact: [Docker's Compose services reference](https://docs.docker.com/reference/compose-file/services/) confirms that `extends` can reference a service **in another file**, that `ports` are **merged as sequences** across the extension, and that the referenced service **need not be part of the project**. So a change confined to `common.yml` genuinely alters the effective ports of an unchanged service in `compose.yml`. Reading only changed files either fabricates a widening on a template that is never deployed, or misses the real one.

`contextGlobs` supplied bytes without a dependency closure, without a guarantee of transitive completeness, and without any rule for re-emitting unchanged consumers. **It is deleted from the model.**

v2 takes both of the reviewer's alternatives, because they are complementary rather than exclusive:

**(a) Read every candidate file on both sides.** The property set is computed over the full tree at base and the full tree at head. Changed-file information is retained only as a *hint* for §5's exit-4 policy and for text rendering — never as a filter on extraction.

**(b) Restrict v1 extractors to file-local syntax, and mark cross-file constructs unanalyzable.** Any Compose service carrying `extends`, or any Compose file with a top-level `include`, produces `Unanalyzed{reason:"unsupported_syntax"}` for that service — not a guessed property. Combined with (a), the closure problem does not arise in v1 because no v1 extractor has a cross-file construct it is willing to interpret.

**The cost, stated plainly.** Full-tree enumeration replaces "2× a diff-scoped scan" with "2× a candidate-filtered tree scan." For Compose and `package.json` the candidate count is trivially small even in large monorepos. IAM is the expensive one, because a naive `**/*.json` filter can match thousands of files. §4.3 bounds it. On this repo the base-side enumeration is a single `git ls-tree -r`, and candidate reads are `git cat-file --batch`-eligible. Measured budget: **≤ 2 s wall on a 10k-file repo**, enforced by a timeout that degrades to `Unanalyzed{reason:"timeout"}` rather than truncating silently.

I am explicitly accepting a slower tool for a correct one. Correct dependency closure precedes diff scoping.

### 4.2 Git plumbing, hardened

All of the reviewer's §6 points are accepted. Verified against the local toolchain (`git 2.43.0`): `--end-of-options` is supported, and the empty-tree OID is `4b825dc642cb6eb9a060e54bf8d69288fbee4904`.

`node/src/utils/git-tree.ts` / `python/rafter_cli/utils/git_tree.py`:

1. **Never use `node/src/utils/git.ts`.** Its `git()` at line 3 interpolates into `execSync`. Use `execFileSync("git", [...])` / `subprocess.run([...], shell=False)`.
2. **Reject option-shaped refs at the CLI boundary.** Any `--base`/`--head` value beginning with `-` is exit 2, `invalid_ref`, before git is invoked.
3. **Resolve to OIDs first, with option termination:** `git rev-parse --verify --quiet --end-of-options <ref>^{commit}`. Every subsequent command takes only the resolved 40-hex OID. This closes git *option* injection, which an argv array alone does not.
4. **Enumerate base:** `git ls-tree -r -z --long <oid>` — gives mode, type, OID, size, and NUL-delimited paths in one call. Mode `120000` (symlink) and `160000` (submodule) entries are skipped with `Unanalyzed{reason:"symlink"}`.
5. **Enumerate working-tree head:** `git ls-files -z --cached --others --exclude-standard`. The `--others` half is the fix for the reviewer's real hit — `git diff --name-status` omits untracked files, so a newly created, never-added `policy.json` was invisible to v1 despite head defaulting to the working tree.
6. **`-z` everywhere.** Paths with tabs, newlines, or quoting bytes are parsed unambiguously.
7. **Symlink containment on working-tree reads:** `lstat` each candidate; if it is a symlink, do not follow — `Unanalyzed{reason:"symlink"}`. Never `realpath`-escape the work tree.
8. **Read base content** via `git cat-file --batch` over a NUL-safe OID list (single long-lived process), falling back to per-file `git cat-file blob <oid>` when batch framing fails.
9. **Changed-file hint set:** `git diff --name-status -z --no-renames <baseOid> [<headOid>]`, plus `git ls-files --others --exclude-standard -z` for the working-tree case. Used only for the `Unanalyzed.changed` flag and rendering.
10. **Resource limits, all producing typed `Unanalyzed` records:** per-file 1 MiB (`too_large`); per-side 2000 candidates after filtering (`too_many_candidates`); JSON nesting depth 64 (`parse_error`); NUL byte in the first 8 KiB (`binary`); 20 s total extraction wall clock (`timeout`).

**Injection regression test, corrected.** v1 proposed creating a branch named `--upload-pack=evil`, which git refuses to create — it tested a case that cannot arise. v2 tests the reachable path: invoke the CLI with `--base=--upload-pack=/bin/false` and `--base=-i` and assert exit 2 with `invalid_ref` and no git subprocess spawned.

### 4.3 IAM candidate filtering

Two stages, both cheap:

- **Stage 1 (path + size, no read):** `*.json` under 256 KiB, excluding `node_modules/`, `.git/`, `dist/`, `vendor/`, `**/package-lock.json`, `**/*.tsbuildinfo`, and lockfile-shaped names. On the base side, sizes come free from `ls-tree --long`.
- **Stage 2 (content sniff, first 4 KiB):** must contain the substring `"Statement"` and parse as an object with a `Statement` array whose first element has an `Effect` key. Anything matching stage 1 but failing to *parse* is silently non-candidate — **not** `Unanalyzed`, because arbitrary JSON in a repo is not a security artifact and flagging it would be pure noise. Anything that parses as IAM-shaped but contains constructs we refuse (§7.2) **is** `Unanalyzed`.

The asymmetry matters: we abstain quietly on "this is not an IAM policy" and loudly on "this is an IAM policy I cannot fully read."

### 4.4 Base resolution and failure behavior

The failure mode to avoid at all costs is: base unresolvable → empty base property set → everything looks `added` → a 40-line "everything is more dangerous" report. That behavior would destroy the feature on first contact.

v1's answer was "never proceed with an empty base; always exit 3." The reviewer is right that this fails on the ordinary CI setup: `actions/checkout` defaults to `fetch-depth: 1`, this repo's own workflows omit `fetch-depth` entirely (`.github/workflows/test-comprehensive.yml`), and — confirmed — `action.yml` is a composite action whose steps begin at "Install Rafter CLI (npm)", so it does not own checkout and cannot set `fetch-depth`. Exit 3 would have been the *expected* result, not an edge case.

v2 separates "never invent an empty base" (kept — this was correct and I am keeping it over the reviewer's silence on it) from "always exit nonzero" (dropped).

Resolution order:

1. `git rev-parse --verify --quiet --end-of-options <base>^{commit}`. Success → proceed.
2. **Proven root/unborn case:** if `<base>` resolves to a commit with no parents and the user asked to diff against its parent, or the repo has no commits at all, use the empty tree OID `4b825dc642cb6eb9a060e54bf8d69288fbee4904`. This is a *proven* empty base, not an invented one. Not an error, exit as normal.
3. **`--fetch-base` (opt-in, default off):** one narrow `git fetch --no-tags --depth=1 origin <base>`. Default-off preserves the repo's no-network-by-default posture (`shared-docs/CLI_SPEC.md:7`). Prefer a targeted one-commit fetch over `fetch-depth: 0`.
4. Otherwise **exit 3** with a machine-readable error. Exit 3 is unaffected by `--fail-on`, including `--fail-on none`: we produced no answer at all, and a report-only mode must not report "clean."

**The composite action fixes itself.** `action.yml` gains a step *before* its scan step:

```yaml
    - name: Fetch surface-diff base
      if: inputs.surface-base != ''
      shell: bash
      run: git fetch --no-tags --depth=1 origin "${{ inputs.surface-base }}" || true
```

This is strictly better than v1's impossible plan (adding `fetch-depth` to a checkout it does not own) and better than only patching `ci init` templates, which the reviewer correctly noted helps nobody who does not regenerate. `node/src/commands/ci/init.ts:110` and its Python mirror still gain `fetch-depth: 0` for newly generated workflows, as a belt-and-braces measure for the users we can reach.

### 4.5 Defaults for local use

Head defaults to the **working tree read from disk**, so bare `rafter surface diff` reflects uncommitted edits — the right answer for a pre-commit hook. `--head <ref>` switches to tree reads. Base defaults to `HEAD`, so bare invocation answers "what does this uncommitted change make more dangerous." CI passes `--base ${{ github.event.pull_request.base.sha }}`.

### 4.6 No snapshot store, and `rafter agent baseline` is not touched

`rafter agent baseline` is a suppression allowlist for *secret findings*, keyed `{file, line, pattern, addedAt}`, with a documented contract at `shared-docs/CLI_SPEC.md:1013` and no content hash or ref binding (`node/src/commands/agent/baseline.ts`) — which is exactly why it silently goes stale. Surface diff needs a content-addressed snapshot of *derived properties* with a different key, lifecycle, and semantics. Overloading it would either break `rafter secrets --baseline` or produce a union type nobody can reason about. Separate store, and in v1, **no store at all**: recompute both sides every run. A committed `.rafter/surface.json` would drift with no invalidation signal and become a merge-conflict magnet. If snapshotting is ever wanted, it gets its own `rafter surface snapshot` writing `{commit, cliVersion, kindSpecHash, properties[]}` where a mismatch on any of the three means recompute. Explicitly not v1.

The reviewer endorsed this decision. I keep it because the argument stands on its own.

---

## 5. False-positive and false-negative posture

**Where this product errs, stated once and applied throughout: in a CI gate, we accept a false positive over a false negative, but we accept an *abstention* over both.** A tool that cries wolf gets disabled; a tool that silently passes a dangerous change is worse than nothing; a tool that says "I could not analyze this changed policy file" is honest and actionable. Every rule below is an application of that ordering.

### R1 — One confidence level, and everything in v1 must earn it

`certain` means: read from a declarative artifact whose grammar the extractor **fully parsed**, with every construct it did not understand explicitly reported. There is no `probable` tier in v1 (see §1). An extractor that cannot reach `certain` does not ship.

### R2 — The precision claim is paired-tree and metamorphic, not per-file

v1 claimed "0 FP on ≥20 negative files, ≥0.90 recall on ≥20 positives." The reviewer is right on both counts: zero failures in 20 trials bounds the failure rate only at roughly 14% at 95% confidence (rule of three), the corpus author picks the negatives, and — most importantly — **single-file corpora cannot measure the actual failure mode**, which is a true property on each side mispaired into a false widening across two trees.

v1-mandatory replacement, all over paired base/head trees:

- **M1 · Metamorphic no-op suite (per extractor).** A generator applies semantics-preserving mutations to each corpus tree — reindent, reorder mapping keys, reorder sequence entries where order is not semantic, add/move comments, rename the enclosing file, split one file into two, merge two into one, rename the subject. **Assertion: zero transitions with `danger:"increased"`.** This is a property test, it is cheap, and it directly targets the mispairing failure mode.
- **M2 · Seeded one-axis widening suite.** For each kind and each axis, a base tree and a head tree differing on exactly that axis by exactly one rank. **Assertion: exactly one transition, `danger:"increased"`, on exactly that axis, with the tabled severity.**
- **M3 · Seeded incomparable suite (IAM).** Trees where one axis increases and another decreases. **Assertion: `danger:"incomparable"`, severity `severityWhenIncomparable`, and — critically — the transition is *not* suppressed.**
- **M4 · Abstention ceiling.** Across the whole corpus, the fraction of stage-2 candidate files marked `Unanalyzed` must be **< 10%**. Without this, an extractor buys perfect precision by refusing to parse anything.
- **M5 · Idempotence and symmetry.** `diff(A, A)` is empty for every corpus tree. `diff(A, B)` and `diff(B, A)` produce the same key set, with `increased`/`decreased` exchanged and `incomparable` preserved.

Aspirational, explicitly **not** v1-blocking: hundreds of independently reviewed no-ops per extractor; a held-out corpus mined from public repositories with real infrastructure history; published precision intervals. These are the right long-run program and I am not going to pretend they are a two-week deliverable.

### R3 — "Could not analyze" and "analyzed, found nothing" are different

The type system enforces it: `extract()` returns `ExtractResult{properties, unanalyzed}`. An extractor that matched a candidate file but did not fully parse it **must** emit an `Unanalyzed` record. A silent `return []` on a candidate file is a PR reject.

The correctness consequence — the single most important anti-cry-wolf rule:

> **Asymmetric unanalyzability suppresses absence claims.** If any candidate file failed to analyze on the **base** side for kind K, then for K, `change:"added"` transitions have `danger` forced to `"unknown"` and `severity` to `null` — we cannot prove the property was absent. Symmetrically, a head-side failure forces `change:"removed"` to `unknown`. A `modified` transition between two *observed* level sets is unaffected, because both endpoints were actually seen.

A base-side YAML parse error must never manifest as "+7 newly exposed ports."

### R4 — Coverage degradation on a *changed* file is inconclusive, not clean

v1 said coverage never affects the exit code. The reviewer is right that this is an **attacker-controlled fail-open**: a PR author who introduces syntax the parser rejects gets exit 0 out of a security gate, on a file they wrote. That is unacceptable in a CI gate.

v2's policy is narrower than either position:

> An `Unanalyzed` record with `changed: true` — i.e. a candidate file that *differs between base and head* and could not be analyzed on either side — makes the run **inconclusive**, and inconclusive is **exit 4**.
>
> An `Unanalyzed` record with `changed: false` — a pre-existing weird file the PR did not touch — is reported in `coverage` and **never** affects the exit code.

This is the reviewer's fix with my refinement. The refinement matters: the unrestricted version means one gnarly legacy `k8s/prod.yaml` blocks every PR in the repo forever, which is how the check gets deleted. Restricting to changed files makes the gate fire exactly when the PR author has the power and the responsibility to fix it, and the remediation message says so.

`--on-inconclusive <exit|warn>` overrides. Default is `exit` unless `--fail-on none`, in which case it is `warn` — report-only mode reports, it does not gate.

**This is the deliberate false-positive-over-false-negative trade.** Some PRs will get an inconclusive on a Compose file using an anchor we refuse. That is a visible, fixable, honest annoyance. The alternative is a silent pass on an author-chosen parser evasion.

### R5 — Noise budget, measured against a corpus that can actually move

v1 proposed replaying over the last 25 commits of this repo. The reviewer is right that this is near-vacuous: this repo's history is TypeScript/Python CLI work, docs, and release bumps, and `fixtures/vulnerable-repo/infra/docker-compose.yml` is one static file with one published port (mongo `27017:27017`). Median zero is guaranteed when most commits touch no claimed artifact.

Replacement: **`fixtures/surface-history/`**, a purpose-built repo constructed by a committed generator script — roughly 30 commits of Compose, IAM, and `package.json` edits, of which about 25 are benign (formatting, renames, comments, adding an internal-only service, tightening a policy) and about 5 are genuine widenings. The gate asserts **zero reportable lines on every benign commit** and **exactly the seeded line on each widening commit**.

I am stating the honesty caveat rather than hiding it: this corpus is author-chosen, so it measures *regression*, not real-world precision. It is a regression net. Real-world precision comes from the held-out corpus in R2's aspirational tier. See §11.

### R6 — No extractor may depend on heuristic reachability or interprocedural dataflow in v1

This directly disqualifies the shell-sink extractor (§0.2) and any auth-inference route table.

---

## 6. CLI surface

### 6.1 Command name

**`rafter surface diff [PATH]`** — a new top-level noun group. Verified: `surface` does not collide with any command registered in `node/src/index.ts` or any `add_typer` in `python/rafter_cli/__main__.py`.

*Why not `--surface` on `rafter secrets`:* `secrets` is scope-limited by its own spec ("Secrets only — not a full code-security scan", `shared-docs/CLI_SPEC.md:400`); its existing `--diff <ref>` already means "added lines only," a genuinely different semantic from "base-vs-head property sets"; and its JSON wrapper `{_note, scan_mode, triage_applied, results:[{file,matches}]}` is structurally incompatible.

*Why not `rafter scan surface`:* `rafter scan` with no subcommand already means "remote backend scan" (`node/src/commands/scan/index.ts:57`) and `scan local` is a deprecated alias. A third meaning under that verb makes the CLI unlearnable.

*Why a group rather than bare `rafter surface`:* `surface snapshot` and `surface list` are foreseeable, and the repo consistently uses noun groups (`agent`, `policy`, `sites`, `issues`, `docs`, `skill`).

### 6.2 Flags

```
rafter surface diff [PATH]
  --base <ref>                 base ref (default: HEAD)
  --head <ref>                 head ref (default: working tree)
  --format <text|json>         output format (default: text)
  --json                       alias for --format json (matches `rafter secrets`)
  --fail-on <low|medium|high|critical|none>   exit-1 threshold (default: high)
  --min-severity <low|medium|high|critical>   display floor (default: low)
  --on-inconclusive <exit|warn>               default: exit, or warn with --fail-on none
  --include-decreased          show danger:"decreased" transitions in text
  --all                        include severity-null transitions (unchanged, non-reportable)
  --explain                    enumerate unanalyzed files in text output
  --fetch-base                 permit one narrow `git fetch` to resolve the base
  --quiet                      suppress stderr status messages
  -h, --help
```

### 6.3 Exit codes

Exit 1 cannot mean "the surface changed," because nearly every PR changes something and a tool that fails every build is removed from CI within a week. Exit 1 means "something got more dangerous, at or above your threshold."

| Code | Meaning |
|------|---------|
| 0 | No reportable danger increase at or above `--fail-on`, and no inconclusive changed candidate. Includes "surface unchanged." |
| 1 | One or more transitions with `danger:"increased"` or `danger:"incomparable"` at or above `--fail-on` (default `high`) |
| 2 | Runtime error — not a git repo, path not found, invalid flag or ref value, extractor crash |
| 3 | Base ref unresolvable — unknown ref, or a shallow clone lacking the base commit. Unaffected by `--fail-on`. |
| 4 | Inconclusive — a candidate file that changed between base and head could not be analyzed (§5 R4). Suppressed to a warning by `--on-inconclusive warn`. |

Precedence when several apply: **3 > 2 > 4 > 1 > 0.** Exit 3 wins because no comparison happened at all. Exit 4 beats 1 because "I could not see part of this change" is a stronger statement than "here is what I did see" — but the JSON body still carries every transition found, so a consumer loses nothing.

`--fail-on none` forces exit 0 for the 0/1 axis (report-only, for the post-a-PR-comment workflow) and makes `--on-inconclusive` *default* to `warn`, downgrading 4. It does not suppress 2 or 3.

**Clarification (A1.3).** As originally written this section read as an unconditional override while §5 R4 described it as a default, and the two dispositions differ when a user passes both flags. §5 R4's reading governs: `--on-inconclusive` explicitly set beats the `--fail-on none` default, so `--fail-on none --on-inconclusive exit` still exits 4. An explicit flag beating a default is the ordinary CLI convention, and it errs toward gating rather than silence — the right direction for a security check. Test-locked in both runtimes.

Exit 3 and 4 are distinct top-level codes rather than variants of 2 because they are the two most common operational outcomes and conflating them with "runtime error" makes every user debug them from scratch. The repo already precedents per-family codes 3/4/5 (`shared-docs/CLI_SPEC.md:20-58`).

---

## 7. The three extractors

### 7.1 E1 · `container.port` — Docker Compose published ports

**Sources:** `docker-compose.y{a,}ml`, `compose.y{a,}ml`, `docker-compose.*.y{a,}ml`, `compose.*.y{a,}ml`, at any depth, excluding `node_modules/`.

**Property:** one per `(file, service, container-port, protocol)`.

**Key:** `container.port:compose:<repo-relative-path>|<service>|<containerPort>/<proto>`.

The path *is* in the key here, deliberately, and this is a change from v1's "file class" scheme. Compose files are independent deployment descriptors; a service named `api` in `docker-compose.yml` and one in `deploy/staging/compose.yml` are different subjects, and v1's three-bucket file-class abstraction both merged genuinely distinct things and — as the reviewer noted — fabricated an appearance when a file was renamed across bucket boundaries. Putting the real path in the key is honest. The rename cost is paid by `pairingScope = <file>` residual pairing (§3.3) plus the file-rename case in the M1 metamorphic suite.

**Comparator:** `ordinal`, one axis `binding`:

| rank | meaning | severity on arrival |
|---|---|---|
| *(absent)* | no mapping for this port | — (`absentRank: "below"`) |
| `not-published` | `expose:` entry, or a long-syntax entry with `mode: host` absent and no host port | `null` |
| `loopback-published` | host IP is `127.0.0.1` or `::1` | `low` |
| `host-published` | no host IP, `0.0.0.0`, `::`, or any other literal address | `high` |

`severityByLevel: [null, "low", "high"]`. Adding an `expose:`-only port is a real transition at `severity: null` — visible only under `--all`, never a reported line. That mechanism (a `null` in the severity table rather than special-casing in code) is v1's and survives.

**Refused constructs, each producing `Unanalyzed{reason:"unsupported_syntax"}` for the affected service:** `extends` on the service; top-level `include`; a YAML merge key (`<<`) anywhere in the service mapping; a port value containing `${...}` interpolation; a port range (`8000-8010:8000-8010`) — ranges are deferred to v1.1 rather than guessed at; `profiles` on the service (whether it is deployed is external state).

**Parity note.** `27017:27017` is a *string* under both parsers only because of §8.1's parsing rule; under default settings PyYAML resolves sexagesimal-adjacent forms and octal-leading port numbers differently from js-yaml. See §8.1 — this is not hypothetical.

### 7.2 E2 · `iam.allow` / `iam.deny` — IAM policy JSON

**Sources:** stage-1/stage-2 filtered `*.json` (§4.3). **Terraform HCL is out of v1** — neither runtime has an HCL parser and hand-mirroring one in two languages is its own project. JSON-only is a defensible slice and it delivers the flagship line.

**Property:** one per statement. Kind is `iam.allow` or `iam.deny` by `Effect`.

**Key:**
- If `Sid` is present: `iam.<effect>:iam-json:<path>|sid=<sid>`. `Sid` is documented as unique within a policy, so this is exact.
- If `Sid` is absent (the common case — `AmazonS3FullAccess` has no `Sid`): `iam.<effect>:iam-json:<path>|act=<sha256 of sorted, lowercased Action set>|prin=<sha256 of canonical Principal, or "none">`.

**`Resource` and `Condition` are deliberately *not* in the key.** They are compared axes, and §3.2 invariant 2 forbids a value from being both. This is precisely the bug that made v1's advertised demo transition structurally impossible to emit. Under v2, `s3:GetObject on arn:aws:s3:::one-bucket/*` → `s3:GetObject on *` keeps the key, matches exactly, and produces `danger:"increased"` on the `resource` axis. The demo works.

When the Action set *also* changes, the key changes and the statement falls to residual pairing with `pairingScope = <policy document path>`: if exactly one removal and one addition remain in that document, they pair and the lattice comparator runs — which for `s3:* on one-bucket` → `s3:GetObject on *` correctly returns **`incomparable`**, reported at `severityWhenIncomparable`. That is the reviewer's own counterexample, handled honestly rather than force-ranked.

**Comparator:** `lattice`, four axes.

| axis | ranks (safest first) | `severityAtTop` |
|---|---|---|
| `action` | `literal` < `service-wildcard` (`s3:*`, `s3:Get*`) < `global-wildcard` (`*`) | `high` |
| `resource` | `literal` < `prefix-wildcard` (contains `*` or `?` but is not bare `*`) < `global-wildcard` (`*`) | `high` |
| `principal` | `absent-or-literal` < `wildcard` (`"*"` or `{"AWS":"*"}`) | `critical` |
| `condition` | `present` < `absent` | `medium` |

`severityWhenIncomparable: "medium"`. Two or more axes reaching their top rank promotes to `critical`.

The `condition` axis is what makes "someone deleted the `aws:SourceIp` condition and changed nothing else" visible — a real widening that v1 could not see at all, because conditions appeared in neither its key nor its levels. When both sides have a condition and the two conditions differ textually, that axis returns **`unknown`** (not `equal`, not `greater`), which propagates to `danger:"unknown"` for the whole statement. Comparing condition *semantics* is out of v1 scope; pretending they are equal because we cannot compare them would be a false negative.

**`invertDanger: true` on `iam.deny`.** A broader Deny is safer; a narrower or deleted Deny is more dangerous. This is one boolean in the kind-spec table and it eliminates v1's "a new `Deny *` is `critical`" defect without an extractor knowing anything about severity.

**Refused constructs, each `Unanalyzed{reason:"unsupported_syntax"}` for that statement:** `NotAction`, `NotResource`, `NotPrincipal` (their semantics invert the lattice in ways v1 will not model); any non-string, non-array-of-string value in `Action`/`Resource`/`Principal`; policy variables (`${aws:username}`) inside `Resource`; a `Statement` that is a bare object rather than an array *is* supported and normalized.

### 7.3 E3 · `pkg.lifecycle_script` — install-time lifecycle scripts

**Sources:** every `package.json` outside `node_modules/`.

**Property:** one per `(manifest path, script name)` for script names in `{preinstall, install, postinstall, prepare, prepack, postpack}`.

**Key:** `pkg.lifecycle_script:npm:<path>|<scriptName>`. Path is in the key because in a workspace monorepo, `packages/a` and `packages/b` are different packages.

**Comparator:** `ordinal`, one axis `fetch`:

| rank | meaning | severity on arrival |
|---|---|---|
| *(absent)* | no such lifecycle script | — (`absentRank: "below"`) |
| `local` | script body contains no remote-fetch token | `null` |
| `fetches-remote` | contains `curl`, `wget`, `Invoke-WebRequest`, `nc `, or an `http://`/`https://` literal | `medium` |
| `pipes-remote-to-interpreter` | a remote-fetch token whose output is piped into `sh`, `bash`, `zsh`, `python`, `node`, `ruby`, `perl`, or consumed by `eval` / `$(…)` / backticks | `critical` |

This replaces v1's `["local-only", "network-or-shell"]`, which the reviewer correctly called incoherent: npm runs *every* lifecycle script through a shell, so "shell" is not a discriminator. "Does this install-time script pull code off the network, and does it execute what it pulls" is a real, ordered, syntactically decidable question — and `curl … | sh` in a `postinstall` is exactly the thing a reviewer wants flagged.

The token match runs against the script string only. Adding a lifecycle script that is purely local is `severity: null` — a real transition, not a reported line.

**Refused constructs:** a script whose body references another script via `npm run` (we do not follow the indirection — `Unanalyzed{reason:"unsupported_syntax"}`); a non-string script value; a `package.json` that is not a JSON object.

### 7.4 Deferred, ranked

| Rank | Extractor | Blocked on |
|---|---|---|
| 1 | Kubernetes `Service` + `Ingress` exposure | Cross-document closure. Key is specified: `(namespace, kind, name, port, protocol)`. |
| 2 | IAM via Terraform HCL | An HCL parser in both runtimes, or a restricted `resource "aws_iam_policy"` + `jsonencode({…})` reader. |
| 3 | CSP / security headers | Requires evaluating JS config, or restricting to genuinely declarative sources (`vercel.json`, `netlify.toml`, nginx `add_header`, `<meta http-equiv>`) — which is a coherent smaller unit and the likely v1.1 shape. |
| 4 | Compose `extends` / `include` closure | A real dependency-closure implementation. Currently `unsupported_syntax` by design. |
| 5 | Egress destinations | Needs an identity model (destinations are keys, not levels) and a vendor catalog that stays byte-identical across two package trees. |
| 6 | `sink.shell` reachable from request-scoped input | No defensible v1 version exists (§0.2). Re-enters with **zero schema change** as an `ordinal` kind with ranks `["unreachable","reachable-unsanitized"]`. |

---

## 8. Cross-runtime parity

This is the real risk. Hand-mirroring a regex list is one thing; hand-mirroring three parsers, a lattice comparator, and a severity table is another.

### 8.1 The YAML rule — now the top parity risk, and it is solved

v1 proposed hand-rolling a restricted YAML reader to avoid adding a dependency. **That premise is dead:** Node depends on `js-yaml ^4.2.0` (resolved 4.3.0) and uses it in five source files including `node/src/core/policy-loader.ts` and `node/src/commands/agent/init.ts`; Python depends on `pyyaml ^6.0.1` and uses it in four. Both runtimes have real YAML parsers.

The actual risk is **semantic divergence**: js-yaml 4 implements YAML 1.2 core schema, PyYAML 6 implements YAML 1.1. I measured it on a 12-line file:

| YAML source | js-yaml 4.3.0 | PyYAML 6 |
|---|---|---|
| `a: yes` | string `"yes"` | bool `True` |
| `b: no` / `c: on` | strings | bools |
| `e: 017` | number **17** | int **15** (octal) |
| `d: 0o17` | number **15** | string `"0o17"` |
| `k: 08` | number `8` | string `"08"` |
| `g: 1_000` | string `"1_000"` | int `1000` |
| `dup: 1` / `dup: 2` | **throws** `duplicated mapping key` | silently `2` |

Five divergence classes in one small file, and the `017` case is *directly port-relevant*.

**The rule, empirically verified:**

> **Neither parser's scalar type resolution may be used.** Parse structure with the native parser configured to emit strings only:
>
> - **Node:** `yaml.load(src, { schema: yaml.FAILSAFE_SCHEMA })`
> - **Python:** `yaml.load(src, Loader=RafterBaseLoader)` where `RafterBaseLoader(yaml.BaseLoader)` adds a mapping constructor that raises on duplicate keys
>
> Rafter's own `parseScalar()` — one shared spec, two mirrored implementations — does all typing.

I ran the same divergence fixture through both configured that way and got **byte-identical output**:

```
node failsafe: {"a":"yes","b":"no","c":"on","d":"0o17","e":"017","f":"0x1F",
                "g":"1_000","h":"27017:27017","i":"27017:27017","j":"3.0","k":"08"}
py  baseloader: {"a": "yes", "b": "no", "c": "on", "d": "0o17", "e": "017", "f": "0x1F",
                 "g": "1_000", "h": "27017:27017", "i": "27017:27017", "j": "3.0", "k": "08"}
```

Three residuals, each handled explicitly:

1. **Empty node.** `c:` yields `null` in js-yaml and `""` in PyYAML. The shared adapter normalizes both to `""`. This is the only scalar difference that survives, and it is one line of code per runtime.
2. **Duplicate keys.** js-yaml throws under `FAILSAFE_SCHEMA` too (verified). PyYAML needs the custom constructor (verified working, ~8 lines). Both then produce `Unanalyzed{reason:"parse_error"}`. Rejecting is the fail-closed choice: a duplicate key in a Compose file is a genuine ambiguity about which mapping wins.
3. **Merge keys.** Under string-only loading, `<<: *b` materializes as a literal key `"<<"` in *both* runtimes (verified identical). That makes it trivially detectable, and E1 treats it as `unsupported_syntax`. Plain anchors/aliases resolved identically under both configurations, so they are **permitted** — this is an evidence-based relaxation of v1's blanket ban.

A test in both suites loads a shared divergence fixture and asserts the string-only output matches a hand-written expectation, so a future `js-yaml` or `PyYAML` major bump surfaces as a test failure rather than a silent behavior change.

### 8.2 Agreement: extend the existing cross-runtime parity test

**I reject the reviewer's proposal to build both packages, install the npm tarball and the wheel into clean environments, and compare — as the v1 mechanism.** Two arguments:

1. **The reviewer's own strongest parity point defeats v1's golden scheme, and the existing test already answers it.** The critique correctly said "Node-only regeneration is a bad oracle — generated golden data proves agreement, not correctness." But `node/tests/cross-runtime-parity.test.ts` **already exists** and does something strictly better on that axis: it invokes *both* live CLIs — `execFileSync("node", [dist/index.js, …])` and `execFileSync("python3", ["-m","rafter_cli", …])` with `PYTHONPATH` into `python/` — on identical inputs and compares exit codes and output structure. Comparing two live implementations on the same input **needs no oracle at all**. It is the repo's established mechanism, and extending it is a fraction of the cost of a packaging harness.
2. **The packaging apparatus tests a different, narrower thing.** It catches "the fixtures are not in the tarball" and "the command does not exist in the published artifact." Real, but small, and it does not need a corpus to catch it.

So: **extend `node/tests/cross-runtime-parity.test.ts`** with a `parity: surface diff` block that, for each `fixtures/surface/cases/<id>/`, materializes base and head into a temp git repo (`mkdtemp` + `execFileSync` git — already the pattern in `node/tests/`), runs both CLIs with `--json`, and asserts **byte-identical canonical stdout** and **identical exit codes**. No golden file is involved in this test.

Two fixes to that file, both required:

- **The silent skip is a real hole.** It currently sets `PYTHON_AVAILABLE = false` and `describe.skip`s when `typer` is not importable, so a broken Python side passes CI invisibly. v1 adds `RAFTER_PARITY_REQUIRED=1`, set in `.github/workflows/test-comprehensive.yml`, which turns the skip into a hard failure. Local runs without Python deps still skip.
- **Field-name wire assertions.** Explicitly assert that Python emits `"from"`/`"to"`, not `from_level`/`to_level` — the one place §2.7's deliberate divergence could leak.

**Partial acceptance of the packaging point:** `publish.yaml` gains **one** post-install smoke case per artifact — generate a two-commit temp repo, run `rafter surface diff --json`, assert `schema_version`, the presence of `transitions` and `coverage`, and exit code 1. Bounded cost, catches the packaging class, does not require shipping fixtures in either package.

### 8.3 Correctness: hand-authored, never regenerated

Agreement and correctness are different jobs and need different mechanisms. v1 conflated them and picked the worse option for both.

`fixtures/surface/cases/<case-id>/` at the repo root, containing `base/`, `head/`, and `expected.json`. **`expected.json` is hand-authored and human-reviewed. There is no `UPDATE_SNAPSHOTS` path for either runtime.** This adopts the reviewer's specific point — do not let either implementation regenerate the oracle unilaterally — while rejecting the apparatus around it. Both suites assert against it; the §8.2 agreement test asserts the two runtimes agree with each other independently.

Note the pattern cost honestly: `fixtures/` is at the repo root, is shipped by neither package (`node/package.json` `files: ["dist","resources"]`; Poetry auto-packages `rafter_cli` under `python/`), and is currently referenced by **zero** tests. A root corpus reachable from both suites via `../fixtures` is a **new pattern in this repo**. It is the right one — a corpus duplicated per runtime is a parity bug generator, and the existing byte-identical-but-unchecked `node/tests/snapshots/` ↔ `python/tests/snapshots/` pair is the cautionary precedent — but it needs to be introduced deliberately in W1, not assumed.

**Kind-spec drift test:** both runtimes serialize `KIND_SPECS` canonically and assert equality against `fixtures/surface/kind-specs.json`. A severity or ordering table that drifts between runtimes is the highest-consequence parity bug this feature can have, and one test closes it.

### 8.4 Canonical JSON, fully specified

The reviewer is right that "no floats" was not sufficient. The full rule:

- **Encoding:** UTF-8, no BOM.
- **String values:** NFC-normalized before emission. Lone surrogates replaced with U+FFFD.
- **Object keys are ASCII, always.** Field names are fixed; `attrs` keys are extractor-fixed ASCII identifiers, enforced by a test that walks every extractor's output over the corpus. This makes key sort order unambiguous — Python sorts by code point, JS `Array.sort` by UTF-16 code unit, and they differ above the BMP. Restricting to ASCII sidesteps it entirely rather than requiring both runtimes to implement a shared collation.
- **Array ordering** where the sort key may be non-ASCII (`transitions` sorted by `key`, `coverage.unanalyzed` by `file`): sort by **UTF-8 byte sequence**, implemented explicitly in both runtimes, not by the language default.
- **Integers:** bounded to ±(2^53−1). A value outside the range is an extractor bug; the property is dropped and the file marked `parse_error`.
- **No floats anywhere.**
- **Serialization:** Python `json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))`; Node a small recursive key-sorting serializer with no spaces.
- **Paths:** repo-relative, forward slashes, NFC-normalized, no leading `./`.

### 8.5 What is built as reusable spine

1. **`BaseTreeReader` + candidate enumeration** — `node/src/utils/git-tree.ts` / `python/rafter_cli/utils/git_tree.py`: `resolveRef`, `listTree(oid)`, `listWorkTree()`, `readAt(oid, path)`, `changedPaths(baseOid, headOid?)`, `isShallow()`. Every sibling feature that compares two trees needs this; none of them need a worktree.
2. **Model, kind specs, comparators, differ** — `core/surface/{model,kind-specs,compare,differ}.*`. Siblings register kinds; they do not fork the differ.
3. **String-only YAML adapter + `parseScalar`** — `core/surface/yaml-safe.*`. This is the §8.1 rule as code, and it is reusable by anything in the repo that parses untrusted YAML.
4. **Canonical JSON serializer** — §8.4.
5. **Extractor interface + a plain registry array.** Not a plugin system. The repo has no registry pattern anywhere (`RegexScanner` is instantiated directly by handlers), and inventing one for three extractors is over-engineering.

**Deliberately not built:** taint hooks, snapshot store, SARIF output, remote upload, config-driven custom kinds in `.rafter.yml`. Each is speculative. The only forward-compat commitment worth making is that the model already expresses reachability as an ordinal ladder, which costs nothing today.

---

## 9. Output contracts

### 9.1 JSON output, in CLI_SPEC.md's documented format

````markdown
#### JSON Output (`--json` / `--format json`)

```json
{
  "_note": "Attack-surface diff: a delta of security properties between two trees, not a findings list. `change` is structural (added/removed/modified); `danger` is semantic and is the only thing severity attaches to. An empty `transitions` array with `coverage.inconclusive: false` means the analyzed surface is unchanged — it does not mean the code is safe.",
  "schema_version": 1,
  "base": { "ref": "origin/main", "resolved": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" },
  "head": { "ref": "WORKTREE", "resolved": null },
  "summary": {
    "increased": 2, "decreased": 0, "incomparable": 1, "unchanged": 1, "unknown": 0,
    "added": 1, "removed": 0, "modified": 3,
    "highest_severity": "high", "reportable": 3
  },
  "transitions": [
    {
      "kind": "iam.allow",
      "key": "iam.allow:iam-json:infra/policy.json|sid=AppBucketAccess",
      "subject": "statement AppBucketAccess",
      "label": "Allow s3:GetObject — resource widened to *",
      "change": "modified",
      "danger": "increased",
      "severity": "high",
      "axes": [
        { "axis": "action",    "from": "literal", "to": "literal",         "order": "equal" },
        { "axis": "resource",  "from": "prefix-wildcard", "to": "global-wildcard", "order": "greater" },
        { "axis": "principal", "from": "absent-or-literal", "to": "absent-or-literal", "order": "equal" },
        { "axis": "condition", "from": "present", "to": "present",         "order": "equal" }
      ],
      "from": null,
      "to": null,
      "confidence": "certain",
      "base_evidence": { "file": "infra/policy.json", "line": 18 },
      "head_evidence": { "file": "infra/policy.json", "line": 18 },
      "attrs": { "effect": "Allow", "action": "s3:GetObject", "resource": "*" },
      "paired": false
    },
    {
      "kind": "container.port",
      "key": "container.port:compose:infra/docker-compose.yml|redis|6379/tcp",
      "subject": "service redis",
      "label": "redis port 6379 published on 0.0.0.0",
      "change": "added",
      "danger": "increased",
      "severity": "high",
      "axes": [
        { "axis": "binding", "from": null, "to": "host-published", "order": "greater" }
      ],
      "from": null,
      "to": "host-published",
      "confidence": "certain",
      "base_evidence": null,
      "head_evidence": { "file": "infra/docker-compose.yml", "line": 15 },
      "attrs": { "service": "redis", "bind": "0.0.0.0", "container_port": 6379, "protocol": "tcp" },
      "paired": false
    },
    {
      "kind": "iam.allow",
      "key": "iam.allow:iam-json:infra/policy.json|act=9f2c1b7e|prin=none",
      "subject": "statement 2",
      "label": "Allow: action narrowed to s3:GetObject, resource widened to *",
      "change": "modified",
      "danger": "incomparable",
      "severity": "medium",
      "axes": [
        { "axis": "action",    "from": "service-wildcard", "to": "literal",         "order": "less" },
        { "axis": "resource",  "from": "prefix-wildcard",  "to": "global-wildcard", "order": "greater" },
        { "axis": "principal", "from": "absent-or-literal","to": "absent-or-literal","order": "equal" },
        { "axis": "condition", "from": "absent",           "to": "absent",           "order": "equal" }
      ],
      "from": null,
      "to": null,
      "confidence": "certain",
      "base_evidence": { "file": "infra/policy.json", "line": 31 },
      "head_evidence": { "file": "infra/policy.json", "line": 31 },
      "attrs": { "effect": "Allow", "action": "s3:GetObject", "resource": "*" },
      "paired": true
    }
  ],
  "coverage": {
    "analyzed": 12,
    "degraded": true,
    "inconclusive": false,
    "unanalyzed": [
      {
        "file": "deploy/legacy-compose.yml",
        "side": "base",
        "reason": "unsupported_syntax",
        "detail": "service 'web' uses extends",
        "changed": false
      }
    ]
  }
}
```

**Top-level field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `_note` | string | Human-readable scope note. JSON has no comments — this `_*` key is the convention. |
| `schema_version` | number | Integer, incremented on any breaking change to this object. Currently `1`. |
| `base` | object | The base side of the comparison. |
| `head` | object | The head side of the comparison. |
| `summary` | object | Transition counts by `danger` and by `change`, plus the highest severity present. |
| `transitions` | array | Every transition, sorted by severity (desc), then `kind`, then `key` (UTF-8 byte order). Empty when the analyzed surface is unchanged. |
| `coverage` | object | What was and was not analyzable. |

**`base` / `head` field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `base.ref` | string | The ref as supplied (`--base`), e.g. `"origin/main"`, `"HEAD"`. `"EMPTY_TREE"` for a proven root/unborn base. |
| `base.resolved` | string\|null | Full 40-char commit SHA; the empty-tree OID `4b825dc6…` for a root/unborn base |
| `head.ref` | string | `"WORKTREE"` when `--head` was not supplied, otherwise the supplied ref |
| `head.resolved` | string\|null | Full commit SHA, or `null` for the working tree |

**`summary` field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `summary.increased` | number | Transitions where head is more dangerous than base |
| `summary.decreased` | number | Transitions where head is less dangerous than base |
| `summary.incomparable` | number | Transitions where one axis widened and another narrowed — neither side dominates |
| `summary.unchanged` | number | Transitions emitted with no danger change (residually-paired renames only) |
| `summary.unknown` | number | Transitions whose danger could not be decided — asymmetric coverage loss, or an undecidable axis |
| `summary.added` | number | Properties absent at base, present at head |
| `summary.removed` | number | Properties present at base, absent at head |
| `summary.modified` | number | Properties present on both sides |
| `summary.highest_severity` | string\|null | `"low"`, `"medium"`, `"high"`, `"critical"`, or `null` when no transition carries a severity |
| `summary.reportable` | number | Count of transitions with a non-null `severity` at or above `--min-severity` |

**`transitions[]` field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `transitions[].kind` | string | `"container.port"`, `"iam.allow"`, `"iam.deny"`, or `"pkg.lifecycle_script"` |
| `transitions[].key` | string | Stable property identity. Independent of line numbers and formatting. Never contains a value that appears in `axes` — identity and comparison are disjoint. |
| `transitions[].subject` | string | Human-facing name of the thing the property is about, e.g. `"service redis"` |
| `transitions[].label` | string | Human-readable phrase for display. Not stable across versions — never key on it. |
| `transitions[].change` | string | `"added"`, `"removed"`, or `"modified"`. **Structural only.** `added` always means absent at base and present at head; there are no exceptions. |
| `transitions[].danger` | string | `"increased"`, `"decreased"`, `"unchanged"`, `"incomparable"`, or `"unknown"`. **Semantic.** Independent of `change`: removing a `Deny` statement is `change:"removed"`, `danger:"increased"`. |
| `transitions[].severity` | string\|null | `"low"`, `"medium"`, `"high"`, `"critical"` when `danger` is `"increased"` or `"incomparable"`; `null` otherwise. Same four-value vocabulary used everywhere else in Rafter. |
| `transitions[].axes` | array | Per-axis comparison. Always present and always authoritative. |
| `transitions[].axes[].axis` | string | Axis name, e.g. `"binding"`, `"action"`, `"resource"`, `"principal"`, `"condition"`, `"fetch"` |
| `transitions[].axes[].from` | string\|null | Rank at base; `null` when the property was absent at base |
| `transitions[].axes[].to` | string\|null | Rank at head; `null` when the property is absent at head |
| `transitions[].axes[].order` | string | `"equal"`, `"greater"` (head more dangerous), `"less"`, or `"unknown"`. **Pre-inversion** — for `iam.deny`, `order:"greater"` corresponds to `danger:"decreased"`. |
| `transitions[].from` | string\|null | Convenience mirror of `axes[0].from` when there is exactly one axis; `null` for multi-axis kinds |
| `transitions[].to` | string\|null | Convenience mirror of `axes[0].to` when there is exactly one axis; `null` for multi-axis kinds |
| `transitions[].confidence` | string | Always `"certain"` in schema version 1. Reserved for a future `"probable"` tier. |
| `transitions[].base_evidence` | object\|null | `{file, line}` on the base side; `null` when absent at base |
| `transitions[].head_evidence` | object\|null | `{file, line}` on the head side; `null` when absent at head |
| `transitions[].attrs` | object | Descriptive key/value pairs for rendering. **Not part of identity and never compared.** ASCII keys; values are string, integer, boolean, or null — never floats. |
| `transitions[].paired` | boolean | `true` when the two sides were matched by unique-residual pairing rather than by `key` equality. A `true` here means the identity match is inferred, not proven. |

**`coverage` field reference:**

| Field | Type | Description |
|-------|------|-------------|
| `coverage.analyzed` | number | Count of (file, side) pairs fully parsed |
| `coverage.degraded` | boolean | `true` when at least one candidate file failed to analyze on either side. When true, some `added`/`removed` transitions were forced to `danger:"unknown"` because absence could not be proven. |
| `coverage.inconclusive` | boolean | `true` when at least one **changed** candidate file failed to analyze. Drives exit code 4. |
| `coverage.unanalyzed[].file` | string | Repo-relative path |
| `coverage.unanalyzed[].side` | string | `"base"` or `"head"` |
| `coverage.unanalyzed[].reason` | string | `"parse_error"`, `"unsupported_syntax"`, `"too_large"`, `"too_many_candidates"`, `"binary"`, `"symlink"`, `"timeout"` |
| `coverage.unanalyzed[].detail` | string | Short human explanation. Never contains file content. |
| `coverage.unanalyzed[].changed` | boolean | `true` when this file differs between base and head. A `true` here is the author's to fix; a `false` is pre-existing and never gates. |

**"Analyzed and found nothing" versus "could not analyze" are distinct and must not be conflated.** An empty `transitions` array with `coverage.degraded: false` means the analyzed surface is unchanged. An empty `transitions` array with `coverage.inconclusive: true` means part of the answer is missing on a file this change touched — and the process exits 4.

Exit codes: 0 = no reportable danger increase, 1 = reportable danger increase found, 2 = runtime error, 3 = base ref unresolvable, 4 = inconclusive. Precedence 3 > 2 > 4 > 1 > 0.
````

### 9.2 Human-readable output

Danger increased:

```
Attack surface: 2 properties became more dangerous, 1 is ambiguous  (origin/main → working tree)

  high      redis 6379 published on 0.0.0.0        infra/docker-compose.yml:15   new
  high      IAM AppBucketAccess resource → *       infra/policy.json:18          prefix-wildcard → global-wildcard
  medium    IAM statement 2: action narrowed,      infra/policy.json:31          incomparable — review by hand
            resource widened

  1 property became safer                          (--include-decreased)
  1 file could not be analyzed                     (--explain)
```

Clean (stdout, one line):

```
Attack surface unchanged  (origin/main → working tree)
```

Degraded-clean — never let this masquerade as clean:

```
Attack surface: no change detected, but 3 files could not be analyzed  (--explain)
```

Inconclusive (exit 4):

```
Attack surface: INCONCLUSIVE — 1 file changed in this diff could not be analyzed.

  infra/docker-compose.yml   service 'web' uses `extends` (cross-file; unsupported)

This is not a clean result. Fix the file, or pass --on-inconclusive warn to
downgrade this to a warning.
```

Base unreachable (stderr, exit 3):

```
Cannot resolve base ref 'origin/main' — this is a shallow clone.
actions/checkout defaults to fetch-depth: 1. Fix with either:
    - uses: actions/checkout@v4
      with: { fetch-depth: 0 }
    - run: git fetch --no-tags --depth=1 origin main
Or run with --fetch-base to fetch it now.
```

**Rendering rules.** Max 10 lines, then `+K more (--json)`. The global `-a/--agent` flag drops color and emoji (already a global option, `shared-docs/CLI_SPEC.md:62`). Result lines go to **stdout**; all status and progress to **stderr**. `--min-severity` filters display only, never the exit code.

---

## 10. Implementation plan

Every unit touches **both** runtimes. That is non-negotiable per `CLAUDE.md` ("Every feature exists in both Node and Python"), and splitting a unit by language is the fastest way to produce divergence.

### Wave 0 — serialized, blocks everything

**W1 · Semantic fixtures first, then the model.**

This unit is deliberately ordered fixtures-before-types, adopting the reviewer's closing recommendation. Writing the paired Compose and IAM cases first is what proves the two-axis model and the lattice comparator before any interface is frozen.

- Files: `fixtures/surface/cases/` — **8 hand-authored paired cases** with hand-written `expected.json`: compose port appears; compose port narrowed to loopback; compose service renamed (must be `unchanged`); IAM resource widened with `Sid`; IAM resource widened without `Sid`; IAM incomparable (action narrows, resource widens); IAM `Deny` removed; IAM `Condition` removed. Plus `fixtures/surface/kind-specs.json` and `fixtures/surface/yaml-divergence.yml`.
- Files: `node/src/core/surface/{model.ts,kind-specs.ts,compare.ts,differ.ts,serialize.ts}`, `python/rafter_cli/core/surface/{model.py,kind_specs.py,compare.py,differ.py,serialize.py}`.
- Tests: `node/tests/surface-differ.test.ts`, `python/tests/test_surface_differ.py` — pure unit tests over synthetic `Property` lists, no I/O: unchanged properties emit nothing; duplicate keys within one side abort the file rather than merging; `absentRank:"above"` inverts absence; `invertDanger` flips `iam.deny`; `severityByLevel: null` yields a non-reportable transition; lattice returns `incomparable` on mixed axes and `unknown` on any unknown axis; residual pairing fires only on a 1:1 residual; coverage-blocked `added` → `unknown`; deterministic UTF-8-byte sort.
- Tests: the invariant test that `keyComponents(kind) ∩ axisNames(kind) = ∅` for every kind.
- Tests: kind-spec equality against `fixtures/surface/kind-specs.json` in both runtimes.

**Human review gate:** the eight `expected.json` files must be reviewed by a person before Wave 1 begins. They are the correctness oracle and nothing regenerates them.

### Wave 1 — parallel after W1 merges

**W2 · Git plumbing (`BaseTreeReader`).**
- Files: `node/src/utils/git-tree.ts`, `python/rafter_cli/utils/git_tree.py`.
- Tests: `node/tests/git-tree.test.ts`, `python/tests/test_git_tree.py` — real `mkdtemp` git repos. `resolveRef` uses `--end-of-options`; `--base=--upload-pack=/bin/false` and `--base=-i` are rejected at the CLI boundary with exit 2 and no git subprocess; `listWorkTree` includes untracked files via `--others --exclude-standard`; `-z` parsing survives a filename containing a newline and a tab; a symlink candidate yields `Unanalyzed{reason:"symlink"}` and is never followed; a root commit yields the empty-tree OID rather than an error; `isShallow()` is true on a `--depth=1` clone; a 2 MiB candidate yields `too_large`; argv-array invocation only, never `node/src/utils/git.ts`.

**W3 · Shared YAML adapter.**
- Files: `node/src/core/surface/yaml-safe.ts`, `python/rafter_cli/core/surface/yaml_safe.py` (including `RafterBaseLoader`), plus the shared `parseScalar`.
- Tests: `node/tests/surface-yaml.test.ts`, `python/tests/test_surface_yaml.py` — both runtimes load `fixtures/surface/yaml-divergence.yml` string-only and match a hand-written expectation byte for byte; a duplicate key raises in both; empty node normalizes to `""` in both; a `<<` key surfaces as a literal `"<<"` in both; anchors/aliases resolve identically.

**W4 · CLI shell, renderers, exit codes.**
- Files: `node/src/commands/surface/{index.ts,diff.ts,render.ts}` + registration in `node/src/index.ts`; `python/rafter_cli/commands/surface.py` + `add_typer` in `python/rafter_cli/__main__.py`.
- Tests: `node/tests/surface-cli.test.ts`, `python/tests/test_surface_cli.py` — the full 0/1/2/3/4 matrix and the 3 > 2 > 4 > 1 > 0 precedence; `--fail-on none` forces 0 and downgrades 4; exit 3 is unaffected by `--fail-on none`; `--on-inconclusive warn`; stdout is valid JSON under `--json` with all status on stderr; `--quiet`; degraded-clean text is visibly different from clean text; inconclusive text is visibly different from both.
- Runs against a stub extractor registry; does not wait on Wave 2.

**W5 · Documentation.**
- Files: `shared-docs/CLI_SPEC.md` (a `### rafter surface diff` section plus an `### Attack-Surface Diff` block under `## Exit Codes`), `CLAUDE.md` architecture tree, `README.md`, `shared-docs/DOCS_SYNC_CHECKLIST.md`.
- Tests: the existing docs-sync check, plus an assertion that every `kind` in `KIND_SPECS` and every `UnanalyzedReason` value appears in `CLI_SPEC.md`.

### Wave 2 — parallel after W1; W3 gates only W6

Each unit adds `node/src/core/surface/extractors/<name>.ts` + the Python mirror, registers in the registry array, and ships its metamorphic and seeded suites (§5 R2 M1–M5) in both runtimes.

**W6 · `container.port` (Compose).** Depends on W3.
- Tests: M1 no-op suite including reindent, key reorder, service rename, file rename, and file split; M2 one-axis widenings for each `binding` rank; `extends` / `include` / `<<` / `${…}` / port range each produce the right `Unanalyzed` reason; the abstention ceiling holds.

**W7 · `iam.allow` / `iam.deny`.**
- Tests: the flagship transition is emitted as a single `modified`/`increased` on the `resource` axis with the key intact; a policy with **no `Sid`** works; the reviewer's `s3:* on bucket → s3:GetObject on *` case yields `incomparable`; a new `Deny *` yields `danger:"decreased"`; a removed `Deny` yields `danger:"increased"`; a removed `Condition` yields `increased` on the `condition` axis; differing conditions yield `unknown`; `NotAction`/`NotResource`/policy variables yield `unsupported_syntax`; two-removals-two-additions in one document produce four unpaired transitions, not two guesses; stage-1/stage-2 candidate filtering does not flag ordinary `*.json`.

**W8 · `pkg.lifecycle_script`.**
- Tests: each `fetch` rank; `curl … | sh` in a `postinstall` is `critical`; a purely local script is a `severity: null` transition; workspace monorepo manifests are distinct keys; `npm run`-indirection is `unsupported_syntax`.

### Wave 3 — after Wave 2

**W9 · Parity, corpus, and noise gates.**
- Extend `node/tests/cross-runtime-parity.test.ts` with a `parity: surface diff` block over `fixtures/surface/cases/`, asserting byte-identical canonical `--json` stdout and identical exit codes; add the `"from"`/`"to"` wire-name assertion; add `RAFTER_PARITY_REQUIRED=1` handling and set it in `.github/workflows/test-comprehensive.yml`.
- Add both suites' assertions against the hand-authored `expected.json`.
- Add `fixtures/surface-history/` and its generator script, plus the R5 noise gate (marked slow).
- Add the §2.4 lint test (no severity or danger literals under `extractors/`) and the §8.4 ASCII-attrs-key test.

**W10 · CI and Action integration.**
- `action.yml`: a new `surface-base` input and a narrow `git fetch --no-tags --depth=1 origin <base>` step before the scan step; a `surface` step and outputs.
- `node/src/commands/ci/init.ts` (+ Python mirror): `fetch-depth: 0` on the generated surface job.
- `github-action/`, `recipes/`.
- Tests: `node/tests/ci-init.test.ts` / `python/tests/test_ci.py` assert the emitted workflow contains `fetch-depth: 0`; `node/tests/github-action.test.ts` asserts the fetch step precedes the scan step.
- `publish.yaml`: the §8.2 post-install smoke case for both artifacts.

**W11 · Release.** Version bump in `node/package.json` and `python/pyproject.toml` (both currently `0.10.0`; `python/tests/test_e2e_cli.py:335` already enforces that they match), `CHANGELOG.md`.

### Concurrency

```
W1  ────────────────────────────────────►  (blocks all; human review gate on fixtures)
      ├── W2 ─┐
      ├── W3 ─┼── W6
      ├── W4  │
      ├── W5  │
      ├── W7 ─┤
      └── W8 ─┘
                       └── W9, W10 ──►  W11
```

W1 is the only true bottleneck. It is larger than v1's W1 because the fixtures come first, and that is the point — the reviewer's closing line ("W1 is not safe to build; start with paired Compose/IAM semantic fixtures") is correct and is adopted as the unit's ordering constraint.

---

## 11. Residual risks I am knowingly accepting

1. **The noise corpus is author-chosen.** `fixtures/surface-history/` measures regression, not real-world precision. A held-out corpus from repositories with genuine infrastructure history is the right answer and is not in v1. If the tool is noisy on real repos, this will not catch it before users do. **Mitigation:** ship behind `--fail-on none` in the recommended CI recipe for one release, gather reports, then flip the default.
2. **Exit 4 will fire on some legitimate PRs.** Compose files using `extends` or anchors, or IAM policies using `NotAction`, will produce inconclusive results on PRs that touch them. This is the deliberate false-positive-over-false-negative trade. **Mitigation:** the message names the exact construct; `--on-inconclusive warn` is one flag.
3. **Residual pairing can pair the wrong two things.** In a commit that removes service `a` and adds unrelated service `b` in the same file, they will be paired. The bounded consequence (§3.4) is a `modified` transition instead of an add/remove pair, with the same danger verdict — it cannot fabricate a widening. But the *label* will be misleading. `paired: true` is on the wire so consumers can discount it.
4. **Full-tree candidate scanning is slower than diff scoping**, and the IAM stage-1 filter could still match thousands of files in a JSON-heavy repo. The 2000-candidate and 20-second budgets convert that into `too_many_candidates` / `timeout` — which, on a changed file, is exit 4. A pathological repo could see systematic inconclusives. **Mitigation:** the budgets are constants in the kind-spec module, tunable without a schema change; `git cat-file --batch` keeps the constant factor low.
5. **Condition comparison is present/absent only.** A condition changed from `aws:SourceIp: 10.0.0.0/8` to `0.0.0.0/0` is a real widening reported as `unknown`, not `increased`. This is a **known false negative**, chosen because a wrong condition comparison is worse than an honest abstention. It is the top v1.1 item for E2.
6. **`git ls-tree` on a huge base tree** is one process but a large buffer. Repos with hundreds of thousands of files will allocate tens of MB. Acceptable; not streamed in v1.
7. **The two runtimes' JSON parsers are not compared.** §8.1 solves YAML; JSON is assumed equivalent. Duplicate keys in a JSON document behave as last-wins in both, and depth limits are enforced by Rafter rather than the parser. Large-integer and Unicode handling is covered by §8.4. Residual: deeply pathological JSON (very long numbers, `\uD800` escapes) is only covered by the corpus, not by an exhaustive differential test.
8. **`fixtures/` at the repo root is a new pattern**, shipped by neither package and currently referenced by no test. The in-checkout parity test reaches it via `../fixtures`. If either package ever gains a test-in-wheel requirement, this needs revisiting.
9. **Three extractors may be too few to demo.** The IAM line and the Compose line are strong; `pkg.lifecycle_script` is a bonus. If the demo needs a fourth, the cheapest addition is declarative-only security headers (`vercel.json` / `netlify.toml` / nginx `add_header`) — genuinely declarative, unlike `helmet()` and `next.config.js`.

---

## 12. Changelog from v1

Legend: **[C]** the critique drove it · **[M]** I drove it · **[R]** I rejected the critique's position.

### Model and transitions

| # | Change | Src | Note |
|---|---|---|---|
| 1 | `Direction` enum replaced by two axes, `change` (added/removed/modified) and `danger` (increased/decreased/unchanged/incomparable/unknown). Severity attaches only to `increased` and `incomparable`. | **[C]** | The critique's #2 was a genuine bug: v1's own algorithm emitted `appeared` with `from:"strict", to:null`. Designed rather than renamed — `change` is now purely structural with no exceptions. |
| 2 | Total-order `levels` replaced by a comparator interface returning `equal/greater/less/incomparable/unknown`, with two families (`ordinal`, `lattice`). | **[C]** | Critique #1. v1's *unification* instinct survives on argument — one differ, one severity table, extractors cannot express danger — but its *totality* assumption is gone. |
| 3 | `polarity: "exposure"\|"protection"` replaced by per-axis `absentRank` plus a per-kind `invertDanger`. | **[C]** | The polarity index trick is what produced the contradiction in #1. `invertDanger` is what makes `iam.deny` correct. |
| 4 | `severity: "incomparable"` is **reported**, not suppressed. | **[M]** | The critique said report `incomparable` rather than inventing a direction; it did not say give it a severity. A CI gate that stays silent on "one axis widened and one narrowed" has a false negative where a human is needed most. |
| 5 | Duplicate keys within one side abort the file rather than merging to max level. | **[C]** | Critique #3's closing point: max-merge can *hide* a widening. Fails loud. |
| 6 | `axes[]` always present and authoritative; `from`/`to` are single-axis convenience mirrors. | **[M]** | Needed once lattice kinds exist; keeps one code path in the renderer. |
| 7 | `confidence` retained with the single value `"certain"`; the `"probable"` tier is cut. | **[M]** | v1 shipped `probable` invisible-by-default, which bought nothing. Keeping the field avoids a `schema_version` bump later. |
| 8 | `attrs` still descriptive, never diffed; still no floats. | *(survives)* | Not attacked. A "attrs changed" transition class would be an infinite noise source. |

### Identity

| # | Change | Src | Note |
|---|---|---|---|
| 9 | Identity is per-extractor and domain-specific; the four generic rules are now *invariants* checked per extractor rather than a one-size key recipe. | **[C]** | Critique #3. |
| 10 | New invariant: **no key component may also be a compared axis**, machine-checked. | **[M]** | This is the general form of the bug behind v1's impossible flagship demo. The critique found the symptom; this is the rule that prevents the class. |
| 11 | Unique-residual pairing within a `pairingScope`, with `paired: true` on the wire. | **[C]** | The critique's "conservative semantic matching only when unique." Argued in §3.4 that it cannot fabricate or hide a finding. |
| 12 | Compose keys include the real repo-relative path; v1's three-bucket "file class" is gone. | **[C]** | Critique's file-class-rename example. Rename cost paid by residual pairing. |
| 13 | IAM identity uses `Sid` when present, otherwise `(path, Effect, Action set, Principal)` — **not** a required `Sid`. | **[R]** | The critique wanted `Sid` required or matching marked ambiguous. I verified `Sid` is optional and that `AmazonS3FullAccess` — the canonical S3 policy — has none. Requiring it silently disables the extractor on the modal real policy. |
| 14 | Metamorphic no-op tests (rename, reorder, move, split, merge) are mandatory per extractor before it ships. | **[C]** | Adopted as stated. |

### Reading the trees

| # | Change | Src | Note |
|---|---|---|---|
| 15 | Changed-files-only extraction dropped as a correctness mechanism; **all candidates read on both sides**. `contextGlobs` deleted from the model. | **[C]** | Critique #4. I verified the Compose `extends` semantics against Docker's own reference: cross-file, ports merged, referenced service need not be in the project. Cost stated in §4.1. |
| 16 | v1 extractors additionally restricted to file-local syntax; `extends`/`include`/`<<` are `unsupported_syntax`. | **[C]** | Both of the critique's alternatives taken, because they are complementary. |
| 17 | Ref resolution uses `--end-of-options` and resolves to OIDs before any other command. | **[C]** | Critique #6. Verified `--end-of-options` is supported at git 2.43. |
| 18 | Working-tree enumeration uses `git ls-files --cached --others --exclude-standard -z`. | **[C]** | The untracked-file omission was a real, exploitable gap. |
| 19 | `-z` everywhere; symlink containment via `lstat` and tree mode `120000`; per-file byte, nesting, count, and wall-clock limits. | **[C]** | All accepted. |
| 20 | Injection regression test rewritten to go through `--base`, not a branch name. | **[C]** | The critique correctly noted git will not create a branch named `--upload-pack=evil`. |
| 21 | Proven root/unborn base uses the empty tree OID `4b825dc6…` and is not an error. | **[C]** | Critique #7. |
| 22 | "Never invent an empty base" retained; "always exit nonzero" dropped. | **[C]/[M]** | The critique wanted the split; I keep exit 3 unconditional (including under `--fail-on none`) because no comparison happened, and a report-only mode must not report "clean." |
| 23 | `action.yml` gains its own narrow `git fetch --depth=1` step before invoking rafter. | **[M]** | v1 proposed adding `fetch-depth` to a checkout the composite action does not own — impossible, confirmed. The critique said "let the wrapper fetch" without saying where; this is the concrete placement. |
| 24 | `--fetch-base` stays opt-in and default-off. | **[R]** | The critique implied more automatic recovery. `CLI_SPEC.md:7` commits to no network by default; I will not break that from a security tool. The Action step (#23) is where the network lives. |
| 25 | No snapshot store; `rafter agent baseline` untouched. | *(survives)* | Endorsed by the critique; the argument in §4.6 stands on its own. |

### FP posture and testing

| # | Change | Src | Note |
|---|---|---|---|
| 26 | Exit code **4 = inconclusive**, fired by an unanalyzable **changed** candidate file. | **[C]/[M]** | The attacker-controlled fail-open was real. My refinement: restricted to *changed* files, so one gnarly legacy file cannot block a repo forever. |
| 27 | "0 FP on 20 negatives / 0.90 recall" dropped. | **[C]** | Rule of three; author-chosen negatives; single-file corpora cannot measure mispairing. |
| 28 | Replaced by M1–M5: metamorphic no-ops, seeded one-axis widenings, seeded incomparables, an abstention ceiling, idempotence/symmetry — all over **paired trees**. | **[C]/[M]** | The critique asked for paired corpora and an abstention cap; M4 and M5 are mine. |
| 29 | The "hundreds of reviewed no-ops / held-out real-repo corpus / published precision intervals" program is named **aspirational**, not v1-blocking. | **[M]** | Good practice, but it is a quarter of work, and saying so keeps the plan shippable. Listed as residual risk #1. |
| 30 | R3's 25-commit replay over this repo dropped; replaced by a generated `fixtures/surface-history/` with real infra history, plus an explicit honesty caveat. | **[C]** | The critique was right that the original gate was vacuous: `fixtures/vulnerable-repo/infra/docker-compose.yml` is one static file with one published port. |
| 31 | R4's asymmetric-unanalyzability suppression retained verbatim. | *(survives)* | Not attacked, and it is the rule that stops a base-side parse error becoming "+7 newly exposed ports." |

### Parity

| # | Change | Src | Note |
|---|---|---|---|
| 32 | **The YAML rule.** Never use either parser's scalar resolution. js-yaml `FAILSAFE_SCHEMA` + PyYAML `BaseLoader` with a duplicate-key-rejecting constructor; Rafter's own `parseScalar` does all typing; empty node normalizes to `""`. | **[M]** | v1's "hand-roll a reader to avoid a dependency" was dead on arrival — both runtimes already have parsers. The real risk is 1.1-vs-1.2 divergence; I measured five classes in a 12-line file (`yes`→bool, `017`→15 vs 17, `08`, `1_000`, duplicate keys throw vs silent) and verified that the string-only configuration produces byte-identical output. |
| 33 | Node-owned golden regeneration **dropped**. `expected.json` is hand-authored and never regenerated by either runtime. | **[C]** | The critique's "generated golden data proves agreement, not correctness" was its best parity point. |
| 34 | Agreement is tested by extending the **existing** `node/tests/cross-runtime-parity.test.ts`, not by a new root-level one-way golden scheme. | **[R]/[M]** | The critique proposed building both packages and installing them into clean environments. Comparing two live implementations on identical input needs **no oracle at all** — which is a stronger answer to the critique's own objection than the critique's answer — at a fraction of the cost, using a mechanism the repo already has. |
| 35 | The parity test's silent skip is closed via `RAFTER_PARITY_REQUIRED=1` in CI. | **[M]** | Real hole: a broken Python side currently passes CI invisibly. |
| 36 | One post-install smoke case per published artifact in `publish.yaml`. | **[C]** *(partial)* | Accepts the packaging point at bounded cost; rejects the full installed-artifact corpus. |
| 37 | Canonical JSON fully specified: NFC normalization, lone-surrogate replacement, ASCII-only object keys, UTF-8 byte-order array sorting, ±2^53−1 integer bound. | **[C]** | The critique was right that "no floats" was not sufficient. |

### Scope

| # | Change | Src | Note |
|---|---|---|---|
| 38 | Five extractors → three: Compose ports, IAM JSON, npm lifecycle scripts. | **[C]** *(partial)* | Critique #9's scope diagnosis accepted; its two-extractor cut rejected. |
| 39 | Dockerfile `EXPOSE` cut. | **[C]** | Factually right: image metadata, publishes nothing. |
| 40 | Kubernetes cut from E1. | **[C]** | Inherently cross-document. Deferred with the key specified: `(namespace, kind, name, port, protocol)`. |
| 41 | CSP / security headers cut. | **[C]** | `helmet()` and `next.config.js` are executable JS; claiming `certain` over them is false. |
| 42 | `net.egress` + vendor catalog cut whole. | **[C]** | Six unrelated grammars, plus `uses:` was misclassified as runtime egress. |
| 43 | `dep.added` cut. | **[M]** | Fires on nearly every dependency PR; `rafter run` already does SCA; the median-empty-report target is worth more. |
| 44 | `pkg.lifecycle_script` **kept** against the critique's cut, with levels rebuilt as `local < fetches-remote < pipes-remote-to-interpreter`. | **[R]/[C]** | Kept on cost: pure JSON, no grammar risk, ~1 day, the only supply-chain line in v1. But the critique's specific correction is accepted in full — npm runs every lifecycle script through a shell, so v1's `local-only` vs `network-or-shell` was incoherent. |
| 45 | `iam.deny` **kept** against the critique's cut. | **[R]** | Cutting Deny does not fix "new `Deny *` scores critical" — it means a PR that *deletes* a `Deny "*"` produces silence from a security gate. `invertDanger` is one boolean in a table. |
| 46 | IAM `Condition` becomes a fourth lattice axis. | **[C]** | Removing a `Condition` was a widening v1 could not see at all. |
| 47 | Terraform HCL still out of v1. | *(survives)* | Neither runtime has an HCL parser; hand-mirroring one is its own project. JSON-only is a defensible slice and it delivers the flagship line. |
| 48 | Citation corrections: `python/rafter_cli/core/risk_rules.py:478` is `assess_command_risk`, not a severity declaration (severity literals are around :485). v1's `Property.level` was typed `string` while its comment permitted `null` — the v2 type is `Record<string, string|null>`. | **[C]** | Both accepted. |

---

### Critical Files for Implementation

- `shared-docs/CLI_SPEC.md` — the exit-code tables and the JSON-documentation format §9.1 must match
- `node/tests/cross-runtime-parity.test.ts` — the parity mechanism v2 extends rather than replaces (§8.2)
- `node/src/index.ts` and `python/rafter_cli/__main__.py` — command registration for the new `surface` group
- `node/src/commands/agent/scan.ts` — the argv-array git invocation pattern W2 hardens (and `node/src/utils/git.ts:3`, the interpolating `execSync` helper that must **not** be used)
- `node/src/core/risk-rules.ts` — the `CommandRiskLevel` vocabulary §2.3 refuses to widen
- `action.yml` — the composite action that gains the narrow base-fetch step (§4.4)