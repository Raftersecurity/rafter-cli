# Closing the `rm` long-flag evasion (sable-urvj)

**Status:** prototype on `fix/rm-long-flag-evasion-sable-urvj`, held for Rome's merge gate.
**Severity:** P1 — a hard-block bypass in shipped behavior (v0.10.0 and earlier).
**Scope:** both implementations. Node and Python land together.

## The gap

`CRITICAL_PATTERNS` and `HIGH_PATTERNS` spell rm's flags only the short way —
`-[a-z]*r[a-z]*`, `-[a-z]*f[a-z]*`. GNU rm accepts long spellings that mean
exactly the same thing, and every one of them walked past the rules:

| command | assessed before | should be |
| --- | --- | --- |
| `rm --recursive --force /` | low | critical |
| `rm --recursive --force /etc` | low | critical |
| `rm --recursive --force --no-preserve-root /` | low | critical |
| `rm --recursive=yes -f /` | low | critical |
| `rm -rf --no-preserve-root /` | low | critical |

The inversion in the third and fifth rows is what makes this worth a P1 rather
than a tidy-up. Modern coreutils *refuses* `rm -rf /` unless
`--no-preserve-root` is also given. So the short form the rules did catch is the
form the operating system already declines to run, and the forms that actually
wipe root — the long spellings, and any spelling carrying `--no-preserve-root` —
were precisely the ones rafter rated `low` and allowed without a prompt.

Two distinct defects hide in that table:

1. **Spelling.** Long and `--flag=value` forms are not in the pattern alphabet.
2. **Adjacency.** The critical patterns anchor the path immediately after the
   flag they match, so *any* intervening flag breaks the match. `rm -rf
   --no-preserve-root /` fails on this count alone, with no long flag involved.

A pattern-table fix has to solve both, which is where the combinatorics get ugly.

## Approach: canonicalize, don't multiply

The rejected option is to widen the patterns — add `(--recursive|-[a-z]*r[a-z]*)`
alternations, tolerate interleaved flags with `.*`, and repeat that across the
four rm rules. That path is bad in three ways. It multiplies the table by every
spelling and interleaving; the `.*` needed for adjacency spans chain operators,
so `rm -r dir && cp -rf a b` starts matching the critical rule; and the next
alias (`--dir`, a future long form) re-opens the same hole.

Instead, one normalization pass runs on the sanitized command before matching,
rewriting each `rm` invocation's flag run to a single canonical short cluster:

```
rm --recursive --force /              ->  rm -rf /
rm --recursive=yes -f /               ->  rm -rf /
rm -r --force --no-preserve-root /    ->  rm -rf /
rm --recursive /tmp                   ->  rm -r /tmp
```

Collapsing the run closes the adjacency defect for free — the path lands
immediately after the canonical cluster, which is what the existing patterns
already expect. **The pattern table is unchanged.** Every existing rule, and
every rule anyone adds later, gets long-flag coverage without knowing this
transformation exists.

### Where it sits

```
raw command
  -> sanitize_command_for_matching   (existing: quoted data redacted, eval'd text kept)
  -> normalize_rm_flags              (new)
  -> CRITICAL / HIGH / MEDIUM patterns
```

Running *after* the sanitizer matters: `git commit -m "never rm --recursive
--force /"` has already had its quoted argument redacted to data by then, so the
normalizer never sees it and prose cannot be canonicalized into a live command.

Node: `normalizeRmFlags` in `node/src/core/risk-rules.ts`, reached through a
`matchTarget()` helper shared by `assessCommandRisk` and `matchedCriticalPattern`.
Python: `normalize_rm_flags` in `python/rafter_cli/core/risk_rules.py`, via
`_match_target()`, shared by `assess_command_risk` and `match_critical_pattern`.
Line-for-line mirrors.

### Scanning rules

Starting just past an `rm` command word (line start or after `; & | (`), consume
consecutive flag tokens. A token ends at whitespace or any of `; & | )`, so a
run can never cross a chain operator into the next command. The run stops at the
first operand or at `--`. A token is read as recursive if it matches
`^--recursive(=|$)`, as force if `^--force(=|$)`, and short clusters
(`^-[a-z]+$`) contribute `r` and `f` by letter.

Only a run carrying a recursive or force flag is rewritten; anything else is
returned byte for byte. `rm -i -v notes.txt` is untouched, and so is every
non-rm command in the string.

Two deliberate readings, both erring toward blocking:

- **`--recursive=yes` counts as recursive.** GNU rm's long options take no
  argument, so this is in truth a usage error the shell would reject. Reading it
  as recursive costs nothing (the command was never going to run) and denies an
  attacker a spelling that looked like a miss.
- **Unknown flags don't stop the run.** `--no-preserve-root` neither sets a bit
  nor terminates scanning; it is simply skipped. That is what makes the
  wipes-root-for-real form collapse to `rm -rf /`.

## Tests

`node/tests/risk-rules-rm-long-flags.test.ts` and
`python/tests/test_risk_rules_rm_long_flags.py` — same 15 cases each, in three
groups:

- **Coverage.** All-long, both orders, mixed short/long, `=value`, the
  `--no-preserve-root` pair, behind `sudo`, and through `&&` / `;` chains.
  Non-critical paths still rate `high`, not `critical`.
- **No false positives.** `rm -i -v notes.txt` and `rm --interactive` stay `low`;
  `rm -- --weird-file` treats the operand as an operand; `rm -r dir && cp -r a b`
  stays `high` rather than being pulled into the critical rule by a run that
  swallowed the chain; `git commit -m "…rm --recursive --force /"` and
  `echo "…" > notes.txt` stay `low`; `npm run format` and `chmod --recursive 755`
  are not touched by a matcher looking for the letters `rm`.
- **Unit.** `normalizeRmFlags` / `normalize_rm_flags` directly, including
  identity on inputs with nothing to canonicalize and every `rm` in a chain.

Both suites pass, alongside the existing risk-rules, interceptor, hook, and
policy tests (Node 332 related + full suite; Python 1590).

Two pre-existing failures are unrelated to this change and reproduce on a clean
`HEAD` (verified by stashing): `cross-runtime-parity` "both report the same
semver" and `test_e2e_cli` "version matches pyproject", both caused by stale
installed `rafter-cli` dist metadata reporting 0.9.0 against a 0.10.0 source
tree, plus `agent-commands` "surfaces a legacy gitleaks install". Tracked
separately; CI installs fresh and does not hit them.

## Differential

This is a change to a *detector*, where a false negative is silent and a false
positive is loud — so green tests are not evidence. Both detector versions were
run over the same corpus and every divergence enumerated: ~7,600 commands, being
every string literal harvested from `node/tests`, `node/src`, `python/tests`,
`python/rafter_cli/core`, plus a generated matrix of 25 flag spellings × 15 paths
× 7 prefixes (`sudo`, `bash -c "`, `&&`, `;`, subshell, env assignment) and `&&`
/ `;` suffixes.

**Lowered: 0.** No command is assessed less severely than before — there are no
lost detections. Every divergence raises risk, and each raise is a spelling of
`rm` carrying both a recursive and a force flag that the old rules missed
(`low -> high`, `low -> critical`) or a flag run the old rules couldn't span
(`high -> critical` for `rm -rf --no-preserve-root /…`).

## Found while reviewing: a second, independent bypass (sable-5adm)

The differential surfaced a defect this change does **not** fix and does not
touch. The critical rm patterns terminate the path with `(\s|$)`, and a chain
operator is in neither set — so one appended character downgrades an
unconditional hard-block to `high`, a tier policy and mode *can* opt out of:

```
rm -rf /             -> critical
rm -rf /;            -> high      <-- same command, still runs
rm -rf /; echo done  -> high
rm -rf /|cat         -> high
rm -rf /etc;         -> high
```

Pre-existing on main in both implementations, reproducible with plain short flags
and no normalizer involved. Filed as **sable-5adm** (P1) with repros and a fix
direction (widen the terminator to the same `[\s;&|)]` token-end class this
normalizer already uses, then audit the rest of the table for it). Deliberately
left out of this branch so the merge gate here stays scoped to one fix.

## Open question for the merge gate

`CommandInterceptor._matches` — the path for **user-authored** `.rafter.yml`
policy patterns — deliberately still matches against the sanitized-but-not-
normalized command, in both implementations.

The argument for normalizing there too: a user's `deny: "rm -rf /"` is evaded by
`rm --recursive --force /` exactly as the built-in rules were. The argument
against: a user who writes `deny: "rm --recursive"` would find their own rule
silently dead, because the target string no longer contains that spelling.

Built-in patterns are ours to keep in sync with the normalizer; user patterns are
not. Making user rules stricter without warning is a smaller harm than making
them stop working, so the honest fix is probably normalize *and* validate
policy patterns against the same canonicalization at load time, warning when a
pattern can no longer match anything. That is a larger change than this bug
needs, so it is left out and flagged rather than half-done.

## Not addressed

The same spelling gap plausibly exists for other flag-bearing rules in the table
(`chmod`, `dd`, `git` subcommands). This change deliberately fixes `rm` only —
the one with a confirmed hard-block bypass — rather than speculatively
generalizing. A sweep of the remaining rules for long-flag equivalents is worth
its own bead.
