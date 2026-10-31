# Changelog / Update Review

You trusted v1.2 last month. v1.3 came out. Most of your past trust is stale — you need to re-verify what changed, not re-verify everything. This doc is the diff-focused companion to the other sub-docs.

## 1. Produce the diff

For a local copy:
```bash
# If you have the old version installed and the new version in a directory:
diff -ru ~/.claude/skills/<name>/ /path/to/new-version/ > /tmp/skill.diff
```

For a git-published skill:
```bash
git -C /tmp/<skill>-old log --oneline
git -C /tmp/<skill>-old diff <old-tag>..<new-tag> > /tmp/skill.diff
```

Skim top-to-bottom once. Then walk the sections below.

## 2. What must be re-reviewed on every update

These categories always need a fresh walk on the new version:

1. **`allowed-tools` changes** — widening by even one tool resets trust. Narrowing is fine.
2. **New outbound URLs** — each one demands §3 of `docs/data-practices.md`.
3. **New shell invocations** — walk `docs/malware-indicators.md` §2.
4. **New filesystem writes or reads outside the previous set**.
5. **New `WebFetch` / live-remote dependencies**.
6. **New env vars read**.

Use:
```bash
grep -E '^\+' /tmp/skill.diff | grep -E 'allowed-tools|https?://|curl|wget|Bash|WebFetch|writeFile|process\.env|os\.environ'
```

## 3. Version semantics

- **Patch bumps (x.y.Z)**: should be bugfixes + docs. A patch bump with new tools / URLs is a provenance red flag — the maintainer is either careless or pretending.
- **Minor bumps (x.Y.z)**: new feature work. Expect new code surface; re-walk the relevant sub-doc.
- **Major bumps (X.y.z)**: re-evaluate from scratch — treat the new version as a new skill. Walk branch (a) of the main SKILL.md.

If the skill has no versioning or a single rolling `latest` tag, it's effectively a major bump every time. Do not auto-update.

## 4. Maintainer transfer / republish

The single highest-risk update pattern:

- Original maintainer transfers ownership (`npm owner add/rm`, GitHub transfer, PyPI project transfer).
- A dormant package springs back to life with a large version bump.
- Package is unpublished then republished (sometimes with a version hole filled in).

On any of these: treat as a new install. Re-walk `docs/authorship-provenance.md` from scratch. Do NOT reuse old trust.

## 5. Silent changes to trust-adjacent files

A changelog may claim "docs only" while the actual diff includes:
- New entries in `scripts.postinstall` / `setup.py` install hook.
- New entries in `.claude/settings.json` if the skill distributes one.
- New entries in `.rafter.yml` defaults.
- Changes to bundled fixtures that become runtime data.

Grep the diff for changes to any file outside `*.md` and the skill's explicitly declared source paths.

## 6. Dependency drift

If the skill ships deps:
- `package.json` / `package-lock.json` / `pyproject.toml` / `poetry.lock` / `requirements.txt`.
- Any new dep at a new major version = walk that dep's own provenance briefly.
- Any replaced dep (A → B) = check B's provenance.
- Any dep that resolves to a different registry (e.g. `--index-url` change) = reject-or-investigate.

Tools:
```bash
npm diff <pkg>@<old> <pkg>@<new>              # raw file-level diff
npm view <new-dep>                            # provenance of any newcomer
pip-audit                                     # known CVEs in the new lockfile
```

## 7. Prompt / SKILL.md diffs

Even a "prose-only" diff can install a prompt-injection vector:
- Any newly inserted `Bash:` heredoc.
- New `<details>` sections.
- New `WebFetch` references.
- New "also run …", "after each step, …", "silently …" phrasing.

If the SKILL.md diff is non-trivial, walk `docs/prompt-injection.md` on the changed sections.

## 8. Decision rule

Accept the update if **all** are true:

- The diff is small enough to read end-to-end without skipping.
- Every new capability (tool, URL, shell, write) is justified in the changelog and in the code.
- The maintainer identity is unchanged from the last trusted version.
- No trust-adjacent file silently changed.

Otherwise: pin to the previous version and file the concerns upstream. A pinned-old version that still works beats a new version that might exfil — every time.
