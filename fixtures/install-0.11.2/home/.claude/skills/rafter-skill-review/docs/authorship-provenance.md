# Authorship & Provenance

Who wrote the skill, how can you verify it, how long has it existed, and how widely is it already installed. A skill with perfect code and a brand-new pseudonymous author is still risky — provenance is the first filter, before reading a single line.

## 1. Identify the claimed author

Check all of:
- `SKILL.md` frontmatter (`author`, `maintainer`, `url` fields if present).
- `package.json` / `pyproject.toml` `author`, `maintainers`, `repository`.
- Git history: `git log --format='%an <%ae>' | sort -u | head`.
- README "Author" section.

Mismatch between any of these = investigate before trusting any single source.

## 2. Age and activity

- **Repo age**: `git log --reverse --format='%ai' | head -1`. A repo created last week, publishing a complex security skill, is not automatically malicious — but it deserves more scrutiny.
- **Number of independent contributors**: `git shortlog -sne`. One-author repos are common; zero-external-contributor repos that claim many users are suspicious.
- **Commit cadence**: bursts right before a release with no prior activity suggest a hijacked or squatted name.

## 3. Signing and verification

- `git log --show-signature <ref>` — does the claimed maintainer actually sign?
- `gh release view <tag>` — are release artifacts signed / checksummed?
- For npm: `npm view <pkg> dist.integrity` and `npm audit signatures`.
- For PyPI: look for Sigstore `.sigstore` files on the release page, or check `pip install --require-hashes`.

Unsigned does not automatically mean bad. **Changed signatures** (used to sign, now doesn't) or **signature mismatch with claimed maintainer** is a hard reject.

## 4. Distribution provenance

- **Registry page**: `npm view <pkg>`, `pip show <pkg>`, plugin marketplace page.
- **Download count / star count**: high numbers don't prove safety, but sudden spikes after a rename / transfer can indicate squatting.
- **Transferred ownership**: `npm view <pkg> maintainers` history, `pypi` project audit log, GitHub transfer events. A skill that changed hands recently is a classic supply-chain pattern — the new owner publishes a trojaned version to existing users.
- **Typo-squat check**: compare name to popular legitimate skills. Levenshtein distance of 1–2 from a well-known name, combined with recent registration, is a strong signal.

## 5. Parallel artifacts from the same author

Look at the author's other repos / packages:

- Similar skills with credentials-adjacent behaviour? Pattern.
- Aggressive telemetry in every project? Pattern.
- Consistent style, history, maintainer responsiveness? Good signal.
- Prior CVEs, prior account bans? Hard signal against.

```bash
gh api users/<login>/repos --jq '.[].full_name' | head -40
```

Skim a few for the same malware-indicator red flags — if two of them trip, treat this one as untrusted regardless of its own code.

## 6. Independent endorsement

A skill on its own repo's README can claim anything. Look for external signals:

- Referenced in a blog post, conference talk, or mainstream doc.
- Shipped as a recommended default by a tool's maintainers (not the skill author).
- Reviewed by a known security practitioner with evidence (post + date + sample output).

Absence of endorsement doesn't mean rejection, but presence of strong endorsement can lower the scrutiny level.

## 7. Revocation readiness

Even trusted skills fail. Before you install:

- Know where the skill lives on disk (`rafter skill list --installed --json`).
- Know how to remove it (`rafter skill uninstall <name>` if rafter-authored, otherwise manual delete).
- Know what config files it might have written (walk `docs/data-practices.md` §2).
- Keep a fresh shell open to re-verify the install path after install.

## 8. Checklist summary

Before proceeding to code-level review:

- [ ] Claimed author matches git history and registry metadata.
- [ ] Repo is at least a few releases old, OR endorsed by a trusted source.
- [ ] Commits are signed by the claimed maintainer (or signing is consistently absent).
- [ ] Ownership hasn't transferred recently without documented reason.
- [ ] Name is not a typo-squat of a well-known skill.
- [ ] Author's other artifacts don't trip the malware-indicator checklist.

Two or more gaps = rescope to "only install in a sandbox after deep code review", or reject.
