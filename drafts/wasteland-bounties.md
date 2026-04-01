# Wasteland Federation Bounties -- Rafter CLI

Posted by: Rafter Security
Date: 2026-03-26

---

## Bounty 1: Integrate Rafter into 10+ Open-Source Repos

### Objective

Add rafter secret scanning to 10 or more popular open-source repositories by opening pull requests with `rafter ci init`-generated GitHub Actions workflows. The goal is real-world adoption -- rafter protecting repos that currently have zero secret scanning in CI.

### Requirements

- Target repos must have 500+ GitHub stars.
- Target repos must NOT already have secret scanning configured (no gitleaks, trufflehog, detect-secrets, or similar in their CI pipelines or pre-commit configs).
- Each PR must use the official GitHub Action: `uses: raftersecurity/rafter-cli@v1`.
- Each PR description must clearly explain what rafter does, why secret scanning matters, and what the workflow adds. No drive-by one-liners.
- PRs must be respectful, well-written, and follow each repository's contribution guidelines (templates, DCO sign-off, branch naming, etc.).
- At least 5 of the 10 PRs must be merged (not just opened).

### Deliverables

- A tracking table with: repo name, star count at time of PR, PR link, and current status (open/merged/closed).
- Screenshot or link showing merged status for each qualifying PR.
- Brief notes on any maintainer feedback received.

### Compensation

[TBD by Rome]

### Acceptance Criteria

- Minimum 10 PRs opened across 10 distinct repositories.
- Minimum 5 of those PRs merged by the target repo's maintainers.
- Zero spam complaints or CoC violations from any maintainer.
- All PRs pass the target repo's CI checks (no broken workflows).
- PRs follow each repo's contribution quality standards.

### Timeline

- 4 weeks from bounty acceptance.
- Progress check-in at week 2 (share PR links opened so far).

---

## Bounty 2: Write Platform-Specific Tutorials / Recipes

### Objective

Create high-quality, published tutorials showing how to set up and use rafter with specific AI coding agent platforms. Each tutorial walks a developer from zero to a fully working rafter integration: secret scanning, policy enforcement, and CI protection.

### Requirements

- One tutorial per platform. Choose from: Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Aider, Continue.dev, OpenClaw.
- Minimum 3 tutorials required. More is better -- compensation scales with quantity.
- Each tutorial must be a complete walkthrough covering:
  - Installation (`npm install -g @rafter-security/cli` or `pip install rafter-cli`).
  - Platform integration (`rafter agent init --with-<platform>`).
  - Live secret scanning demo (plant a fake secret, show rafter catching it).
  - Pre-commit hook setup (`rafter hook commit`).
  - CI integration (GitHub Actions workflow with `raftersecurity/rafter-cli@v1`).
- Must include screenshots or terminal recordings (asciinema/SVG casts preferred).
- Must be published on a real platform with public URL: dev.to, Medium, Hashnode, personal blog with RSS, or similar. GitHub gists do not count.
- Tutorials must be tested against the latest released version of rafter CLI at time of writing.

### Deliverables

- Published URL for each tutorial.
- Source markdown files for each tutorial (for potential inclusion in the rafter `recipes/` directory).
- List of rafter CLI version used for testing.

### Compensation

[TBD by Rome]

### Acceptance Criteria

- Minimum 3 published tutorials covering 3 distinct platforms.
- Technically accurate: every command and screenshot must work against the stated rafter CLI version.
- Well-written: clear structure, correct grammar, no filler. Reviewers will check for obvious AI-generated slop (repetitive phrasing, hallucinated flags, generic padding).
- Each tutorial must be reproducible by a developer following it step-by-step on a clean machine.

### Timeline

- 3 weeks from bounty acceptance.
- First tutorial draft due within 1 week for quality review before continuing with remaining tutorials.

---

## General Terms

- Bounties are open to individuals or teams.
- Work must be original. Plagiarized or copy-pasted content is grounds for immediate disqualification.
- Rafter team reserves the right to reject deliverables that do not meet acceptance criteria.
- Questions: open an issue on the rafter-cli repo or reach out via the Wasteland federation channel.
