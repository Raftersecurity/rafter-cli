# PR Comment Sweep — 2026-05-17 (sable-9si / maylist B6)

**Bead:** sable-9si
**Source ask:** maylist B6 — "Rome added comments to many other Rafter CLI PRs. Get agents on them."

## Method

1. Pulled every issue comment via `gh api repos/Raftersecurity/rafter-cli/issues/comments --paginate` (n=12).
2. Pulled every PR review comment via `gh api repos/Raftersecurity/rafter-cli/pulls/comments --paginate` (n=0).
3. Pulled every PR review via `gh pr list --json reviews` across 98 PRs (33 reviews, all from `Raftersecurity` org-bot).
4. Surveyed every open PR's body, mergeable state, and merge-state-status.

## Findings

### 1. No human Rome-the-user comments exist in the GitHub state

- The 11 issue comments with `user.login` of `Rome-1` / `rome-1` are all **status reports from agents acting under that identity** (PRs #9, #15, #22, #38, #39, #63, #66, #67, #69, #75, #95). They describe what was done; none contain unaddressed asks.
- Review comments: 0 across all 98 PRs.
- Reviews: 33 total, all from the `Raftersecurity` org account (CI bot decisions).

**Conclusion:** the dispatcher's "Rome added comments to many other Rafter CLI PRs" almost certainly refers to the maylist itself (the 29 A-items + 12 B-items dispatched in hq-wisp-7zh on 2026-05-11), **not** GitHub-resident comments. Those asks are already beaded as A1–A29 / B1–B12 and being worked through. No new GitHub-sourced asks exist to triage.

### 2. Open PR state (n=5)

| PR | Status | Disposition |
|----|--------|-------------|
| #95 promo/video-production (rf-zg8z) | Clean, mergeable | Separate work stream (promo), not in maylist scope |
| #83 promo/60s-storyboard (se-p3r) | Mergeable=UNKNOWN | Separate work stream (promo), not in maylist scope |
| #82 prompt-injection detector (DRAFT) | Clean, DRAFT — DO NOT MERGE | In-flight, tracked by sable-h6r (A4) |
| #75 confidence/remediation/fingerprint (rc-23v) | **CONFLICTING** | Already tracked: sable-xli is the blocked-on-redo bead |
| #60 prompt-injection (older, DRAFT) | Clean, DRAFT — DO NOT MERGE | Superseded by #82; tracked under sable-h6r (A4) |

### 3. No follow-up beads required

Every actionable item I found is already beaded. The single non-trivial finding (PR #75 has merge conflicts) is already covered by sable-xli, which is blocked on backend coordination (juno/orin) per its own description.

## What B6 actually asked for vs. what exists

The bead acceptance criteria said:
> Filter to comments from Rome that look like asks/fixes (not just emoji/approvals).
> For each ask: check if there's an existing bead or follow-up PR that resolves it. If no: file a new bead with discovered-from:THIS_BEAD_ID and tag with the PR number.

Result: **zero such comments found in the GitHub state.** The maylist itself is the comment list; it's already beaded.

## Recommendation

Close sable-9si. If a different sweep is intended (e.g., scanning Rome's mail/nudges/Slack for asks that didn't make it into the maylist), that's a different ask and should be a new bead with the actual source named.

