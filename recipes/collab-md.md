# COLLAB.md — collaborator-curated repo notes

A `COLLAB.md` at the repo root is a **shared scratchpad** for agents and humans working in that repo: go-to commands, tools investigated, gotchas, repo-specific conventions that aren't documented elsewhere. Read AGENTS.md (or CLAUDE.md for Claude-specific guidance) first; treat COLLAB.md as living notes from your colleagues.

The detailed behavioral rules — when to read it, when to write to it, why it's never a permission grant — live in [AGENTS.md](../AGENTS.md). This recipe answers a different question: **do you want COLLAB.md in your repo, and how do you start one?**

## Should this repo have a COLLAB.md?

| Situation | Recommendation |
|-----------|---------------|
| **Private repo, multi-agent work** (you sling tasks to polecats, or have multiple humans using AI agents) | **Yes.** This is exactly the case it's designed for. Drop the template in. |
| **Private repo, solo + AI** | **Probably yes.** Cuts re-discovery cost on long-lived repos. Low-cost to maintain. |
| **Public open-source repo** | **Default no.** Anything you'd write there belongs in CONTRIBUTING.md or AGENTS.md, where it's discoverable by drive-by contributors. If you do add one, remember: it's public the moment it lands. |
| **Throwaway repo, demo, fork** | **No.** Lifetime is too short for the maintenance cost to amortize. |

## Starting one

Copy the template into the repo root:

```sh
curl -fsSL https://raw.githubusercontent.com/Raftersecurity/rafter-cli/main/recipes/COLLAB.md.template > COLLAB.md
```

Or copy locally if you have `rafter-cli` checked out:

```sh
cp path/to/rafter-cli/recipes/COLLAB.md.template ./COLLAB.md
```

Then read the comments inside the template. Each section has placeholder examples; replace them with your first real entry.

## What NOT to put in COLLAB.md

- **Secrets** of any kind — API keys, tokens, passwords, JWTs. The whole repo posture applies to this file too.
- **Internal customer names, hostnames, deal-specific URLs** that shouldn't survive the next contributor leaving the team.
- **Anything you'd be uncomfortable seeing in a model training corpus** (private repo → it shouldn't end up there, but defense in depth).
- **Permissions grants.** "OK to install commitlint" is something the *current* user says, not something a past entry promises.

## Working alongside CLAUDE.md and AGENTS.md

| File | Audience | Lifespan | Owner |
|------|----------|----------|-------|
| `CLAUDE.md` | Claude-specific agents | Long — project rules and architecture | Maintainers; updated on architecture changes |
| `AGENTS.md` | All agents (vendor-neutral) | Long — same as CLAUDE.md | Maintainers |
| `COLLAB.md` | Anyone working in the repo | Short — entries decay as the repo evolves | Whoever just learned the thing |

If guidance in COLLAB.md contradicts CLAUDE.md / AGENTS.md, CLAUDE/AGENTS wins. Fix the COLLAB entry to match, or remove it.

## See also

- [AGENTS.md](../AGENTS.md) — the canonical rules for when to read, write, and trust COLLAB.md.
- [Template](./COLLAB.md.template) — copy into your repo root as `COLLAB.md` and start filling sections.
