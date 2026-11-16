# Data Practices

What the skill reads, what it writes, where it sends bytes. The goal: a complete map of the skill's I/O before installation.

> The JSON report from `rafter skill review` gives you URLs and some command patterns. This doc is the structured follow-up: enumerate surface, then decide.

## 1. Filesystem reads

For every Read / Glob / Grep / `cat` the skill performs, answer:

| Question | Expected answer |
|----------|----------------|
| Is the path derived from user input? | Yes, and validated — or no, it's a fixed project path. |
| Does it glob `~/` or `/` roots? | Only with explicit exclusions of credential dirs. |
| Does it follow symlinks? | Only if documented and scoped. |
| Does it touch `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, browser profiles, password managers? | No. Any yes = reject. |

Flag: `fs.readFileSync`, `open(...)`, `readFile`, `fs.readdir`, `glob(...)` with patterns broader than the stated purpose requires.

## 2. Filesystem writes

Every Write / `mv` / `cp` / `mkdir` needs justification:

- **In-repo writes**: fine, if the file is one the user expects the skill to produce.
- **Home-dir writes**: must be `~/.<skill-name>/` or equivalent scoped dir. Writes to `~/.bashrc`, shell rc files, `~/.config/systemd`, crontab, launchd plists are persistence = reject.
- **System-wide writes** (`/etc`, `/usr/local`): reject unless the skill is documented as a sysadmin tool AND requires explicit sudo with prompt.

Search the tree:
```bash
rg -n 'writeFileSync|fs\.write|open\([^)]*"[wa]"|createWriteStream|\.mkdirSync' <skill>
rg -n '\.bashrc|\.zshrc|\.profile|crontab|systemctl|launchctl' <skill>
```

## 3. Network calls

List every outbound URL the skill touches. For each, answer:

1. Is the domain owned by the claimed maintainer? (Check WHOIS / org owner.)
2. Is it HTTPS? Pinned to a specific path and version?
3. Is it called at install time, at run time, or both?
4. Does it include any data from the user's repo or machine as query/body?
5. Is failure handled by **stopping**, not by falling back to a plain-text alternative?

Red flags:
- Outbound POSTs whose body includes file contents, env vars, or user prompts.
- `User-Agent` strings that encode a machine ID or repo name.
- Fallback chains: "try HTTPS, else HTTP, else cache" — the else branches are a downgrade attack.

## 4. Environment variable access

Every `process.env.FOO` / `os.environ["FOO"]` is a potential credential sink. Enumerate them and split:

- **Expected**: `RAFTER_API_KEY` in a rafter-adjacent skill, `OPENAI_API_KEY` in an AI tooling skill.
- **Unexpected**: `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`, `ANTHROPIC_API_KEY`, `DATABASE_URL`. These should never be read by a skill unless that's the skill's stated purpose.
- **Leaky**: any env var that's then passed into a network call (step 3) or into a shell invocation (step 5).

## 5. Shell / tool invocation

Skills declare `allowed-tools` in frontmatter. Reconcile:

- **Stated purpose vs. allowed-tools**: a "code review" skill that declares `allowed-tools: [Bash, Write, WebFetch]` is asking for more than the purpose justifies.
- **Minimal grant**: `Read, Glob, Grep` is usually enough for analysis skills. Each extra tool (`Bash`, `Write`, `WebFetch`, `Edit`) needs a sentence of justification in SKILL.md.
- **Shell calls in `Bash`**: for every shell command the skill invokes, re-run `rafter skill review` worth of checks against that command specifically.

## 6. Silent escalation

Patterns where the skill widens its own surface at run time:

- Adds new tools via MCP server registration.
- Writes to `settings.json` / `.claude/settings.json` to grant permissions.
- Modifies `.rafter.yml` or other policy files.
- Changes shell rc files to export new env vars / aliases.

Any of these = reject unless they are the skill's stated, headline feature (e.g., a skill whose whole job is installing MCP servers).

## 7. Data classification of outputs

For any data the skill emits to stdout / files / network, classify:

- **Public**: analysis results, counts, categories. Safe.
- **Repo-private**: code snippets, file names, diffs. Only OK on HTTPS to a maintainer-owned URL the user has already trusted.
- **Credential-adjacent**: .env files, `~/.aws/config`, keychain excerpts. Should never leave the machine via a skill.

---

## Decision rule

Write out, in one paragraph, the skill's total I/O surface: read-set, write-set, outbound URLs, env vars. If that paragraph has any surprises relative to the skill's stated purpose, reject. If every item is expected and scoped, proceed to `docs/telemetry.md`.
