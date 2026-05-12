# Rafter CLI

[![npm version](https://img.shields.io/npm/v/@rafter-security/cli)](https://www.npmjs.com/package/@rafter-security/cli) [![PyPI version](https://img.shields.io/pypi/v/rafter-cli)](https://pypi.org/project/rafter-cli/) [![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p>
  <a href="docs/platforms.md"><img alt="Claude Code supported" src="https://img.shields.io/badge/Claude%20Code-supported-d97757?style=flat&labelColor=141413&logo=claude&logoColor=faf9f5"></a>
  <a href="docs/platforms.md"><img alt="Codex supported" src="https://img.shields.io/badge/Codex-supported-f5f5f5?style=flat&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyBpZD0iTGF5ZXJfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCAxNTguNzEyOCAxNTcuMjk2Ij4KICA8IS0tIEdlbmVyYXRvcjogQWRvYmUgSWxsdXN0cmF0b3IgMjkuMi4xLCBTVkcgRXhwb3J0IFBsdWctSW4gLiBTVkcgVmVyc2lvbjogMi4xLjAgQnVpbGQgMTE2KSAgLS0%2BCiAgPHBhdGggZmlsbD0iI0ZGRkZGRiIgZD0iTTYwLjg3MzQsNTcuMjU1NnYtMTQuOTQzMmMwLTEuMjU4Ni40NzIyLTIuMjAyOSwxLjU3MjgtMi44MzE0bDMwLjA0NDMtMTcuMzAyM2M0LjA4OTktMi4zNTkzLDguOTY2Mi0zLjQ1OTksMTMuOTk4OC0zLjQ1OTksMTguODc1OSwwLDMwLjgzMDcsMTQuNjI4OSwzMC44MzA3LDMwLjIwMDYsMCwxLjEwMDcsMCwyLjM1OTMtLjE1OCwzLjYxNzhsLTMxLjE0NDYtMTguMjQ2N2MtMS44ODcyLTEuMTAwNi0zLjc3NTQtMS4xMDA2LTUuNjYyOSwwbC0zOS40ODEyLDIyLjk2NTFaTTEzMS4wMjc2LDExNS40NTYxdi0zNS43MDc0YzAtMi4yMDI4LS45NDQ2LTMuNzc1Ni0yLjgzMTgtNC44NzYzbC0zOS40ODEtMjIuOTY1MSwxMi44OTgyLTcuMzkzNGMxLjEwMDctLjYyODUsMi4wNDUzLS42Mjg1LDMuMTQ1OCwwbDMwLjA0NDEsMTcuMzAyNGM4LjY1MjMsNS4wMzQxLDE0LjQ3MDgsMTUuNzI5NiwxNC40NzA4LDI2LjExMDcsMCwxMS45NTM5LTcuMDc2OSwyMi45NjUtMTguMjQ2MSwyNy41Mjd2LjAwMjFaTTUxLjU5Myw4My45OTY0bC0xMi44OTgyLTcuNTQ5N2MtMS4xMDA3LS42Mjg1LTEuNTcyOC0xLjU3MjgtMS41NzI4LTIuODMxNHYtMzQuNjA0OGMwLTE2LjgzMDMsMTIuODk4Mi0yOS41NzIyLDMwLjM1ODUtMjkuNTcyMiw2LjYwNywwLDEyLjc0MDMsMi4yMDI5LDE3LjkzMjQsNi4xMzQ5bC0zMC45ODcsMTcuOTMyNGMtMS44ODcxLDEuMTAwNy0yLjgzMTQsMi42NzM1LTIuODMxNCw0Ljg3NjR2NDUuNjE1OWwtLjAwMTQtLjAwMTVaTTc5LjM1NjIsMTAwLjA0MDNsLTE4LjQ4MjktMTAuMzgxMXYtMjIuMDIwOWwxOC40ODI5LTEwLjM4MTEsMTguNDgxMiwxMC4zODExdjIyLjAyMDlsLTE4LjQ4MTIsMTAuMzgxMVpNOTEuMjMxOSwxNDcuODU5MWMtNi42MDcsMC0xMi43NDAzLTIuMjAzMS0xNy45MzI0LTYuMTM0NGwzMC45ODY2LTE3LjkzMzNjMS44ODcyLTEuMTAwNSwyLjgzMTgtMi42NzI4LDIuODMxOC00Ljg3NTl2LTQ1LjYxNmwxMy4wNTY0LDcuNTQ5OGMxLjEwMDUuNjI4NSwxLjU3MjMsMS41NzI4LDEuNTcyMywyLjgzMTR2MzQuNjA1MWMwLDE2LjgyOTctMTMuMDU2NCwyOS41NzIzLTMwLjUxNDcsMjkuNTcyM3YuMDAxWk01My45NTIyLDExMi43ODIybC0zMC4wNDQzLTE3LjMwMjRjLTguNjUyLTUuMDM0My0xNC40NzEtMTUuNzI5Ni0xNC40NzEtMjYuMTEwNywwLTEyLjExMTksNy4yMzU2LTIyLjk2NTIsMTguNDAzLTI3LjUyNzJ2MzUuODYzNGMwLDIuMjAyOC45NDQzLDMuNzc1NiwyLjgzMTQsNC44NzYzbDM5LjMyNDgsMjIuODA2OC0xMi44OTgyLDcuMzkzOGMtMS4xMDA3LjYyODctMi4wNDUuNjI4Ny0zLjE0NTYsMFpNNTIuMjIyOSwxMzguNTc5MWMtMTcuNzc0NSwwLTMwLjgzMDYtMTMuMzcxMy0zMC44MzA2LTI5Ljg4NzEsMC0xLjI1ODUuMTU3OC0yLjUxNjkuMzE0My0zLjc3NTRsMzAuOTg3LDE3LjkzMjNjMS44ODcxLDEuMTAwNSwzLjc3NTcsMS4xMDA1LDUuNjYyOCwwbDM5LjQ4MTEtMjIuODA3djE0Ljk0MzVjMCwxLjI1ODUtLjQ3MjEsMi4yMDIxLTEuNTcyOCwyLjgzMDhsLTMwLjA0NDMsMTcuMzAyNWMtNC4wODk4LDIuMzU5LTguOTY2MiwzLjQ2MDUtMTMuOTk4OSwzLjQ2MDVoLjAwMTRaTTkxLjIzMTksMTU3LjI5NmMxOS4wMzI3LDAsMzQuOTE4OC0xMy41MjcyLDM4LjUzODMtMzEuNDU5NCwxNy42MTY0LTQuNTYyLDI4Ljk0MjUtMjEuMDc3OSwyOC45NDI1LTM3LjkwOCwwLTExLjAxMTItNC43MTktMjEuNzA2Ni0xMy4yMTMzLTI5LjQxNDMuNzg2Ny0zLjMwMzUsMS4yNTk1LTYuNjA3LDEuMjU5NS05LjkwOSwwLTIyLjQ5MjktMTguMjQ3MS0zOS4zMjQ3LTM5LjMyNTEtMzkuMzI0Ny00LjI0NjEsMC04LjMzNjMuNjI4NS0xMi40MjYyLDIuMDQ1LTcuMDc5Mi02LjkyMTMtMTYuODMxOC0xMS4zMjU0LTI3LjUyNzEtMTEuMzI1NC0xOS4wMzMxLDAtMzQuOTE5MSwxMy41MjY4LTM4LjUzODQsMzEuNDU5MUMxMS4zMjU1LDM2LjAyMTIsMCw1Mi41MzczLDAsNjkuMzY3NWMwLDExLjAxMTIsNC43MTg0LDIxLjcwNjUsMTMuMjEyNSwyOS40MTQyLS43ODY1LDMuMzAzNS0xLjI1ODYsNi42MDY3LTEuMjU4Niw5LjkwOTIsMCwyMi40OTIzLDE4LjI0NjYsMzkuMzI0MSwzOS4zMjQ4LDM5LjMyNDEsNC4yNDYyLDAsOC4zMzYyLS42Mjc3LDEyLjQyNi0yLjA0NDEsNy4wNzc2LDYuOTIxLDE2LjgzMDIsMTEuMzI1MSwyNy41MjcxLDExLjMyNTFaIi8%2BCjwvc3ZnPg%3D%3D"></a>
  <a href="docs/platforms.md"><img alt="Gemini CLI supported" src="https://img.shields.io/badge/Gemini%20CLI-supported-4285f4?style=flat&labelColor=202124&logo=googlegemini&logoColor=8e75b2"></a>
  <a href="docs/platforms.md"><img alt="OpenClaw supported" src="https://img.shields.io/badge/OpenClaw-supported-e8662a?style=flat&labelColor=1a1a1a"></a>
  <a href="docs/platforms.md"><img alt="Cursor supported" src="https://img.shields.io/badge/Cursor-supported-d4d4d4?style=flat&labelColor=1c1c1c&logo=cursor&logoColor=white"></a>
  <a href="docs/platforms.md"><img alt="Windsurf supported" src="https://img.shields.io/badge/Windsurf-supported-00c4b4?style=flat&labelColor=0a0a0a"></a>
  <a href="docs/platforms.md"><img alt="Continue.dev supported" src="https://img.shields.io/badge/Continue.dev-supported-7c3aed?style=flat&labelColor=1e1b2e"></a>
  <a href="docs/platforms.md"><img alt="Aider supported" src="https://img.shields.io/badge/Aider-supported-10b981?style=flat&labelColor=111827"></a>
</p>

Multi-language CLI for [Rafter](https://rafter.so) — the security toolkit built for AI coding agents and the developers who use them.

> **Free forever for individuals and open source. No account required. No telemetry.**
>
> All local security features work with zero setup — no API key, no sign-up, no usage limits.

**Two capabilities:**

1. **Local Security Toolkit** (free, no account) — Secret scanning, policy enforcement, pre-commit hooks, extension auditing, audit logging, and MCP server. Works offline. No telemetry.
2. **Remote Code Analysis** — Agentic SAST/SCA audits via the Rafter API. Structured reports. Code deleted after analysis.

---

## 90-Second Quickstart

**1. Scan the included test fixture for leaked credentials**

```sh
rafter secrets fixtures/vulnerable-repo
# →
# → ⚠️  Found secrets in 5 file(s):
# →
# →   fixtures/vulnerable-repo/config/deploy.key
# →      CRITICAL  private-key  ----***...***----
# →   fixtures/vulnerable-repo/config/tokens.yml
# →      CRITICAL  github-pat  ghp_***...***6789
# →   ...
# → ⚠️  Total: 12 secret(s) detected in 5 file(s)
# → exit 1
```

**2. Install the pre-commit hook**

```sh
rafter agent init --all
# → Installs all detected integrations
# → Downloads Betterleaks (or uses built-in scanner)
```

**3. Try to commit a file with secrets — hook blocks it**

```sh
git add secrets-file.env && git commit -m 'add config'
# → 🔍 Rafter: Scanning staged files for secrets...
# → CRITICAL  secrets-file.env:1  [detected pattern]
# → Commit blocked. Remove secrets before committing.
```

**4. Review the audit log**

```sh
rafter agent audit --last 3
# → 2026-05-12T...  secret_detected  config/payments.env  Stripe API Key
```

That's the core loop: scan → protect → audit. Everything works offline, no API key needed.

### What's free?

| Feature | Free (individuals & OSS) | Enterprise |
|---------|:------------------------:|:----------:|
| Secret scanning (21+ patterns) | **Yes** | Yes |
| Pre-commit hooks | **Yes** | Yes |
| Command interception | **Yes** | Yes |
| Skill/extension auditing | **Yes** | Yes |
| Audit logging | **Yes** | Yes |
| MCP server | **Yes** | Yes |
| CI/CD integration | **Yes** | Yes |
| Remote SAST/SCA/Agentic analysis (API) | Free tier | Higher limits |

No account. No telemetry. No data collection.

---

## Installation

```sh
npm install -g @rafter-security/cli   # Node.js (full features)
pip install rafter-cli                 # Python (full features, requires 3.10+)
```

Then set up integrations:

```sh
rafter agent init --all   # auto-detects Claude Code, Codex, Gemini, Cursor, Windsurf, Aider…
```

See [docs/install.md](docs/install.md) for full installation options and file locations.

---

## Documentation

| Topic | Doc |
|-------|-----|
| Installation & setup | [docs/install.md](docs/install.md) |
| Secret scanning | [docs/secret-scanning.md](docs/secret-scanning.md) |
| Pre-commit hook | [docs/pre-commit.md](docs/pre-commit.md) |
| Policy enforcement & custom rules | [docs/policy.md](docs/policy.md) |
| CI/CD & GitHub Action | [docs/ci.md](docs/ci.md) |
| MCP server | [docs/mcp.md](docs/mcp.md) |
| Supported platforms | [docs/platforms.md](docs/platforms.md) |
| Audit log | [docs/audit-log.md](docs/audit-log.md) |
| Remote code analysis | [docs/remote-analysis.md](docs/remote-analysis.md) |
| Adding a new platform | [docs/adding-a-platform.md](docs/adding-a-platform.md) |
| Exit codes & output contract | [shared-docs/CLI_SPEC.md](shared-docs/CLI_SPEC.md) |
| Full API docs | [docs.rafter.so](https://docs.rafter.so) |

---

## Development

```sh
pnpm install          # install all dependencies (from repo root)
cd node && pnpm test  # run Node test suite
cd python && pytest   # run Python test suite
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CLAUDE.md](CLAUDE.md) for contributor guides.

---

## Badges

[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli) [![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/Raftersecurity/rafter-cli)

```markdown
[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli)
```

More variants in [`badges/`](badges/).

---

## License

[MIT](LICENSE)
