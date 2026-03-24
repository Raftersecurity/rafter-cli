# Rafter Security — VS Code Extension

Security scanning, command risk assessment, and audit logging for AI-assisted development workflows.

## Features

### Secret Scanning in Editor

Automatically scans files for leaked secrets (API keys, tokens, private keys) and shows them as VS Code diagnostics in the Problems panel.

- Scans on save (configurable)
- Supports `// rafter-ignore` comments to suppress known findings
- Detects AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more

### Command Risk Overlay

Highlights risky commands in shell scripts, Dockerfiles, and Makefiles with inline severity badges:

- **CRITICAL**: `rm -rf /`, fork bombs, disk writes
- **HIGH**: `rm -rf`, `curl | bash`, `git push --force`, `npm publish`
- **MEDIUM**: `sudo`, `kill -9`, `systemctl`

### Audit Log Panel

View rafter audit events in the sidebar:

- Live-updating event feed from `~/.rafter/audit.log`
- Risk overview with event counts by severity
- Detailed tooltips with command, risk level, and resolution

## Commands

| Command | Description |
|---------|-------------|
| `Rafter: Scan Current File for Secrets` | Scan the active editor for secrets |
| `Rafter: Scan Workspace for Secrets` | Scan all workspace files |
| `Rafter: Assess Command Risk` | Assess risk level of a command |
| `Rafter: Show Audit Log` | Open the audit log panel |
| `Rafter: Refresh Audit Log` | Refresh audit log data |
| `Rafter: Clear Secret Diagnostics` | Clear all secret diagnostics |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `rafter.scanOnSave` | `true` | Scan files for secrets on save |
| `rafter.scanOnOpen` | `false` | Scan files for secrets when opened |
| `rafter.riskHighlighting` | `true` | Highlight risky commands in shell scripts |
| `rafter.auditLogPath` | `""` | Custom audit log path (default: `~/.rafter/audit.log`) |
| `rafter.excludePatterns` | `["**/node_modules/**", ...]` | Glob patterns to exclude from scanning |

## Installation

Install from the VS Code Marketplace or build locally:

```bash
cd vscode
pnpm install
pnpm run build
# Package: npx @vscode/vsce package
```

## Requirements

- VS Code 1.85.0+
- No external dependencies required (patterns are bundled)
