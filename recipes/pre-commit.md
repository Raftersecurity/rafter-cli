# Pre-Commit Hook

Block secrets from entering version control. Rafter scans staged files before every commit and rejects any that contain hardcoded credentials. 21+ credential patterns via Gitleaks, deterministic results, exit code 1 on findings.

## Pre-commit framework

If you use the [pre-commit](https://pre-commit.com) framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/raftersecurity/rafter-cli
    rev: v0.6.5
    hooks:
      - id: rafter-scan-node   # auto-installs via npm, no global install needed
```

Three hook variants are available:

| Hook ID | Language | Requires global install? |
|---------|----------|--------------------------|
| `rafter-scan` | `system` | Yes — `rafter` must be on PATH |
| `rafter-scan-node` | `node` | No — installs `@rafter-security/cli` automatically |
| `rafter-scan-python` | `python` | No — installs `rafter-cli` automatically |

## One-command install (native)

```sh
# Current repo only
rafter agent install-hook

# All repos on this machine (sets core.hooksPath)
rafter agent install-hook --global
```

That's it. Every `git commit` now runs `rafter agent scan --staged` automatically.

## Manual install

If you prefer to manage hooks yourself, add this to `.git/hooks/pre-commit` (or your global hooks directory):

```bash
#!/bin/bash
# Rafter Security Pre-Commit Hook

if ! command -v rafter &> /dev/null; then
    echo "Warning: rafter CLI not found. Skipping secret scan."
    exit 0
fi

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED_FILES" ] && exit 0

echo "Scanning staged files for secrets..."
rafter agent scan --staged --quiet

if [ $? -ne 0 ]; then
    echo "Commit blocked: secrets detected in staged files."
    echo "Run: rafter agent scan --staged"
    exit 1
fi

exit 0
```

```sh
chmod +x .git/hooks/pre-commit
```

## Bypass (not recommended)

```sh
git commit --no-verify
```

## Verify installation

```sh
rafter agent verify
```

Checks that the hook is installed, Gitleaks binary is present, and config is valid.
