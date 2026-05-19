# Pre-Commit Hook

Block secrets from entering version control. Rafter scans staged files before every commit and rejects any that contain hardcoded credentials. 21+ built-in credential patterns plus optional Betterleaks integration (the gitleaks successor) for higher-recall detection. Deterministic results, exit code 1 on findings.

## Which install path should I use?

Rafter ships three pre-commit install paths. Use this decision tree to pick one:

- **Do you already use the [pre-commit](https://pre-commit.com) framework?** (i.e. `.pre-commit-config.yaml` lives in your repo)
  - **Yes** → use the [pre-commit framework](#pre-commit-framework) section below. Add the `rafter-scan-node` (or `-python`) entry to `.pre-commit-config.yaml`. The framework manages the hook for you alongside your other linters.
  - **No** → do you want the hook in just this repo, or in every repo on this machine?
    - **Just this repo** → `rafter agent install-hook` (writes `.git/hooks/pre-commit`).
    - **Every repo on this machine** → `rafter agent install-hook --global` (sets `core.hooksPath`).

Rule of thumb: if your team already standardises on pre-commit, stay in that ecosystem. If not, the native one-command install is the lowest-friction option and works out of the box.

## Pre-commit framework

If you use the [pre-commit](https://pre-commit.com) framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Raftersecurity/rafter-cli
    rev: v0.8.1
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

That's it. Every `git commit` now runs `rafter secrets --staged` automatically.

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
rafter secrets --staged --quiet

if [ $? -ne 0 ]; then
    echo "Commit blocked: secrets detected in staged files."
    echo "Run: rafter secrets --staged"
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

Checks that the hook is installed, Betterleaks binary is present, and config is valid.
