# Pre-Commit Hook

Automatically scan staged files before every `git commit`. The most effective way to
prevent secrets from entering version control.

## Install

```sh
rafter agent install-hook           # current repo only
rafter agent install-hook --global  # all repos on this machine
```

Blocks commits when secrets are detected. Bypass with `git commit --no-verify` (not recommended).

## How it works

The hook runs `rafter secrets --staged --quiet` before each commit. If secrets are
found (exit code 1), the commit is blocked:

```sh
git add . && git commit -m 'add config'
# → 🔍 Rafter: Scanning staged files for secrets...
# → CRITICAL  .env:1  AWS Access Key ID
# → Commit blocked. Remove secrets before committing.
# → To bypass (NOT recommended): git commit --no-verify
```

## pre-commit framework

Rafter works as a [pre-commit](https://pre-commit.com) hook. Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Raftersecurity/rafter-cli
    rev: v0.8.1
    hooks:
      - id: rafter-scan-node      # auto-installs via npm
      # - id: rafter-scan-python  # auto-installs via pip
      # - id: rafter-scan         # uses system rafter binary
```

The `rafter-scan-node` and `rafter-scan-python` hooks install the CLI automatically —
no global install needed.
