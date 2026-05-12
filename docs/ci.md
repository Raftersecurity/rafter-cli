# CI/CD Integration

## Generate CI config

```sh
rafter ci init                          # auto-detect platform
rafter ci init --platform github        # GitHub Actions
rafter ci init --platform gitlab        # GitLab CI
rafter ci init --platform circleci      # CircleCI
rafter ci init --with-remote            # include remote security audit job
```

## GitHub Action

Use as a reusable action in any GitHub Actions workflow:

```yaml
- uses: Raftersecurity/rafter-cli@v1
  with:
    scan-path: '.'       # default
    args: '--quiet'      # default; override for verbose output
    # install-method: 'pip'  # use pip instead of npm
```

Exit codes: `0` = clean, `1` = secrets found, `2` = scanner error.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-path` | `.` | Path to scan |
| `args` | `--quiet` | Additional args to `rafter secrets` |
| `version` | `latest` | CLI version to install |
| `install-method` | `npm` | `npm` or `pip` |
| `format` | `json` | Output format: `json` or `text` |

### Outputs

| Output | Description |
|--------|-------------|
| `finding-count` | Number of secrets found (0 if clean) |
| `report` | Full scan report |
| `exit-code` | Scanner exit code |

## pre-commit framework

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Raftersecurity/rafter-cli
    rev: v0.8.1
    hooks:
      - id: rafter-scan-node      # auto-installs via npm
      # - id: rafter-scan-python  # auto-installs via pip
      # - id: rafter-scan         # uses system rafter binary
```

The `rafter-scan-node` and `rafter-scan-python` hooks install the CLI automatically.

Requires `rafter` in PATH for the `rafter-scan` hook variant
(`npm i -g @rafter-security/cli` or `pip install rafter-cli`).
