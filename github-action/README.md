# Rafter Security Scan - GitHub Action (Cloud)

Run [Rafter](https://rafter.so) security scans on your GitHub repositories. Finds vulnerabilities, secrets, and misconfigurations in your code.

> **Looking for local-only scanning?** The [root action](../action.yml) (`Raftersecurity/rafter-cli@v0`) runs secret scanning locally with no API key required.

## Features

- Scans on push and pull request events
- Posts findings as PR comments with severity breakdown
- Uploads SARIF to GitHub Code Scanning (appears in Security tab)
- Configurable severity thresholds for CI gating
- Fast and Plus scan modes

## Quick Start

```yaml
name: Security Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write  # Required for SARIF upload
  pull-requests: write    # Required for PR comments

jobs:
  rafter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Raftersecurity/rafter-cli/github-action@main
        with:
          api-key: ${{ secrets.RAFTER_API_KEY }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `api-key` | Your Rafter API key (required) | — |
| `scan-mode` | `fast` or `plus` | `fast` |
| `severity-threshold` | Fail if findings at this level or above: `critical`, `high`, `medium`, `low`, `none` | `high` |
| `comment-on-pr` | Post results as PR comment | `true` |
| `upload-sarif` | Upload SARIF to GitHub Code Scanning | `true` |
| `timeout-minutes` | Max wait time for scan completion | `10` |
| `rafter-url` | API base URL (for self-hosted) | `https://rafter.so` |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | The Rafter scan ID |
| `findings-count` | Total findings |
| `critical-count` | Critical severity findings |
| `high-count` | High severity findings |
| `medium-count` | Medium severity findings |
| `low-count` | Low severity findings |
| `status` | Scan status |

## Examples

### Block PRs with critical findings only

```yaml
- uses: Raftersecurity/rafter-cli/github-action@main
  with:
    api-key: ${{ secrets.RAFTER_API_KEY }}
    severity-threshold: critical
```

### Plus scan without PR comments

```yaml
- uses: Raftersecurity/rafter-cli/github-action@main
  with:
    api-key: ${{ secrets.RAFTER_API_KEY }}
    scan-mode: plus
    comment-on-pr: 'false'
```

### Use scan results in subsequent steps

```yaml
- uses: Raftersecurity/rafter-cli/github-action@main
  id: rafter
  with:
    api-key: ${{ secrets.RAFTER_API_KEY }}
    severity-threshold: none  # Don't fail, just report

- run: echo "Found ${{ steps.rafter.outputs.findings-count }} issues"
```

## Setup

1. Get your API key from [rafter.so/dashboard/settings](https://rafter.so/dashboard/settings)
2. Add it as a repository secret named `RAFTER_API_KEY`
3. Add the workflow file to `.github/workflows/`

## Permissions

The action needs these GitHub token permissions:

- `contents: read` — checkout code
- `security-events: write` — upload SARIF (if `upload-sarif` is enabled)
- `pull-requests: write` — post PR comments (if `comment-on-pr` is enabled)
