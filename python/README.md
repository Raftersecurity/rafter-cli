# rafter-cli

A Python CLI for Rafter Security that supports pip package management.

## Installation

```bash
# Using pip
pip install rafter-cli

# Using pipx (recommended for CLI tools)
pipx install rafter-cli
```

## Quick Start

```bash
# Set your API key
export RAFTER_API_KEY="your-api-key-here"

# Run a security scan
rafter run

# Get scan results
rafter get <scan-id>

# Check API usage
rafter usage
```

## Commands

### `rafter run [options]`

Trigger a new security scan for your repository.

**Options:**
- `-r, --repo <repo>` - Repository in format `org/repo` (default: auto-detected)
- `-b, --branch <branch>` - Branch name (default: auto-detected)
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)
- `-f, --format <format>` - Output format: `json` or `md` (default: `json`)
- `--skip-interactive` - Don't wait for scan completion
- `--quiet` - Suppress status messages

**Examples:**
```bash
# Basic scan with auto-detection
rafter run

# Scan specific repo/branch
rafter run --repo myorg/myrepo --branch feature-branch

# Non-interactive scan
rafter run --skip-interactive
```

### `rafter get <scan-id> [options]`

Retrieve results from a completed scan.

**Options:**
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)
- `-f, --format <format>` - Output format: `json` or `md` (default: `json`)
- `--interactive` - Poll until scan completes
- `--quiet` - Suppress status messages

**Examples:**
```bash
# Get scan results
rafter get <scan-id>

# Wait for scan completion
rafter get <scan-id> --interactive
```

### `rafter usage [options]`

Check your API quota and usage.

**Options:**
- `-k, --api-key <key>` - API key (or set `RAFTER_API_KEY` env var)

**Example:**
```bash
rafter usage
```

## Configuration

### Environment Variables

- `RAFTER_API_KEY` - Your Rafter API key (alternative to `--api-key` flag)

### Git Auto-Detection

The CLI automatically detects your repository and branch from the current Git repository:

1. **Repository**: Extracted from Git remote URL
2. **Branch**: Current branch name, or `main`

**Note**: The CLI only scans remote repositories, not your current local branch.

## Documentation

For comprehensive documentation, API reference, and examples, see [https://docs.rafter.so](https://docs.rafter.so). 