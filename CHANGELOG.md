# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Agent security command group (`rafter agent`)
- Pattern-based secret scanning (21+ secret types: AWS, GitHub, Stripe, Slack, npm, PyPI, etc.)
- Gitleaks integration with automatic binary download and graceful fallback
- Command interception with risk assessment (critical/high/medium/low)
- Dangerous command blocking (fork bombs, `rm -rf /`, `dd /dev/sda`)
- High-risk command approval workflow (`git push --force`, `sudo rm`, etc.)
- Pre-execution secret scanning for git commits
- Config management system (`~/.rafter/config.json`) with dot-notation paths
- Structured audit logging (`~/.rafter/audit.log`)
- Init wizard with environment auto-detection (OpenClaw, Claude Code)
- Skill auditing system with 12-dimension security analysis
- Pre-commit hooks (per-repo and global) for automatic secret scanning
- Claude Code integration (backend + agent security skills)
- `scan` alias for `run` command
- CI/CD publish workflows

### Changed
- Modularized CLI structure (backend commands extracted to `commands/backend/`)

## [0.3.0] - 2025-12-15

### Added
- Backend scan commands (`rafter run`, `rafter get`, `rafter usage`)
- Git repository auto-detection
- Interactive scan setup wizard
- JSON output support (`--format json`)
- Quiet mode for CI (`--quiet`)
- Python CLI (`pip install rafter-cli`)
- Node.js CLI (`npm install -g @rafter-security/cli`)
