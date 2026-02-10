---
name: rafter
description: "Trigger security scans on GitHub repositories using Rafter's backend API. Use when the user asks about code security, vulnerability scanning, SAST analysis, security audit, dependency vulnerabilities, or wants to analyze their codebase for security issues. Also use when starting new features or reviewing pull requests to check for security concerns."
---

# Rafter Security Scanning

Rafter provides automated security scanning for GitHub repositories via backend API.

## Core Commands

### Trigger a Security Scan

```bash
rafter run [--repo org/repo] [--branch branch-name]
# or
rafter scan [--repo org/repo] [--branch branch-name]
```

Triggers a comprehensive security scan on a repository. Auto-detects current repo and branch if in a git directory. (`scan` is an alias for `run`)

**When to use:**
- User asks: "Can you scan this code for security issues?"
- Starting work on a new feature
- Before merging a PR
- After dependency updates
- User mentions: security audit, vulnerability scan, SAST, code analysis

**Example:**
```bash
# In a git repo (auto-detects repo + branch)
rafter scan

# Specific repo
rafter scan --repo myorg/myrepo --branch main
```

### Get Scan Results

```bash
rafter get <scan-id>
```

Retrieves results from a completed or in-progress scan.

**When to use:**
- After triggering a scan with `rafter run`
- User asks: "What were the results?" or "Did the scan finish?"
- Checking on a scan's progress

### Check API Usage

```bash
rafter usage
```

View your API quota and usage statistics.

## Configuration

Rafter requires an API key:
```bash
export RAFTER_API_KEY="your-api-key-here"
```

## Common Workflows

**Quick Security Check:**
1. Trigger scan: `rafter run`
2. Get results: `rafter get <scan-id>`
3. Review findings and suggest fixes

**Pre-PR Review:**
1. Check quota: `rafter usage`
2. Trigger scan on feature branch: `rafter run --branch feature-branch`
3. Review results before creating PR

## Output Format

Scans return:
- **Vulnerability findings** -- CVEs, severity, affected packages
- **Code quality issues** -- Security anti-patterns
- **Dependency risks** -- Outdated or vulnerable dependencies
- **Configuration issues** -- Insecure settings

## Best Practices

1. **Proactive scanning** -- Suggest scans when user is working on security-sensitive code
2. **Quota awareness** -- Check usage before triggering multiple scans
3. **Context interpretation** -- Explain findings in context of user's code
4. **Actionable recommendations** -- Provide specific fixes for each finding
