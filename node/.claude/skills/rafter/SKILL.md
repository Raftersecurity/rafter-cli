---
name: rafter
description: "Trigger Rafter backend security scans on GitHub repositories. Use when the user asks about SAST, code security analysis, vulnerability scanning, or wants to scan a repo for security issues before merging or deploying. Also use when starting new features or reviewing pull requests."
version: 0.5.6
allowed-tools: [Bash]
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
# In a git repo
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

**Example:**
```bash
rafter get scan_abc123xyz
```

### Check API Usage

```bash
rafter usage
```

View your API quota and usage statistics.

**When to use:**
- User asks about remaining scans
- Before triggering a scan to confirm quota
- User mentions: quota, usage, limits, remaining scans

## Configuration

Rafter requires an API key. Set via:
```bash
export RAFTER_API_KEY="your-api-key-here"
```

Or create `.env` file:
```bash
echo "RAFTER_API_KEY=your-api-key-here" >> .env
```

## Common Workflows

**Workflow 1: Quick Security Check**
1. Trigger scan: `rafter run`
2. Get results: `rafter get <scan-id>`
3. Review findings and suggest fixes

**Workflow 2: Pre-PR Review**
1. Check quota: `rafter usage`
2. Trigger scan on feature branch: `rafter run --branch feature-branch`
3. Review results before creating PR

**Workflow 3: Dependency Update Check**
1. User updates dependencies
2. Trigger scan: `rafter run`
3. Check for new vulnerabilities

## Output Format

Scans return:
- **Code security findings** - SAST issues, security anti-patterns, hardcoded credentials
- **Configuration issues** - Insecure settings, exposed secrets
- **Severity levels** - Each finding rated by risk impact

## Best Practices

1. **Proactive scanning** - Suggest scans when user is working on security-sensitive code
2. **Quota awareness** - Check usage before triggering multiple scans
3. **Context interpretation** - Explain findings in context of user's code
4. **Actionable recommendations** - Provide specific fixes for each finding

## Integration Tips

- Auto-detect git repo for convenient `rafter run` with no arguments
- Wait for scan completion or show scan ID for later retrieval
- Parse JSON output for structured analysis
- Link findings to specific files and lines when available
