# Drafted Fixes for Rome-1/docs

These are the exact changes to apply to the docs site (docs.rafter.so).

---

## Fix 1: Add `github_token` to API scan endpoint docs (C2)

**File**: `api-reference/endpoint/static/scan.mdx`

Add row to Fields table after `scan_mode`:

```
| `github_token` | string | No | Fine-grained GitHub PAT for scanning private repositories. Only needs `Contents:Read` permission. Can also be set via `RAFTER_GITHUB_TOKEN` environment variable when using the CLI. |
```

Update the example request body:

```json
{
  "repository_name": "myorg/myrepo",
  "branch_name": "main",
  "scan_mode": "fast",
  "github_token": "github_pat_..."
}
```

Add a note after the example:

```
<Note>The `github_token` field is optional. When omitted, the scan uses the OAuth credentials linked to your Rafter account. Use this field for scanning private repositories without OAuth — the token only needs `Contents:Read` permission.</Note>
```

---

## Fix 2: Fix 403 response `remaining` → `used` (C3)

**File**: `api-reference/endpoint/static/scan.mdx`

Replace lines 70-78:

```json
{
  "error": "You have reached your Plus scan limit for this billing period.",
  "scan_mode": "plus",
  "used": 1,
  "limit": 1
}
```

---

## Fix 3: Add 429 response (C4)

**File**: `api-reference/endpoint/static/scan.mdx`

Add after the 404 error response:

```markdown
**Error (429 Too Many Requests):**
```json
{
  "error": "Rate limit exceeded. Please try again later."
}
```

The CLI maps this to exit code 3 (quota exhausted).
```

---

## Fix 4: Add `--github-token` to quick-reference.mdx (C2)

**File**: `guides/quick-reference.mdx`

Add to the "Scan a Repo" section:

```bash
# Scan a private repo with a GitHub PAT
rafter run --github-token ghp_... --format md

# Or use an environment variable
export RAFTER_GITHUB_TOKEN=ghp_...
rafter run --format md
```

---

## Fix 5: Add `RAFTER_GITHUB_TOKEN` to Environment Variables (M2)

**File**: `guides/agent-security/reference.mdx`

Add to the Environment Variables table (line 890):

```
| `RAFTER_GITHUB_TOKEN` | GitHub PAT for private repo scanning (needs `Contents:Read` scope) |
```

---

## Fix 6: Add local scanning to quickstart (M4)

**File**: `quickstart.mdx`

Add before the "What's happening?" section:

```markdown
## Local Security (No Account Required)

Rafter's local features work with zero setup — no API key, no sign-up:

```bash
# Install
npm install -g @rafter-security/cli

# Set up agent security
rafter agent init --all

# Scan for secrets
rafter scan local .
```

This gives you secret scanning, pre-commit hooks, command interception, and audit logging — all offline, all free.
```

---

## Summary

| Fix | File | Severity | Description |
|-----|------|----------|-------------|
| 1 | api-reference/endpoint/static/scan.mdx | CRITICAL | Add `github_token` field |
| 2 | api-reference/endpoint/static/scan.mdx | CRITICAL | Fix `remaining` → `used` |
| 3 | api-reference/endpoint/static/scan.mdx | HIGH | Add 429 response |
| 4 | guides/quick-reference.mdx | MEDIUM | Add `--github-token` examples |
| 5 | guides/agent-security/reference.mdx | MEDIUM | Add `RAFTER_GITHUB_TOKEN` env var |
| 6 | quickstart.mdx | MEDIUM | Add local scanning section |
