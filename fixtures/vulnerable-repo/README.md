# Rafter Fixture: Vulnerable Repository

A curated test repository with **intentionally planted vulnerabilities** for
validating Rafter's secret scanning and command interception.

**All secrets are fake.** They exist solely to trigger Rafter's detection patterns.

## Usage

```bash
# Scan with Rafter regex scanner
rafter scan local ./fixtures/vulnerable-repo

# Scan with Gitleaks engine
rafter scan local ./fixtures/vulnerable-repo --engine gitleaks

# Scan with built-in patterns engine (tests all 21+ patterns)
rafter scan local ./fixtures/vulnerable-repo --engine patterns

# Expected: 27+ findings across all severity levels
```

## Coverage Matrix

### Built-in Secret Patterns (24 findings)

| # | Pattern | Severity | File | Line |
|---|---------|----------|------|------|
| 1 | AWS Access Key ID | critical | src/cloud.py | 4 |
| 2 | AWS Secret Access Key | critical | src/cloud.py | 5 |
| 3 | GitHub Personal Access Token | critical | config/tokens.yml | 3 |
| 4 | GitHub OAuth Token | critical | config/tokens.yml | 4 |
| 5 | GitHub App Token (ghu_) | critical | config/tokens.yml | 5 |
| 6 | GitHub App Token (ghs_) | critical | config/tokens.yml | 6 |
| 7 | GitHub Refresh Token | critical | config/tokens.yml | 7 |
| 8 | Google API Key | critical | src/app.js | 3 |
| 9 | Google OAuth Client ID | critical | src/app.js | 4 |
| 10 | Slack Token | critical | config/tokens.yml | 10 |
| 11 | Slack Webhook | high | src/notify.py | 4 |
| 12 | Stripe API Key (live) | critical | config/payments.env | 2 |
| 13 | Stripe Restricted API Key | critical | config/payments.env | 3 |
| 14 | Twilio API Key | critical | src/app.js | 7 |
| 15 | Private Key (RSA) | critical | config/server.key | 1 |
| 16 | Private Key (EC) | critical | config/ec.key | 1 |
| 17 | Private Key (OPENSSH) | critical | config/deploy.key | 1 |
| 18 | Database Connection String (postgres) | critical | src/cloud.py | 8 |
| 19 | Database Connection String (mongodb) | critical | infra/docker-compose.yml | 7 |
| 20 | Database Connection String (mysql) | critical | infra/docker-compose.yml | 14 |
| 21 | npm Access Token | critical | config/tokens.yml | 13 |
| 22 | PyPI Token | critical | config/tokens.yml | 15 |
| 23 | Generic API Key | high | src/app.js | 10 |
| 24 | Generic Secret | high | src/app.js | 11 |
| 25 | Bearer Token | high | src/cloud.py | 11 |
| 26 | JSON Web Token | high | src/app.js | 14 |

### Custom Patterns (from .rafter.yml)

| # | Pattern | Severity | File | Line |
|---|---------|----------|------|------|
| 27 | Internal Service Token | critical | src/app.js | 17 |
| 28 | Fixture DB Password | high | infra/docker-compose.yml | 15 |

## Command Interception Fixtures

`scripts/deploy.sh` contains commands across all 4 risk tiers for testing
Rafter's command interception engine:

| Tier | Examples |
|------|----------|
| Low (always allowed) | `npm install`, `git status`, `ls -la` |
| Medium (contextual) | `sudo systemctl restart`, `chmod`, `docker run` |
| High (requires approval) | `npm publish`, `git push --force`, `curl -X DELETE` |
| Critical (always blocked) | `rm -rf /`, `dd if=/dev/zero`, fork bomb |

## Policy Fixture

`.rafter.yml` demonstrates custom policy configuration:
- `approve-dangerous` mode for command interception
- 3 blocked patterns (destructive commands)
- 3 approval-required patterns (publish/force-push/delete)
- 2 custom secret patterns (internal service token, fixture DB password)
- Scan exclusion paths (`node_modules/`, `.git/`, `vendor/`)

## Realistic Misconfigurations

- `.gitignore` intentionally omits `.env`, `*.key`, and `tokens.yml` —
  a common mistake that causes secrets to be committed to version control
