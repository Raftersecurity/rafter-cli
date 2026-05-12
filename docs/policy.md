# Policy Enforcement

Execute shell commands through a risk-assessment layer. Route commands through
`rafter agent exec` to enforce policy on destructive operations.

## Command interception

```sh
rafter agent exec "npm install"                    # low risk → runs immediately
rafter agent exec "git commit -m 'Add feature'"    # scans staged files first
rafter agent exec "sudo rm /tmp/old-files"         # high risk → requires approval
rafter agent exec "rm -rf /"                       # critical → blocked
```

| Risk | Action | Examples |
|------|--------|----------|
| Critical | Blocked | `rm -rf /`, fork bombs, `dd` to device, `mkfs` |
| High | Approval required | `rm -rf`, `sudo rm`, `chmod 777`, `curl\|sh`, `git push --force`, `npm publish` |
| Medium | Approval on moderate+ | `sudo`, `chmod`, `kill -9`, `systemctl` |
| Low | Allowed | `npm install`, `git commit`, `ls`, `cat` |

For git commands (`git commit`, `git push`), Rafter scans staged files for secrets before
execution and blocks if any are found.

## Configuration

```sh
rafter agent config show                                    # view all settings
rafter agent config get agent.riskLevel                     # read a value
rafter agent config set agent.riskLevel aggressive          # write a value
rafter agent config set agent.commandPolicy.mode deny-list  # dot-notation paths
```

**Risk levels:** `minimal` (guidance only) · `moderate` (default) · `aggressive`

**Command policies:** `allow-all` · `approve-dangerous` (default) · `deny-list`

Config lives at `~/.rafter/config.json`. Project-level overrides via `.rafter.yml`.

## Policy file (`.rafter.yml`)

Drop a `.rafter.yml` in your project root to define per-repo security policies.
The CLI walks from cwd to git root looking for it.

```yaml
version: "1"
risk_level: moderate
command_policy:
  mode: approve-dangerous
  blocked_patterns: ["rm -rf /"]
  require_approval: ["npm publish"]
scan:
  exclude_paths: ["vendor/", "third_party/"]
  custom_patterns:
    - name: "Internal API Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
audit:
  retention_days: 90
  log_level: info
```

Policy file values override `~/.rafter/config.json`. Arrays replace (not append).
