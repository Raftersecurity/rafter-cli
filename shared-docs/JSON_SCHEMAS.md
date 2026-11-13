# JSON Output Reference

[CLI_SPEC.md](CLI_SPEC.md) is the canonical behavior reference. This document
records observed outputs and does not introduce compatibility guarantees.

The examples below were captured from Rafter CLI **0.11.7**, revision
`1ebad941815d91d45d7befe3295d15f23a8b05ad`, in both Node and Python.
The local scan, audit, configuration, and policy cases were replayed
against this source using fresh fixtures and isolated profiles. Additional
local command, hook and MCP captures use the same revision. A November 10
backend capture adds submission, queued/processing, completed-result and quota
examples from one authorized Fast scan, with the same result read by both CLIs.

This initial contribution documents the captured outputs listed below. Sites CLI
and Sites MCP response shapes, and unobserved backend variants, are explicitly
deferred. The pending coverage section identifies the evidence still needed;
this reference does not claim full command coverage or new stability guarantees.

## Contents

- [Coverage](#coverage)
- [Reading the field tables](#reading-the-field-tables)
- [Local secret scans](#local-secret-scans)
- [Audit JSONL](#audit-jsonl)
- [Configuration](#configuration)
- [Claude policy export](#claude-policy-export)
- [Agent status and verification](#agent-status-and-verification)
- [Component inventory and baselines](#component-inventory-and-baselines)
- [Skill inventories and review reports](#skill-inventories-and-review-reports)
- [Project document outputs](#project-document-outputs)
- [Security gate map](#security-gate-map)
- [Local usage counters](#local-usage-counters)
- [Hook protocol outputs](#hook-protocol-outputs)
- [MCP tool and resource results](#mcp-tool-and-resource-results)
- [Watch output framing](#watch-output-framing)
- [Hosted Fast scan and quota responses](#hosted-fast-scan-and-quota-responses)
- [Pending coverage and evidence](#pending-coverage-and-evidence)

## Coverage

| Output family | Entry points | Status |
|---|---|---|
| Local scan JSON | `secrets --json`, `secrets --format json`; deprecated `agent scan` and `scan local` spellings | Documented below; clean, finding, suppression, unreadable-file and fallback cases captured in both runtimes |
| Audit events | `~/.rafter/audit.jsonl`; consumed by `agent audit` and MCP | Documented below as JSONL storage, not an `agent audit --json` command |
| Configuration JSON | `agent config show`; object-valued `agent config get` | Documented below with runtime variants |
| Claude policy export | `policy export --format claude` | Documented below; Codex output is TOML |
| Agent inventory/status | `agent list --json`, `agent status --json`, `agent verify --json`, `agent baseline show --json` | Documented below; actual fresh/populated and filtered cases |
| Skills | `skill list --json`, `skill review --json` / `--format json`, deprecated `agent audit-skill --json` | Documented below; local, multi-skill, installed and empty cases |
| Docs, gates, counters | `docs list --json`, `docs show --json`, `gates --json`, `counters show --json` | Documented below; actual local-file/code/counter fixtures |
| Hook protocols | `hook pretool`, `hook posttool`, platform-specific JSON envelopes | Documented below; actual neutral/deny/redaction formats |
| Local MCP | Seven tools and three resources | Seven real local tools and three resources captured in both runtimes |
| Backend scan CLI | `run --format json`, `get --format json`, `usage`; remote aliases | One actual Python run, paired Node/Python retrieval and before/after quota; aliases share source-traced and offline-rehearsed routing |
| Backend Sites CLI | Sites create/scan/list/get | Pending authorized captures; published endpoint definitions alone do not establish real output |
| Backend MCP | `sites_create`, `sites_scan`, `sites_list`, `sites_get` | Pending the same backend evidence |

## Reading the field tables

`[]` denotes each array element. A dotted path names a field inside its parent
object, not a literal key containing dots. A field marked conditional is absent
unless its stated condition applies; absence and JSON `null` are different.
Arrays may be empty. A JSON type describes the serialized value, not a promise
that every consumer can parse an entire command stream as one JSON document.

**Stability:** `U` means **unspecified**: the version's writer and captures
establish the shape, but no field-level compatibility guarantee is asserted.
The existing [exit-code contract](CLI_SPEC.md#exit-codes) remains explicit and
stable. Preserve any other guarantee where the spec states it; do not infer
stability merely because the same field appears in Node and Python.

The local examples came from real Node 24.16.0 and Python 3.13.2 executions
on Windows, with isolated profiles and built-in pattern scanning. They are not
mocked backend responses. Additional Python MCP examples use Python 3.12.3 in
Ubuntu WSL; their runtime and SDK differences are identified below. Paths
alone were sanitized in those local examples: `<fixture>` replaces the fixture
root, `<home>` replaces the scratch profile, and path separators become `/`.
Those tokens are explanatory strings, not literal paths to copy. Keys, array
contents, timestamps, session identifiers, redactions, numbers and nulls remain
as captured. Audit examples containing paths cannot be used to recompute the
original raw-byte chain hashes after sanitization.

## Local secret scans

```sh
rafter secrets clean.txt --json --engine patterns --no-auto-update
rafter secrets finding.txt --format json --engine patterns --no-auto-update
rafter agent scan finding.txt --json --engine patterns --no-auto-update
rafter scan local finding.txt --json --engine patterns --no-auto-update
```

The last two spellings are deprecated aliases. The clean/finding captures for
all three spellings produced the same JSON objects in both runtimes. This does
not imply that every alias accepts every newer flag; the file-output example
below uses `secrets`.

For these examples `clean.txt` contains ordinary text, while `finding.txt`
contains `aws_access_key_id = AKIAIOSFODNN7ABCDEFG` followed by a newline.
That is the deliberately fake fixture value. The match begins at column 21.

A successful JSON scan writes one object to stdout. Scan status/warnings go to
stderr. Exit 0 means clean and complete, exit 1 means retained findings, and
exit 2 means a runtime error or incomplete scan without retained findings.
Findings take precedence when some other files are unreadable. Do not discard
an exit-1 JSON body as though it were a process crash.

### Clean and finding examples

Clean fixture, exit 0; both runtimes agreed:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false
}
```

Fake-key fixture, exit 1; both runtimes agreed:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [
    {
      "file": "<fixture>/project/finding.txt",
      "matches": [
        {
          "pattern": {
            "name": "AWS Access Key ID",
            "severity": "critical",
            "description": "AWS Access Key ID detected"
          },
          "line": 1,
          "column": 21,
          "redacted": "AKIA************DEFG"
        }
      ]
    }
  ],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `_note` | string | Always in this wrapper | Explains local-only detection and absence of contextual backend triage; not a machine-readable finding | U; paired scan writers |
| `scan_mode` | string | Always; `"local"` here | Distinguishes these results from hosted scan payloads | U; paired scan writers |
| `triage_applied` | boolean | Always; `false` here | Local results have not received backend agentic triage | U; paired scan writers |
| `results` | array of objects | Always; empty when no retained findings | Files containing non-suppressed findings, not an inventory of all files scanned | U; paired scan writers |
| `results[].file` | string | Each result | File path; captured invocations returned absolute Windows paths | U; paired scan writers |
| `results[].matches` | array of objects | Each result | Findings in that file | U; paired scan writers |
| `results[].matches[].pattern` | object | Each match | Rule identity and severity | U; paired scan writers |
| `results[].matches[].pattern.name` | string | Each match | Pattern/rule name | U; paired scan writers |
| `results[].matches[].pattern.severity` | string | Each match | Rule severity; built-in levels are `low`, `medium`, `high`, `critical` | U; pattern definitions and writers |
| `results[].matches[].pattern.description` | string | Each match | Description, with `""` when the rule has no description | U; paired scan writers |
| `results[].matches[].line` | number or null | Each match | One-based source line, or null if unavailable | U; paired scan writers |
| `results[].matches[].column` | number or null | Each match | One-based source column, or null if unavailable | U; paired scan writers |
| `results[].matches[].redacted` | string | Each match | Redacted representation; the raw matched secret is not a scan-output field | U; paired scan writers |
| `results[].matches[].engines` | array of strings | Conditional, auto-mode union findings | Engine provenance, such as `patterns` / `betterleaks`; source-traced, not captured with both engines here | U; union/writer paths |
| `engine_requested` | string | Always in one-shot scan JSON; omitted in watch objects | Requested `patterns`, `betterleaks`, or `auto` | U; engine-report writers |
| `engine_used` | string | Always in one-shot scan JSON; omitted in watch objects | Resolved `patterns`, `betterleaks`, or `both` | U; engine-report writers |
| `degraded` | boolean | Always in one-shot scan JSON; omitted in watch objects | Requested Betterleaks contribution was unavailable or failed | U; engine-report writers |
| `degraded_reason` | string | Degraded report with a nonempty reason | Explanation of fallback, not a stable error-code enum | U; engine-report writers |
| `_suppressed` | array of objects | Only when findings were hidden | Suppressed finding metadata, described below | U; suppression writers |
| `unreadable` | array of objects | Only when file reads failed | Incomplete scan metadata, described below | U; paired scan writers |

`engine_requested`, `engine_used` and `degraded` are always present in the
JSON result of a one-shot local scan. The current watch-mode writers omit
these three fields; see [watch output framing](#watch-output-framing).

### Suppression metadata

The fixture policy was:

```yaml
ignore:
  - paths: ["finding.txt"]
    rules: ["AWS Access Key ID"]
    reason: "Documentation fixture with an obviously fake key"
```

The real scan returned exit 0 in both runtimes, with the retained results empty:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false,
  "_suppressed": [
    {
      "file": "<fixture>/suppressed/finding.txt",
      "line": 1,
      "column": 21,
      "rule": "AWS Access Key ID",
      "severity": "critical",
      "reason": "Documentation fixture with an obviously fake key",
      "source": ".rafter.yml"
    }
  ]
}
```

A legacy `.rafterignore` containing `finding.txt` instead yielded `source`
`".rafterignore"` and `reason: null`, also with exit 0:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false,
  "_suppressed": [
    {
      "file": "<fixture>/legacy/finding.txt",
      "line": 1,
      "column": 21,
      "rule": "AWS Access Key ID",
      "severity": "critical",
      "reason": null,
      "source": ".rafterignore"
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `_suppressed[].file` | string | Each suppressed finding | File containing the hidden finding | U; paired suppression writers |
| `_suppressed[].line` | number or null | Each suppressed finding | One-based line, or null when unavailable | U; paired suppression writers |
| `_suppressed[].column` | number or null | Each suppressed finding | One-based column, or null when unavailable | U; paired suppression writers |
| `_suppressed[].rule` | string | Each suppressed finding | Rule name, unlike the nested `pattern` object in retained matches | U; paired suppression writers |
| `_suppressed[].severity` | string | Each suppressed finding | Severity of the hidden finding | U; paired suppression writers |
| `_suppressed[].reason` | string or null | Each suppressed finding | Policy explanation, or null when none was supplied | U; paired suppression writers |
| `_suppressed[].source` | string | Each suppressed finding | `.rafter.yml` or `.rafterignore` for these local cases | U; paired suppression writers |

`_suppressed` is absent when nothing was suppressed. Suppressed findings do not
by themselves produce exit 1. Hosted suppression artifacts have additional
fields and are not established by these local examples.

### Unreadable files, missing paths, and fallback

For an existing fixture held open with an exclusive Windows file handle, Node
returned exit 2 with the following real read error:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false,
  "unreadable": [
    {
      "file": "<fixture>/project/unreadable.txt",
      "error": "EBUSY"
    }
  ]
}
```

Python returned exit 2 for the same fixture with its own error wording:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "patterns",
  "engine_used": "patterns",
  "degraded": false,
  "unreadable": [
    {
      "file": "<fixture>/project/unreadable.txt",
      "error": "permission denied"
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `unreadable[].file` | string | Each failed read | File that could not be read | U; paired scan writers |
| `unreadable[].error` | string | Each failed read | Platform/runtime reason, such as captured `EBUSY` or `permission denied`; do not treat wording as an enum | U; paired scanners/writers |

Both runtimes returned exit 1 when a retained finding and an unreadable file
were supplied together. A nonexistent input path failed earlier, with exit 2;
do not assume every scan failure provides this wrapper or a JSON error object.

Requesting an unavailable Betterleaks engine with auto-update disabled produced
real fallback output without installing an engine:

```json
{
  "_note": "Local-only scan: pattern-based detection without agentic-intelligence triage. Findings have not been evaluated for context (public exposure, key validity, deployment environment). Investigate each before acting; do not dismiss. Run 'rafter run' for backend agentic analysis.",
  "scan_mode": "local",
  "triage_applied": false,
  "results": [],
  "engine_requested": "betterleaks",
  "engine_used": "patterns",
  "degraded": true,
  "degraded_reason": "betterleaks requested but not available"
}
```

The capture above is Node's wording. Python also reported requested
`betterleaks`, used `patterns`, and `degraded: true`; human-readable reason
wording is implementation detail. No successful Betterleaks-only or dual-engine
example is claimed here.

### Output boundaries

`rafter secrets finding.txt --json --engine patterns --no-auto-update --out scan.json`
wrote the wrapper to the requested file in both runtimes, returned exit 1 for
the finding, and left stdout empty. Status remained on stderr. Parse the file,
not stdout, for that invocation. Text and SARIF are separate formats; an
explicit SARIF selection follows the SARIF writer even when `--json` is also
present. Watch mode is a stream of scan updates rather than a single terminal
JSON document; see [Watch output framing](#watch-output-framing) for
the additional bounded real captures and mixed-stdout boundary.

Source: Node [scan output writer](../node/src/commands/agent/scan.ts),
[suppression metadata](../node/src/core/custom-patterns.ts), and
[scan result type](../node/src/scanners/regex-scanner.ts); Python
[scan output writer](../python/rafter_cli/commands/agent.py),
[suppression metadata](../python/rafter_cli/core/custom_patterns.py), and
[scan result type](../python/rafter_cli/scanners/regex_scanner.py).

## Audit JSONL

The normal storage path is `~/.rafter/audit.jsonl`, subject to the runtime's
global audit-path configuration. Each nonempty line is a separate JSON object;
the file is not a JSON array. `rafter agent audit` presents human-readable
output. **`rafter agent audit --json` is unsupported**: the actual captures
returned Node exit 1 and Python exit 2. Do not use it to generate an example.

These first-record examples were written by actual clean scans into fresh
scratch profiles. Node omitted an unresolved `gitRepo`:

```jsonl
{"eventType":"scan_executed","securityCheck":{"passed":true,"reason":"Secret scan completed with no findings","details":{"filesWithFindings":0,"totalMatches":0,"patterns":[]}},"resolution":{"actionTaken":"allowed"},"cwd":"<fixture>/project","prevHash":null,"timestamp":"2026-11-04T03:20:44.609Z","sessionId":"1793762444581-40a18ca95104e758"}
```

Python serialized that absence as null:

```jsonl
{"timestamp":"2026-11-04T03:21:29.551461+00:00","sessionId":"1793762489550-761f05c4","cwd":"<fixture>/project","gitRepo":null,"prevHash":null,"eventType":"scan_executed","securityCheck":{"passed":true,"reason":"Secret scan completed with no findings","details":{"filesWithFindings":0,"totalMatches":0,"patterns":[]}},"resolution":{"actionTaken":"allowed"}}
```

### Logger-managed and event-specific fields

These are the normal logger-managed fields and known event payloads. They are
an observed writer reference, not runtime JSON validation: the generic logger
accepts caller-provided event dictionaries/objects. In particular, CLI_SPEC
describes `securityCheck` and `resolution` as required, while the Node interface
and generic writer permit their absence. The known scan/convenience events
below include them; do not silently extend that observation to arbitrary events.

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `timestamp` | string | Normal logger-managed field | UTC ISO 8601 event time; Node uses `Z`, Python uses `+00:00` in the captures | U; paired audit writers |
| `sessionId` | string | Normal logger-managed field | Opaque identifier generated per logger instance; do not parse or depend on random-suffix length | U; paired audit writers |
| `eventType` | string | Event input | Known names: `command_intercepted`, `secret_detected`, `content_sanitized`, `policy_override`, `scan_executed`, `config_changed` | U; event writers/types |
| `cwd` | string | Normal logger-managed field | Supplied or process working directory | U; paired audit writers |
| `gitRepo` | string or null | Node omits if unresolved; Python emits null | Enclosing Git root when found | U; paired audit writers |
| `prevHash` | string or null | Normal logger-managed field | SHA-256 link to the previous stored nonempty line, including its line ending; null for the first entry | U; paired audit writers |
| `agentType` | string or null | Event-dependent; Node can omit, Python convenience methods can emit null | Agent label; examples use `claude-code` when supplied | U; event writers |
| `action` | object | Event-dependent | Action metadata, not present on every event | U; event writers |
| `action.command` | string | Command-interception / some override events | Redacted command string in the convenience command logger | U; event writers |
| `action.tool` | string | When supplied by caller | Tool name | U; source-traced field |
| `action.riskLevel` | string | When classified | `low`, `medium`, `high`, or `critical` | U; event writers |
| `securityCheck` | object | Known scan/convenience events; generic writer permits absence | Check result | U; event writers; see spec difference above |
| `securityCheck.passed` | boolean | In a check object | Whether that security check passed | U; event writers |
| `securityCheck.reason` | string or null | Event-dependent; Node can omit, Python convenience call can emit null | Explanation | U; event writers |
| `securityCheck.details` | object for the known events below | Event-dependent | Event-specific structured information; generic writer does not constrain its JSON value | U; event writers |
| `resolution` | object | Known scan/convenience events; generic writer permits absence | Resulting disposition | U; event writers; see spec difference above |
| `resolution.actionTaken` | string | In known resolution objects | `allowed`, `blocked`, `overridden`, or `redacted` | U; event writers |
| `resolution.overrideReason` | string | Policy override when supplied | User's override explanation | U; source-traced field |
| `securityCheck.details.filesWithFindings` | number | `scan_executed` | Count of files with retained findings | U; paired scan audit writers |
| `securityCheck.details.totalMatches` | number | `scan_executed` | Count of retained findings | U; paired scan audit writers |
| `securityCheck.details.patterns` | array of strings | `scan_executed` | Sorted unique pattern names, not matched values | U; paired scan audit writers |
| `securityCheck.details.context` | string | Scan mode supplies context | Scan context label | U; source-traced conditional field |
| `securityCheck.details.contentType` | string | Convenience `content_sanitized` | Kind of content sanitized | U; paired convenience writers |
| `securityCheck.details.patternsMatched` | number | Convenience `content_sanitized` | Number of sensitive-pattern matches | U; paired convenience writers |
| `securityCheck.details.file` | string | Watch-mode secret event | File with the finding | U; source-traced watch path |
| `securityCheck.details.line` | number or null | Watch-mode secret event | Finding line when available | U; source-traced watch path |
| `securityCheck.details.pattern` | string | Watch-mode secret event | Pattern name | U; source-traced watch path |
| `securityCheck.details.severity` | string | Watch-mode secret event | Finding severity | U; source-traced watch path |
| `securityCheck.details.watchMode` | boolean | Watch-mode secret event | `true` for this path | U; source-traced watch path |

An actual call to each runtime's `AuditLogger` command convenience method,
with controlled input `echo documentation`, `passed=true`, action `allowed`,
and no reason/agent, wrote these first records. The command string was logged,
not executed. Node omitted the absent optional reason/agent:

```json
{
  "eventType": "command_intercepted",
  "action": {
    "command": "echo documentation",
    "riskLevel": "low"
  },
  "securityCheck": {
    "passed": true
  },
  "resolution": {
    "actionTaken": "allowed"
  },
  "cwd": "<fixture>/project",
  "prevHash": null,
  "timestamp": "2026-11-04T03:22:36.583Z",
  "sessionId": "1793762556578-140757959f16cc45"
}
```

Python emitted null values for them:

```json
{
  "timestamp": "2026-11-04T03:22:46.352528+00:00",
  "sessionId": "1793762566339-43d2bc6d",
  "cwd": "<fixture>/project",
  "gitRepo": null,
  "prevHash": null,
  "eventType": "command_intercepted",
  "agentType": null,
  "action": {
    "command": "echo documentation",
    "riskLevel": "low"
  },
  "securityCheck": {
    "passed": true,
    "reason": null
  },
  "resolution": {
    "actionTaken": "allowed"
  }
}
```

The captures also exercised the real secret-detected and content-sanitized
convenience methods with fixture inputs. The watch, policy-override and
config-changed paths remain source-traced here; no captured example for those
paths is claimed. Scan audit entries contain counts and rule names, not raw
matched credentials.

### Hash-chain and byte handling

Verify the stored bytes, not re-indented or sanitized examples. The Node scan
capture used LF and its CLI `agent audit --verify` returned exit 0. The Python
Windows scan capture used CRLF: all stored links matched the preceding raw
line bytes, but its CLI verifier returned exit 1 with 12 breaks because its
text read normalizes CRLF before verification. This version/platform
limitation is not evidence that the newly generated fixture log was modified.
Do not claim that the captured Python CLI verification passed.

Source: [Node audit logger](../node/src/core/audit-logger.ts),
[Python audit logger](../python/rafter_cli/core/audit_logger.py), and the paired
scan writers linked above. See [Audit Log Schema](CLI_SPEC.md#audit-log-schema)
for retention and configuration behavior. The logger's retention sidecar is
a separate maintenance artifact, not an event in this JSONL stream.

## Configuration

```sh
rafter agent config show
rafter agent config get agent.audit
```

`show` prints one JSON object, with credential-named string values masked.
It loads global configuration/defaults, not the effective project-policy merge.
Node serializes its camelCase structure; Python `show` uses dataclass names in
snake_case. These are runtime variants, not two spellings to rewrite in the
same captured object. `version` is the configuration schema version, not the
CLI package version.

### Complete controlled-configuration examples

The following examples are actual `show` output from separately prepared
scratch configurations. To keep the command-policy arrays readable, the
fixtures explicitly stored only `^DOC_BLOCKED$`, `^DOC_APPROVAL$`, and
`^DOC_SAFE$` in the blocked, approval and allowed lists. They also stored an
obviously fake backend key and one custom local pattern. These are controlled
fixture settings, **not the factory command-policy defaults or installed
integration state**. No backend request was made.

Node:

```json
{
  "version": "1.0.0",
  "initialized": "2026-11-04T03:22:28.239Z",
  "backend": {
    "endpoint": "https://rafter.so/api/",
    "apiKey": "exam****"
  },
  "agent": {
    "riskLevel": "moderate",
    "environments": {
      "openclaw": {
        "enabled": false,
        "skillPath": "<home>/.openclaw/skills/rafter-security.md"
      },
      "claudeCode": {
        "enabled": false,
        "mcpPath": "<home>/.claude/mcp/rafter-security.json"
      },
      "codex": {
        "enabled": false,
        "skillsDir": "<home>/.agents/skills"
      },
      "gemini": {
        "enabled": false,
        "configPath": "<home>/.gemini/settings.json"
      },
      "aider": {
        "enabled": false,
        "configPath": "<home>/.aider.conf.yml"
      },
      "cursor": {
        "enabled": false,
        "mcpPath": "<home>/.cursor/mcp.json"
      },
      "windsurf": {
        "enabled": false,
        "mcpPath": "<home>/.codeium/windsurf/mcp_config.json"
      },
      "continueDev": {
        "enabled": false,
        "configPath": "<home>/.continue/config.json"
      }
    },
    "skills": {
      "autoUpdate": true,
      "installOnInit": true,
      "backupBeforeUpdate": true
    },
    "commandPolicy": {
      "mode": "approve-dangerous",
      "blockedPatterns": [
        "^DOC_BLOCKED$"
      ],
      "requireApproval": [
        "^DOC_APPROVAL$"
      ],
      "allowedPatterns": [
        "^DOC_SAFE$"
      ],
      "allowProjectOverride": false
    },
    "outputFiltering": {
      "redactSecrets": true,
      "blockPatterns": true
    },
    "audit": {
      "logAllActions": true,
      "retentionDays": 30,
      "logLevel": "info"
    },
    "notifications": {
      "minRiskLevel": "high"
    },
    "scan": {
      "customPatterns": [
        {
          "name": "Documentation marker",
          "regex": "DOC_FIXTURE_[0-9]+",
          "severity": "low"
        }
      ]
    }
  }
}
```

Python:

```json
{
  "version": "1.0.0",
  "initialized": "2026-11-04T03:22:38.156048+00:00",
  "backend": {
    "api_key": "exam****",
    "endpoint": "https://rafter.so/api/"
  },
  "agent": {
    "risk_level": "moderate",
    "environments": {
      "openclaw": {
        "enabled": false,
        "path": "<home>/.openclaw/skills/rafter-security.md"
      },
      "claude_code": {
        "enabled": false,
        "path": "<home>/.claude/mcp/rafter-security.json"
      },
      "codex": {
        "enabled": false,
        "path": "<home>/.agents/skills"
      },
      "gemini": {
        "enabled": false,
        "path": "<home>/.gemini/settings.json"
      },
      "aider": {
        "enabled": false,
        "path": "<home>/.aider.conf.yml"
      },
      "cursor": {
        "enabled": false,
        "path": "<home>/.cursor/mcp.json"
      },
      "windsurf": {
        "enabled": false,
        "path": "<home>/.codeium/windsurf/mcp_config.json"
      },
      "continue_dev": {
        "enabled": false,
        "path": "<home>/.continue/config.json"
      }
    },
    "skills": {
      "auto_update": true,
      "install_on_init": true,
      "backup_before_update": true,
      "installed_version": null,
      "last_checked": null
    },
    "command_policy": {
      "mode": "approve-dangerous",
      "blocked_patterns": [
        "^DOC_BLOCKED$"
      ],
      "require_approval": [
        "^DOC_APPROVAL$"
      ],
      "allow_project_override": false,
      "allowed_patterns": [
        "^DOC_SAFE$"
      ]
    },
    "output_filtering": {
      "redact_secrets": true,
      "block_patterns": true
    },
    "audit": {
      "log_all_actions": true,
      "retention_days": 30,
      "log_level": "info",
      "log_path": null
    },
    "notifications": {
      "webhook": null,
      "min_risk_level": "high"
    },
    "scan": {
      "exclude_paths": [],
      "custom_patterns": [
        {
          "name": "Documentation marker",
          "regex": "DOC_FIXTURE_[0-9]+",
          "severity": "low"
        }
      ],
      "ignore": [],
      "auto_update_betterleaks": true,
      "plus_requires_approval": false,
      "ignore_base_dir": null
    },
    "hooks": {
      "enabled": null,
      "secret_scan": null,
      "command_policy": null
    },
    "usage": {
      "enabled": null
    },
    "components": {}
  }
}
```

### Known fields and runtime naming

In the table below, **D** means present in that runtime's fresh-default capture,
**O** means optional/configured and not necessarily present, and **D-null**
means the fresh Python default includes a JSON null. These are presence
observations, not newly promised cross-version requirements. Node may retain
additional configured keys; neither table defines a closed JSON Schema.

| Node field path | Python field path | JSON type | Presence / condition and meaning | Stability |
|---|---|---|---|---|
| `version` | `version` | string | D/D; config schema version, captured as `1.0.0` | U; config schemas/defaults |
| `initialized` | `initialized` | string | D/D; stored or default-config creation time; a fresh unstored default can regenerate this timestamp | U; config schemas/defaults |
| `backend` | `backend` | object | D/D; backend connection settings, not a usage/scan response | U; config schemas/defaults |
| `backend.endpoint` | `backend.endpoint` | string | D/D; API endpoint URL | U; config schemas/defaults |
| `backend.apiKey` | `backend.api_key` | string; Python also null | O/D-null; masked if a credential string is configured | U; config schemas/redactor |
| `agent` | `agent` | object | D/D; local agent settings | U; config schemas/defaults |
| `agent.riskLevel` | `agent.risk_level` | string | D/D; `minimal`, `moderate`, or `aggressive` | U; config schemas |
| `agent.environments` | `agent.environments` | object | D/D; platform entries in the next table | U; config schemas/defaults |
| `agent.skills` | `agent.skills` | object | D/D; skill-management preferences | U; config schemas/defaults |
| `agent.skills.autoUpdate` | `agent.skills.auto_update` | boolean | D/D; auto-update preference | U; config schemas |
| `agent.skills.installOnInit` | `agent.skills.install_on_init` | boolean | D/D; installation-on-init preference, not proof an install occurred | U; config schemas |
| `agent.skills.backupBeforeUpdate` | `agent.skills.backup_before_update` | boolean | D/D; backup preference | U; config schemas |
| `agent.skills.installedVersion` | `agent.skills.installed_version` | string; Python also null | O/D-null; recorded installed skill version | U; source-traced optional metadata |
| `agent.skills.lastChecked` | `agent.skills.last_checked` | string; Python also null | O/D-null; recorded last-check timestamp | U; source-traced optional metadata |
| `agent.commandPolicy` | `agent.command_policy` | object | D/D; command-risk policy | U; config schemas |
| `agent.commandPolicy.mode` | `agent.command_policy.mode` | string | D/D; `allow-all`, `approve-dangerous`, or `deny-list` | U; config schemas |
| `agent.commandPolicy.blockedPatterns` | `agent.command_policy.blocked_patterns` | array of strings | D/D; blocked-command regexes | U; config schemas |
| `agent.commandPolicy.requireApproval` | `agent.command_policy.require_approval` | array of strings | D/D; approval-triggering regexes | U; config schemas |
| `agent.commandPolicy.allowedPatterns` | `agent.command_policy.allowed_patterns` | array of strings | D/D; opt-in allowlist, subject to runtime safety rules | U; config schemas |
| `agent.commandPolicy.allowProjectOverride` | `agent.command_policy.allow_project_override` | boolean | O/D; owner permission for project policy to loosen command rules | U; config schemas |
| `agent.outputFiltering` | `agent.output_filtering` | object | D/D; output-filter preferences | U; config schemas |
| `agent.outputFiltering.redactSecrets` | `agent.output_filtering.redact_secrets` | boolean | D/D; redaction preference | U; config schemas |
| `agent.outputFiltering.blockPatterns` | `agent.output_filtering.block_patterns` | boolean | D/D; blocking preference | U; config schemas |
| `agent.audit` | `agent.audit` | object | D/D; audit preferences | U; config schemas |
| `agent.audit.logAllActions` | `agent.audit.log_all_actions` | boolean | D/D; logging enabled | U; config schemas |
| `agent.audit.retentionDays` | `agent.audit.retention_days` | number | D/D; retention interval, captured as 30 | U; config schemas/validators |
| `agent.audit.logLevel` | `agent.audit.log_level` | string | D/D; `debug`, `info`, `warn`, or `error`; stored preference | U; config schemas |
| `agent.audit.logPath` | `agent.audit.log_path` | string; Python also null | O/D-null; global log-path override | U; source-traced optional field |
| `agent.notifications` | `agent.notifications` | object | D/D; notification preferences | U; config schemas |
| `agent.notifications.webhook` | `agent.notifications.webhook` | string; Python also null | O/D-null; configured webhook URL, absent/unset in these captures | U; source-traced optional field |
| `agent.notifications.minRiskLevel` | `agent.notifications.min_risk_level` | string | D/D; `high` or `critical` notification threshold | U; config schemas |
| `agent.scan` | `agent.scan` | object | O/D; local scan settings | U; config schemas |
| `agent.scan.excludePaths` | `agent.scan.exclude_paths` | array of strings | O/D; scan exclusions | U; config schemas |
| `agent.scan.customPatterns` | `agent.scan.custom_patterns` | array of objects | O/D; configured additional patterns | U; config schemas |
| `agent.scan.customPatterns[].name` | `agent.scan.custom_patterns[].name` | string | Each custom pattern; display name | U; config schemas |
| `agent.scan.customPatterns[].regex` | `agent.scan.custom_patterns[].regex` | string | Each custom pattern; regular expression | U; config schemas |
| `agent.scan.customPatterns[].severity` | `agent.scan.custom_patterns[].severity` | string | Each normalized Python pattern; Node permits omission; `low`, `medium`, `high`, `critical` for declared valid patterns | U; config schemas/loaders |
| `agent.scan.ignore` | `agent.scan.ignore` | array of objects | O/D; stored ignore rules; project ignore rules are not merged into `show` | U; config schemas |
| `agent.scan.ignore[].paths` | `agent.scan.ignore[].paths` | array of strings | Each declared ignore rule; path selectors | U; source-traced rule fields |
| `agent.scan.ignore[].rules` | `agent.scan.ignore[].rules` | array of strings; Python also null | Optional rule-name selectors | U; source-traced rule fields |
| `agent.scan.ignore[].reason` | `agent.scan.ignore[].reason` | string; Python also null | Optional suppression explanation | U; source-traced rule fields |
| `agent.scan.autoUpdateBetterleaks` | `agent.scan.auto_update_betterleaks` | boolean | O/D; stale-engine update preference | U; config schemas |
| `agent.scan.plusRequiresApproval` | `agent.scan.plus_requires_approval` | boolean | O/D; paid Plus-scan confirmation gate | U; config schemas |
| `agent.scan.ignoreBaseDir` | `agent.scan.ignore_base_dir` | string; Python also null | Usually absent / D-null; policy merging derives an ignore anchor, but `show` does not perform that merge | U; source-traced runtime field |
| `agent.hooks` | `agent.hooks` | object | O/D; runtime hook controls, not installation records | U; config schemas |
| `agent.hooks.enabled` | `agent.hooks.enabled` | boolean; Python also null | O/D-null; master hook switch; unset defaults to enabled | U; config schemas |
| `agent.hooks.secretScan` | `agent.hooks.secret_scan` | boolean; Python also null | O/D-null; secret-scan switch | U; config schemas |
| `agent.hooks.commandPolicy` | `agent.hooks.command_policy` | boolean; Python also null | O/D-null; command-risk switch | U; config schemas |
| `agent.usage` | `agent.usage` | object | O/D; local counter preferences | U; config schemas |
| `agent.usage.enabled` | `agent.usage.enabled` | boolean; Python also null | O/D-null; local usage switch | U; config schemas |
| `agent.components` | `agent.components` | object | O/D; component-ID map; keys such as `claude-code.hooks` retain their literal spelling | U; component-state schema |
| `agent.components[componentId].enabled` | same | boolean | Each declared component state; installation enable/disable record | U; source-traced component-state field |
| `agent.components[componentId].updatedAt` | same | string | Optional update timestamp; not automatically renamed in Python's raw component map | U; source-traced component-state field |

Each platform value under `agent.environments` is an object with `enabled`
(boolean, D/D) and the following path field (string, D/D). All fields in this
mapping have unspecified field stability, sourced from the paired schemas and
default generators. A configured path does not prove a platform was installed.

| Platform | Node entry and path field | Python entry and path field |
|---|---|---|
| OpenClaw | `openclaw.skillPath` | `openclaw.path` |
| Claude Code | `claudeCode.mcpPath` | `claude_code.path` |
| Codex | `codex.skillsDir` | `codex.path` |
| Gemini | `gemini.configPath` | `gemini.path` |
| Aider | `aider.configPath` | `aider.path` |
| Cursor | `cursor.mcpPath` | `cursor.path` |
| Windsurf | `windsurf.mcpPath` | `windsurf.path` |
| Continue | `continueDev.configPath` | `continue_dev.path` |

### Object-valued get, masking, and scalar boundaries

`agent config get agent.audit` returned this Node JSON:

```json
{
  "logAllActions": true,
  "retentionDays": 30,
  "logLevel": "info"
}
```

The same command returned this Python JSON:

```json
{
  "log_all_actions": true,
  "retention_days": 30,
  "log_level": "info",
  "log_path": null
}
```

The selected object becomes the root; it is not wrapped in `agent.audit`.
Known child fields have the same types/meanings as the table above. Node also
JSON-serializes arrays. Python JSON-serializes dictionaries only: its captured
array `get` output used a Python list representation, not JSON. For the compact
fixture's blocked array, the actual stdout strings were:

```text
Node:   [
          "^DOC_BLOCKED$"
        ]
Python: ['^DOC_BLOCKED$']
```

String/scalar results are not a uniform JSON API. The captured risk setting
printed `moderate` without JSON string quotes; a boolean printed `true` in Node
and `True` in Python. Missing keys returned exit 1 and a stderr message, with
empty stdout. Python also treats a selected null as missing. Node's branch can
serialize a selected null, though that source-only case was not captured here.

Both redactors recursively mask string values whose key names match
`api_?key`, `token`, `secret`, `password`, `passwd`, or `credential`, without
case sensitivity. A string longer than four characters becomes its four-character
prefix plus `****`; shorter or empty credential strings become `****`.
The controlled fake backend key was displayed as `exam****` in both `show` and
direct key `get`. A direct masked-key `get` prints plain text, not a quoted
JSON string. Nulls remain null. Reading config does not return real server data.

Source: Node [config command](../node/src/commands/agent/config.ts),
[manager/redactor](../node/src/core/config-manager.ts),
[schema](../node/src/core/config-schema.ts), and
[defaults](../node/src/core/config-defaults.ts); Python
[config commands](../python/rafter_cli/commands/agent.py),
[manager/redactor](../python/rafter_cli/core/config_manager.py), and
[schema/defaults](../python/rafter_cli/core/config_schema.py).
See [CONFIG.md](CONFIG.md) for the separate project-policy configuration surface.

## Claude policy export

```sh
rafter policy export --format claude
```

Both runtimes printed the same JSON object to stdout and returned exit 0:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "rafter hook pretool"
          }
        ]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "rafter hook pretool"
          }
        ]
      }
    ]
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `hooks` | object | Always in this export | Claude hook configuration fragment | U; paired generators |
| `hooks.PreToolUse` | array of objects | Always; two entries in this version | Tool matchers and their hook actions | U; paired generators |
| `hooks.PreToolUse[].matcher` | string | Each entry | Captured `Bash` and `Write\|Edit\|MultiEdit` matcher values | U; paired generators |
| `hooks.PreToolUse[].hooks` | array of objects | Each entry | Hook actions for that matcher | U; paired generators |
| `hooks.PreToolUse[].hooks[].type` | string | Each action; `command` here | Action kind | U; paired generators |
| `hooks.PreToolUse[].hooks[].command` | string | Each command action | Captured `rafter hook pretool` command | U; paired generators |

This is generated integration configuration, not a serialized copy of the
complete Rafter command-risk policy. Printing it does not install hooks or
modify a real agent's settings. `--format codex` produces TOML rather than JSON.

`--output <path>` selects a separate file-output branch. The Python capture
wrote the same JSON to that file and printed a human-readable success message
on stdout. The captured Node ESM build instead returned exit 1 with
`ReferenceError: require is not defined in ES module scope`; it did not create
the file. That implementation limitation is not a different JSON schema and
does not change the successful stdout example above.

Invalid format selection returned exit 1 in both runtimes without a JSON
error envelope. Node wrote the error to stderr; Python printed its first
human-readable error line to stdout and the valid-format hint to stderr.
Check the exit code before treating stdout as a successful JSON export.

Source: [Node policy export](../node/src/commands/policy/export.ts) and
[Python policy export](../python/rafter_cli/commands/policy.py).

## Agent status and verification

`rafter agent status --json` writes one object and exits 0. A fresh profile is
valid input and reports `installed: false`; `installed` checks the config file,
not whether every hook or agent integration works. Both runtimes returned this
fresh-profile shape:

```json
{
  "installed": false,
  "version": "0.11.7",
  "stale": false,
  "installed_version": null,
  "needs_reconcile": [],
  "agents_detected": [],
  "hooks_installed": [],
  "betterleaks_available": false,
  "config_path": "~/.rafter/config.json",
  "audit_log_path": "~/.rafter/audit.jsonl",
  "hook_control": {
    "hook_enabled": true,
    "secret_scan_enabled": true,
    "command_policy_enabled": true,
    "source": {
      "hook": "default",
      "secret_scan": "default",
      "command_policy": "default"
    }
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `installed` | boolean | Always | Whether the Rafter configuration file exists; not proof every integration works. | U |
| `version` | string | Always | Running CLI package version. | U |
| `stale` | boolean | Always | Whether installed integrations are older than the current CLI. | U |
| `installed_version` | string or null | Always | CLI version from the install manifest; null when absent. | U |
| `needs_reconcile` | array of strings | Always | Modified integration files with pending `.rafter-new` replacements; may be empty. | U |
| `agents_detected` | array of strings | Always | Detected agent environments; detection alone does not mean Rafter is installed. | U |
| `hooks_installed` | array of strings | Always | Detected Rafter Git hooks, such as pre-commit or pre-push. | U |
| `betterleaks_available` | boolean | Always | Runtime detection of a supported/local engine or legacy installation; not a successful scan result. | U |
| `config_path` | string | Always | Configuration location, normally rendered under `~`. | U |
| `audit_log_path` | string | Always | Audit JSONL location, normally rendered under `~`. | U |
| `hook_control` | object | Always | Effective trusted-source hook switches. | U |
| `hook_control.hook_enabled` | boolean | Always | Master hook switch. | U |
| `hook_control.secret_scan_enabled` | boolean | Always | Effective secret-scanning switch. | U |
| `hook_control.command_policy_enabled` | boolean | Always | Effective command-policy switch. | U |
| `hook_control.source` | object | Always | Where each effective switch came from. | U |
| `hook_control.source.hook` | string | Always | Master switch source: default, global-config, or env. | U |
| `hook_control.source.secret_scan` | string | Always | Secret-scan switch source. | U |
| `hook_control.source.command_policy` | string | Always | Command-policy switch source. | U |

`rafter agent verify --json` writes its diagnostic object even when required
checks fail. It exits 1 for hard failures, and 0 when there are none; optional
warnings and version staleness are informational. In the captured fresh profile,
the config and Betterleaks checks failed and the optional agent checks warned.
The expected exit 1 is a verification result, not an unreadable JSON stream.

```json
{
  "checks": [
    {
      "name": "Config",
      "status": "fail",
      "detail": "Not found: <home>/.rafter/config.json"
    },
    {
      "name": "Betterleaks",
      "status": "fail",
      "detail": "Not found on PATH or at <home>/.rafter/bin/betterleaks.exe"
    },
    {
      "name": "Claude Code",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-claude-code' to enable"
    },
    {
      "name": "OpenClaw",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-openclaw' to enable"
    },
    {
      "name": "Codex CLI",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-codex' to enable"
    },
    {
      "name": "Gemini CLI",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-gemini' to enable"
    },
    {
      "name": "Cursor",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-cursor' to enable"
    },
    {
      "name": "Windsurf",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-windsurf' to enable"
    },
    {
      "name": "Continue.dev",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-continue' to enable"
    },
    {
      "name": "Aider",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-aider' to enable"
    },
    {
      "name": "Hermes",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-hermes' to enable"
    },
    {
      "name": "OpenCode",
      "status": "warn",
      "detail": "Not detected — run 'rafter agent init --with-opencode' to enable"
    }
  ],
  "summary": {
    "passed": 0,
    "warned": 10,
    "failed": 2,
    "total": 12,
    "probe": false
  },
  "stale": false,
  "installed_version": null,
  "needs_reconcile": []
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `checks` | array of objects | Always | Individual checks in execution order. | U |
| `checks[].name` | string | Each check | Human-readable check name. | U |
| `checks[].status` | string | Each check | `pass`, optional `warn`, or hard `fail`. | U |
| `checks[].detail` | string | Each check | Human-readable diagnostic; wording and paths vary. | U |
| `summary` | object | Always | Counts across the emitted checks, including optional checks. | U |
| `summary.passed` | number | Always | Checks that passed. | U |
| `summary.warned` | number | Always | Optional checks that did not pass. | U |
| `summary.failed` | number | Always | Hard failures; a nonzero count produces exit 1. | U |
| `summary.total` | number | Always | Number of checks emitted. | U |
| `summary.probe` | boolean | Always | Whether optional end-to-end hook probing was requested; false in these captures. | U |
| `stale` | boolean | Always | Informational installed-version staleness. | U |
| `installed_version` | string or null | Always | Version from the install manifest, or null. | U |
| `needs_reconcile` | array of strings | Always | Modified files needing manual reconciliation. | U |

`--probe` can execute a configured hook; it was not used for these examples.
The summary counts all emitted checks, including optional checks. Human display
phrases such as “core checks” are not alternate definitions of `summary.total`.

Source: Node [status](../node/src/commands/agent/status.ts) and
[verify](../node/src/commands/agent/verify.ts); Python
[agent commands](../python/rafter_cli/commands/agent.py).

## Component inventory and baselines

`rafter agent list --json` returns `{components: [...]}` and exits 0.
`--installed` and `--detected` filter those rows; an empty filtered inventory is
`{"components": []}`, not a missing response. This is one actual member of
`components`, selected from the full captured report:

```json
{
  "id": "claude-code.hooks",
  "platform": "claude-code",
  "kind": "hooks",
  "description": "Claude Code PreToolUse + PostToolUse hooks",
  "path": "<home>/.claude/settings.json",
  "state": "not-installed",
  "installed": false,
  "detected": true,
  "configEnabled": false
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `components` | array of objects | Always | Inventory rows after requested installed/detected filters; may be empty. | U |
| `components[].id` | string | Each row | Component identifier; compatibility is unspecified. | U |
| `components[].platform` | string | Each row | Agent environment identifier. | U |
| `components[].kind` | string | Each row | Component kind, such as hooks, instructions, skills, or mcp. | U |
| `components[].description` | string | Each row | Human description of the integration. | U |
| `components[].path` | string | Each row | Resolved component location, possibly project-scoped. | U |
| `components[].state` | string | Each row | `installed`, `not-installed`, or `not-detected`. | U |
| `components[].installed` | boolean | Each row | Current on-disk component detection. | U |
| `components[].detected` | boolean | Each row | Whether the host platform is detected. | U |
| `components[].configEnabled` | boolean | Each row | Configuration records that component as enabled; can differ from detected state. | U |

`rafter agent baseline show --json` prints the baseline storage object and exits
0. An absent baseline has version 1, empty `created`/`updated` strings and an
empty `entries` array. The following baseline was generated by an actual
`rafter agent baseline create finding.txt --engine patterns` run in a disposable
profile; the creation command itself prints text, not this JSON response.

```json
{
  "version": 1,
  "created": "2026-11-04T04:59:57.637Z",
  "updated": "2026-11-04T04:59:57.637Z",
  "entries": [
    {
      "file": "<fixture>/project/finding.txt",
      "line": 1,
      "pattern": "AWS Access Key ID",
      "addedAt": "2026-11-04T04:59:57.637Z"
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `version` | number | Always | Baseline storage format version, observed as 1. | U |
| `created` | string | Always | Creation timestamp; empty string for an absent/default baseline. | U |
| `updated` | string | Always | Last update timestamp; empty string for an absent/default baseline. | U |
| `entries` | array of objects | Always | Known findings recorded by a real baseline scan; may be empty. | U |
| `entries[].file` | string | Each entry | Finding path. | U |
| `entries[].line` | number or null | Each entry | One-based finding line, or null when unavailable. | U |
| `entries[].pattern` | string | Each entry | Detected pattern name. | U |
| `entries[].addedAt` | string | Each entry | Timestamp when the entry was recorded. | U |

Source: Node [component list](../node/src/commands/agent/list.ts),
[component state](../node/src/commands/agent/components.ts) and
[baseline](../node/src/commands/agent/baseline.ts); Python
[agent commands](../python/rafter_cli/commands/agent.py).

## Skill inventories and review reports

`rafter skill list --json` exits 0 with two arrays: `skills` describes the
bundled catalog and `installations` describes platform/file state. `--installed`
and `--platform` filter installations; they do not remove the bundled catalog.
The first installation below came from an inert, locally authored frontmatter
fixture inside the scratch profile. Its intentionally old version exercises
metadata detection; no executable integration or third-party skill was installed.

```json
{
  "name": "rafter",
  "platform": "claude-code",
  "path": "<home>/.claude/skills/rafter/SKILL.md",
  "detected": true,
  "installed": true,
  "version": "0.0.0"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `skills` | array of objects | Always | Bundled skill catalog; installation filters affect installations, not this catalog. | U |
| `skills[].name` | string | Each bundled skill | Bundled skill identifier. | U |
| `skills[].version` | string | Each bundled skill | Skill version, distinct from CLI version. | U |
| `skills[].description` | string | Each bundled skill | Shipped human-readable description. | U |
| `installations` | array of objects | Always | Skill/platform rows after filters; may be empty. | U |
| `installations[].name` | string | Each installation | Bundled skill identifier. | U |
| `installations[].platform` | string | Each installation | Supported agent environment. | U |
| `installations[].path` | string | Each installation | Expected or detected skill location. | U |
| `installations[].detected` | boolean | Each installation | Whether the agent environment is detected. | U |
| `installations[].installed` | boolean | Each installation | Whether the skill file exists in that location. | U |
| `installations[].version` | string or null | Each installation | Parsed installed frontmatter version, or null. | U |

### Single skill review

`rafter skill review <local-path> --json` and `--format json` use the same
report writer. Exit 0 means the deterministic summary is clean, exit 1 means
findings, and exit 2 covers invalid input or acquisition/engine failures.
`--summary` selects human text for installed reviews, even when JSON was also
requested. The captured finding report below includes actual frontmatter,
redaction, command-pattern, Unicode-obfuscation, and binary-inventory results.
URLs and command strings were scanned as data and were not fetched or executed.

```json
{
  "target": {
    "input": "<fixture>/detailed-skill",
    "kind": "directory",
    "resolvedPath": "<fixture>/detailed-skill"
  },
  "frontmatter": [
    {
      "file": "SKILL.md",
      "name": "documentation-fixture",
      "version": "1.0.0",
      "description": "Local review fixture",
      "allowedTools": [
        "Read"
      ]
    }
  ],
  "secrets": [
    {
      "pattern": "AWS Access Key ID",
      "severity": "critical",
      "file": "SKILL.md",
      "line": null,
      "redacted": "AKIA************DEFG"
    }
  ],
  "urls": [
    "https://example.invalid/fixture.sh"
  ],
  "highRiskCommands": [
    {
      "command": "curl | sh",
      "file": "SKILL.md",
      "line": 8
    }
  ],
  "obfuscation": [
    {
      "kind": "zero-width-char",
      "file": "SKILL.md",
      "line": 10,
      "sample": "U+200B"
    }
  ],
  "inventory": {
    "textFiles": 1,
    "binaryFiles": 1,
    "suspiciousFiles": [
      {
        "path": "sample.bin",
        "bytes": 30,
        "kind": "binary"
      }
    ]
  },
  "summary": {
    "severity": "critical",
    "findings": 4,
    "reasons": [
      "1 secret finding(s)",
      "1 high-risk command(s)",
      "1 obfuscation signal(s)",
      "1 suspicious file(s)"
    ]
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `target` | object | Always | Resolved review target. | U |
| `target.input` | string | Always | User-supplied path, URL, or shorthand. | U |
| `target.kind` | string | Always | file, directory, git-url, github, gitlab, or npm; remote kinds are source-traced only here. | U |
| `target.resolvedPath` | string | Always | Resolved local content path. | U |
| `target.source` | object | Conditional remote resolution | Acquisition metadata; not captured by this local-only interval. | U |
| `target.source.url` | string | Conditional remote resolution | Resolved repository or tarball URL. | U |
| `target.source.sha` | string | Conditional Git resolution | Resolved commit identity. | U |
| `target.source.version` | string | Conditional npm resolution | Resolved package version. | U |
| `target.source.subpath` | string | Conditional subpath selection | Selected subtree. | U |
| `target.source.cacheHit` | boolean | Conditional remote resolution | Whether persistent cached content was used. | U |
| `target.skillRelDir` | string | Conditional nested skill report | Skill subtree relative to the original scope. | U |
| `frontmatter` | array of objects | Always | Parsed SKILL.md frontmatter; may be empty. | U |
| `frontmatter[].file` | string | Each metadata row | Relative metadata file. | U |
| `frontmatter[].name` | string or null | Conditional metadata | Parsed name; Node omits unavailable values, Python emits null. | U |
| `frontmatter[].version` | string or null | Conditional metadata | Parsed version; same absent/null distinction. | U |
| `frontmatter[].description` | string or null | Conditional metadata | Parsed description; same absent/null distinction. | U |
| `frontmatter[].allowedTools` | array of strings or null | Conditional metadata | Declared allowed tool names; same absent/null distinction. | U |
| `secrets` | array of objects | Always | Redacted secret findings; may be empty. | U |
| `secrets[].pattern` | string | Each secret | Matched secret pattern name. | U |
| `secrets[].severity` | string | Each secret | Finding severity tier. | U |
| `secrets[].file` | string | Each secret | Relative file containing the match. | U |
| `secrets[].line` | number or null | Each secret | Location when supplied; null in these whole-text pattern captures. | U |
| `secrets[].redacted` | string | Each secret | Redacted match; never the full credential. | U |
| `urls` | array of strings | Always | Extracted URLs; listing one does not fetch it. | U |
| `highRiskCommands` | array of objects | Always | Recognized command-pattern indicators; no listed command is executed. | U |
| `highRiskCommands[].command` | string | Each indicator | Recognized pattern label, not necessarily the original full command text. | U |
| `highRiskCommands[].file` | string | Each indicator | Relative file containing the indicator. | U |
| `highRiskCommands[].line` | number | Each indicator | One-based source line. | U |
| `obfuscation` | array of objects | Always | Obfuscation indicators; may be empty. | U |
| `obfuscation[].kind` | string | Each signal | base64-blob, hex-escape-rope, zero-width-char, bidi-override, or html-comment-imperative. | U |
| `obfuscation[].file` | string | Each signal | Relative source file. | U |
| `obfuscation[].line` | number | Each signal | One-based source line. | U |
| `obfuscation[].sample` | string | Each signal | Bounded diagnostic sample or code point. | U |
| `inventory` | object | Always | Reviewed file counts and suspicious entries. | U |
| `inventory.textFiles` | number | Always | Text files inspected. | U |
| `inventory.binaryFiles` | number | Always | Binary, oversize, or suspicious-extension files counted separately. | U |
| `inventory.suspiciousFiles` | array of objects | Always | Suspicious inventory entries; may be empty. | U |
| `inventory.suspiciousFiles[].path` | string | Each suspicious entry | Relative file path. | U |
| `inventory.suspiciousFiles[].bytes` | number | Each suspicious entry | Observed file size in bytes. | U |
| `inventory.suspiciousFiles[].kind` | string | Each suspicious entry | Classification, observed as binary. | U |
| `summary` | object | Always | Deterministic review summary. | U |
| `summary.severity` | string | Always | clean, low, medium, high, or critical. | U |
| `summary.findings` | number | Always | Count of detected indicators across the review categories. | U |
| `summary.reasons` | array of strings | Always | Human-readable reasons for the summary. | U |
| `deepScan` | object | Conditional --deep, source-only | Optional engine result; not installed or captured here. | U |
| `deepScan.engine` | string | Conditional deep result | skill-scanner. | U |
| `deepScan.maxSeverity` | string or null | Conditional deep result | Maximum normalized severity, or null when none. | U |
| `deepScan.analyzersUsed` | array of strings | Conditional deep result | Analyzer identifiers. | U |
| `deepScan.findings` | array of objects | Conditional deep result | Normalized external-engine findings. | U |
| `deepScan.findings[].ruleId` | string | Each deep finding, source-only | Rule identifier. | U |
| `deepScan.findings[].severity` | string | Each deep finding, source-only | Normalized severity tier. | U |
| `deepScan.findings[].category` | string | Each deep finding, source-only | Finding category. | U |
| `deepScan.findings[].title` | string | Each deep finding, source-only | Short title. | U |
| `deepScan.findings[].description` | string | Each deep finding, source-only | Explanation. | U |
| `deepScan.findings[].file` | string or null | Each deep finding, source-only | File when available. | U |
| `deepScan.findings[].line` | number or null | Each deep finding, source-only | Line when available. | U |
| `deepScan.findings[].snippet` | string or null | Each deep finding, source-only | Snippet when available. | U |
| `deepScan.findings[].analyzer` | string | Each deep finding, source-only | Analyzer that emitted the finding. | U |

The same LF-encoded fixture produced equal JSON in both runtimes after path
sanitization. In a separate CRLF metadata fixture, Node omitted unavailable
frontmatter values while Python emitted nulls. For example, this is the actual
Python `frontmatter[0]` member from that separate capture:

```json
{
  "file": "SKILL.md",
  "name": null,
  "version": null,
  "description": null,
  "allowedTools": null
}
```

Treat missing values and explicit nulls separately. Files other than `SKILL.md`
can have an empty `frontmatter` array. A clean review still emits
the arrays and summary, with empty findings collections.

Remote repository/package targets can add `target.source` metadata; their
acquisition paths were not exercised here. Optional `deepScan` fields are
source-traced above, not actual external-engine captures. Installing or invoking
that engine is outside these examples.

### Multiple and installed skill reviews

A directory containing multiple skill subtrees emits `target.mode: multi-skill`,
a `skills` array and an aggregate summary. Below is one actual `skills` member;
its `report` follows the entire single-review field table.

```json
{
  "relDir": "one",
  "report": {
    "target": {
      "input": "<fixture>/multi-skills",
      "kind": "directory",
      "resolvedPath": "<fixture>/multi-skills/one",
      "skillRelDir": "one"
    },
    "frontmatter": [
      {
        "file": "SKILL.md"
      }
    ],
    "secrets": [],
    "urls": [],
    "highRiskCommands": [],
    "obfuscation": [],
    "inventory": {
      "textFiles": 1,
      "binaryFiles": 0,
      "suspiciousFiles": []
    },
    "summary": {
      "severity": "clean",
      "findings": 0,
      "reasons": []
    }
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `target` | object | Always | Original resolved multi-skill scope; common input/kind/resolvedPath/source fields follow the single-review table. | U |
| `target.input` | string | Always | Original review argument. | U |
| `target.kind` | string | Always | Resolved target kind. | U |
| `target.resolvedPath` | string | Always | Resolved scope root. | U |
| `target.mode` | string | Always | multi-skill discriminator. | U |
| `skills` | array of objects | Always | Discovered skill subtrees, each with a complete single-skill report. | U |
| `skills[].relDir` | string | Each skill | Skill directory relative to scope root. | U |
| `skills[].name` | string or null | Conditional metadata | Parsed name; Node can omit it, Python can emit null. | U |
| `skills[].version` | string or null | Conditional metadata | Parsed version; same runtime distinction. | U |
| `skills[].report` | object | Each skill | Single-review object; reuse all single-review field paths below this prefix. | U |
| `summary` | object | Always | Aggregate across reviewed skills. | U |
| `summary.totalSkills` | number | Always | Number of discovered skills. | U |
| `summary.severityCounts` | object | Always | Counts by clean/low/medium/high/critical tier. | U |
| `summary.severityCounts.[tier]` | number | Each tier | Number of skills with that summary tier. | U |
| `summary.findings` | number | Always | Sum of per-skill findings. | U |
| `summary.worst` | string | Always | Worst summary severity. | U |
| `summary.reasons` | array of strings | Always | Aggregate human-readable reasons. | U |

`rafter skill review --installed --json` emits the separate installed wrapper.
`--agent` restricts discovery. The following actual response reviewed one inert
metadata fixture; an empty profile instead returned `installations: []`, zero
counts and `worst: clean` with exit 0.

```json
{
  "target": {
    "mode": "installed",
    "agent": "all"
  },
  "installations": [
    {
      "platform": "claude-code",
      "skill": "documentation-fixture",
      "path": "<home>/.claude/skills/documentation-fixture/SKILL.md",
      "report": {
        "target": {
          "input": "<home>/.claude/skills/documentation-fixture/SKILL.md",
          "kind": "file",
          "resolvedPath": "<home>/.claude/skills/documentation-fixture/SKILL.md"
        },
        "frontmatter": [
          {
            "file": "SKILL.md"
          }
        ],
        "secrets": [],
        "urls": [],
        "highRiskCommands": [],
        "obfuscation": [],
        "inventory": {
          "textFiles": 1,
          "binaryFiles": 0,
          "suspiciousFiles": []
        },
        "summary": {
          "severity": "clean",
          "findings": 0,
          "reasons": []
        }
      }
    }
  ],
  "summary": {
    "totalSkills": 1,
    "severityCounts": {
      "clean": 1,
      "low": 0,
      "medium": 0,
      "high": 0,
      "critical": 0
    },
    "platformCounts": {
      "claude-code": 1
    },
    "findings": 0,
    "worst": "clean"
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `target` | object | Always | Installed-review selection. | U |
| `target.mode` | string | Always | installed discriminator. | U |
| `target.agent` | string | Always | Requested agent filter, or all. | U |
| `installations` | array of objects | Always | Discovered local skill files; may be empty. | U |
| `installations[].platform` | string | Each installation | Agent platform identifier. | U |
| `installations[].skill` | string | Each installation | Discovered skill identifier. | U |
| `installations[].path` | string | Each installation | Absolute discovered metadata path. | U |
| `installations[].report` | object | Each installation | Complete single-review object; reuse its field paths below this prefix. | U |
| `summary` | object | Always | Aggregate installed-review counts. | U |
| `summary.totalSkills` | number | Always | Number of discovered/reviewed files. | U |
| `summary.severityCounts` | object | Always | Counts by clean/low/medium/high/critical tier. | U |
| `summary.severityCounts.[tier]` | number | Each tier | Number of skills with this summary severity. | U |
| `summary.platformCounts` | object | Always | Counts by platform, possibly empty. | U |
| `summary.platformCounts.[platform]` | number | Each observed platform | Number of reviewed skills on that platform. | U |
| `summary.findings` | number | Always | Sum of findings. | U |
| `summary.worst` | string | Always | Worst summary severity; clean when no findings. | U |

Reuse the single-review field paths beneath `skills[].report` or
`installations[].report`; this includes nested summaries and optional deep data.
Multi-skill `target` uses the common target fields plus its `mode` discriminator.

Source: Node [skill inventory](../node/src/commands/skill/list.ts),
[registry](../node/src/commands/skill/registry.ts),
[review writer and report types](../node/src/commands/skill/review.ts), and
[deep normalization](../node/src/scanners/skill-scanner.ts); Python
[skill commands](../python/rafter_cli/commands/skill.py) and
[deep normalization](../python/rafter_cli/scanners/skill_scanner.py).

### Deprecated audit-skill wrapper

`rafter agent audit-skill <path> --json` has its own legacy wrapper, not the
single-review schema. Its local quick scan exits 1 for findings and 0 otherwise.
The actual finding response is:

```json
{
  "skill": "SKILL.md",
  "path": "<fixture>/detailed-skill/SKILL.md",
  "quickScan": {
    "secrets": 1,
    "urls": [
      "https://example.invalid/fixture.sh"
    ],
    "highRiskCommands": [
      {
        "command": "curl | sh",
        "line": 8
      }
    ]
  },
  "openClawAvailable": false,
  "rafterSkillInstalled": false
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `skill` | string | Always | Audited file basename. | U |
| `path` | string | Always | Resolved input path. | U |
| `quickScan` | object | Always | Legacy deterministic scan summary. | U |
| `quickScan.secrets` | number | Always | Number of secret matches; not a list of findings. | U |
| `quickScan.urls` | array of strings | Always | Extracted URLs, without fetching them. | U |
| `quickScan.highRiskCommands` | array of objects | Always | Recognized risky command indicators. | U |
| `quickScan.highRiskCommands[].command` | string | Each indicator | Pattern label. | U |
| `quickScan.highRiskCommands[].line` | number | Each indicator | One-based line. | U |
| `openClawAvailable` | boolean | Always | OpenClaw availability detection. | U |
| `rafterSkillInstalled` | boolean | Always | Whether the Rafter OpenClaw skill is detected. | U |
| `deepScan` | object | Conditional --deep, source-only | Same normalized deep-result fields as the single-review deepScan table. | U |

Its optional `deepScan` object uses the normalized deep-result fields above;
no deep-engine success example was captured. Source: Node
[audit-skill](../node/src/commands/agent/audit-skill.ts); Python
[agent commands](../python/rafter_cli/commands/agent.py).

## Project document outputs

`rafter docs list --json` prints a metadata array. It exits 0 when entries match,
or prints `[]` and exits 3 when no docs are configured or a tag filter matches
nothing. Listing a local path reports policy metadata without reading its
content, so a listed entry can refer to a missing file.

```json
[
  {
    "id": "security",
    "source": "security.md",
    "source_kind": "path",
    "description": "Local documentation fixture",
    "tags": [
      "security",
      "all"
    ],
    "cache_status": "local"
  },
  {
    "id": "broken",
    "source": "absent.md",
    "source_kind": "path",
    "description": "",
    "tags": [
      "broken",
      "all"
    ],
    "cache_status": "local"
  }
]
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `[].id` | string | Each entry | Policy document identifier. | U |
| `[].source` | string | Each entry | Declared relative path or URL. | U |
| `[].source_kind` | string | Each entry | path or url. | U |
| `[].description` | string | Each entry | Description, empty string when omitted. | U |
| `[].tags` | array of strings | Each entry | Selection tags; empty when omitted. | U |
| `[].cache_status` | string | Each entry | local, cached, not-cached, or stale. Only local is captured here. | U |

`rafter docs show <id-or-tag> --json` prints an array of successfully fetched
documents. Exit 3 means no configured docs; exit 2 means no selector match;
exit 1 means a fetch/read error. When some documents succeed and others fail,
it still prints the successful array, reports errors to stderr and exits 1.
The next example is an actual partial-success result from a tag selecting one
existing and one missing local file:

```json
[
  {
    "id": "security",
    "source": "security.md",
    "source_kind": "path",
    "stale": false,
    "content": "# Security fixture\r\nRead local files and keep credentials redacted.\r\n"
  }
]
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `[].id` | string | Each fetched document | Matched policy document identifier. | U |
| `[].source` | string | Each fetched document | Source path or URL. | U |
| `[].source_kind` | string | Each fetched document | path or url. | U |
| `[].stale` | boolean | Each fetched document | Whether fallback cached content is stale. | U |
| `[].content` | string | Each fetched document | Document text with its observed line endings. | U |

Node preserved the local fixture's CRLF content; Python's text read returned LF.
URL-backed cache states, refresh and stale fallback are source-traced here;
these examples used local files and made no network request.

Source: Node [list](../node/src/commands/docs/list.ts),
[show](../node/src/commands/docs/show.ts) and
[loader](../node/src/core/docs-loader.ts); Python
[commands](../python/rafter_cli/commands/docs.py) and
[loader](../python/rafter_cli/core/docs_loader.py).

## Security gate map

`rafter gates <path> --json` emits a map and exits 0, including when there are
no eligible source files. Missing paths or an invalid `--limit` exit 2 with a
stderr diagnostic rather than a JSON error object. The map is a heuristic
inventory, not proof that a named gate is correct or vulnerable.

This real three-file fixture produced a flagged pair: one `authenticate`
function calls an escape helper and the other does not. Both runtimes returned
the same map:

```json
{
  "stats": {
    "files_scanned": 3,
    "gates_found": 3,
    "gates_shown": 3,
    "twin_groups": 1,
    "flagged_groups": 1
  },
  "gates": [
    {
      "file": "safe.py",
      "line": 1,
      "name": "authenticate",
      "kind": "function",
      "language": "python",
      "score": 7,
      "signature": "def authenticate(conn, username, password):"
    },
    {
      "file": "unsafe.py",
      "line": 1,
      "name": "authenticate",
      "kind": "function",
      "language": "python",
      "score": 7,
      "signature": "def authenticate(conn, username, password):"
    },
    {
      "file": "middleware.js",
      "line": 1,
      "name": "requireAdmin",
      "kind": "function",
      "language": "javascript",
      "score": 5,
      "signature": "function requireAdmin(req, res, next) {"
    }
  ],
  "twins": [
    {
      "key": "authenticate",
      "flagged": true,
      "missing": [
        "escape"
      ],
      "members": [
        {
          "file": "safe.py",
          "line": 1,
          "name": "authenticate",
          "guards": {
            "escape": [
              "escape_filter_chars"
            ]
          },
          "lacks": []
        },
        {
          "file": "unsafe.py",
          "line": 1,
          "name": "authenticate",
          "guards": {},
          "lacks": [
            "escape"
          ]
        }
      ]
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `stats` | object | Always | Mapping totals for the supplied scope. | U |
| `stats.files_scanned` | number | Always | Eligible source files inspected. | U |
| `stats.gates_found` | number | Always | Candidate security gates found before display limiting. | U |
| `stats.gates_shown` | number | Always | Number included in gates after --limit. | U |
| `stats.twin_groups` | number | Always | Groups of related gate implementations. | U |
| `stats.flagged_groups` | number | Always | Groups where some members lack a guard category. | U |
| `gates` | array of objects | Always | Ranked candidate gates, possibly empty. | U |
| `gates[].file` | string | Each gate | Relative source path. | U |
| `gates[].line` | number | Each gate | One-based definition line. | U |
| `gates[].name` | string | Each gate | Function, method, or variable name. | U |
| `gates[].kind` | string | Each gate | Parsed definition kind. | U |
| `gates[].language` | string | Each gate | Detected source language. | U |
| `gates[].score` | number | Each gate | Heuristic ranking score, not a severity guarantee. | U |
| `gates[].signature` | string | Each gate | Bounded source signature. | U |
| `twins` | array of objects | Always | Related gate groups, possibly empty. | U |
| `twins[].key` | string | Each group | Normalized group key. | U |
| `twins[].flagged` | boolean | Each group | Whether some member lacks a guard present in a peer. | U |
| `twins[].missing` | array of strings | Each group | Guard categories missing from at least one member. | U |
| `twins[].members` | array of objects | Each group | Grouped implementations. | U |
| `twins[].members[].file` | string | Each member | Relative source path. | U |
| `twins[].members[].line` | number | Each member | One-based definition line. | U |
| `twins[].members[].name` | string | Each member | Parsed name. | U |
| `twins[].members[].guards` | object | Each member | Observed guard categories and called names; may be empty. | U |
| `twins[].members[].guards.[category]` | array of strings | Each present category | Sorted guard call names in that category. | U |
| `twins[].members[].lacks` | array of strings | Each member | Categories this member lacks relative to its peers. | U |

Source: Node [command](../node/src/commands/gates.ts) and
[scanner](../node/src/scanners/gate-scanner.ts); Python
[command](../python/rafter_cli/commands/gates.py) and
[scanner](../python/rafter_cli/scanners/gate_scanner.py).

## Local usage counters

`rafter counters show --json` writes one report and exits 0. `--days` accepts
integers 1 through 7; invalid values exit 2 with a stderr error and no report.
The older `telemetry` command is not an alias. `counters clear` prints text.

Ordinary capture children disabled counting. For this report only, an isolated
child profile opted in, ran a real clean scan and pretool evaluation, and
contained inert old-version skill metadata. A report can include counts from
earlier `counters show` invocations, since that command is counted at its exit.

```json
{
  "schema": 1,
  "notice": "Nothing leaves this machine: these counts are stored locally and rafter has no code to upload them.",
  "cli_version": "0.11.7",
  "runtime": "node",
  "runtime_major": 24,
  "os": "win32",
  "enabled": true,
  "enabled_source": "default",
  "store": "~/.rafter/usage",
  "days": 7,
  "since": "2026-10-29",
  "counters": {
    "unknown_command": {},
    "unknown_option": {},
    "command": {
      "command:counters.show:exit:0": 1,
      "command:hook.pretool:exit:0": 1,
      "command:secrets:exit:0": 1
    },
    "hook": {
      "hook:shell:allow:low": 1
    },
    "scan_engine": {
      "scan_engine:patterns:patterns": 1
    },
    "scan_fallback": {},
    "scan_duration": {
      "scan_duration:patterns:lt1s": 1
    },
    "error_class": {}
  },
  "skills": [
    {
      "name": "rafter",
      "platform": "claude-code",
      "installed_version": "0.0.0",
      "current_version": "0.7.0",
      "stale": true
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `schema` | number | Always | Usage-report schema version, observed as 1. | U |
| `notice` | string | Always | Local-only storage notice. | U |
| `cli_version` | string | Always | Running CLI version. | U |
| `runtime` | string | Always | node or python. | U |
| `runtime_major` | number | Always | Runtime major version. | U |
| `os` | string | Always | Node process.platform or Python sys.platform. | U |
| `enabled` | boolean | Always | Effective local counting switch. | U |
| `enabled_source` | string | Always | default, config, env:RAFTER_USAGE_COUNTERS, or env:DO_NOT_TRACK. | U |
| `store` | string | Always | Literal ~/.rafter/usage; never an expanded private home path. | U |
| `days` | number | Always | Requested window, integer 1 through 7. | U |
| `since` | string | Always | UTC start date of the reporting window, YYYY-MM-DD. | U |
| `counters` | object | Always | All eight counter-family maps, even when empty. | U |
| `counters.unknown_command` | object | Always | Unknown-command counters. | U |
| `counters.unknown_option` | object | Always | Unknown-option counters. | U |
| `counters.command` | object | Always | Command-path and exit-class counters. | U |
| `counters.hook` | object | Always | Tool-kind, decision, and risk counters. | U |
| `counters.scan_engine` | object | Always | Requested/used engine counters. | U |
| `counters.scan_fallback` | object | Always | Fallback-reason counters. | U |
| `counters.scan_duration` | object | Always | Engine/duration-bucket counters. | U |
| `counters.error_class` | object | Always | Allowlisted error-class counters. | U |
| `counters.[family].[key]` | number | Each stored counter | Full colon-delimited allowlisted counter key mapped to its summed count. | U |
| `skills` | array of objects | Always | Detected bundled-skill staleness rows; no paths or skill content included. | U |
| `skills[].name` | string | Each row | Enumerated bundled skill name. | U |
| `skills[].platform` | string | Each row | Agent platform identifier. | U |
| `skills[].installed_version` | string or null | Each row | Parsed installed version, or null. | U |
| `skills[].current_version` | string | Each row | Version shipped by this CLI for that skill. | U |
| `skills[].stale` | boolean | Each row | Installed skill version or CLI frontmatter pin differs. | U |

The canonical spec explicitly states that the JSON shape's **key order is
stable**, that all eight family maps are present and their counter keys are
sorted. In the table, `[key]` is one literal JSON property: dots inside a command
counter key belong to its name and do not introduce nested objects. Preserve
that existing guarantee; the U field labels do not add broader
field-compatibility promises. Counts use the vocabulary in
[usage-counters.json](usage-counters.json); they do not report arbitrary command
contents. A disabled report still exists, has `enabled: false`, and can show
previously stored counts. Skill versions are distinct from `cli_version`.

Source: [CLI_SPEC counters contract](CLI_SPEC.md#rafter-counters-show-options), Node
[command](../node/src/commands/counters.ts) and
[counter store](../node/src/core/usage-counters.ts); Python
[command](../python/rafter_cli/commands/counters.py) and
[counter store](../python/rafter_cli/core/usage_counters.py).

## Hook protocol outputs

`rafter hook pretool` and `rafter hook posttool` consume JSON on stdin; these
are host-protocol responses, not scan CLI wrappers. `--format` selects the
platform. Use `--format claude` for Claude, Codex and Continue; the other
documented values are cursor, gemini and windsurf. The captures exercised
Claude, Codex, Continue, Cursor, Gemini and
Windsurf input forms without installing any user hook. Command-policy strings
were evaluated, never executed.

### Pretool decisions

Claude/Codex/Continue use `{}` for no objection. A denial writes this envelope
with exit 0; the host reads its decision field:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "✗ Rafter blocked: rm -rf /\n  Rule: rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+\\/\\*?(\\s|$)\n  Risk: CRITICAL—irreversible system damage"
  }
}
```

Cursor has no neutral schema: no objection is `{"permission":"allow"}`; a
block is the following actual object, also with exit 0:

```json
{
  "permission": "deny",
  "agentMessage": "✗ Rafter blocked: rm -rf /\n  Rule: rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+\\/\\*?(\\s|$)\n  Risk: CRITICAL—irreversible system damage",
  "userMessage": "✗ Rafter blocked: rm -rf /\n  Rule: rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+\\/\\*?(\\s|$)\n  Risk: CRITICAL—irreversible system damage"
}
```

Gemini uses `{}` for no objection and this denial object:

```json
{
  "decision": "deny",
  "reason": "✗ Rafter blocked: rm -rf /\n  Rule: rm\\s+(-[a-z]*r[a-z]*\\s+)*-[a-z]*f[a-z]*\\s+\\/\\*?(\\s|$)\n  Risk: CRITICAL—irreversible system damage"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `hookSpecificOutput` | object | Conditional Claude/Codex/Continue deny | Platform-specific denial envelope; absent for neutral response. | U |
| `hookSpecificOutput.hookEventName` | string | Conditional envelope | PreToolUse. | U |
| `hookSpecificOutput.permissionDecision` | string | Conditional envelope | deny; a neutral response does not contain allow. | U |
| `hookSpecificOutput.permissionDecisionReason` | string | Conditional envelope | Human-readable denial reason, including fail-closed runtime errors. | U |
| `permission` | string | Cursor responses | allow for no objection, deny for a block. | U |
| `agentMessage` | string | Conditional Cursor denial | Explanation for the agent. | U |
| `userMessage` | string | Conditional Cursor denial | Explanation for the user. | U |
| `decision` | string | Conditional Gemini denial | deny; neutral Gemini response is an empty object. | U |
| `reason` | string | Conditional Gemini denial | Human-readable reason. | U |

Windsurf emits **no JSON body**: exit 0 permits normal host flow; exit 2 and a
stderr reason deny. Invalid/non-object JSON is treated as no objection. An
internal policy-evaluation error is handled separately: the actual malformed
command-value captures produced a denial with an error reason in both runtimes.
Diagnostic wording varies. A neutral Claude/Codex/Continue/Gemini object has
no `permissionDecision: allow` field; the host's normal permissions still apply.

### Posttool redaction

For Claude/Codex/Continue, the neutral result contains only the event envelope.
The real redaction example below supplied a deliberately fake key in output,
content and error fields, and all three returned redacted:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "modifiedToolResult": {
      "output": "aws_access_key_id = AKIA************DEFG",
      "content": "aws_access_key_id = AKIA************DEFG",
      "error": "aws_access_key_id = AKIA************DEFG"
    }
  }
}
```

Cursor and Gemini emit notifications on modification:

```json
{
  "agentMessage": "Rafter redacted secrets from tool output"
}
```

```json
{
  "systemMessage": "Rafter redacted secrets from tool output"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `hookSpecificOutput` | object | Claude/Codex/Continue response | Post-tool envelope, including neutral responses. | U |
| `hookSpecificOutput.hookEventName` | string | Each envelope | PostToolUse. | U |
| `hookSpecificOutput.modifiedToolResult` | object | Conditional modification | Copied response fields with detected secrets redacted; other input keys can be preserved. | U |
| `hookSpecificOutput.modifiedToolResult.output` | string | Conditional input field | Redacted tool stdout/output text. | U |
| `hookSpecificOutput.modifiedToolResult.content` | string | Conditional input field | Redacted content text. | U |
| `hookSpecificOutput.modifiedToolResult.error` | string | Conditional input field | Redacted error text. | U |
| `agentMessage` | string | Conditional Cursor modification | Notification; this envelope does not contain replacement tool text. | U |
| `systemMessage` | string | Conditional Gemini modification | Notification; this envelope does not contain replacement tool text. | U |

Cursor emits no stdout for a neutral result. Gemini emits `{}`. Windsurf uses
exit 0 and no JSON, with a stderr notification when redaction occurred. These
three notification forms do not contain replacement tool text. Posttool
invalid input or unexpected errors use the neutral/fail-open response; this
differs from pretool's internal-error denial. The captured hook invocations
returned exit 0 except Windsurf pretool denials, which returned 2.

Source: Node [pretool](../node/src/commands/hook/pretool.ts) and
[posttool](../node/src/commands/hook/posttool.ts); Python
[hook writers](../python/rafter_cli/commands/hook.py).

## MCP tool and resource results

The registered surface has **11 tools**, comprising seven local tools below
and four Sites tools held for backend evidence. It has three resources. These
examples use the actual built Node server with the installed SDK transport and
the actual Python CLI server over stdio in Ubuntu WSL. No handler or backend
response was mocked. They show SDK-decoded result objects, not JSON-RPC request
IDs or a promise about every client's internal model representation.

The captured SDK versions are Node **1.32.1** and Python MCP
**1.30.0**. Python model serialization omits null model metadata. Node results
usually omit `isError` on success; Python models include `isError: false` and
successful tool results include `structuredContent`. For example, these are
the actual `evaluate_command` results for the same benign string:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"allowed\":true,\"risk_level\":\"low\",\"requires_approval\":false}"
    }
  ]
}
```

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"allowed\": true, \"risk_level\": \"low\", \"requires_approval\": false}"
    }
  ],
  "structuredContent": {
    "result": "{\"allowed\": true, \"risk_level\": \"low\", \"requires_approval\": false}"
  },
  "isError": false
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `content` | array of objects | Tool result | MCP content blocks; parse JSON-bearing text individually, not the whole array as one JSON string. | U |
| `content[].type` | string | Each captured tool block | text in these Rafter results. | U |
| `content[].text` | string | Each captured tool block | JSON-encoded local result, or plain diagnostic text for Python errors. | U |
| `isError` | boolean | Conditional Node errors; Python model results | Tool execution error flag; a JSON-RPC/resource error is separate. | U |
| `structuredContent` | object | Python successful tool results | FastMCP/SDK structured wrapper; absent in Node captures. | U |
| `structuredContent.result` | string or array of strings | Conditional structured wrapper | JSON text; scan_secrets uses an array of its JSON-text blocks, other local tools use one string. | U |
| `contents` | array of objects | Resource result | MCP resource content blocks. | U |
| `contents[].uri` | string | Each resource block | Resource identity, such as rafter://docs. | U |
| `contents[].mimeType` | string | Each captured resource block | application/json in Node; text/plain in the current Python FastMCP captures. | U |
| `contents[].text` | string | Each captured resource block | JSON-encoded resource content; MIME type alone does not establish its JSON shape. | U |

Decode each JSON-bearing `content[].text` separately. In the current Python
wrapper, `structuredContent.result` is itself a JSON string for most tools and
an array of JSON strings for `scan_secrets`; it is not an already decoded
finding/configuration object. Error text need not be JSON. Resource JSON text
also needs separate decoding regardless of MIME type.

### scan_secrets

The primary block decodes to an **array of per-file results**, not the
`{results, engine_requested, engine_used, ...}` CLI wrapper. This is an actual
decoded finding block:

```json
[
  {
    "file": "<fixture>/mcp-node/finding.txt",
    "matches": [
      {
        "pattern": "AWS Access Key ID",
        "severity": "critical",
        "line": 1,
        "redacted": "AKIA************DEFG"
      }
    ]
  }
]
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `[].file` | string | Each scanned file | Resolved file path, including clean files when returned by the scanner. | U |
| `[].matches` | array of objects | Each scanned file | Retained secret matches; may be empty. | U |
| `[].matches[].pattern` | string | Each match | Pattern name. | U |
| `[].matches[].severity` | string | Each match | Severity tier. | U |
| `[].matches[].line` | number or null | Conditional location | Finding line when available; Node can omit undefined locations. | U |
| `[].matches[].redacted` | string | Each match | Redacted secret match. | U |
| `[].matches[].engines` | array of strings | Conditional auto-mode union | Contributing engines; source-traced, not a dual-engine capture here. | U |

An existing clean file was returned as an array member with `matches: []` in
both captures. Suppression can instead leave the primary array empty. A
second block reports suppressed metadata, and a separate block can report
unreadable paths; inspect all blocks before treating empty findings as clean.
The following blocks were decoded from real suppressed and unreadable calls:

```json
{
  "suppressed_count": 1,
  "_suppressed": [
    {
      "file": "<fixture>/mcp-node/finding.txt",
      "line": 1,
      "column": 21,
      "rule": "AWS Access Key ID",
      "severity": "critical",
      "reason": "Documentation fixture, deliberately fake key",
      "source": ".rafter.yml"
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `suppressed_count` | number | Suppression block | Number of filtered findings. | U |
| `_suppressed` | array of objects | Suppression block | Secret-free suppression metadata; same member fields as local scan suppression. | U |
| `_suppressed[].file` | string | Each suppressed match | Finding path. | U |
| `_suppressed[].line` | number or null | Each suppressed match | Location when available. | U |
| `_suppressed[].column` | number or null | Each suppressed match | Column when available. | U |
| `_suppressed[].rule` | string | Each suppressed match | Rule name or identifier. | U |
| `_suppressed[].severity` | string | Each suppressed match | Original severity. | U |
| `_suppressed[].reason` | string or null | Each suppressed match | Recorded rationale, or null for legacy/no-reason rules. | U |
| `_suppressed[].source` | string | Each suppressed match | Policy source, such as .rafter.yml or .rafterignore. | U |

```json
{
  "unreadable_count": 1,
  "unreadable": [
    {
      "file": "<fixture>/mcp-python/unreadable.txt",
      "error": "permission denied"
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `unreadable_count` | number | Unreadable block | Number of paths that could not be read. | U |
| `unreadable` | array of objects | Unreadable block | Read-error metadata; no secret text. | U |
| `unreadable[].file` | string | Each failed read | Requested unreadable path. | U |
| `unreadable[].error` | string | Each failed read | Runtime/platform diagnostic, not an enum. | U |

A deliberately missing path raised a protocol-level error (-32603) in the Node
capture; Python returned `isError: true` with plain diagnostic text. A requested
but absent Betterleaks engine returned a tool error. There is no external-engine
success example here.

### evaluate_command and read_audit_log

`evaluate_command` classifies a string without executing it. This decoded
dangerous-string result was the same in both runtimes:

```json
{
  "allowed": false,
  "risk_level": "critical",
  "requires_approval": false,
  "reason": "Matches built-in blocked pattern (critical destructive command)"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `allowed` | boolean | Always | Policy evaluation result; the command was not executed. | U |
| `risk_level` | string | Always | low, medium, high, or critical risk classification. | U |
| `requires_approval` | boolean | Always | Whether the policy requires approval. | U |
| `reason` | string | Conditional evaluation reason | Human-readable matched-policy explanation. | U |

`read_audit_log` decodes to an array of real audit events; reuse the
[audit JSONL event fields](#audit-jsonl) for each array member. The format here is
one JSON array inside a text block, not raw JSONL. A fresh profile and an
unmatched `event_type` filter returned `[]`; after a real logger event, the
`limit: 1` call returned that event. `since` accepts an ISO timestamp.

### get_config

Full configuration uses the [configuration field tables](#configuration) and
masks credentials. For a supplied key, Node returns the selected JSON value
directly. Python returns a `key`/`value` wrapper; this actual keyed result shows
the missing-key null case:

```json
{
  "key": "agent.noSuchField",
  "value": null
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `key` | string | Python keyed get_config | Requested dotted key. | U |
| `value` | any JSON value | Python keyed get_config | Value, with credentials masked and null for a missing key. Node returns the value directly. | U |

The captured fake-key reads returned `exam****` in both implementations. Node's
missing-key call did not produce a valid text block: the SDK rejected its
undefined text with -32602. This is a recorded implementation limit, not a
documented JSON-null response for Node.

### list_docs, get_doc and suppress_finding

`list_docs` uses the [docs metadata fields](#project-document-outputs).
`get_doc` uses the fetched-document array fields in that section. The actual
file-backed calls returned configured metadata/content; unmatched `list_docs`
tags returned `[]`. Unlike CLI `docs list`, this empty tool result is successful
and has no process exit-3 interpretation.

`suppress_finding` writes `.rafter.yml` in the project. The following decoded
success body was followed by an actual rescan that returned an empty primary
array plus the suppressed metadata shown above:

```json
{
  "ok": true,
  "file": "<fixture>/mcp-node/.rafter.yml",
  "action": "appended",
  "entry": {
    "paths": [
      "finding.txt"
    ],
    "rules": [
      "AWS Access Key ID"
    ],
    "reason": "Documentation fixture, deliberately fake key"
  },
  "suppression_count": 1
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability |
|---|---|---|---|---|
| `ok` | boolean | Successful suppress_finding | true after a policy write. | U |
| `file` | string | Successful suppress_finding | Absolute policy-file path written. | U |
| `action` | string | Successful suppress_finding | created, appended, or updated. | U |
| `entry` | object | Successful suppress_finding | Persisted ignore rule. | U |
| `entry.paths` | array of strings | Each rule | Suppressed paths/globs. | U |
| `entry.rules` | array of strings | Conditional rule filter | Specific rule names/IDs; absent means all rules for the paths. | U |
| `entry.reason` | string | Conditional supplied reason | Human rationale persisted with the rule. | U |
| `suppression_count` | number | Successful suppress_finding | Total persisted ignore rules after the write. | U |

The tool requires a path; rules and rationale are optional in the writer, but a
useful triage call supplies a reason. Only a disposable fixture was modified.
An unmatched document produces a tool error. Node's actual result contains
JSON-encoded `{error: ...}`:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"error\":\"No doc matched id or tag: absent\"}"
    }
  ],
  "isError": true
}
```

Python's actual result contains plain diagnostic text instead:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Error executing tool get_doc: No doc matched id or tag: absent"
    }
  ],
  "isError": true
}
```

These are tool errors (`isError: true`), distinct from protocol-level failures.
Missing required tool arguments and unknown tools also produced actual error
responses. Do not infer a uniform `{error}` payload for both runtimes.

### Resources

| URI | Decoded text payload | Captured MIME type, Node / Python |
|---|---|---|
| `rafter://config` | Full masked global configuration | application/json / text/plain |
| `rafter://policy` | Masked configuration merged with active project policy | application/json / text/plain |
| `rafter://docs` | Document metadata array, not document content | application/json / text/plain |

All three were read from both real servers. The next two actual docs-resource
results show the MIME-type difference while preserving JSON text:

```json
{
  "contents": [
    {
      "uri": "rafter://docs",
      "mimeType": "application/json",
      "text": "[\n  {\n    \"id\": \"security\",\n    \"source\": \"security.md\",\n    \"source_kind\": \"path\",\n    \"description\": \"Local documentation fixture\",\n    \"tags\": [\n      \"security\"\n    ],\n    \"cache_status\": \"local\"\n  }\n]"
    }
  ]
}
```

```json
{
  "contents": [
    {
      "uri": "rafter://docs",
      "mimeType": "text/plain",
      "text": "[\n  {\n    \"id\": \"security\",\n    \"source\": \"security.md\",\n    \"source_kind\": \"path\",\n    \"description\": \"Local documentation fixture\",\n    \"tags\": [\n      \"security\"\n    ],\n    \"cache_status\": \"local\"\n  }\n]"
    }
  ]
}
```

An unknown resource raised a protocol error rather than a tool's `isError`
response. The four registered `sites_*` tools were listed but never called;
their real backend results remain pending.

Source: Node [registrations and result writers](../node/src/commands/mcp/server.ts)
and [suppression writer](../node/src/core/suppression-writer.ts); Python
[FastMCP registrations and handlers](../python/rafter_cli/commands/mcp_server.py)
and [suppression writer](../python/rafter_cli/core/suppression_writer.py).

## Watch output framing

The two bounded real `secrets --watch --json --engine patterns` captures mixed
human status lines and pretty-printed scan objects on stdout. An initial clean
scan printed a human success line rather than a clean JSON wrapper. Updating
the disposable file to contain a fake key produced JSON objects; another edit
produced another object. Both owned watchers were intentionally stopped after
two complete objects, so their termination codes are not scan-completion codes.

Watch stdout is **neither one JSON document nor JSONL**. A consumer must handle
the observed status text and repeated objects explicitly. The individual scan
objects use the [local scan fields](#local-secret-scans), except that
`engine_requested`, `engine_used` and `degraded` are currently omitted by both
watch-mode writers. One-shot examples do not establish whole-stream parsing
for watch mode.

## Hosted Fast scan and quota responses

These six selections come from one actual November 10, 2026 Fast scan of
`bbdevelops/rafter-cli` at `main`, using Python CLI 0.11.7. The response's
`scanned_commit` matches `1ebad941815d91d45d7befe3295d15f23a8b05ad`.
The backend reports `rafter-fast@0.10`; this is separate from the CLI version.
Node 24.16.0 and Python 3.13.2 then retrieved the same saved scan ID, and both
returned the same complete JSON as the original Python run.

Only `scan_id` is replaced with `<scan-id>` in these examples. The completed
example is an explicitly selected excerpt, described below; counts and other
values remain unchanged.
Field stability is **unspecified** unless an existing contract says otherwise.

```sh
rafter run --repo bbdevelops/rafter-cli --branch main --mode fast --format json
rafter get <scan-id> --format json
rafter usage
```

`scan` and `scan remote` route to the same remote handler. Their exact request
construction was checked offline, with sockets blocked; they were not each
submitted live. A second invocation would create another job. Use `get` for
result reuse. Credentials came from the operator's environment, not argv.

### Submission and progress

The first object is the actual **HTTP submission response**, not a CLI stdout
object. The normal run wrote `Scan ID:` and progress to stderr, then emitted
the completed report on stdout. `--skip-interactive` returns without that final
JSON; adding `--quiet` also hides the ID. Saving the response/ID before polling
allows later retrieval without a second submission.

```json
{
  "success": true,
  "scan_id": "<scan-id>"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability / source |
|---|---|---|---|---|
| `success` | boolean | Observed response | Request accepted | U; submission API and capture |
| `scan_id` | string | Observed response | ID used for later retrieval | U; submission API and capture |

Actual queued and processing HTTP poll bodies follow. They describe progress,
not an empty or completed findings report. The public result endpoint also
describes pending; that state was not observed in this capture.

```json
{
  "status": "queued"
}
```

```json
{
  "status": "processing"
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability / source |
|---|---|---|---|---|
| `status` | string | Observed queued/processing responses | Current job state | U; result API and captures |

### Completed report

The full report has **73 findings**: 12 error, 47 warning and 14 note. This
excerpt selects the first finding of each severity, in original array order.
The summary still counts all 73; it does not describe only the three shown.
All seven finding fields were present in all 73 actual entries. Every captured
line_end was null; published nullable alternatives for file_path and line_start
were not observed. Findings are reported results, with no triage or validity
claim implied by this schema example.

```json
{
  "status": "completed",
  "partial": false,
  "version": "rafter-fast@0.10",
  "scan_mode": "fast",
  "repository_name": "bbdevelops/rafter-cli",
  "branch_name": "main",
  "scanned_commit": "1ebad941815d91d45d7befe3295d15f23a8b05ad",
  "scan_date": "2026-11-10T06:10:18.800608+00:00",
  "scan_id": "<scan-id>",
  "summary": {
    "errors": 12,
    "warnings": 47,
    "notes": 14
  },
  "vulnerabilities": [
    {
      "rule_id": "rules.rafter.javascript.general.rafter.javascript.general.zip-slip-path-join",
      "severity": "error",
      "title": "General Rafter Javascript General Zip Slip Path Join",
      "description": "Archive entry path is used directly in path.join or path.resolve without validating that the result stays within the target directory. A crafted archive with entries like \"../../etc/cron.d/backdoor\" (Zip Slip) can write files outside the intended extraction directory. After joining, verify: if (!resolved.startsWith(base)) throw new Error('zip slip');\n",
      "file_path": "node/src/commands/agent/install-files.ts",
      "line_start": 494,
      "line_end": null
    },
    {
      "rule_id": "B202",
      "severity": "warning",
      "title": "tarfile_unsafe_members",
      "description": "Found tarfile.extractall(members=?) but couldn't identify the type of members. Check if the members were properly validated {'Other': 'members'}).",
      "file_path": "python/rafter_cli/commands/skill_remote.py",
      "line_start": 355,
      "line_end": null
    },
    {
      "rule_id": "B106",
      "severity": "note",
      "title": "hardcoded_password_funcarg",
      "description": "Possible hardcoded password: 'default'",
      "file_path": "python/rafter_cli/commands/hook.py",
      "line_start": 376,
      "line_end": null
    }
  ]
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability / source |
|---|---|---|---|---|
| `status` | string | Captured completed report | Job state | U; result API and capture |
| `partial` | boolean | Captured completed report | Whether checks were incomplete | U; result API and capture |
| `version` | string | Captured completed report | Backend engine version; separate from CLI version | U; result API and capture |
| `scan_mode` | string | Captured completed report | Requested analysis tier | U; result API and capture |
| `repository_name` | string | Captured completed report | Scanned owner/repository | U; result API and capture |
| `branch_name` | string | Captured completed report | Scanned branch | U; result API and capture |
| `scanned_commit` | string | Observed; not in published field table | Backend-reported commit SHA | U; actual capture only |
| `scan_date` | string | Captured completed report | Creation time in ISO 8601 form | U; result API and capture |
| `scan_id` | string | Captured completed report | Same job ID as submission | U; result API and capture |
| `summary` | object | Captured completed report | Counts for the full report | U; result API and capture |
| `summary.errors` | integer | Captured summary | Error-level findings | U; result API and capture |
| `summary.warnings` | integer | Captured summary | Warning-level findings | U; result API and capture |
| `summary.notes` | integer | Captured summary | Note-level findings | U; result API and capture |
| `vulnerabilities` | array of objects | Captured; 73 findings | Reported findings; no triage implied | U; result API and capture |
| `vulnerabilities[]` | object | Each captured finding | One finding | U; actual capture |
| `vulnerabilities[].rule_id` | string | Every captured finding | Rule identifier | U; result API and capture |
| `vulnerabilities[].severity` | string | Every captured finding | error, warning or note; all three observed | U; result API and capture |
| `vulnerabilities[].title` | string | Every captured finding | Short finding label | U; result API and capture |
| `vulnerabilities[].description` | string | Every captured finding | Detailed finding text | U; result API and capture |
| `vulnerabilities[].file_path` | string or null | All captured values are strings | Location; null is published but unobserved here | U; result API and capture |
| `vulnerabilities[].line_start` | integer or null | All captured values are integers | Start line; null is published but unobserved here | U; result API and capture |
| `vulnerabilities[].line_end` | integer or null | All captured values are null | End line; currently null per endpoint docs | U; result API and capture |

All three actual run/get commands exited **0**, despite the nonempty findings
array. Here that indicates successful retrieval/output, not a clean security
assessment. Read status, partial, summary and vulnerabilities. The captured
partial value is false; no partial, failed or empty completed report was forced
to obtain additional examples.

The wire field was `severity`, matching the endpoint-specific definition and
the current issue builder. Older CLI_SPEC/generic examples use `level`; no
captured finding had that property. Do not rename the observed field to match
an older example. Legacy compatibility and future field guarantees still need
maintainer guidance. `scanned_commit` was observed but is absent from the
published result-field table, so its presence is not asserted as guaranteed.

### Account quota

Before the submission:

```json
{
  "quota": {
    "fast": {
      "used": 0,
      "limit": 1,
      "remaining": 1
    },
    "plus": {
      "used": 0,
      "limit": 0,
      "remaining": 0
    },
    "quota_reset_date": "2026-12-10T05:03:53.652467+00:00"
  }
}
```

After the same single Fast submission:

```json
{
  "quota": {
    "fast": {
      "used": 1,
      "limit": 1,
      "remaining": 0
    },
    "plus": {
      "used": 0,
      "limit": 0,
      "remaining": 0
    },
    "quota_reset_date": "2026-12-10T05:03:53.652467+00:00"
  }
}
```

| Field path | JSON type | Presence / condition | Meaning | Stability / source |
|---|---|---|---|---|
| `quota` | object | Both captured usage responses | Account allowance | U; usage API and capture |
| `quota.fast` | object | Both usage responses | Fast counters | U; usage API and capture |
| `quota.fast.used` | integer | Both usage responses | Fast scans used this period | U; usage API and capture |
| `quota.fast.limit` | integer | Both usage responses | Fast allowance | U; usage API and capture |
| `quota.fast.remaining` | integer | Both usage responses | Fast scans remaining | U; usage API and capture |
| `quota.plus` | object | Both usage responses | Plus counters | U; usage API and capture |
| `quota.plus.used` | integer | Both usage responses | Plus scans used this period | U; usage API and capture |
| `quota.plus.limit` | integer | Both usage responses | Plus allowance | U; usage API and capture |
| `quota.plus.remaining` | integer | Both usage responses | Plus scans remaining | U; usage API and capture |
| `quota.quota_reset_date` | string | Both usage responses | Period reset time in ISO 8601 form | U; usage API and capture |

These counters are account/period-specific examples, not default plan limits.
Fast remaining changed from 1 to 0; Plus stayed at zero. Read-only result reuse
did not create another job. Ordinary local usage counters are a different
output family from this authenticated usage response.

Unobserved response branches remain source/published-definition evidence:
failed/partial/empty results, auth/quota errors, reserved cwe/confidence fields,
nullable finding locations, Markdown/SARIF formats, and open-source bypass
metadata. No success example or compatibility promise is claimed for them.

Sources: official [submission](https://docs.rafter.so/api-reference/endpoint/static/scan),
[result](https://docs.rafter.so/api-reference/endpoint/static/get) and
[usage](https://docs.rafter.so/api-reference/endpoint/usage) definitions;
Node [run](../node/src/commands/backend/run.ts),
[get](../node/src/commands/backend/get.ts),
[usage](../node/src/commands/backend/usage.ts) and
[payload writer](../node/src/utils/api.ts);
Python [backend handlers](../python/rafter_cli/commands/backend.py) and
[payload writer](../python/rafter_cli/utils/api.py).
## Pending coverage and evidence

Run/get/usage now have actual Fast-scan evidence and published field definitions,
with the observed/unobserved boundaries stated above. Sites clients and the
four Sites MCP tools still need real authorized captures and authoritative backend
evidence for full nested shapes; local mocked tests cannot establish them.
The Sites tools were not called, and no Site was created or scanned.

Deep scanners, remote skill acquisition, URL-doc cache variants, optional
verification probes and successful dual-engine scans remain explicitly
source-traced branches, with no captured success claimed. Observed backend
fields are documented without introducing compatibility guarantees.
