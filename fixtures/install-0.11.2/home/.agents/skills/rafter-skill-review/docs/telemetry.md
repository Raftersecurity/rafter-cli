# Telemetry

The narrow case of data practices: phone-home traffic that isn't load-bearing for the skill's purpose. Subtle because it's often opt-in in theory and on-by-default in practice.

> The `rafter skill review` JSON report already lists outbound URLs. This doc is how you decide which ones are legitimate and which ones are surveillance.

## 1. What counts as telemetry

- Any outbound request whose response is not used to change behaviour.
- Any outbound request whose *body* contains anything about the user / repo / machine beyond what's needed for the stated feature.
- "Analytics" SDKs (Mixpanel, Amplitude, Segment, PostHog, Sentry, GA, Hotjar, RudderStack).
- "Anonymous" install/usage pings (`/v1/install`, `/track`, `/ping`, `/beacon`).

Legitimate exceptions:
- Update check (`/latest.json` with no body) — fine if it's infrequent and you can opt out.
- Error reporting with PII scrubbing — fine if it's opt-in and redaction is auditable in the code.

## 2. Patterns to grep

```bash
rg -n 'mixpanel|amplitude|segment\.io|posthog|sentry|rudderstack|fullstory|datadog|hotjar' <skill>
rg -n '/track|/metrics|/events|/telemetry|/analytics|/beacon' <skill>
rg -n 'navigator\.sendBeacon|fetch\([^)]*track|axios\.post\([^)]*track' <skill>
```

Node / Python specific:
- `@sentry/node`, `@amplitude/*`, `posthog-node`, `mixpanel`, `segment-analytics-node`.
- `sentry-sdk`, `posthog`, `mixpanel`, `analytics-python`, `statsd`.

## 3. Identifiers that feel anonymous but aren't

- **Persistent machine UUID** written to `~/.<skill>/id` — re-used across runs, re-used across installs until the user wipes the file. Links your sessions to your machine.
- **MAC address** / **hostname** / **username** included in install pings.
- **Repo URL** or **git remote** in telemetry — leaks private repo names/orgs.
- **First commit hash** — unique per repo, effectively a repo-ID.
- **Working-directory absolute path** — leaks home dir, username, org-specific path conventions.

Any of these = reject unless they are documented and opt-in.

## 4. Opt-out versus opt-in

Rule of thumb: a security-oriented skill should be **telemetry-off by default**. If the skill sends any telemetry unless you proactively set `TELEMETRY=0`, treat that as a defect and file it upstream at minimum. For a skill you don't yet trust, it's grounds to reject.

Questions to answer:

1. Can you disable telemetry with a single env var / flag / config line?
2. Does the disable take effect *before* the first outbound packet of a fresh install?
3. Is the disable documented in SKILL.md or README, or only in buried source?
4. On disable, does the code path short-circuit, or does it still hit a "check if allowed" endpoint?

## 5. Second-order telemetry

Skills sometimes call *other tools* that telemeter on their behalf. Examples:

- Runs `npm` with default config → npm fetches registry metadata tied to your proxy config.
- Runs `pip install --index-url` — leaks your repo's deps graph to whichever index.
- Triggers a `WebFetch` of docs through an external CDN with full URLs as log lines.

When the skill shells out, the telemetry surface includes the child process's telemetry. Skim the child's docs for anything obvious.

## 6. Log aggressiveness

- `console.log(...)` / `print(...)` of prompt contents, user input, file contents in production paths.
- Log files written to world-readable locations (`/tmp/<skill>.log`).
- Log lines that concatenate secrets (API keys, tokens) with other fields.

Not telemetry in the narrow sense, but the same risk: data leakage.

---

## Decision rule

A well-behaved skill has:
- zero telemetry by default, OR
- opt-in telemetry with an unambiguous disable documented in SKILL.md, AND
- no identifiers beyond a fresh random per-invocation ID.

If the skill fails any of those, either reject or install only in a sandbox (separate HOME, firewall rules) and re-evaluate after reading outbound traffic for a few runs.
