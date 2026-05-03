# Rafter — 60s Promo Video Storyboard

**Length:** 60s hard ceiling
**Audience:** developers and founders adopting AI coding agents (Claude Code, Cursor, Codex, Gemini, Windsurf, Continue, Aider)
**Dual angle:**
1. **Rafter the company is AI-first** — built by agents, shipped at agent velocity, dogfooding its own guardrails.
2. **Rafter empowers any business to go AI-first safely** — secret scanning, policy enforcement, skill auditing, MCP, and llms.txt parity across every major coding agent.
**Single CTA:** `rafter.so` · `npm i -g @rafter-security/cli`

---

## Tone & motion notes

- **Pace:** fast first 10s (cold-open hook), settle to a steady rhythm 10–50s, slow into the payoff at 55–60s. ~14 beats total, ~4s average, but variable.
- **Visual language:** terminal-first. Real `rafter` output, not mockups. Where we cut to product surfaces (Claude Code, Cursor) show the actual chrome — viewers should recognize the tool they already use.
- **Motion graphics:** monospace type animating in line-by-line; redacted secrets (`AKIA****MPLE`) typeset in danger red, then swapped for a green "blocked" stamp. Use the Rafter green (`#2ea44f`, the badge color) as the "safe" accent and a sharp red for the "bad" state. Avoid stock corporate gloss.
- **Transitions:** hard cuts on terminal beats; whip-pan or quick wipe when moving between agent surfaces (each transition = one new platform). Logo lockup at the end fades in over a held terminal frame.
- **Music:** moody, propulsive electronic — think Mr. Robot main title or Oneohtrix Point Never's *Uncut Gems* score crossed with a Linear product launch reel. 90–100 BPM. Drops out for ~1s on beat 13 ("Become AI-first. Safely.") to land the line, returns under the CTA.
- **Sound design:** terminal key-clacks under typing beats, a single low "thunk" when the pre-commit hook blocks, a clean *ding* on the green "all clear" stamp. No voiceover music swell at the end — let silence + CTA card do the work.
- **Typography:** JetBrains Mono or Berkeley Mono for terminal. Inter for any UI/marketing text. No serifs.
- **Aspect:** master at 16:9 1080p; reframe to 9:16 and 1:1 cuts for social. Keep all critical text in the 1:1 safe area.

---

## Cold open (0–5s) — the hook

The first 4 seconds must work with sound off. Lead with the failure state, not the brand.

| # | Time | Visual | On-screen text | Audio / transition |
|---|------|--------|----------------|--------------------|
| 1 | 0:00–0:03 | Tight on a code editor. An AI agent's diff streams in: `+ AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`. Cursor blinks. The line flashes red. | *(none — let the key speak)* | Music starts low. Soft keystrokes. |
| 2 | 0:03–0:05 | Hard cut to terminal: `git push` runs, then a Slack/email notification card slides in: "$1,247.30 charged · OpenAI". | **Your AI agent just leaked a key.** | Single low *thunk*. Cut to black for 4 frames. |

---

## Act I — what Rafter does (5–18s)

Show the product working in three tight beats: scan, block, recognize the brand.

| # | Time | Visual | On-screen text | Audio / transition |
|---|------|--------|----------------|--------------------|
| 3 | 0:05–0:09 | Same terminal, rewound. `rafter agent scan --staged` runs. Output: `CRITICAL  .env:1  aws-access-key-id  AKIA****MPLE`. Exit `1`. | `rafter` (cursor-prompt style, lower-third) | Sharp keystroke; green-to-red flicker as the finding lands. |
| 4 | 0:09–0:13 | `git commit -m "..."` — pre-commit hook prints `[rafter] Commit blocked. Remove secrets or use --no-verify to bypass.` Red bar slides across. | **Pre-commit hook. Zero setup. Zero telemetry.** | Whip-pan transition out. |
| 5 | 0:13–0:18 | Logo lockup over a calm terminal frame. Tagline below. | **Rafter** — the security primitive for AI-first dev. | Music opens up; first full bar lands. |

---

## Act II — how AI-first Rafter is (18–32s)

The "built by agents" angle. Make it visible — these aren't claims, they're screen-recorded artifacts.

| # | Time | Visual | On-screen text | Audio / transition |
|---|------|--------|----------------|--------------------|
| 6 | 0:18–0:22 | Time-lapse of the `rafter-cli` GitHub commit graph; PRs scroll past, most authored by `claude[bot]` / `codex[bot]` / agent handles. Velocity counter ticks up. | **Built by agents.** Shipped at agent velocity. | Quick cuts on every PR row. |
| 7 | 0:22–0:26 | Split screen: left = Claude Code running `rafter scan`, right = the same scan in Cursor's chat. Same JSON output in both. | **Same contract. Every agent.** | Whip-pan between the two halves. |
| 8 | 0:26–0:30 | Logo wall flashes through one per beat: Claude Code · Codex · Gemini · Cursor · Windsurf · Continue · Aider · OpenClaw. Each frame, a `rafter agent init --with-<x>` line types itself underneath. | **8 platforms. One CLI.** | Each logo lands on the beat. |
| 9 | 0:30–0:34 | `rafter skill review github:some/skill` runs. Output enumerates: external URLs, `curl \| sh`, base64 blobs, obfuscation signals. Red highlights resolve into a fix-hint column. | **Treat third-party skills as hostile by default.** | Music sustains. |

---

## Act III — empowering any business (32–50s)

The "anyone can become AI-first" angle. Move the camera off Rafter-the-product and onto the customer.

| # | Time | Visual | On-screen text | Audio / transition |
|---|------|--------|----------------|--------------------|
| 10 | 0:34–0:38 | Three founder-style developer cameos in quick succession (or three different `git log` headers — fintech, healthtech, devtools). Each repo has the green Rafter shield badge in the README. | **Any team. Any stack.** | Hard cuts; one founder per beat. |
| 11 | 0:38–0:42 | MCP server boot: `rafter mcp serve` → an agent (Cursor chat) calls `scan_secrets`, gets structured JSON back, makes a decision. | **Your agents get guardrails. For free.** | Soft *ding* on the tool-result return. |
| 12 | 0:42–0:46 | Audit log scrolls: `secret_detected`, `command_intercepted`, `policy_override` — each entry chained by `prevHash`. A `rafter agent audit --verify` line returns `chain ok ✓`. | **Cryptographic audit. Tamper-evident.** | Bass note on `chain ok`. |
| 13 | 0:46–0:50 | Clean shot of `rafter.so` dashboard: SAST + SCA + agentic findings on a real repo, single-pane. Toggle to Markdown export. | **Local free forever. Remote when you scale.** | Music begins building. |

---

## Payoff + CTA (50–60s)

Close on the dual thesis as one sentence, then a single clear CTA.

| # | Time | Visual | On-screen text | Audio / transition |
|---|------|--------|----------------|--------------------|
| 14 | 0:50–0:55 | Pull back from the dashboard into a wide shot: terminal on the left, Claude Code / Cursor on the right, both displaying the same green "scanned by Rafter" state. | **Become AI-first. Safely.** | Music drops to a single sustained chord. |
| 15 | 0:55–1:00 | Black card. Logo center. CTA underneath. URL types itself in. | **rafter.so** &nbsp;·&nbsp; `npm i -g @rafter-security/cli` &nbsp;·&nbsp; *Free forever for individuals & OSS.* | Music resolves. End frame holds 1s in silence. |

---

## Voiceover script (~140 words, ~60s @ ~2.3 wps)

Read tight, conversational, low-affect. No hype voice. Pauses marked `(beat)`.

> *(0:00)* Your AI agent just leaked a key. *(beat)*
>
> *(0:05)* Rafter would've caught it — *(beat)* in the pre-commit hook, before the push, before the bill.
>
> *(0:13)* Rafter is the security primitive for AI-first dev. *(beat)*
>
> *(0:18)* We're built by agents. Shipped at agent velocity. Dogfooded on every commit you're watching. *(beat)*
>
> *(0:26)* One CLI, eight platforms — Claude Code, Cursor, Codex, Gemini, Windsurf, and the rest. Same scan. Same contract. *(beat)*
>
> *(0:30)* Audit third-party skills before they run. Block destructive commands by policy. Sign every event into a tamper-evident log.
>
> *(0:38)* Your agents get guardrails. For free. Local-only. No telemetry.
>
> *(0:46)* Scale up to remote SAST, SCA, and agentic analysis when you need it.
>
> *(0:50)* Become AI-first. *(beat)* Safely.
>
> *(0:55)* Rafter. rafter.so.

**Word count: 142.** Reads in 58–60s with the marked beats; trim *"and the rest"* in beat 7 if the read goes long.

---

## Production checklist (out of scope for this storyboard, captured for follow-on work)

- Capture real terminal recordings at 60fps (`asciinema` for source, re-render in `agg` or `terminalizer` for hi-res)
- License or compose a 60s music bed at 96 BPM with a clean drop at 0:50
- Render 16:9 master + 9:16 and 1:1 social cuts
- Caption pass for sound-off social (the cold open already works mute, but lines 6–13 need burned-in captions)
- A/B variant: swap beat 1's leaked key for a destructive shell command (`rm -rf /`) blocked by policy, to test which failure mode hooks better
