# Drafted Fixes for securable-bolt

These are the exact changes to apply to Rome-1/securable-bolt.

---

## Fix 1: CLIFeaturetteSection.tsx — Update supported agents list (H1)

**File**: `components/home/CLIFeaturetteSection.tsx`

Replace `agentLogos` array (lines 30-46):

```tsx
const agentLogos = [
  {
    name: 'Claude Code',
    path: '~/.claude/skills/',
    description: 'PreToolUse hooks + security skills',
  },
  {
    name: 'Codex CLI',
    path: '~/.agents/skills/',
    description: 'Security skills',
  },
  {
    name: 'OpenClaw',
    path: '~/.openclaw/skills/',
    description: 'Security skills',
  },
  {
    name: 'Gemini CLI',
    path: 'MCP server config',
    description: 'MCP integration',
  },
  {
    name: 'Cursor',
    path: '.cursor/mcp.json',
    description: 'MCP integration',
  },
  {
    name: 'Windsurf',
    path: '~/.codeium/windsurf/',
    description: 'MCP integration',
  },
  {
    name: 'Continue.dev',
    path: '~/.continue/',
    description: 'MCP integration',
  },
  {
    name: 'Aider',
    path: '~/.aider.conf.yml',
    description: 'MCP integration',
  },
];
```

Update grid layout (line 135) from `md:grid-cols-3` to `md:grid-cols-4`:

```tsx
<div className="grid md:grid-cols-4 gap-4 max-w-5xl mx-auto">
```

---

## Fix 2: CLIFeaturetteSection.tsx — Update header text (H2)

**File**: `components/home/CLIFeaturetteSection.tsx`

Replace line 70:

```tsx
// OLD:
<p className="text-lg text-muted-foreground max-w-2xl mx-auto">
  First-class integrations with Claude Code, Codex CLI, and Open Claw. One command installs local-first security guardrails—no API key required.
</p>

// NEW:
<p className="text-lg text-muted-foreground max-w-2xl mx-auto">
  First-class integrations with Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider, and OpenClaw. One command installs security guardrails across all 8 platforms — no API key required.
</p>
```

---

## Fix 3: CLIFeaturetteSection.tsx — Update terminal mockup (H3)

**File**: `components/home/CLIFeaturetteSection.tsx`

Replace lines 104-108:

```tsx
<p className="text-slate-400">✓ Detected Claude Code at ~/.claude</p>
<p className="text-slate-400">✓ Detected Codex CLI at ~/.codex</p>
<p className="text-slate-400">✓ Detected Gemini CLI at ~/.gemini</p>
<p className="text-slate-400">✓ Detected Cursor at .cursor/</p>
<p className="text-slate-400">✓ Detected OpenClaw at ~/.openclaw</p>
<p className="text-green-400 mt-2">✓ Agent security enabled for all detected agents</p>
```

---

## Fix 4: CLIFeaturetteSection.tsx — Fix audit log path (H7)

**File**: `components/home/CLIFeaturetteSection.tsx`

Replace line 119:

```tsx
// OLD:
<p className="text-slate-400">• Full audit logging in ~/.rafter/audit.log</p>

// NEW:
<p className="text-slate-400">• Full audit logging in ~/.rafter/audit.jsonl</p>
```

---

## Fix 5: CLIFeaturetteSection.tsx — Fix "Open Claw" spelling (L1)

**File**: `components/home/CLIFeaturetteSection.tsx`

Find/replace all occurrences of "Open Claw" with "OpenClaw" in this file. Instances:
- Line 43: agent name `'Open Claw'`
- Line 107: terminal detection message `✓ Detected Open Claw at ~/.openclaw`

---

## Fix 6: getting-started/page.tsx — Update agent list (H4)

**File**: `app/getting-started/page.tsx`

Replace `aiAgents` array (lines 88-98):

```tsx
const aiAgents = [
  'Claude Code',
  'Codex CLI',
  'Cursor',
  'Windsurf',
  'Gemini CLI',
  'Aider',
  'OpenClaw',
  'Continue.dev',
  'GitHub Copilot',
  'Cody',
  'Amazon Q Developer',
];
```

This puts the 8 platforms with actual Rafter integrations first, then the "works with" platforms.

---

## Fix 7: roadmap/page.tsx — Fix scan mode name (M5)

**File**: `app/roadmap/page.tsx`

Replace line 29:

```tsx
// OLD:
title: 'Code Security Scans (Fast + Max)',

// NEW:
title: 'Code Security Scans (Fast + Plus)',
```

---

## Summary

| Fix | File | Severity | Description |
|-----|------|----------|-------------|
| 1 | CLIFeaturetteSection.tsx | HIGH | Add 5 missing platforms to agent list |
| 2 | CLIFeaturetteSection.tsx | HIGH | Update header to mention all 8 platforms |
| 3 | CLIFeaturetteSection.tsx | HIGH | Update terminal mockup with more platforms |
| 4 | CLIFeaturetteSection.tsx | HIGH | Fix audit.log → audit.jsonl |
| 5 | CLIFeaturetteSection.tsx | LOW | Fix "Open Claw" → "OpenClaw" |
| 6 | getting-started/page.tsx | HIGH | Reorder agents, add Codex CLI + Gemini CLI |
| 7 | roadmap/page.tsx | MEDIUM | Fix "Max" → "Plus" scan mode |
