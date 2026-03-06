# Rafter CLI — Golden Path Demo
# Renders to demo.gif for README, docs, and social.
# Requires: node >=18, git, vhs
#
# Usage:
#   vhs demo.tape          # renders demo.gif
#
# NOTE: The fake AWS key is split across two printf args so this file
# itself passes Rafter's secret scanner. It reassembles at runtime.

Output demo.gif

Require git
Require node
Require npm

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set WindowBar Colorful

# ── 0. Hidden setup ──────────────────────────────────────────────
# Clean prompt, git identity, temp dir — all invisible to viewer.

Hide
Type "PS1='demo> '"
Enter
Type "export GIT_AUTHOR_NAME='Demo' GIT_AUTHOR_EMAIL='demo@example.com'"
Enter
Type "export GIT_COMMITTER_NAME='Demo' GIT_COMMITTER_EMAIL='demo@example.com'"
Enter
Type "DEMO=$(mktemp -d) && cd $DEMO && git init -q . && clear"
Enter
Sleep 2s
Show

Type "# Rafter — catch secrets before they ship"
Enter
Sleep 1.5s

# ── 1. Plant a fake secret ───────────────────────────────────────
# Key split across printf args so this .tape passes secret scanning.

Type '# 1. A developer drops an AWS key into a config file'
Enter
Sleep 500ms

Type "printf 'AWS_ACCESS_KEY_ID=\"%s%s\"\\n' 'AKIAIOSF' 'ODNN7EXAMPLE' > config.env"
Enter
Sleep 500ms

Type "cat config.env"
Enter
Sleep 2s

# ── 2. Install Rafter ────────────────────────────────────────────

Type "# 2. Install Rafter"
Enter
Sleep 500ms

Type "npm install -g @rafter-security/cli 2>&1 | tail -1"
Enter
Sleep 15s

# ── 3. Scan — shows redacted finding + nonzero exit ──────────────

Type "# 3. Scan for secrets"
Enter
Sleep 500ms

Type 'rafter agent scan . ; echo "^ exit code: $?"'
Enter
Sleep 5s

# ── 4. Install pre-commit hook ────────────────────────────────────

Type "# 4. Install the pre-commit hook"
Enter
Sleep 500ms

Type "rafter agent install-hook"
Enter
Sleep 2s

# ── 5. Attempt commit — blocked ──────────────────────────────────

Type "# 5. Try to commit — the hook blocks it"
Enter
Sleep 500ms

Type "git add config.env && git commit -m 'add config'"
Enter
Sleep 5s

# ── 6. Audit log ─────────────────────────────────────────────────

Type "# 6. Check the audit trail"
Enter
Sleep 500ms

Type "rafter agent audit --event secret_detected --last 1"
Enter
Sleep 4s

# ── 7. Closing ────────────────────────────────────────────────────

Type "# Secrets caught. Commit blocked. Audit logged. That's Rafter."
Enter

Sleep 5s
