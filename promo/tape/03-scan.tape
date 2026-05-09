# Beat 3 — `rafter agent scan --staged` finds the leaked AWS key
# Output: 4-second MP4, 1920x1080, 60fps
# Frame target: 0:05–0:09 in the timeline

Output remotion/public/tape/03-scan.mp4

Require rafter

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 28
Set Width 1920
Set Height 1080
Set Padding 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 32ms
Set WindowBar Colorful
Set WindowBarSize 36
Set Framerate 60

# ── Hidden setup: create a staged file with a fake key ──────────
# Key is split so this file passes Rafter's own scanner.
Hide
Type "PS1='\\[\\e[38;5;141m\\]rafter\\[\\e[0m\\] \\[\\e[38;5;245m\\]›\\[\\e[0m\\] '" Enter
Type "cd $(mktemp -d)" Enter
Type "git init -q && git commit --allow-empty -q -m init" Enter
Type 'printf "AWS_ACCESS_KEY_ID=%s%s\n" AKIAIOSFODNN7 EXAMPLE > .env' Enter
Type "git add .env" Enter
Type "clear" Enter
Show

# ── Visible: the scan ────────────────────────────────────────────
Type "rafter agent scan --staged"
Sleep 400ms
Enter
Sleep 2500ms
Type "echo \"exit: $?\""
Enter
Sleep 800ms
