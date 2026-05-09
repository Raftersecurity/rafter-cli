# Beat 9 — `rafter skill review` flags a hostile third-party skill
# Output: 4-second MP4
# Frame target: 0:30–0:34

Output remotion/public/tape/09-skill-review.mp4

Require rafter

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 26
Set Width 1920
Set Height 1080
Set Padding 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 28ms
Set WindowBar Colorful
Set WindowBarSize 36
Set Framerate 60

Hide
Type "PS1='\\[\\e[38;5;141m\\]rafter\\[\\e[0m\\] \\[\\e[38;5;245m\\]›\\[\\e[0m\\] '" Enter
# Use a pre-built fixture skill that ships with the repo
Type "cd $REPO_ROOT/fixtures/skills/hostile-example" Enter
Type "clear" Enter
Show

Type "rafter skill review ."
Sleep 400ms
Enter
Sleep 3200ms
