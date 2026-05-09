# Beat 4 — pre-commit hook blocks the commit
# Output: 4-second MP4
# Frame target: 0:09–0:13

Output remotion/public/tape/04-blocked.mp4

Require rafter
Require git

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

Hide
Type "PS1='\\[\\e[38;5;141m\\]rafter\\[\\e[0m\\] \\[\\e[38;5;245m\\]›\\[\\e[0m\\] '" Enter
Type "cd $(mktemp -d) && git init -q && git commit --allow-empty -q -m init" Enter
Type "rafter agent install-hook" Enter
Type 'printf "AWS_ACCESS_KEY_ID=%s%s\n" AKIAIOSFODNN7 EXAMPLE > .env' Enter
Type "git add .env" Enter
Type "clear" Enter
Show

Type 'git commit -m "add config"'
Sleep 400ms
Enter
Sleep 3000ms
