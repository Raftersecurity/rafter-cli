#!/usr/bin/env node

// Postinstall hint: suggest rafter agent init after global install
// Kept minimal — just a console.log hint

console.log(
  "\n  \x1b[36mrafter\x1b[0m installed successfully.\n" +
    "  Run \x1b[1mrafter agent init --all\x1b[0m to set up security for your AI agents.\n"
);
