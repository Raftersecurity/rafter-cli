import { Command } from "commander";
import fs from "fs";
import path from "path";
import { PatternEngine } from "../../core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "../../scanners/secret-patterns.js";
import { SkillManager } from "../../utils/skill-manager.js";

interface QuickScanResults {
  secrets: number;
  urls: string[];
  highRiskCommands: Array<{ command: string; line: number }>;
}

export function createAuditSkillCommand(): Command {
  return new Command("audit-skill")
    .description("Security audit of a Claude Code skill file")
    .argument("<skill-path>", "Path to skill file to audit")
    .option("--skip-openclaw", "Skip OpenClaw integration, show manual review prompt")
    .option("--json", "Output results as JSON")
    .action(async (skillPath: string, opts: { skipOpenclaw?: boolean; json?: boolean }) => {
      await auditSkill(skillPath, opts);
    });
}

async function auditSkill(
  skillPath: string,
  opts: { skipOpenclaw?: boolean; json?: boolean }
): Promise<void> {
  // Validate skill file exists
  if (!fs.existsSync(skillPath)) {
    console.error(`Error: Skill file not found: ${skillPath}`);
    process.exit(1);
  }

  const absolutePath = path.resolve(skillPath);
  const skillContent = fs.readFileSync(absolutePath, "utf-8");
  const skillName = path.basename(absolutePath);

  // Run deterministic analysis
  if (!opts.json) {
    console.log(`\n🔍 Auditing skill: ${skillName}\n`);
    console.log("═".repeat(60));
    console.log("Running quick security scan...\n");
  }

  const quickScan = await runQuickScan(skillContent);

  // Display quick scan results
  if (!opts.json) {
    displayQuickScan(quickScan, skillName);
  }

  // Check OpenClaw availability
  const skillManager = new SkillManager();
  const openClawAvailable = skillManager.isOpenClawInstalled();
  const skillAuditorInstalled = skillManager.isSkillAuditorInstalled();

  if (opts.json) {
    // JSON output
    const result = {
      skill: skillName,
      path: absolutePath,
      quickScan,
      openClawAvailable,
      skillAuditorInstalled
    };
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // Check if we can use OpenClaw
  if (openClawAvailable && !opts.skipOpenclaw) {
    if (!skillAuditorInstalled) {
      console.log("\n⚠️  Skill auditor not installed in OpenClaw.");
      console.log("   Run: rafter agent init\n");
    } else {
      console.log("\n🤖 For comprehensive security review:\n");
      console.log("   1. Open OpenClaw");
      console.log(`   2. Run: /audit-skill ${absolutePath}`);
      console.log("\n   The auditor will analyze:");
      console.log("   • Trust & attribution");
      console.log("   • Network security");
      console.log("   • Command execution risks");
      console.log("   • File system access");
      console.log("   • Credential handling");
      console.log("   • Input validation & injection risks");
      console.log("   • Data exfiltration patterns");
      console.log("   • Obfuscation techniques");
      console.log("   • Scope & intent alignment");
      console.log("   • Error handling & info disclosure");
      console.log("   • Dependencies & supply chain");
      console.log("   • Environment manipulation\n");
    }
  } else {
    // OpenClaw not available or skipped - show manual review prompt
    console.log("\n📋 Manual Security Review Prompt\n");
    console.log("═".repeat(60));
    console.log("\nCopy the following to your AI assistant for review:\n");
    console.log("─".repeat(60));
    console.log(generateManualReviewPrompt(skillName, absolutePath, quickScan, skillContent));
    console.log("─".repeat(60));
  }

  console.log();
}

async function runQuickScan(content: string): Promise<QuickScanResults> {
  // 1. Scan for secrets
  const patternEngine = new PatternEngine(DEFAULT_SECRET_PATTERNS);
  const secretMatches = patternEngine.scan(content);

  // 2. Extract URLs
  const urlRegex = /https?:\/\/[^\s<>"]+/gi;
  const urls = Array.from(new Set(content.match(urlRegex) || []));

  // 3. Detect high-risk commands
  const highRiskPatterns = [
    { pattern: /rm\s+-rf\s+\/(?!\w)/gi, name: "rm -rf /" },
    { pattern: /sudo\s+rm/gi, name: "sudo rm" },
    { pattern: /curl[^|]*\|\s*(?:ba)?sh/gi, name: "curl | sh" },
    { pattern: /wget[^|]*\|\s*(?:ba)?sh/gi, name: "wget | sh" },
    { pattern: /eval\s*\(/gi, name: "eval()" },
    { pattern: /exec\s*\(/gi, name: "exec()" },
    { pattern: /chmod\s+777/gi, name: "chmod 777" },
    { pattern: /:\(\)\{\s*:\|:&\s*\};:/g, name: "fork bomb" },
    { pattern: /dd\s+if=\/dev\/(?:zero|random)\s+of=\/dev/gi, name: "dd to device" },
    { pattern: /mkfs/gi, name: "mkfs (format)" },
    { pattern: /base64\s+-d[^|]*\|\s*(?:ba)?sh/gi, name: "base64 decode | sh" }
  ];

  const commands: Array<{ command: string; line: number }> = [];
  const lines = content.split('\n');

  for (const { pattern, name } of highRiskPatterns) {
    pattern.lastIndex = 0; // Reset regex
    let match;
    while ((match = pattern.exec(content)) !== null) {
      // Find line number
      const lineNumber = content.substring(0, match.index).split('\n').length;
      commands.push({
        command: name,
        line: lineNumber
      });
    }
  }

  return {
    secrets: secretMatches.length,
    urls,
    highRiskCommands: commands
  };
}

function displayQuickScan(scan: QuickScanResults, skillName: string): void {
  console.log("📊 Quick Scan Results");
  console.log("═".repeat(60));

  // Secrets
  if (scan.secrets === 0) {
    console.log("✓ Secrets: None detected");
  } else {
    console.log(`⚠️  Secrets: ${scan.secrets} found`);
    console.log("   → API keys, tokens, or credentials detected");
    console.log("   → Run: rafter agent scan <path> for details");
  }

  // URLs
  if (scan.urls.length === 0) {
    console.log("✓ External URLs: None");
  } else {
    console.log(`⚠️  External URLs: ${scan.urls.length} found`);
    scan.urls.slice(0, 5).forEach(url => {
      console.log(`   • ${url}`);
    });
    if (scan.urls.length > 5) {
      console.log(`   ... and ${scan.urls.length - 5} more`);
    }
  }

  // High-risk commands
  if (scan.highRiskCommands.length === 0) {
    console.log("✓ High-risk commands: None detected");
  } else {
    console.log(`⚠️  High-risk commands: ${scan.highRiskCommands.length} found`);
    scan.highRiskCommands.slice(0, 5).forEach(cmd => {
      console.log(`   • ${cmd.command} (line ${cmd.line})`);
    });
    if (scan.highRiskCommands.length > 5) {
      console.log(`   ... and ${scan.highRiskCommands.length - 5} more`);
    }
  }

  console.log();
}

function generateManualReviewPrompt(
  skillName: string,
  skillPath: string,
  scan: QuickScanResults,
  content: string
): string {
  return `You are reviewing a Claude Code skill for security issues. Analyze the skill below and provide:

1. **Security Assessment**: Evaluate trustworthiness, identify risks
2. **External Dependencies**: Review URLs, APIs, network calls - are they trustworthy?
3. **Command Safety**: Analyze shell commands - any dangerous patterns?
4. **Bundled Resources**: Check for suspicious scripts, images, binaries
5. **Prompt Injection Risks**: Could malicious input exploit this skill?
6. **Data Exfiltration**: Does it send sensitive data externally?
7. **Credential Handling**: How are API keys/secrets managed?
8. **Input Validation**: Is user input properly sanitized?
9. **File System Access**: What files does it read/write?
10. **Scope Alignment**: Does behavior match stated purpose?
11. **Recommendations**: Should I install this? What precautions?

**Skill**: ${skillName}
**Path**: ${skillPath}

**Quick Scan Findings**:
- Secrets detected: ${scan.secrets}
- External URLs: ${scan.urls.length}${scan.urls.length > 0 ? `\n  ${scan.urls.join('\n  ')}` : ''}
- High-risk commands: ${scan.highRiskCommands.length}${scan.highRiskCommands.length > 0 ? `\n  ${scan.highRiskCommands.map(c => `${c.command} (line ${c.line})`).join('\n  ')}` : ''}

**Skill Content**:
\`\`\`markdown
${content}
\`\`\`

Provide a clear risk rating (LOW/MEDIUM/HIGH/CRITICAL) and actionable recommendations.`;
}
