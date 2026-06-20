import { Command } from "commander";
import fs from "fs";
import path from "path";
import { PatternEngine } from "../../core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "../../scanners/secret-patterns.js";
import {
  SkillScanner,
  hasFindings as deepHasFindings,
  INSTALL_HINT,
  type DeepScanResult,
} from "../../scanners/skill-scanner.js";
import { SkillManager } from "../../utils/skill-manager.js";
import { fmt, isAgentMode } from "../../utils/formatter.js";

interface QuickScanResults {
  secrets: number;
  urls: string[];
  highRiskCommands: Array<{ command: string; line: number }>;
}

interface AuditSkillOpts {
  skipOpenclaw?: boolean;
  json?: boolean;
  deep?: boolean;
  engine?: string;
}

export function createAuditSkillCommand(): Command {
  return new Command("audit-skill")
    .description("[deprecated] Security audit of a Claude Code skill file — use `rafter skill review` instead")
    .argument("<skill-path>", "Path to skill file or directory to audit")
    .option("--skip-openclaw", "Skip OpenClaw integration, show manual review prompt")
    .option("--json", "Output results as JSON")
    .option(
      "--deep",
      "Run the optional DEEP engine (Cisco AI Defense skill-scanner) in addition to the quick scan. Offline analyzers only — no LLM/cloud/network. Requires cisco-ai-skill-scanner.",
    )
    .option("--engine <engine>", "Deep engine selector. 'skill-scanner' is equivalent to --deep.")
    .action(async (skillPath: string, opts: AuditSkillOpts) => {
      process.stderr.write(
        "[deprecated] `rafter agent audit-skill` is deprecated; use `rafter skill review <path-or-url>` instead.\n",
      );
      await auditSkill(skillPath, opts);
    });
}

async function auditSkill(
  skillPath: string,
  opts: AuditSkillOpts
): Promise<void> {
  // Validate target exists. Accept either a skill *file* (.md) or a skill
  // *directory*. The deep engine (--deep) is most thorough on a directory,
  // where it can also see bundled scripts / .pyc; the quick scan reads the
  // directory's SKILL.md (or the file itself).
  if (!fs.existsSync(skillPath)) {
    console.error(fmt.error(`Skill path not found: ${skillPath}`));
    process.exit(2);
  }

  const absolutePath = path.resolve(skillPath);
  const isDir = fs.statSync(absolutePath).isDirectory();
  let skillContent: string;
  if (isDir) {
    const skillMd = path.join(absolutePath, "SKILL.md");
    skillContent = fs.existsSync(skillMd) ? fs.readFileSync(skillMd, "utf-8") : "";
  } else {
    skillContent = fs.readFileSync(absolutePath, "utf-8");
  }
  const skillName = path.basename(absolutePath);

  // Validate --engine early (mirrors the Python contract).
  const wantDeep = !!opts.deep || opts.engine === "skill-scanner";
  if (opts.engine != null && opts.engine !== "skill-scanner") {
    console.error(fmt.error(`unknown --engine '${opts.engine}' (supported: skill-scanner)`));
    process.exit(2);
  }

  // Run deterministic analysis
  if (!opts.json) {
    console.log(fmt.header(`Auditing skill: ${skillName}`));
    console.log(fmt.divider());
    console.log("Running quick security scan...\n");
  }

  const quickScan = await runQuickScan(skillContent);

  // Display quick scan results
  if (!opts.json) {
    displayQuickScan(quickScan, skillName);
  }

  // Optional DEEP engine (skill-scanner) — opt-in via --deep or
  // --engine skill-scanner. Offline analyzers only; preserves our
  // no-telemetry default (sable-7g7).
  let deepResult: DeepScanResult | null = null;
  if (wantDeep) {
    const scanner = new SkillScanner();
    if (!scanner.isAvailable()) {
      // --deep requested but tool missing: clear hint, non-zero exit, no crash.
      console.error(INSTALL_HINT);
      process.exit(2);
    }
    deepResult = await scanner.scanPath(absolutePath);
    if (deepResult.error) {
      console.error(fmt.error(`deep scan failed: ${deepResult.error}`));
      process.exit(2);
    }
    if (!opts.json) {
      displayDeepScan(deepResult);
    }
  }

  const quickHasFindings = quickScan.secrets > 0 || quickScan.highRiskCommands.length > 0;
  const deepFound = deepResult ? deepHasFindings(deepResult) : false;

  // Check OpenClaw availability
  const skillManager = new SkillManager();
  const openClawAvailable = skillManager.isOpenClawInstalled();
  const rafterSkillInstalled = skillManager.isRafterSkillInstalled();

  if (opts.json) {
    // JSON output
    const result: Record<string, unknown> = {
      skill: skillName,
      path: absolutePath,
      quickScan,
      openClawAvailable,
      rafterSkillInstalled
    };
    if (deepResult) {
      result.deepScan = {
        engine: "skill-scanner",
        maxSeverity: deepResult.maxSeverity,
        analyzersUsed: deepResult.analyzersUsed,
        findings: deepResult.findings,
      };
    }
    console.log(JSON.stringify(result, null, 2));
    if (quickHasFindings || deepFound) {
      process.exit(1);
    }
    return;
  }

  // Check if we can use OpenClaw
  if (openClawAvailable && !opts.skipOpenclaw) {
    if (!rafterSkillInstalled) {
      console.log(`\n${fmt.warning("Rafter Security skill not installed in OpenClaw.")}`);
      console.log("   Run: rafter agent init\n");
    } else {
      console.log(`\n${fmt.info("For comprehensive security review:")}\n`);
      console.log("   1. Open OpenClaw");
      console.log(`   2. Run: /rafter-audit-skill ${absolutePath}`);
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
    console.log(fmt.header("Manual Security Review Prompt"));
    console.log(fmt.divider());
    console.log("\nCopy the following to your AI assistant for review:\n");
    console.log(fmt.divider());
    console.log(generateManualReviewPrompt(skillName, absolutePath, quickScan, skillContent));
    console.log(fmt.divider());
  }

  console.log();

  if (quickHasFindings || deepFound) {
    process.exit(1);
  }
}

function displayDeepScan(deep: DeepScanResult): void {
  console.log(`\n🔎 Deep Scan Results (skill-scanner)`);
  console.log(fmt.divider());
  if (!deep.available) {
    console.log(fmt.warning("skill-scanner not available"));
    return;
  }
  const actionable = deep.findings.filter((f) =>
    ["critical", "high", "medium"].includes(f.severity),
  );
  if (actionable.length === 0) {
    console.log(fmt.success("No critical/high/medium findings"));
  } else {
    console.log(
      fmt.warning(`${actionable.length} finding(s) (max severity: ${deep.maxSeverity})`),
    );
    actionable.slice(0, 10).forEach((f) => {
      const loc = f.line ? ` (line ${f.line})` : "";
      console.log(`   • [${f.severity.toUpperCase()}] ${f.category}: ${f.title}${loc}`);
    });
    if (actionable.length > 10) {
      console.log(`   ... and ${actionable.length - 10} more`);
    }
  }
  if (deep.analyzersUsed.length > 0) {
    console.log(`   analyzers: ${deep.analyzersUsed.join(", ")} (offline only)`);
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
  console.log(fmt.header("Quick Scan Results"));
  console.log(fmt.divider());

  // Secrets
  if (scan.secrets === 0) {
    console.log(fmt.success("Secrets: None detected"));
  } else {
    console.log(fmt.warning(`Secrets: ${scan.secrets} found`));
    console.log("   → API keys, tokens, or credentials detected");
    console.log("   → Run: rafter secrets <path> for details");
  }

  // URLs
  if (scan.urls.length === 0) {
    console.log(fmt.success("External URLs: None"));
  } else {
    console.log(fmt.warning(`External URLs: ${scan.urls.length} found`));
    scan.urls.slice(0, 5).forEach(url => {
      console.log(`   - ${url}`);
    });
    if (scan.urls.length > 5) {
      console.log(`   ... and ${scan.urls.length - 5} more`);
    }
  }

  // High-risk commands
  if (scan.highRiskCommands.length === 0) {
    console.log(fmt.success("High-risk commands: None detected"));
  } else {
    console.log(fmt.warning(`High-risk commands: ${scan.highRiskCommands.length} found`));
    scan.highRiskCommands.slice(0, 5).forEach(cmd => {
      console.log(`   - ${cmd.command} (line ${cmd.line})`);
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
