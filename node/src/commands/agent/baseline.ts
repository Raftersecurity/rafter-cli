import { Command } from "commander";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt } from "../../utils/formatter.js";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { GitleaksScanner } from "../../scanners/gitleaks.js";
import { ConfigManager } from "../../core/config-manager.js";

const BASELINE_PATH = path.join(os.homedir(), ".rafter", "baseline.json");

interface BaselineEntry {
  file: string;
  line: number | null;
  pattern: string;
  addedAt: string;
}

interface Baseline {
  version: number;
  created: string;
  updated: string;
  entries: BaselineEntry[];
}

function loadBaseline(): Baseline {
  if (!fs.existsSync(BASELINE_PATH)) {
    return { version: 1, created: "", updated: "", entries: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8")) as Baseline;
  } catch {
    return { version: 1, created: "", updated: "", entries: [] };
  }
}

function saveBaseline(baseline: Baseline): void {
  const dir = path.dirname(BASELINE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2), "utf-8");
}

export function createBaselineCommand(): Command {
  const baseline = new Command("baseline")
    .description("Manage the findings baseline (allowlist for known findings)");

  baseline.addCommand(createBaselineCreateCommand());
  baseline.addCommand(createBaselineShowCommand());
  baseline.addCommand(createBaselineClearCommand());
  baseline.addCommand(createBaselineAddCommand());

  return baseline;
}

function createBaselineCreateCommand(): Command {
  return new Command("create")
    .description("Scan and save all current findings as the baseline")
    .argument("[path]", "Path to scan", ".")
    .option("--engine <engine>", "Scan engine: gitleaks or patterns", "auto")
    .action(async (scanPath: string, opts: { engine?: string }) => {
      const resolvedPath = path.resolve(scanPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(2);
      }

      const manager = new ConfigManager();
      const cfg = manager.loadWithPolicy();
      const scanCfg = cfg.agent?.scan;

      console.error(`Scanning ${resolvedPath} to build baseline...`);

      const engine = await selectEngine(opts.engine || "auto");
      let results;

      if (fs.statSync(resolvedPath).isDirectory()) {
        results = await scanDirectory(resolvedPath, engine, scanCfg);
      } else {
        results = await scanFile(resolvedPath, engine);
      }

      const now = new Date().toISOString();
      const entries: BaselineEntry[] = [];
      for (const r of results) {
        for (const m of r.matches) {
          entries.push({
            file: r.file,
            line: m.line ?? null,
            pattern: m.pattern.name,
            addedAt: now,
          });
        }
      }

      const existing = loadBaseline();
      const baseline: Baseline = {
        version: 1,
        created: existing.created || now,
        updated: now,
        entries,
      };
      saveBaseline(baseline);

      if (entries.length === 0) {
        console.log(fmt.success("No findings — baseline is empty (all clean)"));
      } else {
        console.log(fmt.success(`Baseline saved: ${entries.length} finding(s) recorded`));
        console.log(`  Location: ${BASELINE_PATH}`);
        console.log();
        console.log("Future scans with --baseline will suppress these findings.");
      }
    });
}

function createBaselineShowCommand(): Command {
  return new Command("show")
    .description("Show current baseline entries")
    .option("--json", "Output as JSON")
    .action((opts: { json?: boolean }) => {
      const baseline = loadBaseline();

      if (opts.json) {
        console.log(JSON.stringify(baseline, null, 2));
        return;
      }

      if (baseline.entries.length === 0) {
        console.log("Baseline is empty. Run: rafter agent baseline create");
        return;
      }

      console.log(`Baseline: ${baseline.entries.length} entries`);
      if (baseline.updated) {
        console.log(`Updated: ${baseline.updated}`);
      }
      console.log();

      // Group by file
      const byFile = new Map<string, BaselineEntry[]>();
      for (const entry of baseline.entries) {
        const list = byFile.get(entry.file) || [];
        list.push(entry);
        byFile.set(entry.file, list);
      }

      for (const [file, entries] of byFile) {
        console.log(fmt.info(file));
        for (const e of entries) {
          const loc = e.line != null ? `line ${e.line}` : "unknown location";
          console.log(`  ${e.pattern} (${loc})`);
        }
        console.log();
      }
    });
}

function createBaselineClearCommand(): Command {
  return new Command("clear")
    .description("Remove all baseline entries")
    .action(() => {
      if (!fs.existsSync(BASELINE_PATH)) {
        console.log("No baseline file found — nothing to clear.");
        return;
      }
      fs.unlinkSync(BASELINE_PATH);
      console.log(fmt.success("Baseline cleared"));
    });
}

function createBaselineAddCommand(): Command {
  return new Command("add")
    .description("Manually add a finding to the baseline")
    .requiredOption("--file <path>", "File path")
    .requiredOption("--pattern <name>", "Pattern name (e.g. 'AWS Access Key')")
    .option("--line <number>", "Line number")
    .action((opts: { file: string; pattern: string; line?: string }) => {
      const baseline = loadBaseline();
      const now = new Date().toISOString();

      const entry: BaselineEntry = {
        file: path.resolve(opts.file),
        line: opts.line != null ? parseInt(opts.line, 10) : null,
        pattern: opts.pattern,
        addedAt: now,
      };

      baseline.entries.push(entry);
      baseline.updated = now;
      if (!baseline.created) baseline.created = now;
      saveBaseline(baseline);

      console.log(fmt.success(`Added to baseline: ${opts.pattern} in ${opts.file}`));
    });
}

// ── helpers ─────────────────────────────────────────────────────────

async function selectEngine(preference: string): Promise<"gitleaks" | "patterns"> {
  if (preference === "patterns") return "patterns";
  if (preference === "gitleaks") {
    const g = new GitleaksScanner();
    return (await g.isAvailable()) ? "gitleaks" : "patterns";
  }
  const g = new GitleaksScanner();
  return (await g.isAvailable()) ? "gitleaks" : "patterns";
}

async function scanFile(
  filePath: string,
  engine: "gitleaks" | "patterns",
) {
  if (engine === "gitleaks") {
    try {
      const g = new GitleaksScanner();
      const r = await g.scanFile(filePath);
      return r.matches.length > 0 ? [r] : [];
    } catch {
      const s = new RegexScanner();
      const r = s.scanFile(filePath);
      return r.matches.length > 0 ? [r] : [];
    }
  }
  const s = new RegexScanner();
  const r = s.scanFile(filePath);
  return r.matches.length > 0 ? [r] : [];
}

async function scanDirectory(
  dirPath: string,
  engine: "gitleaks" | "patterns",
  scanCfg?: { excludePaths?: string[] },
) {
  if (engine === "gitleaks") {
    try {
      const g = new GitleaksScanner();
      return await g.scanDirectory(dirPath);
    } catch {
      const s = new RegexScanner();
      return s.scanDirectory(dirPath, { excludePaths: scanCfg?.excludePaths });
    }
  }
  const s = new RegexScanner();
  return s.scanDirectory(dirPath, { excludePaths: scanCfg?.excludePaths });
}
