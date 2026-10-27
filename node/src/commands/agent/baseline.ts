import { Command } from "commander";
import fs from "fs";
import os from "os";
import path from "path";
import { fmt } from "../../utils/formatter.js";
import { ConfigManager } from "../../core/config-manager.js";
import { selectEngine, scanFile, scanDirectory } from "./scan.js";

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
    .option("--engine <engine>", "Scan engine: betterleaks or patterns", "auto")
    .action(async (scanPath: string, opts: { engine?: string }) => {
      const validEngines = ["auto", "betterleaks", "patterns"];
      const engineValue = opts.engine || "auto";
      if (!validEngines.includes(engineValue)) {
        console.error(`Invalid engine: ${engineValue}. Valid values: ${validEngines.join(", ")}`);
        process.exit(2);
      }

      const resolvedPath = path.resolve(scanPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path not found: ${resolvedPath}`);
        process.exit(2);
      }

      const manager = new ConfigManager();
      const cfg = manager.loadWithPolicy();
      const scanCfg = cfg.agent?.scan;

      console.error(`Scanning ${resolvedPath} to build baseline...`);

      // Use the same engine selection and union the scan command uses, so the
      // baseline captures exactly what a later `rafter secrets` would find
      // (sable-qb9g). In `auto` this runs BOTH engines and unions; the old
      // local helpers ran betterleaks-only, so a secret only the patterns
      // engine catches never made it into the baseline.
      const autoUpdate = scanCfg?.autoUpdateBetterleaks !== false;
      const { engine } = await selectEngine(opts.engine || "auto", false, autoUpdate);
      let results;

      if (fs.statSync(resolvedPath).isDirectory()) {
        results = await scanDirectory(resolvedPath, engine, scanCfg);
      } else {
        results = await scanFile(resolvedPath, engine, scanCfg);
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

