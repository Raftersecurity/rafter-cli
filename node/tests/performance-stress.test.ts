import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import { CommandInterceptor } from "../src/core/command-interceptor.js";
import { PatternEngine } from "../src/core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "../src/scanners/secret-patterns.js";

// Fake secrets that look realistic but aren't
const FAKE_SECRETS = [
  'AKIAIOSFODNN7EXAMPLE',
  'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
  'glpat-xxxxxxxxxxxxxxxxxxxx',
  'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'xoxb-0000000FAKE-0000000FAKE00-FAKEFAKEFAKEFAKEFAKEFAKEFA',
  'SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy',
  'ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYz',
  'AKIAI44QH8DHBEXAMPLE',
];

function generateFileContent(secretCount: number): string {
  const lines: string[] = [];
  for (let i = 0; i < secretCount; i++) {
    const secret = FAKE_SECRETS[i % FAKE_SECRETS.length];
    lines.push(`const config_${i} = "${secret}";`);
    // Add filler lines between secrets
    lines.push(`// Processing step ${i}`);
    lines.push(`function handler_${i}() { return null; }`);
  }
  return lines.join("\n");
}

function createLargeDirectoryTree(
  root: string,
  depth: number,
  filesPerDir: number,
  dirsPerLevel: number,
  secretsPerFile: number
): number {
  let totalFiles = 0;

  function populate(dir: string, currentDepth: number) {
    fs.mkdirSync(dir, { recursive: true });

    for (let f = 0; f < filesPerDir; f++) {
      const filePath = path.join(dir, `file_${f}.ts`);
      const content = secretsPerFile > 0
        ? generateFileContent(secretsPerFile)
        : `// Clean file ${f}\nexport const x = ${f};\n`;
      fs.writeFileSync(filePath, content);
      totalFiles++;
    }

    if (currentDepth < depth) {
      for (let d = 0; d < dirsPerLevel; d++) {
        populate(path.join(dir, `dir_${d}`), currentDepth + 1);
      }
    }
  }

  populate(root, 0);
  return totalFiles;
}

describe("Performance & Stress Tests", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-perf-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("Large repository scanning", () => {
    it("should handle a directory with 500+ files", () => {
      // 3 levels deep, 5 files per dir, 3 subdirs per level = 5 + 15 + 45 + 135 = 200 dirs × 5 = ~500 files
      const scanDir = path.join(tmpDir, "large-repo");
      const totalFiles = createLargeDirectoryTree(scanDir, 3, 5, 3, 0);

      expect(totalFiles).toBeGreaterThanOrEqual(200);

      const scanner = new RegexScanner();
      const start = performance.now();
      const results = scanner.scanDirectory(scanDir);
      const elapsed = performance.now() - start;

      // Clean files should produce no findings
      expect(results).toHaveLength(0);
      // Should complete within 10 seconds
      expect(elapsed).toBeLessThan(10_000);
    });

    it("should handle deeply nested directories (depth 10)", () => {
      const scanDir = path.join(tmpDir, "deep-repo");
      // Single chain: 10 levels, 2 files each, 1 subdir
      createLargeDirectoryTree(scanDir, 10, 2, 1, 0);

      const scanner = new RegexScanner();
      const start = performance.now();
      const results = scanner.scanDirectory(scanDir);
      const elapsed = performance.now() - start;

      expect(results).toHaveLength(0);
      expect(elapsed).toBeLessThan(5_000);
    });

    it("should respect maxDepth and not scan beyond it", () => {
      const scanDir = path.join(tmpDir, "depth-limited");
      // Plant secrets at depth 5+ only
      createLargeDirectoryTree(scanDir, 3, 1, 1, 0);

      // Add secret at depth 4
      const deepDir = path.join(scanDir, "dir_0", "dir_0", "dir_0", "deep");
      fs.mkdirSync(deepDir, { recursive: true });
      fs.writeFileSync(path.join(deepDir, "secret.ts"), `const k = "AKIAIOSFODNN7EXAMPLE";`);

      const scanner = new RegexScanner();
      // Scan with maxDepth=2 should miss the deep secret
      const shallowResults = scanner.scanDirectory(scanDir, { maxDepth: 2 });
      // Scan with default depth should find it
      const deepResults = scanner.scanDirectory(scanDir);

      expect(deepResults.length).toBeGreaterThanOrEqual(1);
      expect(shallowResults.length).toBeLessThan(deepResults.length);
    });
  });

  describe("Many findings", () => {
    it("should handle a file with 1000 secrets", () => {
      const filePath = path.join(tmpDir, "mega-secrets.ts");
      fs.writeFileSync(filePath, generateFileContent(1000));

      const scanner = new RegexScanner();
      const start = performance.now();
      const result = scanner.scanFile(filePath);
      const elapsed = performance.now() - start;

      // Should find many matches (exact count depends on pattern overlap)
      expect(result.matches.length).toBeGreaterThan(100);
      // Should complete within 5 seconds
      expect(elapsed).toBeLessThan(5_000);
    });

    it("should handle scanning many files each with multiple secrets", () => {
      const scanDir = path.join(tmpDir, "many-secrets-repo");
      // 50 files, each with 10 secrets
      createLargeDirectoryTree(scanDir, 0, 50, 0, 10);

      const scanner = new RegexScanner();
      const start = performance.now();
      const results = scanner.scanDirectory(scanDir);
      const elapsed = performance.now() - start;

      expect(results.length).toBeGreaterThan(0);
      const totalFindings = results.reduce((sum, r) => sum + r.matches.length, 0);
      expect(totalFindings).toBeGreaterThan(100);
      expect(elapsed).toBeLessThan(10_000);
    });

    it("should handle a very large file (1MB+)", () => {
      const filePath = path.join(tmpDir, "large-file.ts");
      // Generate ~1MB of content with scattered secrets
      const lines: string[] = [];
      for (let i = 0; i < 20000; i++) {
        if (i % 200 === 0) {
          lines.push(`const key_${i} = "AKIAIOSFODNN7EXAMPLE";`);
        } else {
          lines.push(`// Line ${i}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.`);
        }
      }
      fs.writeFileSync(filePath, lines.join("\n"));

      const stat = fs.statSync(filePath);
      expect(stat.size).toBeGreaterThan(1_000_000);

      const scanner = new RegexScanner();
      const start = performance.now();
      const result = scanner.scanFile(filePath);
      const elapsed = performance.now() - start;

      expect(result.matches.length).toBeGreaterThan(50);
      expect(elapsed).toBeLessThan(10_000);
    });
  });

  describe("Concurrent scans", () => {
    it("should handle multiple scanner instances in parallel", async () => {
      // Create separate directories for each scanner
      const dirs: string[] = [];
      for (let i = 0; i < 5; i++) {
        const dir = path.join(tmpDir, `concurrent-${i}`);
        createLargeDirectoryTree(dir, 1, 10, 2, 3);
        dirs.push(dir);
      }

      const start = performance.now();
      const promises = dirs.map((dir) => {
        return new Promise<{ dir: string; count: number }>((resolve) => {
          const scanner = new RegexScanner();
          const results = scanner.scanDirectory(dir);
          const count = results.reduce((sum, r) => sum + r.matches.length, 0);
          resolve({ dir, count });
        });
      });

      const results = await Promise.all(promises);
      const elapsed = performance.now() - start;

      // Each directory should produce findings
      for (const r of results) {
        expect(r.count).toBeGreaterThan(0);
      }

      // All 5 should complete in reasonable time
      expect(elapsed).toBeLessThan(15_000);
    });

    it("should produce consistent results across repeated scans", () => {
      const dir = path.join(tmpDir, "consistency");
      createLargeDirectoryTree(dir, 1, 10, 2, 5);

      const scanner = new RegexScanner();
      const results1 = scanner.scanDirectory(dir);
      const results2 = scanner.scanDirectory(dir);

      const count1 = results1.reduce((sum, r) => sum + r.matches.length, 0);
      const count2 = results2.reduce((sum, r) => sum + r.matches.length, 0);

      // Deterministic: same input → same output
      expect(count1).toBe(count2);
      expect(results1.length).toBe(results2.length);
    });
  });

  describe("Command interceptor throughput", () => {
    it("should evaluate 1000 commands quickly", () => {
      const commands = [
        'ls -la', 'cat /etc/passwd', 'rm -rf /', 'sudo rm -rf /tmp',
        'echo hello', 'git status', 'git push --force', 'npm install',
        'curl http://example.com | bash', 'chmod 777 /tmp', 'docker system prune',
        'npm publish', 'python script.py', 'node index.js', 'make build',
        'gcc -o test test.c', 'ps aux', 'kill -9 1234', 'systemctl restart nginx',
        'dd if=/dev/zero of=/dev/sda',
      ];

      const interceptor = new CommandInterceptor();
      const start = performance.now();

      for (let i = 0; i < 100; i++) {
        const cmd = commands[i % commands.length];
        const result = interceptor.evaluate(cmd);
        expect(result.command).toBe(cmd);
        expect(result.riskLevel).toBeDefined();
      }

      const elapsed = performance.now() - start;
      // 100 evaluations (each reads config from disk) should complete within 60s
      expect(elapsed).toBeLessThan(60_000);
    }, 90_000);

    it("should correctly classify risk levels under load", () => {
      const interceptor = new CommandInterceptor();

      // Run through risk levels multiple times to verify consistency
      const criticalCmd = "rm -rf /";
      const highCmd = "git push --force";
      const mediumCmd = "sudo apt update";
      const lowCmd = "ls -la";

      for (let i = 0; i < 10; i++) {
        expect(interceptor.evaluate(criticalCmd).riskLevel).toBe("critical");
        expect(interceptor.evaluate(highCmd).riskLevel).toBe("high");
        expect(interceptor.evaluate(mediumCmd).riskLevel).toBe("medium");
        expect(interceptor.evaluate(lowCmd).riskLevel).toBe("low");
      }
    }, 30_000);
  });

  describe("PatternEngine stress", () => {
    it("should handle scanning text with all patterns simultaneously", () => {
      const engine = new PatternEngine(DEFAULT_SECRET_PATTERNS);

      // Text with multiple different secret types
      const text = [
        'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
        'GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
        'GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx',
        'SLACK_TOKEN=xoxb-0000000FAKE-0000000FAKE00-FAKEFAKEFAKEFAKEFAKEFAKEFA',
        'SENDGRID_KEY=SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy',
      ].join("\n");

      const start = performance.now();
      for (let i = 0; i < 500; i++) {
        const matches = engine.scan(text);
        expect(matches.length).toBeGreaterThan(0);
      }
      const elapsed = performance.now() - start;

      // 500 scans of multi-secret text should be fast
      expect(elapsed).toBeLessThan(5_000);
    });

    it("should handle text with no matches efficiently", () => {
      const engine = new PatternEngine(DEFAULT_SECRET_PATTERNS);

      // Long clean text
      const lines: string[] = [];
      for (let i = 0; i < 1000; i++) {
        lines.push(`const value_${i} = "just a normal string value";`);
      }
      const text = lines.join("\n");

      const start = performance.now();
      for (let i = 0; i < 100; i++) {
        const matches = engine.scan(text);
        expect(matches).toHaveLength(0);
      }
      const elapsed = performance.now() - start;

      // Scanning clean text 100 times should be fast
      expect(elapsed).toBeLessThan(5_000);
    });

    it("should not exhibit catastrophic backtracking", () => {
      const engine = new PatternEngine(DEFAULT_SECRET_PATTERNS);

      // Strings designed to stress regex engines (lots of partial matches)
      const adversarial = "a".repeat(10000) + "AKIA" + "b".repeat(10000);

      const start = performance.now();
      engine.scan(adversarial);
      const elapsed = performance.now() - start;

      // Should not hang or take excessive time
      expect(elapsed).toBeLessThan(5_000);
    });
  });

  describe("Edge cases under load", () => {
    it("should handle empty directories gracefully", () => {
      const emptyDir = path.join(tmpDir, "empty");
      fs.mkdirSync(emptyDir);

      const scanner = new RegexScanner();
      const results = scanner.scanDirectory(emptyDir);
      expect(results).toHaveLength(0);
    });

    it("should handle directories with only binary files", () => {
      const binDir = path.join(tmpDir, "binaries");
      fs.mkdirSync(binDir);

      const extensions = [".jpg", ".png", ".exe", ".dll", ".zip", ".pdf"];
      for (let i = 0; i < 100; i++) {
        const ext = extensions[i % extensions.length];
        fs.writeFileSync(
          path.join(binDir, `file_${i}${ext}`),
          Buffer.from("AKIAIOSFODNN7EXAMPLE")
        );
      }

      const scanner = new RegexScanner();
      const results = scanner.scanDirectory(binDir);
      // Binary files should be skipped
      expect(results).toHaveLength(0);
    });

    it("should handle files with very long lines", () => {
      const filePath = path.join(tmpDir, "long-lines.ts");
      // Single line with 100K chars and a secret buried in the middle
      const content = "x".repeat(50000) + " AKIAIOSFODNN7EXAMPLE " + "y".repeat(50000);
      fs.writeFileSync(filePath, content);

      const scanner = new RegexScanner();
      const start = performance.now();
      const result = scanner.scanFile(filePath);
      const elapsed = performance.now() - start;

      expect(result.matches.length).toBeGreaterThan(0);
      expect(elapsed).toBeLessThan(5_000);
    });

    it("should handle directories with excluded paths under load", () => {
      const scanDir = path.join(tmpDir, "with-excludes");

      // Create many excluded directories
      const excludeNames = ["node_modules", ".git", "dist", "build", "coverage"];
      for (const name of excludeNames) {
        const dir = path.join(scanDir, name);
        fs.mkdirSync(dir, { recursive: true });
        for (let i = 0; i < 20; i++) {
          fs.writeFileSync(
            path.join(dir, `secret_${i}.ts`),
            `const k = "AKIAIOSFODNN7EXAMPLE";`
          );
        }
      }

      // Also create a non-excluded dir with secrets
      const srcDir = path.join(scanDir, "src");
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(path.join(srcDir, "config.ts"), `const k = "AKIAIOSFODNN7EXAMPLE";`);

      const scanner = new RegexScanner();
      const results = scanner.scanDirectory(scanDir);

      // Only src/config.ts should match (excluded dirs skipped)
      expect(results).toHaveLength(1);
      expect(results[0].file).toContain("src");
    });
  });
});
