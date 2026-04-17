import { Command } from "commander";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RegexScanner } from "../../scanners/regex-scanner.js";
import { GitleaksScanner } from "../../scanners/gitleaks.js";
import { CommandInterceptor } from "../../core/command-interceptor.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { ConfigManager } from "../../core/config-manager.js";
import { listDocs, resolveDocSelector, fetchDoc } from "../../core/docs-loader.js";
import { createRequire } from "module";

const _require = createRequire(import.meta.url);
const { version: CLI_VERSION } = _require("../../../package.json");

interface ScanResultOutput {
  file: string;
  matches: Array<{
    pattern: string;
    severity: string;
    line: number | undefined;
    redacted: string;
  }>;
}

function formatScanResults(results: Array<{ file: string; matches: any[] }>): ScanResultOutput[] {
  return results.map(r => ({
    file: r.file,
    matches: r.matches.map(m => ({
      pattern: m.pattern.name,
      severity: m.pattern.severity,
      line: m.line,
      redacted: m.redacted || m.match.slice(0, 4) + "****",
    })),
  }));
}

function textResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

function errorResult(message: string) {
  return { content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }], isError: true as const };
}

export function createServer(): Server {
  const server = new Server(
    { name: "rafter", version: CLI_VERSION },
    { capabilities: { tools: {}, resources: {} } },
  );

  // ── Tools ───────────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "scan_secrets",
        description: "Scan files or directories for leaked secrets, API keys, tokens, passwords, and credentials. Use before pushing code, when handling config files, or when asked 'is this safe to commit?' or 'check for leaked keys'.",
        inputSchema: {
          type: "object" as const,
          properties: {
            path: { type: "string", description: "File or directory path to scan" },
            engine: {
              type: "string",
              enum: ["auto", "gitleaks", "patterns"],
              description: "Scan engine: auto (default), gitleaks, or patterns",
            },
          },
          required: ["path"],
        },
      },
      {
        name: "evaluate_command",
        description: "Check if a shell command is safe to run per security policy. Use when asked 'is this command safe?' or before running destructive or privileged operations.",
        inputSchema: {
          type: "object" as const,
          properties: {
            command: { type: "string", description: "Shell command to evaluate" },
          },
          required: ["command"],
        },
      },
      {
        name: "read_audit_log",
        description: "Read security event history — blocked commands, detected secrets, policy overrides. Use when asked 'what happened?' or 'show security events'.",
        inputSchema: {
          type: "object" as const,
          properties: {
            limit: { type: "number", description: "Maximum entries to return (default: 20)" },
            event_type: {
              type: "string",
              description: "Filter by event type (e.g. command_intercepted, secret_detected)",
            },
            since: { type: "string", description: "ISO 8601 timestamp — only return entries after this time" },
          },
        },
      },
      {
        name: "get_config",
        description: "Read Rafter security policy and configuration. Use to understand what protections are active and what risk level is configured.",
        inputSchema: {
          type: "object" as const,
          properties: {
            key: {
              type: "string",
              description: "Dot-path config key (e.g. agent.commandPolicy). Omit for full config.",
            },
          },
        },
      },
      {
        name: "list_docs",
        description: "List repo-specific security docs declared in .rafter.yml. Call this early in any security-relevant task to discover project-specific rules, threat models, or compliance policies the user expects agents to follow.",
        inputSchema: {
          type: "object" as const,
          properties: {
            tag: { type: "string", description: "Filter to docs whose tags include this value" },
          },
        },
      },
      {
        name: "get_doc",
        description: "Return the content of a repo-specific security doc by id or tag. Use after list_docs to read a specific document.",
        inputSchema: {
          type: "object" as const,
          properties: {
            id_or_tag: { type: "string", description: "Doc id or tag selector" },
            refresh: { type: "boolean", description: "Force re-fetch for URL-backed docs (bypass cache)" },
          },
          required: ["id_or_tag"],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "scan_secrets": {
        const scanPath = args?.path as string;
        const engine = (args?.engine as string) || "auto";

        if (engine === "gitleaks" || engine === "auto") {
          const gitleaks = new GitleaksScanner();
          if (await gitleaks.isAvailable()) {
            try {
              const results = await gitleaks.scanDirectory(scanPath);
              return textResult(formatScanResults(results));
            } catch {
              if (engine === "gitleaks") return errorResult("Gitleaks scan failed");
            }
          } else if (engine === "gitleaks") {
            return errorResult("Gitleaks not installed");
          }
        }

        const scanner = new RegexScanner();
        let results;
        try {
          results = scanner.scanDirectory(scanPath);
        } catch {
          results = [scanner.scanFile(scanPath)];
        }
        return textResult(formatScanResults(results));
      }

      case "evaluate_command": {
        const command = args?.command as string;
        const interceptor = new CommandInterceptor();
        const result = interceptor.evaluate(command);
        const out: Record<string, unknown> = {
          allowed: result.allowed,
          risk_level: result.riskLevel,
          requires_approval: result.requiresApproval,
        };
        if (result.reason) out.reason = result.reason;
        return textResult(out);
      }

      case "read_audit_log": {
        const logger = new AuditLogger();
        const entries = logger.read({
          limit: (args?.limit as number) ?? 20,
          eventType: args?.event_type as any,
          since: args?.since ? new Date(args.since as string) : undefined,
        });
        return textResult(entries);
      }

      case "get_config": {
        const manager = new ConfigManager();
        const key = args?.key as string | undefined;
        const value = key ? manager.get(key) : manager.load();
        return textResult(value);
      }

      case "list_docs": {
        const tag = args?.tag as string | undefined;
        const entries = listDocs().filter(d =>
          !tag || (Array.isArray(d.tags) && d.tags.includes(tag))
        );
        return textResult(entries.map(e => ({
          id: e.id,
          source: e.source,
          source_kind: e.sourceKind,
          description: e.description || "",
          tags: e.tags || [],
          cache_status: e.cacheStatus,
        })));
      }

      case "get_doc": {
        const selector = args?.id_or_tag as string;
        if (!selector) return errorResult("id_or_tag is required");
        const matches = resolveDocSelector(selector);
        if (matches.length === 0) return errorResult(`No doc matched id or tag: ${selector}`);
        const refresh = Boolean(args?.refresh);
        const results: Array<{ id: string; source: string; source_kind: string; stale: boolean; content: string }> = [];
        for (const entry of matches) {
          try {
            const fetched = await fetchDoc(entry, { refresh });
            results.push({
              id: entry.id,
              source: fetched.source,
              source_kind: fetched.sourceKind,
              stale: fetched.stale,
              content: fetched.content,
            });
          } catch (err: any) {
            return errorResult(`Failed to fetch ${entry.id}: ${err.message || err}`);
          }
        }
        return textResult(results);
      }

      default:
        return errorResult(`Unknown tool: ${name}`);
    }
  });

  // ── Resources ───────────────────────────────────────────────────────

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      {
        uri: "rafter://config",
        name: "Rafter Configuration",
        description: "Current Rafter configuration",
        mimeType: "application/json",
      },
      {
        uri: "rafter://policy",
        name: "Rafter Policy",
        description: "Active security policy (merged .rafter.yml + config)",
        mimeType: "application/json",
      },
      {
        uri: "rafter://docs",
        name: "Rafter Docs",
        description: "Repo-specific security docs declared in .rafter.yml (metadata only, no content)",
        mimeType: "application/json",
      },
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    const manager = new ConfigManager();

    switch (uri) {
      case "rafter://config":
        return {
          contents: [{
            uri: "rafter://config",
            mimeType: "application/json",
            text: JSON.stringify(manager.load(), null, 2),
          }],
        };

      case "rafter://policy":
        return {
          contents: [{
            uri: "rafter://policy",
            mimeType: "application/json",
            text: JSON.stringify(manager.loadWithPolicy(), null, 2),
          }],
        };

      case "rafter://docs": {
        const entries = listDocs().map(e => ({
          id: e.id,
          source: e.source,
          source_kind: e.sourceKind,
          description: e.description || "",
          tags: e.tags || [],
          cache_status: e.cacheStatus,
        }));
        return {
          contents: [{
            uri: "rafter://docs",
            mimeType: "application/json",
            text: JSON.stringify(entries, null, 2),
          }],
        };
      }

      default:
        throw new Error(`Unknown resource: ${uri}`);
    }
  });

  return server;
}

export function createMcpServeCommand(): Command {
  return new Command("serve")
    .description("Start MCP server over stdio transport")
    .option("--transport <type>", "Transport type (currently only stdio)", "stdio")
    .action(async () => {
      const server = createServer();
      const transport = new StdioServerTransport();
      await server.connect(transport);
    });
}
