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

function createServer(): Server {
  const server = new Server(
    { name: "rafter", version: "0.5.0" },
    { capabilities: { tools: {}, resources: {} } },
  );

  // ── Tools ───────────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "scan_secrets",
        description: "Scan files or directories for hardcoded secrets and credentials",
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
        description: "Evaluate whether a shell command is allowed by Rafter security policy",
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
        description: "Read Rafter audit log entries with optional filtering",
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
        description: "Read Rafter configuration (full config or a specific key)",
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
