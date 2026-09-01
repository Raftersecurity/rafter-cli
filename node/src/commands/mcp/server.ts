import { Command } from "commander";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RegexScanner, ScanResult } from "../../scanners/regex-scanner.js";
import { BetterleaksScanner } from "../../scanners/betterleaks.js";
import { unionScanResults } from "../../scanners/union.js";
import { CommandInterceptor } from "../../core/command-interceptor.js";
import { AuditLogger } from "../../core/audit-logger.js";
import { ConfigManager, redactConfigSecrets, isSecretConfigKey, maskSecretValue } from "../../core/config-manager.js";
import { listDocs, resolveDocSelector, fetchDoc } from "../../core/docs-loader.js";
import { writeSuppression } from "../../core/suppression-writer.js";
import { apiUrl, apiClient} from "../../utils/api.js";
import { describeSitesError, resolveMcpApiKey } from "../sites/errors.js";
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
    engines?: string[];
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
      // sable-j85 — engine attribution, set only for both-engine (auto) scans.
      ...(m.engines ? { engines: m.engines } : {}),
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
              enum: ["auto", "betterleaks", "patterns"],
              description: "Scan engine: auto (default), betterleaks, or patterns.",
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
      {
        name: "suppress_finding",
        description: "Triage a false positive by persisting a suppression rule into the project's .rafter.yml. Use when a scan_secrets finding (or a remote scan finding) is a confirmed false positive — e.g. a test fixture or sample credential. Suppressed findings still surface under '_suppressed' in scan output, so the decision is reviewable and version-controlled. Always include a reason.",
        inputSchema: {
          type: "object" as const,
          properties: {
            path: { type: "string", description: "File path or glob to suppress findings in (e.g. 'test/fixtures/**')" },
            rules: {
              type: "array",
              items: { type: "string" },
              description: "Specific rules to suppress, matched case-insensitively against a finding's rule name OR rule id — e.g. 'AWS Access Key' (local pattern name) or 'R-6D5E2' (remote SAST/SCA rule id). Omit to suppress all rules for the path. Honored by both local scans and remote `rafter run`.",
            },
            reason: { type: "string", description: "Why this is a false positive — persisted with the rule. Strongly recommended." },
          },
          required: ["path"],
        },
      },
      {
        name: "sites_create",
        description: "Register a URL as a Rafter Site for live-application security monitoring (exposed backends, DNS misconfig, SEO, accessibility) and kick off its first scan. Use when asked to start monitoring a domain/site.",
        inputSchema: {
          type: "object" as const,
          properties: {
            url: { type: "string", description: "URL of the site to monitor" },
          },
          required: ["url"],
        },
      },
      {
        name: "sites_scan",
        description: "Trigger a re-scan of an existing Rafter Site. Identify the site by projectId OR url (exactly one required). Use when asked to re-scan or refresh a site's findings.",
        inputSchema: {
          type: "object" as const,
          properties: {
            projectId: { type: "string", description: "The site's project id (use this or url, not both)" },
            url: { type: "string", description: "The site's URL (use this or projectId, not both)" },
            sections: {
              type: "array",
              items: { type: "string", enum: ["flight", "security", "dns"] },
              description: "Subset of scan sections to run. Omit to run all.",
            },
          },
        },
      },
      {
        name: "sites_list",
        description: "List Rafter Sites registered for monitoring, paginated. Use when asked 'what sites are being monitored?' or to browse before calling sites_get.",
        inputSchema: {
          type: "object" as const,
          properties: {
            limit: { type: "number", description: "Results per page, 1-100 (default: 25)" },
            offset: { type: "number", description: "Pagination offset (default: 0)" },
            include_archived: { type: "boolean", description: "Include archived sites (default: false)" },
          },
        },
      },
      {
        name: "sites_get",
        description: "Get a Rafter Site's status, latest scan run, and findings summary by its project id. Use after sites_list or sites_create to check a specific site's results.",
        inputSchema: {
          type: "object" as const,
          properties: {
            id: { type: "string", description: "The site's project id" },
          },
          required: ["id"],
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

        const runPatterns = (): ScanResult[] => {
          const scanner = new RegexScanner();
          try {
            return scanner.scanDirectory(scanPath);
          } catch {
            return [scanner.scanFile(scanPath)];
          }
        };

        if (engine === "betterleaks") {
          const bl = new BetterleaksScanner();
          if (!(await bl.isAvailable())) return errorResult("Betterleaks not installed");
          try {
            return textResult(formatScanResults(await bl.scanDirectory(scanPath)));
          } catch {
            return errorResult("Betterleaks scan failed");
          }
        }

        if (engine === "auto") {
          // sable-j85 — run BOTH engines and union, so a betterleaks miss
          // (e.g. AWS access keys) is still caught by patterns. Degrades to
          // patterns-only when betterleaks is unavailable or errors.
          const bl = new BetterleaksScanner();
          if (await bl.isAvailable()) {
            try {
              const blResults = await bl.scanDirectory(scanPath);
              return textResult(formatScanResults(unionScanResults(blResults, runPatterns())));
            } catch {
              // betterleaks failed — fall through to patterns-only.
            }
          }
          return textResult(formatScanResults(runPatterns()));
        }

        // patterns (and any unrecognized value — the tool schema enums this).
        return textResult(formatScanResults(runPatterns()));
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
        const raw = key ? manager.get(key) : manager.load();
        // Never hand a stored credential (e.g. backend.apiKey) to the MCP client.
        const leaf = key ? (key.split(".").pop() ?? key) : undefined;
        const value = leaf && isSecretConfigKey(leaf) && typeof raw === "string"
          ? maskSecretValue(raw)
          : redactConfigSecrets(raw);
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

      case "suppress_finding": {
        const suppressPath = args?.path as string | undefined;
        if (!suppressPath) return errorResult("path is required");
        const rules = Array.isArray(args?.rules)
          ? (args!.rules as unknown[]).map((r) => String(r))
          : undefined;
        const reason = args?.reason as string | undefined;
        try {
          const result = writeSuppression({ paths: [suppressPath], rules, reason });
          return textResult({
            ok: true,
            file: result.file,
            action: result.action,
            entry: result.entry,
            suppression_count: result.suppressionCount,
          });
        } catch (err: any) {
          return errorResult(`Failed to write suppression: ${err.message || err}`);
        }
      }

      case "sites_create": {
        const url = args?.url as string | undefined;
        if (!url) return errorResult("url is required");
        const key = resolveMcpApiKey();
        if (!key) return errorResult("No API key configured. Set RAFTER_API_KEY or run 'rafter agent config set backend.apiKey <key>'.");
        try {
          const { data } = await apiClient.post(apiUrl("static/sites"), { url }, { headers: { "x-api-key": key } });
          return textResult(data);
        } catch (e: any) {
          return errorResult(describeSitesError(e).message);
        }
      }

      case "sites_scan": {
        const projectId = args?.projectId as string | undefined;
        const url = args?.url as string | undefined;
        if (!projectId && !url) return errorResult("Provide exactly one of projectId or url");
        if (projectId && url) return errorResult("Provide exactly one of projectId or url, not both");
        const key = resolveMcpApiKey();
        if (!key) return errorResult("No API key configured. Set RAFTER_API_KEY or run 'rafter agent config set backend.apiKey <key>'.");
        const body: Record<string, unknown> = projectId ? { projectId } : { url };
        if (Array.isArray(args?.sections)) body.sections = (args!.sections as unknown[]).map((s) => String(s));
        try {
          const { data } = await apiClient.post(apiUrl("static/sites/scan"), body, { headers: { "x-api-key": key } });
          return textResult(data);
        } catch (e: any) {
          return errorResult(describeSitesError(e).message);
        }
      }

      case "sites_list": {
        const key = resolveMcpApiKey();
        if (!key) return errorResult("No API key configured. Set RAFTER_API_KEY or run 'rafter agent config set backend.apiKey <key>'.");
        const params: Record<string, string> = {};
        if (args?.limit !== undefined) params.limit = String(args.limit);
        if (args?.offset !== undefined) params.offset = String(args.offset);
        if (args?.include_archived) params.include_archived = "true";
        try {
          const { data } = await apiClient.get(apiUrl("static/sites"), { params, headers: { "x-api-key": key } });
          return textResult(data);
        } catch (e: any) {
          return errorResult(describeSitesError(e).message);
        }
      }

      case "sites_get": {
        const id = args?.id as string | undefined;
        if (!id) return errorResult("id is required");
        const key = resolveMcpApiKey();
        if (!key) return errorResult("No API key configured. Set RAFTER_API_KEY or run 'rafter agent config set backend.apiKey <key>'.");
        try {
          const { data } = await apiClient.get(apiUrl(`static/sites/${encodeURIComponent(id)}`), { headers: { "x-api-key": key } });
          return textResult(data);
        } catch (e: any) {
          return errorResult(describeSitesError(e).message);
        }
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
            text: JSON.stringify(redactConfigSecrets(manager.load()), null, 2),
          }],
        };

      case "rafter://policy":
        return {
          contents: [{
            uri: "rafter://policy",
            mimeType: "application/json",
            text: JSON.stringify(redactConfigSecrets(manager.loadWithPolicy()), null, 2),
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
