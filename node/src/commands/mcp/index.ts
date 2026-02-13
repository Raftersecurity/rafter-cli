import { Command } from "commander";
import { createMcpServeCommand } from "./server.js";

export function createMcpCommand(): Command {
  const mcp = new Command("mcp")
    .description("MCP server for cross-platform security tools");

  mcp.addCommand(createMcpServeCommand());

  return mcp;
}
