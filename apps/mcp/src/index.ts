// Entry point: serve Fixly over stdio (the transport every MCP client —
// Claude Code, Cursor, Windsurf — speaks for local servers).

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createFixlyServer } from "./server";

const server = createFixlyServer();
const transport = new StdioServerTransport();
await server.connect(transport);

// stdout belongs to the protocol; stderr is our log channel.
process.stderr.write("fixly-mcp ready (tools: check_package, scan_project, suggest_safe_alternative)\n");
