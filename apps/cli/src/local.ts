// Local scanning lives in @fixly/core/node so the CLI and the MCP server
// share one implementation.
export { scanLocalProject, type LocalScanOptions } from "@fixly/core/node";
