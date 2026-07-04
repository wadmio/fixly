// Real protocol-level tests: an actual MCP Client talks to the server over a
// linked in-memory transport, with the network mocked at the fetch layer.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { clearRegistryCache, clearIntelCache } from "@fixly/core";
import { createFixlyServer } from "../src/server";

function jsonRes(status: number, body: unknown) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

async function connectedClient() {
  const server = createFixlyServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
  return client;
}

function parsePayload(result: unknown): Record<string, unknown> {
  const content = (result as { content: Array<{ type: string; text: string }> }).content;
  return JSON.parse(content[0].text) as Record<string, unknown>;
}

describe("fixly MCP server", () => {
  beforeEach(() => {
    clearRegistryCache();
    clearIntelCache();
    process.env.FIXLY_DISABLE_INTEL = "1";
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.FIXLY_DISABLE_INTEL;
  });

  it("lists the three tools with agent-facing descriptions", async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(["check_package", "scan_project", "suggest_safe_alternative"]);
    const checkTool = tools.find((t) => t.name === "check_package");
    expect(checkTool?.description).toContain("before adding");
  });

  it("check_package returns a compact BLOCK verdict for a nonexistent package", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonRes(404, {})));
    const client = await connectedClient();
    const result = await client.callTool({
      name: "check_package",
      arguments: { name: "hallucinated-pkg-xyz" },
    });
    const payload = parsePayload(result);
    expect(payload.verdict).toBe("block");
    expect(String(payload.summary)).toContain("DO NOT INSTALL");
    // Compact by design: no raw vulnerability array in the response.
    expect(payload.vulnerabilities).toBeUndefined();
  });

  it("suggest_safe_alternative resolves and verifies the intended package", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        // The typo name doesn't exist; the real one does, cleanly.
        if (url.includes("registry.npmjs.org/lodahs")) return jsonRes(404, {});
        if (url.includes("registry.npmjs.org/lodash/latest")) {
          return jsonRes(200, { version: "4.17.21" });
        }
        if (url.includes("api.osv.dev")) return jsonRes(200, { vulns: [] });
        return jsonRes(404, {});
      })
    );
    const client = await connectedClient();
    const result = await client.callTool({
      name: "suggest_safe_alternative",
      arguments: { name: "lodahs" },
    });
    const payload = parsePayload(result);
    const suggestion = payload.suggestion as Record<string, unknown>;
    expect(suggestion.package).toBe("lodash");
    expect(suggestion.verdict).toBe("safe");
    expect(String(payload.advice)).toContain('Use "lodash" instead');
  });

  it("scan_project returns the compact graded report, never a finding dump", async () => {
    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = await mkdtemp(join(tmpdir(), "fixly-mcp-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "agent-app", dependencies: { "left-pad": "1.3.0" } })
      );
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string) =>
          jsonRes(200, url.includes("querybatch") ? { results: [{}] } : {})
        )
      );
      const client = await connectedClient();
      const result = await client.callTool({
        name: "scan_project",
        arguments: { dir },
      });
      const payload = parsePayload(result);
      expect(payload.grade).toBe("A");
      expect(payload.headline).toContain("Ship it");
      expect((payload.packages as { total: number }).total).toBe(1);
      expect(payload.vulnerabilities).toBeUndefined(); // compact contract
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("scan_project surfaces a friendly error for a non-project directory", async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: "scan_project",
      arguments: { dir: "C:/definitely/not/a/project" },
    });
    const payload = parsePayload(result);
    expect(String(payload.error)).toContain("No package.json");
    expect((result as { isError?: boolean }).isError).toBe(true);
  });
});
