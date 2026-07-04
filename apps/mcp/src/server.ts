// The Fixly MCP server — dependency security *inside* the agent loop.
//
// The moment of risk in AI-assisted development is the moment the agent picks
// a dependency. These tools let the agent ask first: check_package before an
// install, scan_project after edits, suggest_safe_alternative when a package
// is blocked. Tool descriptions are written FOR the model: they say exactly
// when to call and what the verdict means.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkPackage, computeGrade } from "@fixly/core";
import { scanLocalProject } from "@fixly/core/node";
import { compactVerdict, compactScan } from "./responses";

const VERSION = "0.1.0";

function textResult(payload: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

export function createFixlyServer(): McpServer {
  const server = new McpServer({ name: "fixly", version: VERSION });

  server.tool(
    "check_package",
    "ALWAYS call this before adding, installing, or recommending an npm package (including in generated package.json edits). Returns a security verdict: " +
      "'safe' → proceed; 'caution' → proceed only with the reasons in mind and tell the user; 'block' → do NOT install — the package is malware, doesn't exist " +
      "(likely a hallucinated name), or has actively-exploited vulnerabilities; 'unknown' → could NOT verify (npm registry/OSV unreachable) — do not assume safe, tell the user and retry. " +
      "When blocked, prefer `didYouMean`/`fixCommand` or ask suggest_safe_alternative.",
    {
      name: z.string().min(1).describe("npm package name, e.g. 'lodash' or '@scope/pkg'"),
      version: z
        .string()
        .optional()
        .describe("exact version to evaluate; omit to evaluate what `npm install` would fetch today"),
    },
    async ({ name, version }) => {
      try {
        const verdict = await checkPackage(name, version ?? null);
        return textResult(compactVerdict(verdict));
      } catch (err) {
        return textResult(
          { error: err instanceof Error ? err.message : String(err) },
          true
        );
      }
    }
  );

  server.tool(
    "scan_project",
    "Scan the npm project at `dir` (its package.json + package-lock.json, full transitive tree) for vulnerable and malicious dependencies. Returns a compact " +
      "report: an A–F grade, malicious/exploited-in-the-wild callouts, and the top fixes with copy-paste commands. Call after dependency changes, or when the " +
      "user asks about their project's security.",
    {
      dir: z.string().min(1).describe("absolute path to the project root (the folder containing package.json)"),
    },
    async ({ dir }) => {
      try {
        const result = await scanLocalProject(dir, { includeTransitive: true });
        if (result.error) return textResult({ error: result.error.message }, true);
        return textResult(compactScan(result, computeGrade(result)));
      } catch (err) {
        return textResult(
          { error: err instanceof Error ? err.message : String(err) },
          true
        );
      }
    }
  );

  server.tool(
    "suggest_safe_alternative",
    "Given a package name that was blocked or looks suspicious, suggest what to use instead: resolves the likely-intended real package (typosquat/hallucination " +
      "target) and returns ITS verdict so the substitution is verified, not guessed.",
    {
      name: z.string().min(1).describe("the suspicious/blocked npm package name"),
    },
    async ({ name }) => {
      try {
        const original = await checkPackage(name);
        const target = original.signals.typosquatOf;
        if (!target) {
          return textResult({
            original: compactVerdict(original),
            suggestion: null,
            advice:
              original.verdict === "safe"
                ? "This package itself looks safe — no substitution needed."
                : "No obvious intended package found. Search npm for an established alternative (high weekly downloads, recent releases) and check_package it before installing.",
          });
        }
        const suggestion = await checkPackage(target);
        return textResult({
          original: compactVerdict(original),
          suggestion: compactVerdict(suggestion),
          advice:
            suggestion.verdict === "safe"
              ? `Use "${target}" instead — verified ${suggestion.verdict}.`
              : `The likely-intended package is "${target}", but verify its verdict details before installing.`,
        });
      } catch (err) {
        return textResult(
          { error: err instanceof Error ? err.message : String(err) },
          true
        );
      }
    }
  );

  return server;
}
