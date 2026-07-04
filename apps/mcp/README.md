# Fixly MCP server

Dependency security **inside the agent loop**. AI coding agents pick npm
packages mid-generation — and [~20% of AI-suggested package names don't even
exist](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/),
which attackers exploit by pre-registering them (slopsquatting). This server
lets the agent **ask first**.

## Tools

| Tool | When the agent calls it | Returns |
|---|---|---|
| `check_package` | Before adding/installing/recommending any npm package | `safe` / `caution` / `block` verdict + reasons, `didYouMean`, fix command |
| `scan_project` | After dependency changes, or "how secure is my project?" | Compact graded report: A–F, malicious/KEV callouts, top fixes |
| `suggest_safe_alternative` | When a package was blocked | The likely-intended real package, **with its own verified verdict** |

Responses are deliberately compact — a verdict and its reasons, never a raw
finding dump. Full reports belong to `fixly scan` and the web app.

## Install

Build once from the repo root:

```bash
pnpm --filter fixly-mcp build
```

**Claude Code**

```bash
claude mcp add fixly -- node <repo>/apps/mcp/dist/index.js
```

**Cursor / Windsurf / any MCP client** — add to the MCP config:

```json
{
  "mcpServers": {
    "fixly": {
      "command": "node",
      "args": ["<repo>/apps/mcp/dist/index.js"]
    }
  }
}
```

Optional env: `NVD_API_KEY` (raises NVD coverage), `GITHUB_TOKEN` (not needed
for these tools), `FIXLY_DISABLE_INTEL=1` / `FIXLY_DISABLE_NVD=1` (offline).

## Verdict semantics

- **safe** — no malware records, no known vulnerabilities at the evaluated
  version, no red flags. Proceed.
- **caution** — real signals (vulns with fixes, brand-new package, install
  scripts, near-miss name). Proceed only deliberately; tell the user.
- **block** — evidence: OSV `MAL-` malware record, the name doesn't exist
  (likely hallucinated), CISA-KEV exploited vulnerability, or a hard
  typosquat profile. Do not install; use `didYouMean` / `suggest_safe_alternative`.

"Couldn't check" is never treated as "safe" — degraded signals are listed in
`warnings`.
