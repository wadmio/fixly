# Development

## Prerequisites

- Node.js 20 (pinned in [.nvmrc](../.nvmrc); CI runs Node 20)
- pnpm (this repo pins `pnpm@10.11.1` via `packageManager`)

**Use pnpm only.** There is no `package-lock.json`; mixing npm/yarn will create a conflicting lock
file. Install once at the root:

```bash
pnpm install
```

## Environment

Fixly runs with no environment variables. One is optional:

- **`GITHUB_TOKEN`** (server-side only) — raises GitHub's API rate limit from
  ~60/hour to ~5,000/hour for repo scanning. See [.env.example](../.env.example).
  - Web app: copy `.env.example` to `apps/web/.env.local` and set the value.
  - Validation / extension host: export `GITHUB_TOKEN` in your shell.
  - It is read by `@fixly/core` on the server and is never sent to the browser.
- **`FIXLY_DISABLE_SCAN_CACHE`** — set to `1` to disable the in-memory scan cache
  (repeated same-URL scans are otherwise served from a 5-minute, per-process cache
  during development/demo).

## Workspace tasks (from the repo root)

All tasks run through Turborepo, which executes them across every package:

| Command | What it does |
|---|---|
| `pnpm dev` | Start the web app dev server (http://localhost:3000). |
| `pnpm build` | `next build` for the web app + esbuild bundle for the extension. |
| `pnpm lint` | ESLint every package. |
| `pnpm typecheck` | `tsc --noEmit` every package. |
| `pnpm test` | Vitest (tests live in `packages/core`). |

### Targeting one package

```bash
pnpm --filter @fixly/core test
pnpm --filter @fixly/core exec vitest run tests/github.test.ts   # a single test file
pnpm --filter fixly-vscode build
pnpm --filter @fixly/web dev
```

## Running the web app

```bash
pnpm --filter @fixly/web dev
```

Open http://localhost:3000, go to the dashboard, and paste a public GitHub repo URL
(e.g. `https://github.com/OWASP/NodeGoat`).

Test the scanner without the UI:

```bash
curl -X POST localhost:3000/api/scan -H "Content-Type: application/json" \
  -d '{"repoUrl":"https://github.com/OWASP/NodeGoat"}'
```

## Running the VS Code extension

```bash
pnpm --filter fixly-vscode build
```

Then open `apps/extension` in VS Code and press <kbd>F5</kbd> to launch an Extension Development
Host. F5 uses the **Run Fixly Extension** configuration in
[apps/extension/.vscode/launch.json](../apps/extension/.vscode/launch.json) (an `extensionHost`
launch pointing at `dist/`), so build first. In that window, open a Node.js project folder and run
**Fixly: Scan Current Project** from the command palette. The report opens in a webview; logs go
to the "Fixly" output channel.

## Validation (live)

`pnpm validate` ([scripts/validate.ts](../scripts/validate.ts)) runs the real
scanner against a fixed set of repositories — vulnerable, clean, invalid URL,
non-GitHub, repo-not-found, missing `package.json`, and branch+subpath — and
prints a report. It hits the live GitHub + OSV APIs; set `GITHUB_TOKEN` to avoid
rate limits. The captured results live in
[../validation-notes.md](../validation-notes.md).

```bash
pnpm validate
```

## Adding dependencies

Add to the specific package, not the root:

```bash
pnpm --filter @fixly/web add <pkg>
pnpm --filter @fixly/core add -D <pkg>
```

Shared workspace packages are referenced with the workspace protocol, e.g.
`"@fixly/core": "workspace:*"`.

If a dependency has a native postinstall build step (like `esbuild`), pnpm will block it until it is
added to `pnpm.onlyBuiltDependencies` in the root `package.json`, then `pnpm install` again.

## Tests

Unit tests live in `packages/core/tests` and cover the pure logic: GitHub URL parsing, dependency
extraction, lock-file version resolution (v1/v2/v3), severity normalization, result sorting, and
warning generation. They make no network calls. Add new tests there as `*.test.ts`.

## Conventions

- Internal packages export TypeScript **source** — no build step, no `dist/` to keep in sync.
- `@fixly/core` must stay free of React/DOM/Next imports so it runs in both the Next server and the
  VS Code extension host. It uses global `fetch`/`Buffer`.
- TypeScript is strict (`tsconfig.base.json`, including `noUnusedLocals`/`noUnusedParameters`).
- Reuse `<Badge>` and the severity helpers from `@fixly/ui` rather than re-styling severities.
