// Bundle the extension (and the @fixly/core source it imports) into a single
// CommonJS file for the VS Code extension host. `vscode` is provided at runtime.
import { build } from "esbuild";

await build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "dist/extension.js",
  platform: "node",
  target: "node20",
  format: "cjs",
  external: ["vscode"],
  sourcemap: true,
  logLevel: "info",
});
