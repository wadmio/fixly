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
  // `vscode` is provided by the host; onnxruntime-node is an optional native
  // module loaded lazily at runtime (the extension ships without the ML model,
  // so name-risk scoring simply stays off in the editor).
  external: ["vscode", "onnxruntime-node"],
  sourcemap: true,
  logLevel: "info",
});
