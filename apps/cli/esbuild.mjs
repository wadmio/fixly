import { build } from "esbuild";

await build({
  entryPoints: ["src/cli.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: "dist/cli.js",
  banner: { js: "#!/usr/bin/env node" },
  // Optional native module — loaded lazily from node_modules at runtime, never
  // bundled (it ships platform-specific .node binaries).
  external: ["onnxruntime-node"],
  sourcemap: true,
  logLevel: "info",
});
