// Shared flat ESLint config for non-Next packages (@fixly/core, @fixly/ui, extension).
// apps/web keeps its own eslint-config-next setup.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "**/*.d.ts", "coverage/**"] },
  js.configs.recommended,
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    extends: [...tseslint.configs.recommended],
  },
  {
    // Plain config/build scripts (esbuild.mjs, eslint.config.mjs, vitest config).
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
