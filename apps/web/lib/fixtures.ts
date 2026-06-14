// Bundled demo fixtures — a local fallback so a live demo does not depend on
// GitHub's unauthenticated rate limit (~60/hour). Scanning a fixture skips the
// GitHub fetch entirely and runs the same `scanProjectFiles` pipeline against
// real OSV data.
//
// These are REAL packages pinned to REAL old releases that have published OSV
// advisories. Nothing here is fabricated — OSV decides what (if anything) is
// reported, exactly as it would for a real repo. Versions are pinned in a
// lockfile so they resolve exactly (high-confidence, in-range findings).

export interface DemoFixture {
  id: string;
  /** Shown as the scanned "repo" label on the report. */
  label: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageJson: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageLock: Record<string, any>;
}

const VULNERABLE_DEPS: Record<string, string> = {
  lodash: "4.17.4",
  minimist: "1.2.0",
  axios: "0.21.0",
  "node-fetch": "2.6.0",
  handlebars: "4.0.11",
  ejs: "2.6.1",
};

const lockPackages: Record<string, { version: string }> = {};
for (const [name, version] of Object.entries(VULNERABLE_DEPS)) {
  lockPackages[`node_modules/${name}`] = { version };
}

const vulnerableDemo: DemoFixture = {
  id: "vulnerable-demo",
  label: "Sample: intentionally-vulnerable Node project",
  description:
    "A small package.json/package-lock.json pinned to old releases of popular packages with known OSV advisories. Runs without GitHub — only OSV is queried.",
  packageJson: {
    name: "fixly-vulnerable-demo",
    version: "1.0.0",
    private: true,
    dependencies: { ...VULNERABLE_DEPS },
  },
  packageLock: {
    name: "fixly-vulnerable-demo",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "fixly-vulnerable-demo",
        version: "1.0.0",
        dependencies: { ...VULNERABLE_DEPS },
      },
      ...lockPackages,
    },
  },
};

export const FIXTURES: Record<string, DemoFixture> = {
  [vulnerableDemo.id]: vulnerableDemo,
};

export function getFixture(id: string): DemoFixture | null {
  return FIXTURES[id] ?? null;
}
