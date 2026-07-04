// fixly — dependency security for vibecoders.
//
//   fixly vibecheck [dir]          10-second grade + the fixes that matter
//   fixly scan [dir | github-url]  full report; --json/--sarif/--fail-on for CI
//   fixly check <pkg>[@version]    SAFE/CAUTION/BLOCK before you install
//
// Zero runtime dependencies beyond @fixly/core (bundled). Node >= 20.

import { parseArgs } from "node:util";
import { vibecheck } from "./commands/vibecheck";
import { scan, type FailOn } from "./commands/scan";
import { check } from "./commands/check";
import { bold, dim, red } from "./ui";

const VERSION = "0.1.0";

const HELP = `
  ${bold("fixly")} ${dim(`v${VERSION}`)} — dependency security for vibecoders

  ${bold("Usage")}
    fixly vibecheck [dir]             grade your project (A–F) + top fixes
    fixly scan [dir | github-url]     full vulnerability report
    fixly check <pkg>[@version]       is this package safe to install?

  ${bold("Options")}
    --json                machine-readable output (all commands)
    --sarif               SARIF 2.1.0 output for code scanning (scan)
    --fail-on <level>     exit 1 at/above: critical|high|medium|low|any|never
                          (scan; default: never. Malware always fails a gate.)
    --no-transitive       direct dependencies only (scan/vibecheck)
    -v, --version         print version
    -h, --help            this help

  ${bold("Exit codes")}
    0 ok · 1 gate failed / caution verdict · 2 error / block verdict

  ${bold("Examples")}
    npx fixly vibecheck
    npx fixly check lodahs
    fixly scan https://github.com/OWASP/NodeGoat --fail-on high
    fixly scan --sarif > fixly.sarif
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      sarif: { type: "boolean", default: false },
      "fail-on": { type: "string", default: "never" },
      transitive: { type: "boolean", default: true },
      "no-transitive": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });

  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const [command, ...rest] = positionals;
  if (values.help || !command) {
    process.stdout.write(HELP + "\n");
    return values.help || !command ? 0 : 2;
  }

  const transitive = values["no-transitive"] ? false : values.transitive;

  switch (command) {
    case "vibecheck":
      return vibecheck({ dir: rest[0] ?? ".", json: values.json });

    case "scan": {
      const failOn = values["fail-on"] as FailOn;
      const validFailOn: FailOn[] = ["critical", "high", "medium", "low", "any", "never"];
      if (!validFailOn.includes(failOn)) {
        process.stderr.write(
          `${red("✖")} --fail-on must be one of: ${validFailOn.join(", ")}\n`
        );
        return 2;
      }
      return scan({
        target: rest[0] ?? ".",
        json: values.json,
        sarif: values.sarif,
        failOn,
        transitive,
        version: VERSION,
      });
    }

    case "check": {
      if (!rest[0]) {
        process.stderr.write(`${red("✖")} usage: fixly check <pkg>[@version]\n`);
        return 2;
      }
      return check({ spec: rest[0], json: values.json });
    }

    default:
      process.stderr.write(`${red("✖")} unknown command "${command}"\n${HELP}\n`);
      return 2;
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`${red("✖")} ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  });
