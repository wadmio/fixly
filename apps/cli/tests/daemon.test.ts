// Daemon tests — the pure event derivation (diff/escalation/snapshot), state
// persistence round-trips, and the remediate step (apply → install → verify)
// driven through an injected fake IO. The long-running loop itself is
// exercised manually (docs/daemon.md); everything it decides with lives here.

import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ScanResult, ScanVulnerability } from "@fixly/core";
import {
  diffAgainstSnapshot,
  loadState,
  saveState,
  snapshotFromScan,
  type DaemonState,
} from "../src/daemon-state";
import {
  buildWebhookPayload,
  remediate,
  type DaemonIO,
} from "../src/commands/daemon";

function makeVuln(overrides: Partial<ScanVulnerability> = {}): ScanVulnerability {
  return {
    osvId: "GHSA-test-0001",
    cveId: null,
    package: "lodash",
    installedVersion: "4.17.20",
    fixedVersion: "4.17.21",
    severity: "high",
    cvssVector: null,
    cvssScore: null,
    affectedRanges: [],
    versionInRange: true,
    versionSource: "lockfile",
    dependencyType: "dependencies",
    sources: ["osv"],
    nvd: null,
    malicious: false,
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    kevDateAdded: null,
    pocCount: null,
    title: "Test vulnerability",
    description: "",
    references: [],
    ...overrides,
  };
}

function makeResult(
  vulns: ScanVulnerability[],
  overrides: Partial<ScanResult> = {}
): ScanResult {
  return {
    repo: "fixture",
    target: {
      owner: null,
      repo: "fixture",
      branch: null,
      subpath: null,
      filesFound: ["package.json", "package-lock.json"],
      filesMissing: [],
    },
    scannedAt: "2027-01-01T00:00:00.000Z",
    source: "osv",
    dependencies: [],
    totalPackages: 10,
    directPackages: 5,
    transitivePackages: 5,
    resolvedPackages: 10,
    vulnerabilities: vulns,
    warnings: [],
    ...overrides,
  };
}

describe("snapshotFromScan / diffAgainstSnapshot", () => {
  it("snapshots grade and finding metadata", () => {
    const snap = snapshotFromScan(makeResult([makeVuln()]));
    expect(snap.findings["lodash::GHSA-test-0001"]).toEqual({
      severity: "high",
      knownExploited: false,
    });
    expect(snap.grade.score).toBeLessThan(100);
  });

  it("detects added findings", () => {
    const prev = snapshotFromScan(makeResult([makeVuln()]));
    const next = makeResult([
      makeVuln(),
      makeVuln({ package: "minimist", osvId: "GHSA-test-0002" }),
    ]);
    const diff = diffAgainstSnapshot(prev, next);
    expect(diff.added.map((v) => v.package)).toEqual(["minimist"]);
    expect(diff.escalated).toEqual([]);
    expect(diff.resolvedKeys).toEqual([]);
  });

  it("detects a KEV escalation on a carried-over finding (same key)", () => {
    const prev = snapshotFromScan(makeResult([makeVuln()]));
    const next = makeResult([makeVuln({ knownExploited: true })]);
    const diff = diffAgainstSnapshot(prev, next);
    expect(diff.added).toEqual([]);
    expect(diff.escalated.map((v) => v.osvId)).toEqual(["GHSA-test-0001"]);
  });

  it("does not re-escalate an already known-exploited finding", () => {
    const prev = snapshotFromScan(makeResult([makeVuln({ knownExploited: true })]));
    const diff = diffAgainstSnapshot(prev, makeResult([makeVuln({ knownExploited: true })]));
    expect(diff.escalated).toEqual([]);
  });

  it("reports resolved keys", () => {
    const prev = snapshotFromScan(makeResult([makeVuln()]));
    const diff = diffAgainstSnapshot(prev, makeResult([]));
    expect(diff.resolvedKeys).toEqual(["lodash::GHSA-test-0001"]);
  });
});

describe("daemon state persistence", () => {
  let home: string;
  const originalHome = process.env.FIXLY_HOME;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "fixly-daemon-test-"));
    process.env.FIXLY_HOME = home;
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.FIXLY_HOME;
    else process.env.FIXLY_HOME = originalHome;
    await rm(home, { recursive: true, force: true });
  });

  it("round-trips state through save/load", async () => {
    const state: DaemonState = {
      version: 1,
      projects: {
        "/tmp/proj": snapshotFromScan(makeResult([makeVuln()])),
      },
    };
    await saveState(state);
    const loaded = await loadState();
    expect(loaded).toEqual(state);
  });

  it("treats a missing state file as a first run", async () => {
    expect(await loadState()).toEqual({ version: 1, projects: {} });
  });

  it("treats a corrupt state file as a first run", async () => {
    await mkdir(home, { recursive: true });
    await writeFile(join(home, "daemon-state.json"), "{not json", "utf8");
    expect(await loadState()).toEqual({ version: 1, projects: {} });
  });
});

const MANIFEST = `{
  "name": "fixture",
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
`;

interface FakeIOState {
  manifest: string;
  installs: number;
  verifyScans: ScanResult[];
  installExit: number;
  now: number;
}

function fakeIO(state: FakeIOState): DaemonIO {
  return {
    scan: async () => {
      const next = state.verifyScans.shift();
      if (!next) throw new Error("unexpected scan");
      return next;
    },
    readManifest: async () => state.manifest,
    writeManifest: async (_dir, text) => {
      state.manifest = text;
    },
    runInstall: async () => {
      state.installs++;
      return { code: state.installExit, output: state.installExit === 0 ? "" : "EINTEGRITY boom" };
    },
    now: () => (state.now += 1_000),
  };
}

describe("remediate", () => {
  it("applies the plan, installs, verifies, and measures MTTR", async () => {
    const detection = makeResult([makeVuln()]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      verifyScans: [makeResult([])],
      installExit: 0,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: false, detectedAt: 0 },
      fakeIO(ioState)
    );

    expect(outcome.applied).toBe(true);
    expect(outcome.installed).toBe(true);
    expect(outcome.verified).toBe(true);
    expect(outcome.failure).toBeNull();
    expect(outcome.changes).toEqual(['lodash: "^4.17.20" → "^4.17.21"']);
    expect(ioState.manifest).toContain('"lodash": "^4.17.21"');
    expect(ioState.installs).toBe(1);
    expect(outcome.mttrMs).toBeGreaterThan(0);
  });

  it("reports honestly when no fix is published", async () => {
    const detection = makeResult([makeVuln({ fixedVersion: null })]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      verifyScans: [],
      installExit: 0,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: false, detectedAt: 0 },
      fakeIO(ioState)
    );
    expect(outcome.applied).toBe(false);
    expect(outcome.failure).toContain("no published fix");
    expect(ioState.manifest).toBe(MANIFEST);
    expect(ioState.installs).toBe(0);
  });

  it("stops with a failure when npm install fails", async () => {
    const detection = makeResult([makeVuln()]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      verifyScans: [],
      installExit: 1,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: false, detectedAt: 0 },
      fakeIO(ioState)
    );
    expect(outcome.applied).toBe(true);
    expect(outcome.installed).toBe(false);
    expect(outcome.verified).toBe(false);
    expect(outcome.failure).toContain("npm install failed");
  });

  it("--no-install rewrites the manifest but never claims verification", async () => {
    const detection = makeResult([makeVuln()]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      verifyScans: [],
      installExit: 0,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: true, detectedAt: 0 },
      fakeIO(ioState)
    );
    expect(outcome.applied).toBe(true);
    expect(outcome.installed).toBe(false);
    expect(outcome.verified).toBe(false);
    expect(outcome.failure).toBeNull();
    expect(ioState.installs).toBe(0);
    expect(ioState.manifest).toContain('"lodash": "^4.17.21"');
  });

  it("fails verification when the triggering finding survives the re-scan", async () => {
    const detection = makeResult([makeVuln()]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      verifyScans: [makeResult([makeVuln()])],
      installExit: 0,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: false, detectedAt: 0 },
      fakeIO(ioState)
    );
    expect(outcome.verified).toBe(false);
    expect(outcome.failure).toContain("still reports");
  });

  it("verifies against plan promises only — unfixable findings don't fail it", async () => {
    const fixable = makeVuln();
    const unfixable = makeVuln({
      package: "left-pad",
      osvId: "GHSA-test-0003",
      fixedVersion: null,
    });
    const detection = makeResult([fixable, unfixable]);
    const ioState: FakeIOState = {
      manifest: MANIFEST,
      installs: 0,
      // The unfixable finding correctly survives the verify scan.
      verifyScans: [makeResult([unfixable])],
      installExit: 0,
      now: 0,
    };
    const outcome = await remediate(
      "/proj",
      detection,
      detection.vulnerabilities,
      { noInstall: false, detectedAt: 0 },
      fakeIO(ioState)
    );
    expect(outcome.verified).toBe(true);
    expect(outcome.plan.unfixable.map((u) => u.osvId)).toEqual(["GHSA-test-0003"]);
  });
});

describe("buildWebhookPayload", () => {
  it("shapes the event envelope", () => {
    const v = makeVuln({ knownExploited: true, epssScore: 0.42 });
    const payload = buildWebhookPayload(
      "remediated",
      { dir: "/proj", name: "proj" },
      { grade: "D", score: 61 },
      { grade: "A", score: 96 },
      [v],
      {
        applied: true,
        installed: true,
        verified: true,
        plan: { actions: [], unfixable: [], forecast: { before: { grade: "D", score: 61 }, after: { grade: "A", score: 96 }, pointsRecovered: 35 }, totalFindings: 1, fixableFindings: 1 },
        changes: ['lodash: "^4.17.20" → "^4.17.21"'],
        mttrMs: 5100,
        verifyResult: null,
        failure: null,
      },
      "2027-01-01T00:00:00.000Z"
    );
    expect(payload.event).toBe("remediated");
    expect(payload.findings[0]).toEqual({
      package: "lodash",
      id: "GHSA-test-0001",
      severity: "high",
      knownExploited: true,
      epssScore: 0.42,
    });
    expect(payload.remediation?.mttrMs).toBe(5100);
    expect(payload.grade.before.grade).toBe("D");
  });
});
