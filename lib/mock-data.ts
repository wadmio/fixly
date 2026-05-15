export type Severity = "critical" | "high" | "medium" | "low";

export interface Vulnerability {
  id: string;
  cve: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  severity: Severity;
  cvss: number;
  title: string;
  description: string;
  affectedPaths: string[];
  recommendation: string;
}

export interface Scan {
  id: string;
  projectId: string;
  date: string;
  status: "completed" | "running" | "failed";
  vulnerabilities: Vulnerability[];
}

export interface Project {
  id: string;
  name: string;
  repo: string;
  lastScanned: string;
  scans: Scan[];
}

const vulnerabilities: Vulnerability[] = [
  {
    id: "v1",
    cve: "CVE-2024-29041",
    package: "express",
    installedVersion: "4.18.2",
    fixedVersion: "4.19.2",
    severity: "high",
    cvss: 7.5,
    title: "Open Redirect in express",
    description:
      "Versions of Express.js prior to 4.19.2 are vulnerable to an open redirect attack. A malicious user can craft a request with a specially crafted Host header to redirect users to an arbitrary URL.",
    affectedPaths: ["node_modules/express"],
    recommendation: "Upgrade express to version 4.19.2 or later.",
  },
  {
    id: "v2",
    cve: "CVE-2024-21538",
    package: "cross-spawn",
    installedVersion: "7.0.3",
    fixedVersion: "7.0.5",
    severity: "medium",
    cvss: 5.9,
    title: "ReDoS in cross-spawn",
    description:
      "cross-spawn before 7.0.5 is vulnerable to Regular Expression Denial of Service (ReDoS). The issue occurs in the processing of shell argument strings.",
    affectedPaths: ["node_modules/cross-spawn", "node_modules/jest/node_modules/cross-spawn"],
    recommendation: "Upgrade cross-spawn to version 7.0.5 or later.",
  },
  {
    id: "v3",
    cve: "CVE-2024-45296",
    package: "path-to-regexp",
    installedVersion: "0.1.7",
    fixedVersion: "0.1.10",
    severity: "critical",
    cvss: 9.8,
    title: "Backtracking ReDoS in path-to-regexp",
    description:
      "path-to-regexp before 0.1.10 is vulnerable to catastrophic backtracking in certain patterns, potentially causing denial of service when processing untrusted route patterns.",
    affectedPaths: ["node_modules/express/node_modules/path-to-regexp"],
    recommendation: "Upgrade path-to-regexp to version 0.1.10 or later. Update express to 4.21.1+.",
  },
  {
    id: "v4",
    cve: "CVE-2023-26159",
    package: "follow-redirects",
    installedVersion: "1.15.3",
    fixedVersion: "1.15.4",
    severity: "medium",
    cvss: 6.1,
    title: "URL Redirection in follow-redirects",
    description:
      "follow-redirects before 1.15.4 does not properly validate URLs before following redirects, which can lead to information disclosure via SSRF.",
    affectedPaths: ["node_modules/axios/node_modules/follow-redirects"],
    recommendation: "Upgrade follow-redirects to version 1.15.4 or later.",
  },
  {
    id: "v5",
    cve: "CVE-2024-37890",
    package: "ws",
    installedVersion: "8.17.0",
    fixedVersion: "8.17.1",
    severity: "high",
    cvss: 7.5,
    title: "DoS in ws WebSocket library",
    description:
      "ws versions before 8.17.1 are vulnerable to a denial of service when processing specially crafted HTTP requests that trigger excessive memory usage.",
    affectedPaths: ["node_modules/ws"],
    recommendation: "Upgrade ws to version 8.17.1 or later.",
  },
  {
    id: "v6",
    cve: "CVE-2024-28863",
    package: "node-tar",
    installedVersion: "6.2.0",
    fixedVersion: "6.2.1",
    severity: "low",
    cvss: 3.7,
    title: "Denial of service in node-tar",
    description:
      "node-tar before 6.2.1 is vulnerable to denial of service via crafted tar archives with excessive symlink depth.",
    affectedPaths: ["node_modules/node-tar"],
    recommendation: "Upgrade node-tar to version 6.2.1 or later.",
  },
];

export const projects: Project[] = [
  {
    id: "proj-1",
    name: "fixly-api",
    repo: "github.com/org/fixly-api",
    lastScanned: "2026-04-09T10:23:00Z",
    scans: [
      {
        id: "scan-1",
        projectId: "proj-1",
        date: "2026-04-09T10:23:00Z",
        status: "completed",
        vulnerabilities: [vulnerabilities[0], vulnerabilities[1], vulnerabilities[2]],
      },
      {
        id: "scan-2",
        projectId: "proj-1",
        date: "2026-04-07T08:00:00Z",
        status: "completed",
        vulnerabilities: [vulnerabilities[0], vulnerabilities[1]],
      },
    ],
  },
  {
    id: "proj-2",
    name: "fixly-web",
    repo: "github.com/org/fixly-web",
    lastScanned: "2026-04-09T09:10:00Z",
    scans: [
      {
        id: "scan-3",
        projectId: "proj-2",
        date: "2026-04-09T09:10:00Z",
        status: "completed",
        vulnerabilities: [vulnerabilities[3], vulnerabilities[4]],
      },
    ],
  },
  {
    id: "proj-3",
    name: "auth-service",
    repo: "github.com/org/auth-service",
    lastScanned: "2026-04-08T14:45:00Z",
    scans: [
      {
        id: "scan-4",
        projectId: "proj-3",
        date: "2026-04-08T14:45:00Z",
        status: "completed",
        vulnerabilities: [vulnerabilities[5]],
      },
    ],
  },
  {
    id: "proj-4",
    name: "notifications-worker",
    repo: "github.com/org/notifications-worker",
    lastScanned: "2026-04-06T11:30:00Z",
    scans: [
      {
        id: "scan-5",
        projectId: "proj-4",
        date: "2026-04-06T11:30:00Z",
        status: "running",
        vulnerabilities: [],
      },
    ],
  },
];

export function getProject(id: string): Project | undefined {
  return projects.find((p) => p.id === id);
}

export function getScan(projectId: string, scanId: string): Scan | undefined {
  return getProject(projectId)?.scans.find((s) => s.id === scanId);
}

export function getVuln(projectId: string, scanId: string, vulnId: string): Vulnerability | undefined {
  return getScan(projectId, scanId)?.vulnerabilities.find((v) => v.id === vulnId);
}

export function severityCounts(vulns: Vulnerability[]) {
  return vulns.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>
  );
}
