import Link from "next/link";
import { projects, severityCounts } from "@/lib/mock-data";
import Badge from "@/components/Badge";
import StatusDot from "@/components/StatusDot";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
  });
}

function getGlobalStats() {
  const latestScans = projects.map((p) => p.scans[0]).filter(Boolean);
  const allVulns = latestScans.flatMap((s) => s.vulnerabilities);
  const counts = severityCounts(allVulns);
  return { projects: projects.length, total: allVulns.length, ...counts };
}

const stats = getGlobalStats();

const statCards = [
  {
    label: "Projects",
    value: stats.projects,
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M2 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V7z" />
      </svg>
    ),
    color: "text-[#BFC3C7] bg-[#0A0A0A]",
  },
  {
    label: "Critical",
    value: stats.critical,
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      </svg>
    ),
    color: "text-red-400 bg-red-950",
  },
  {
    label: "High",
    value: stats.high,
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      </svg>
    ),
    color: "text-orange-400 bg-orange-950",
  },
  {
    label: "Medium",
    value: stats.medium,
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    color: "text-yellow-400 bg-yellow-950",
  },
  {
    label: "Low",
    value: stats.low,
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    color: "text-blue-400 bg-blue-950",
  },
];

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Dashboard</h1>
          <p className="mt-0.5 text-sm text-[#BFC3C7]">
            {stats.total} open {stats.total === 1 ? "vulnerability" : "vulnerabilities"} across {stats.projects} projects
          </p>
        </div>
        <button className="flex items-center gap-2 rounded-md bg-white px-3.5 py-2 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors">
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          New scan
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        {statCards.map((card) => (
          <div key={card.label} className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-4">
            <div className={`inline-flex h-8 w-8 items-center justify-center rounded-lg ${card.color}`}>
              {card.icon}
            </div>
            <p className="mt-3 text-2xl font-semibold text-white">{card.value}</p>
            <p className="mt-0.5 text-xs text-[#BFC3C7]">{card.label}</p>
          </div>
        ))}
      </div>

      {/* Projects table */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-white">Projects</h2>
        <div className="overflow-hidden rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#D1D5DB]/10 text-left text-xs font-medium text-[#BFC3C7]">
                <th className="px-4 py-3">Project</th>
                <th className="px-4 py-3">Last scan</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Vulnerabilities</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D1D5DB]/10">
              {projects.map((project) => {
                const latestScan = project.scans[0];
                const counts = severityCounts(latestScan?.vulnerabilities ?? []);
                const total = Object.values(counts).reduce((a, b) => a + b, 0);

                return (
                  <tr key={project.id} className="group hover:bg-[#0A0A0A] transition-colors">
                    <td className="px-4 py-3.5">
                      <p className="font-medium text-white">{project.name}</p>
                      <p className="text-xs text-[#BFC3C7] mt-0.5">{project.repo}</p>
                    </td>

                    <td className="px-4 py-3.5 text-[#BFC3C7]">
                      {latestScan ? (
                        <span>
                          {formatDate(latestScan.date)}{" "}
                          <span className="text-[#BFC3C7]/60">· {formatTime(latestScan.date)}</span>
                        </span>
                      ) : (
                        <span className="text-[#BFC3C7]/60">Never</span>
                      )}
                    </td>

                    <td className="px-4 py-3.5">
                      {latestScan ? (
                        <StatusDot status={latestScan.status} />
                      ) : (
                        <span className="text-[#BFC3C7]/60 text-xs">—</span>
                      )}
                    </td>

                    <td className="px-4 py-3.5">
                      {total === 0 ? (
                        latestScan?.status === "running" ? (
                          <span className="text-xs text-[#BFC3C7]/60">Scanning…</span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
                            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                            Clean
                          </span>
                        )
                      ) : (
                        <div className="flex flex-wrap gap-1.5">
                          {(["critical", "high", "medium", "low"] as const).map((sev) =>
                            counts[sev] > 0 ? (
                              <span key={sev} className="flex items-center gap-1">
                                <Badge severity={sev} />
                                <span className="text-xs text-[#BFC3C7]">{counts[sev]}</span>
                              </span>
                            ) : null
                          )}
                        </div>
                      )}
                    </td>

                    <td className="px-4 py-3.5 text-right">
                      {latestScan && latestScan.status === "completed" ? (
                        <Link
                          href={`/dashboard/${project.id}/scan/${latestScan.id}`}
                          className="text-xs font-medium text-white hover:text-[#BFC3C7] opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          View results →
                        </Link>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent scans */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-white">Recent scans</h2>
        <div className="space-y-2">
          {projects
            .flatMap((p) =>
              p.scans.map((s) => ({ ...s, projectName: p.name, projectId: p.id }))
            )
            .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
            .slice(0, 6)
            .map((scan) => {
              const counts = severityCounts(scan.vulnerabilities);
              const total = Object.values(counts).reduce((a, b) => a + b, 0);

              return (
                <div
                  key={scan.id}
                  className="flex items-center justify-between rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] px-4 py-3"
                >
                  <div className="flex items-center gap-4">
                    <StatusDot status={scan.status} />
                    <div>
                      <span className="text-sm font-medium text-white">{scan.projectName}</span>
                      <span className="ml-2 text-xs text-[#BFC3C7]/60">
                        {formatDate(scan.date)} · {formatTime(scan.date)}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    {total > 0 ? (
                      <div className="flex gap-1.5">
                        {(["critical", "high", "medium", "low"] as const).map((sev) =>
                          counts[sev] > 0 ? (
                            <span key={sev} className="flex items-center gap-1">
                              <Badge severity={sev} />
                              <span className="text-xs text-[#BFC3C7]">{counts[sev]}</span>
                            </span>
                          ) : null
                        )}
                      </div>
                    ) : scan.status !== "running" ? (
                      <span className="text-xs text-emerald-400 font-medium">Clean</span>
                    ) : (
                      <span className="text-xs text-[#BFC3C7]/60">Scanning…</span>
                    )}

                    {scan.status === "completed" && (
                      <Link
                        href={`/dashboard/${scan.projectId}/scan/${scan.id}`}
                        className="text-xs font-medium text-white hover:text-[#BFC3C7] transition-colors"
                      >
                        View →
                      </Link>
                    )}
                  </div>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
}
