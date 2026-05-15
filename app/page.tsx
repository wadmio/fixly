import Link from "next/link";

const features = [
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    title: "Instant scanning",
    description:
      "Analyze your entire dependency tree in seconds. No setup scripts, no CI plugins required to get started.",
  },
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
    title: "CVE-backed data",
    description:
      "Every result is tied to a real CVE with a CVSS score, affected versions, and a clear remediation path.",
  },
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
      </svg>
    ),
    title: "Built for developers",
    description:
      "Designed around your workflow. Results map directly to packages, paths, and the exact version to upgrade to.",
  },
];

const steps = [
  {
    number: "01",
    title: "Connect your project",
    description: "Point Fixly at your package.json or lock file. Works with npm, yarn, and pnpm.",
  },
  {
    number: "02",
    title: "Run a scan",
    description: "Fixly audits your dependency tree against a live vulnerability database.",
  },
  {
    number: "03",
    title: "Fix what matters",
    description: "Prioritized results by severity. One-line fix commands ready to copy.",
  },
];

const stats = [
  { value: "180k+", label: "CVEs indexed" },
  { value: "<2s", label: "Average scan time" },
  { value: "npm · yarn · pnpm", label: "Package managers" },
];

export default function LandingPage() {
  return (
    <div className="flex min-h-full flex-col bg-[#0A0A0A] text-white font-sans">
      {/* Navbar */}
      <header className="sticky top-0 z-10 border-b border-[#D1D5DB]/10 bg-[#0A0A0A]/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <img src="/fixly_logo.svg" alt="Fixly" className="h-6 w-auto" />
          <nav className="flex items-center gap-6">
            <a href="#how-it-works" className="text-sm text-[#BFC3C7] hover:text-white transition-colors">
              How it works
            </a>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#BFC3C7] hover:text-white transition-colors"
              aria-label="GitHub"
            >
              <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844a9.59 9.59 0 012.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </a>
            <Link
              href="/dashboard"
              className="rounded-md bg-white px-3.5 py-1.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
            >
              Open dashboard
            </Link>
          </nav>
        </div>
      </header>

      <main className="flex-1">
        {/* Hero */}
        <section className="mx-auto max-w-6xl px-6 pb-24 pt-20 text-center">
          <div className="flex justify-center mb-10">
            <img src="/fixly_logo.svg" alt="Fixly" className="h-20 w-auto" />
          </div>

          <div className="inline-flex items-center gap-2 rounded-full border border-[#D1D5DB]/20 bg-[#1A1A1A] px-3 py-1 text-xs font-medium text-[#BFC3C7] mb-8">
            <span className="h-1.5 w-1.5 rounded-full bg-[#BFC3C7]" />
            Open source · Node.js &amp; Next.js
          </div>

          <h1 className="mx-auto max-w-3xl text-5xl font-semibold tracking-tight text-white leading-tight">
            Find vulnerable dependencies
            <br />
            <span className="text-[#BFC3C7]">before they find you.</span>
          </h1>

          <p className="mx-auto mt-6 max-w-xl text-lg text-[#BFC3C7] leading-relaxed">
            Fixly scans your Node.js and Next.js projects for known security vulnerabilities, maps
            them to real CVEs, and tells you exactly what to upgrade.
          </p>

          <div className="mt-10 flex items-center justify-center gap-4">
            <Link
              href="/dashboard"
              className="rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
            >
              Start scanning free
            </Link>
            <a
              href="#how-it-works"
              className="rounded-lg border border-[#D1D5DB]/20 px-5 py-2.5 text-sm font-medium text-[#BFC3C7] hover:border-[#D1D5DB]/40 hover:text-white transition-colors"
            >
              See how it works
            </a>
          </div>

          {/* Stats row */}
          <div className="mx-auto mt-16 grid max-w-2xl grid-cols-3 gap-px overflow-hidden rounded-xl border border-[#D1D5DB]/10 bg-[#D1D5DB]/10">
            {stats.map((stat) => (
              <div key={stat.label} className="flex flex-col items-center bg-[#1A1A1A] px-6 py-5">
                <span className="text-2xl font-semibold text-white">{stat.value}</span>
                <span className="mt-1 text-xs text-[#BFC3C7]">{stat.label}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Features */}
        <section className="border-y border-[#D1D5DB]/10 bg-[#1A1A1A]">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
              {features.map((f) => (
                <div key={f.title} className="flex flex-col gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#0A0A0A] text-[#BFC3C7]">
                    {f.icon}
                  </div>
                  <h3 className="text-sm font-semibold text-white">{f.title}</h3>
                  <p className="text-sm leading-relaxed text-[#BFC3C7]">{f.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* How it works */}
        <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-24">
          <div className="mb-12 text-center">
            <h2 className="text-3xl font-semibold tracking-tight text-white">How it works</h2>
            <p className="mt-3 text-[#BFC3C7]">Three steps from zero to secured.</p>
          </div>

          <div className="relative grid grid-cols-1 gap-8 md:grid-cols-3">
            <div className="absolute top-6 left-0 right-0 hidden h-px bg-[#D1D5DB]/10 md:block" style={{ left: "calc(16.66% + 1.5rem)", right: "calc(16.66% + 1.5rem)" }} />

            {steps.map((step) => (
              <div key={step.number} className="flex flex-col gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[#D1D5DB]/20 bg-[#1A1A1A] text-sm font-semibold text-[#BFC3C7]">
                  {step.number}
                </div>
                <h3 className="text-sm font-semibold text-white">{step.title}</h3>
                <p className="text-sm leading-relaxed text-[#BFC3C7]">{step.description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CTA Banner */}
        <section className="border-t border-[#D1D5DB]/10 bg-[#1A1A1A]">
          <div className="mx-auto max-w-6xl px-6 py-16 text-center">
            <h2 className="text-2xl font-semibold text-white">Ready to audit your project?</h2>
            <p className="mt-3 text-[#BFC3C7]">
              No account required. Paste your package.json and get results instantly.
            </p>
            <Link
              href="/dashboard"
              className="mt-8 inline-flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
            >
              Open dashboard
              <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 8l4 4m0 0l-4 4m4-4H3" />
              </svg>
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#D1D5DB]/10 bg-[#0A0A0A]">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-white">
              <svg className="h-3.5 w-3.5 text-[#0A0A0A]" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span className="text-sm font-semibold text-white">Fixly</span>
          </div>
          <p className="text-xs text-[#BFC3C7]">
            Built as a proof of concept. Not for production use.
          </p>
        </div>
      </footer>
    </div>
  );
}
