import Link from "next/link";
import Image from "next/image";

const features = [
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    title: "Instant scanning",
    description:
      "Scan your project's dependencies in seconds. No setup scripts, no CI plugins required to get started.",
  },
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
    title: "Real advisory data",
    description:
      "Findings come straight from the OSV database, cross-referenced with NVD and enriched with KEV, EPSS, and public-PoC exploit intel.",
  },
  {
    icon: (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
      </svg>
    ),
    title: "Built for developers",
    description:
      "An A–F Fixly Score, a Grade Forecast, and a remediation plan of copy-paste commands — the exact version to upgrade to, per package.",
  },
];

const steps = [
  {
    number: "01",
    title: "Connect your project",
    description: "Point Fixly at a public GitHub repo. It reads your package.json and package-lock.json.",
  },
  {
    number: "02",
    title: "Run a scan",
    description: "Fixly audits your dependency tree against a live vulnerability database.",
  },
  {
    number: "03",
    title: "Fix what matters",
    description: "Prioritized results by severity, each with the fixed version to upgrade to.",
  },
];

const stats = [
  { value: "OSV + NVD", label: "Advisory sources" },
  { value: "KEV · EPSS · PoC", label: "Exploit intel" },
  { value: "A–F", label: "Fixly Score" },
];

export default function LandingPage() {
  return (
    <div className="flex min-h-full flex-col bg-[#0A0A0A] text-white font-sans">
      {/* Navbar */}
      <header className="sticky top-0 z-10 border-b border-white/[0.06] bg-[#0A0A0B]/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-6">
          <Image src="/fixly_logo.svg" alt="Fixly" width={640} height={180} className="h-6 w-auto" unoptimized />
          <nav className="flex items-center gap-6">
            <a href="#how-it-works" className="text-sm text-[#BFC3C7] hover:text-white transition-colors">
              How it works
            </a>
            <a
              href="https://github.com/wadmio/fixly"
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
        <section className="relative mx-auto max-w-6xl px-6 pb-24 pt-24 text-center">
          {/* Ambient glow */}
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-0 top-0 h-[420px] bg-[radial-gradient(ellipse_55%_100%_at_50%_0%,rgba(52,211,153,0.08),transparent)]"
          />

          <div className="relative inline-flex items-center gap-2 rounded-full border border-white/[0.1] bg-[#111214] px-3 py-1 text-xs font-medium text-[#BFC3C7] mb-8">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Open source · Node.js &amp; Next.js
          </div>

          <h1 className="mx-auto max-w-3xl text-5xl font-semibold tracking-tight text-white leading-tight">
            Find vulnerable dependencies
            <br />
            <span className="text-[#BFC3C7]">before they find you.</span>
          </h1>

          <p className="mx-auto mt-6 max-w-xl text-lg text-[#BFC3C7] leading-relaxed">
            Fixly checks every npm package in your project — direct and transitive — against
            live vulnerability databases, grades it A–F, and tells you exactly what to upgrade.
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

          {/* Illustrative report preview */}
          <div className="panel relative mx-auto mt-16 max-w-3xl overflow-hidden p-6 text-left">
            <div
              aria-hidden="true"
              className="pointer-events-none absolute -left-12 -top-12 h-48 w-48 rounded-full bg-yellow-400 opacity-[0.06] blur-3xl"
            />
            <div className="relative">
              <div className="flex items-center gap-2 border-b border-white/[0.06] pb-4">
                <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M12 2 4 5.4v5.4c0 5 3.4 8.8 8 10.2 4.6-1.4 8-5.2 8-10.2V5.4L12 2Z" stroke="#34d399" strokeWidth="1.6" strokeLinejoin="round" />
                  <path d="M13.1 6.8 8.9 12.6h2.6l-1 4.6 4.6-6.2h-2.7l0.7-4.2Z" fill="#34d399" />
                </svg>
                <span className="text-sm font-semibold text-white">Fixly</span>
                <span className="text-white/15">/</span>
                <span className="font-mono text-xs text-[#9DA2A8]">acme/webapp</span>
                <span className="ml-auto rounded border border-white/[0.1] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-[#6E7378]">
                  Example
                </span>
              </div>

              <div className="flex flex-col gap-6 pt-5 sm:flex-row sm:items-center">
                <div className="relative h-20 w-20 shrink-0" aria-hidden="true">
                  <svg className="h-20 w-20" viewBox="0 0 84 84">
                    <circle cx="42" cy="42" r="36" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="5" />
                    <circle cx="42" cy="42" r="36" fill="none" stroke="#facc15" strokeWidth="5" strokeLinecap="round" strokeDasharray="163 226.2" transform="rotate(-90 42 42)" />
                  </svg>
                  <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 text-2xl font-bold text-yellow-400">
                    C
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="microlabel">Fixly Score</p>
                  <p className="mt-1 text-sm text-[#C9CDD1]">
                    72/100 — 9 vulnerable packages, 1 exploited in the wild.
                  </p>
                  <div className="mt-3 flex h-1.5 max-w-sm gap-0.5 overflow-hidden rounded" aria-hidden="true">
                    <span className="block rounded-sm" style={{ flex: 2, background: "#f87171" }} />
                    <span className="block rounded-sm" style={{ flex: 3, background: "#fb923c" }} />
                    <span className="block rounded-sm" style={{ flex: 4, background: "#facc15" }} />
                  </div>
                  <p className="mt-3 text-xs text-[#9DA2A8]">
                    Fix everything → <span className="font-mono font-semibold text-emerald-400">A (97/100)</span>
                    <span className="text-[#6E7378]"> · 6 actions</span>
                  </p>
                  <code className="mt-2 inline-block rounded-md border border-white/[0.06] bg-[#0A0A0B] px-2 py-1 font-mono text-[11px] text-emerald-400">
                    $ npm install lodash@4.17.21
                  </code>
                </div>
              </div>
            </div>
          </div>

          {/* Stats row */}
          <div className="relative mx-auto mt-10 grid max-w-2xl grid-cols-3 gap-px overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.07]">
            {stats.map((stat) => (
              <div key={stat.label} className="flex flex-col items-center bg-[#101113] px-6 py-5">
                <span className="text-lg font-semibold text-white sm:text-xl">{stat.value}</span>
                <span className="mt-1 text-xs text-[#8B8F94]">{stat.label}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Features */}
        <section className="border-y border-white/[0.06] bg-[#0E0F10]">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
              {features.map((f) => (
                <div key={f.title} className="flex flex-col gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.07] bg-[#0A0A0B] text-emerald-400/80">
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
            <div className="absolute top-6 left-0 right-0 hidden h-px bg-white/[0.07] md:block" style={{ left: "calc(16.66% + 1.5rem)", right: "calc(16.66% + 1.5rem)" }} />

            {steps.map((step) => (
              <div key={step.number} className="flex flex-col gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-full border border-white/[0.1] bg-[#111214] font-mono text-sm font-semibold text-[#BFC3C7]">
                  {step.number}
                </div>
                <h3 className="text-sm font-semibold text-white">{step.title}</h3>
                <p className="text-sm leading-relaxed text-[#BFC3C7]">{step.description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CTA Banner */}
        <section className="border-t border-white/[0.06] bg-[#0E0F10]">
          <div className="mx-auto max-w-6xl px-6 py-16 text-center">
            <h2 className="text-2xl font-semibold text-white">Ready to audit your project?</h2>
            <p className="mt-3 text-[#BFC3C7]">
              No account required. Paste a public GitHub repo URL and get results instantly.
            </p>
            <Link
              href="/dashboard"
              className="mt-8 inline-flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
            >
              Open dashboard
              <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 8l4 4m0 0l-4 4m4-4H3" />
              </svg>
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/[0.06] bg-[#0A0A0B]">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-white">
              <svg className="h-3.5 w-3.5 text-[#0A0A0A]" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
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
