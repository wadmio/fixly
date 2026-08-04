import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar />
        <main className="relative flex-1 overflow-y-auto bg-[#0A0A0B]">
          {/* Faint top glow — depth without decoration. */}
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-[radial-gradient(ellipse_60%_100%_at_50%_0%,rgba(52,211,153,0.05),transparent)]"
          />
          <div className="relative mx-auto w-full max-w-5xl px-6 py-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
