"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const nav = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    label: "Projects",
    href: "/dashboard",
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M2 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V7z" />
      </svg>
    ),
  },
  {
    label: "Vulnerabilities",
    href: "/dashboard",
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      </svg>
    ),
  },
  {
    label: "Settings",
    href: "/dashboard",
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    ),
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-full w-56 flex-col bg-[#1A1A1A] text-[#BFC3C7]">
      {/* Logo */}
      <div className="flex h-14 items-center border-b border-[#D1D5DB]/10 px-4">
        <img src="/fixly_logo.svg" alt="Fixly" className="h-14 w-auto" />
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 p-3">
        {nav.map((item) => {
          const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.label}
              href={item.href}
              className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                active
                  ? "bg-[#0A0A0A] text-white"
                  : "text-[#BFC3C7] hover:bg-[#0A0A0A] hover:text-white"
              }`}
            >
              {item.icon}
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-[#D1D5DB]/10 p-3">
        <div className="flex items-center gap-2.5 rounded-md px-3 py-2">
          <div className="h-7 w-7 rounded-full bg-[#0A0A0A] border border-[#D1D5DB]/20 flex items-center justify-center text-xs font-medium text-[#BFC3C7]">
            U
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-white truncate">user@example.com</p>
            <p className="text-xs text-[#BFC3C7] truncate">Free plan</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
