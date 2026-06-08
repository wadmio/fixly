"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";

const nav = [
  {
    label: "New scan",
    href: "/dashboard",
    icon: (
      <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z" />
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
        <Link href="/">
          <Image src="/fixly_logo.svg" alt="Fixly" width={640} height={180} className="h-14 w-auto" unoptimized />
        </Link>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 p-3">
        {nav.map((item) => {
          const active = pathname.startsWith(item.href);
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
        <a
          href="https://github.com/wadmio/fixly"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-[#BFC3C7] hover:bg-[#0A0A0A] hover:text-white transition-colors"
        >
          <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
            <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844a9.59 9.59 0 012.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
          </svg>
          View on GitHub
        </a>
      </div>
    </aside>
  );
}
