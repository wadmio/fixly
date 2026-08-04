import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
  display: "swap",
});

const description =
  "Scan any public GitHub repo for vulnerable npm dependencies — direct and transitive — with an A–F Fixly Score, exploit intel (KEV, EPSS, PoC), and a copy-paste remediation plan.";

export const metadata: Metadata = {
  title: {
    default: "Fixly — Dependency Security Scanner",
    template: "%s · Fixly",
  },
  description,
  openGraph: {
    title: "Fixly — Dependency Security Scanner",
    description,
    siteName: "Fixly",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#0A0A0A",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="h-full bg-[#0A0A0A] text-white">{children}</body>
    </html>
  );
}
