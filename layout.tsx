import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "CTF Copilot",
  description: "Autonomous assistant for authorized CTF challenges",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-bg text-gray-100 font-mono">
        <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between">
          <a href="/" className="text-accent font-bold text-lg tracking-tight">
            CTF_COPILOT
          </a>
          <nav className="text-sm text-gray-400 space-x-4">
            <a href="/" className="hover:text-accent">
              solve
            </a>
          </nav>
        </header>
        <main className="px-6 py-8 max-w-5xl mx-auto">{children}</main>
      </body>
    </html>
  );
}
