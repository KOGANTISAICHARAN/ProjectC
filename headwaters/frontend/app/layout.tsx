import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Headwaters",
  description:
    "Email threat detection and forensic intelligence. Deterministic forensics establish fact; the AI layer reads intent only.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
