import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  // The API base URL is deliberately NOT prefixed with NEXT_PUBLIC_: the browser
  // never talks to FastAPI directly. Route handlers under app/api/ proxy the
  // call server-side so no bearer token or upstream URL reaches the client
  // bundle. See docs/ARCHITECTURE.md, "Why the dashboard proxies".
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
};

export default config;
