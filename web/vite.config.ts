/// <reference types="node" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Ports are shared with the API (server/src/index.ts) so its Host/Origin allowlists match this dev server.
const apiPort = Number(process.env.AGENTSHIELD_API_PORT ?? 3000);
const webPort = Number(process.env.AGENTSHIELD_WEB_PORT ?? 5173);

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: webPort,
    strictPort: true,
    // changeOrigin rewrites Host to the API's own host (the only Host it accepts); the browser's Origin stays
    // http://127.0.0.1:<webPort>, which the API allowlists explicitly. Cookies stay same-origin from the browser's view.
    proxy: { "/api": { target: `http://127.0.0.1:${apiPort}`, changeOrigin: true } },
  },
});
