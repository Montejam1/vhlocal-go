import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Dev: Vite serves the SPA and proxies /api + /static to the Python engine so
// there's no CORS and one origin. Prod: `npm run build` emits ../vhlocal/web/app,
// which the existing Python server serves at /app — one process, offline at runtime.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  base: "/app/",
  build: {
    outDir: path.resolve(__dirname, "../vhlocal/web/app"),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8420", changeOrigin: true },
      "/static": { target: "http://127.0.0.1:8420", changeOrigin: true },
    },
  },
});
