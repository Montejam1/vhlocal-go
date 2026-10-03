import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 30_000,
  workers: 1,
  use: { baseURL: process.env.VHLOCAL_BROWSER_URL || "http://127.0.0.1:18421", headless: true },
  reporter: [["list"], ["html", { open: "never" }]],
});
