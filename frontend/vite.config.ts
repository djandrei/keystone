import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": resolve(__dirname, "src") } },
  server: { host: true, port: 5173 },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/tests/setup.ts"],
    css: false,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["node_modules", "dist", "e2e/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      // entry point, type decls, test files and setup aren't unit-testable code
      exclude: ["src/main.tsx", "src/**/*.d.ts", "src/**/*.{test,spec}.{ts,tsx}", "src/tests/**"],
      // statements/lines/branches gate at 80%; functions is lower because v8 counts
      // every uninvoked callback/handler as an uncovered function.
      thresholds: { statements: 80, lines: 80, branches: 80, functions: 65 },
    },
  },
});
