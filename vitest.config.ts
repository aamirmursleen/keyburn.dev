import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: { IP_HASH_SECRET: "test-only-ip-hash-secret" },
      },
    }),
  ],
  test: {
    // test/cli/ runs in plain Node (vitest.cli.config.ts).
    include: ["test/*.test.ts"],
    testTimeout: 30_000,
    coverage: {
      provider: "istanbul",
      include: ["src/worker/**/*.ts", "src/shared/**/*.ts", "src/cli/client.ts", "src/cli/http.ts", "src/cli/links.ts"],
      exclude: ["src/worker/worker-configuration.d.ts"],
      reporter: ["text", "html"],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
});
