import { defineConfig } from "vitest/config";

// The agent tool (src/cli) runs on Node, not in workerd, so its unit tests run in plain Node.
// src/cli/client.ts talks to the Worker and is tested in the workerd pool (test/cli-client.test.ts).
export default defineConfig({
  test: {
    include: ["test/cli/**/*.test.ts"],
    environment: "node",
    testTimeout: 30_000,
    coverage: {
      provider: "istanbul",
      include: ["src/cli/**/*.ts"],
      exclude: ["src/cli/main.ts", "src/cli/client.ts"],
      reportsDirectory: "coverage/cli",
      reporter: ["text", "html"],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
});
