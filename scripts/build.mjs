// Builds the browser bundle (public/assets/app.js), the agent tool
// (public/cli/osss-<version>.mjs) and the agent skills index. No source maps, no eval, no
// third-party code.
//
// The agent tool is pinned: src/cli/release.json records the SHA-256 of each released
// version, and the build fails if the code changes without a version bump, so a published
// URL never changes content. Run `node scripts/build.mjs --release` to record a new version;
// `--verify-release` (wrangler's build command, so every deploy) fails instead of warning
// when they differ, except for local dev servers started with OSSS_DEV=1.
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { build } from "esbuild";

await build({
  entryPoints: ["src/client/main.ts"],
  outfile: "public/assets/app.js",
  bundle: true,
  format: "esm",
  target: ["es2022", "chrome111", "firefox113", "safari16.4"],
  minify: true,
  sourcemap: false,
  legalComments: "none",
  tsconfig: "tsconfig.client.json",
  logLevel: "info",
});

const version = /VERSION = "(\d+\.\d+\.\d+)"/.exec(await readFile("src/cli/version.ts", "utf8"))?.[1];
if (!version) throw new Error("src/cli/version.ts must define VERSION");
const outfile = `public/cli/osss-${version}.mjs`;
await mkdir("public/cli", { recursive: true });
await build({
  entryPoints: ["src/cli/main.ts"],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: ["node22"],
  // Readable on purpose, so anyone can audit what runs on their machine.
  minify: false,
  sourcemap: false,
  legalComments: "none",
  charset: "ascii",
  banner: { js: "#!/usr/bin/env node" },
  tsconfig: "tsconfig.cli.json",
  logLevel: "info",
});
// Only the current version is published; remove other builds (and any unversioned copy).
for (const name of await readdir("public/cli")) {
  if (name.endsWith(".mjs") && name !== `osss-${version}.mjs`) await rm(`public/cli/${name}`, { force: true });
}
const sha256 = createHash("sha256").update(await readFile(outfile)).digest("hex");

// Pages that tell people what to download and which fingerprint to expect.
const PINNED_DOCS = [
  "public/agents.html",
  "public/md/agents.md",
  "public/s.html",
  "public/md/s.md",
  "public/.well-known/agent-skills/osss/SKILL.md",
  "README.md",
];
const FILE_REF = /osss-\d+\.\d+\.\d+\.mjs/g;
const HASH_REF = /[0-9a-f]{64}(?=  osss\.download)/g;

const problems = [];
const releases = JSON.parse(await readFile("src/cli/release.json", "utf8").catch(() => "{}"));
if (process.argv.includes("--release")) {
  if (releases[version] && releases[version] !== sha256) {
    throw new Error(`osss ${version} was already released with a different hash; bump VERSION in src/cli/version.ts`);
  }
  releases[version] = sha256;
  await writeFile("src/cli/release.json", `${JSON.stringify(releases, null, 2)}\n`);
  for (const doc of PINNED_DOCS) {
    const text = await readFile(doc, "utf8");
    await writeFile(doc, text.replace(FILE_REF, `osss-${version}.mjs`).replace(HASH_REF, sha256));
  }
} else if (releases[version] !== sha256) {
  problems.push(
    releases[version]
      ? `osss ${version} changed after release (expected ${releases[version]}, got ${sha256}). Bump VERSION in src/cli/version.ts, then run: node scripts/build.mjs --release`
      : `osss ${version} is not recorded yet. Run: node scripts/build.mjs --release`,
  );
}
for (const doc of PINNED_DOCS) {
  const text = await readFile(doc, "utf8");
  const files = new Set(text.match(FILE_REF) ?? []);
  const hashes = new Set(text.match(HASH_REF) ?? []);
  if (files.size !== 1 || !files.has(`osss-${version}.mjs`) || hashes.size !== 1 || !hashes.has(sha256)) {
    problems.push(`${doc} must pin osss-${version}.mjs with sha256 ${sha256} (run: node scripts/build.mjs --release)`);
  }
}
// Deploys verify strictly; plain builds and local dev servers (OSSS_DEV=1) only warn, so work
// in progress still builds.
const strict = process.argv.includes("--verify-release") && process.env.OSSS_DEV !== "1";
if (problems.length && strict) throw new Error(problems.join("\n"));
for (const problem of problems) console.warn(`warning: ${problem}`);
await writeFile("public/cli/SHA256SUMS", `${sha256}  osss-${version}.mjs\n`);

// Agent Skills discovery index (v0.2.0), with the digest of the skill as it will be served.
const skill = await readFile("public/.well-known/agent-skills/osss/SKILL.md");
const skillDescription = /^description: (.+)$/m.exec(skill.toString("utf8"))?.[1];
if (!skillDescription) throw new Error("SKILL.md needs a description in its front matter");
await writeFile(
  "public/.well-known/agent-skills/index.json",
  `${JSON.stringify(
    {
      $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
      skills: [
        {
          name: "osss",
          type: "skill-md",
          description: skillDescription,
          url: "https://keyburn.dev/.well-known/agent-skills/osss/SKILL.md",
          digest: `sha256:${createHash("sha256").update(skill).digest("hex")}`,
        },
      ],
    },
    null,
    2,
  )}\n`,
);
console.log(`osss ${version} sha256 ${sha256}`);
