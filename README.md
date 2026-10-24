# One Smart Sheep · Secret

Zero-knowledge, self-destructing secret sharing for **secret.onesmartsheep.com**, hosted entirely
on Cloudflare (Workers, Durable Objects, R2).

- **Share a secret**: text up to 64 KB and/or a file up to 25 MB, encrypted in the browser.
  Expiry from 15 minutes to 7 days, 1–10 views, optional passphrase (5 wrong tries destroy it).
- **Receipts**: the sender gets a private link showing when and from which country it was opened,
  and can destroy it early.
- **Request a secret**: send a client a link. What they submit (text and/or file) is encrypted to
  your private inbox link, so only you can open it.

How it protects data is described in [docs/SECURITY.md](docs/SECURITY.md); there is a
plain-language version for clients at `/security`.

## Architecture

```
Browser (WebCrypto: AES-256-GCM, HKDF, PBKDF2, ECDH P-256)
   │  ciphertext + token hashes only — keys stay in the URL #fragment
   ▼
Cloudflare Worker  (src/worker)  — strict headers, validation, rate limits, routing
   ├── Vault Durable Object (one per secret/request)  — atomic one-time state, alarms
   ├── Quota Durable Object (per client/day + global) — strict daily budgets
   ├── R2 bucket "osss-secret-files"                  — encrypted file attachments
   └── Static assets (public/)                        — HTML/CSS + bundled client JS
```

| Path | Page |
| --- | --- |
| `/` | Share a secret |
| `/s#…` | Open a secret (recipient) |
| `/m#…` | Sender's receipt / destroy |
| `/request` | Create a request link |
| `/r#…` | Client submits a secret |
| `/i#…` | Requester's private inbox |
| `/security` | How it works |
| `/agents` | The `osss` CLI and MCP server for AI agents |

For agents and crawlers there are also `/robots.txt` (with Content Signals), `/sitemap.xml`,
`/llms.txt`, `/auth.md`, `/openapi.json`, `/api/v1/health`, `/.well-known/api-catalog`
(RFC 9727), `/.well-known/ai-catalog.json` (ARD), `/.well-known/agent-skills/index.json` and
Markdown versions of the public pages (`Accept: text/markdown`, or `/index.md`, `/agents.md`, …).

## AI agents: the `osss` CLI and MCP server

`src/cli` is a zero-dependency Node 22+ tool, bundled by `scripts/build.mjs` into
`public/cli/osss-<version>.mjs` and served at `/cli/`. It lets Claude Code, Codex and other agents
open secret links on the user's computer without the value entering the conversation: opened
secrets are stored encrypted in `~/.osss` (the key exists only in the handle the agent gets), and
`osss run <handle> -- <command>` passes them to one command as environment variables, with output
redaction. Passphrases are only ever typed at a terminal. Design and limits:
[docs/SECURITY.md](docs/SECURITY.md#ai-agents-osss).

Install (the fingerprint is checked by the build against `src/cli/release.json`):

```sh
(umask 077 && mkdir -p ~/.osss && cd ~/.osss && rm -f osss.download \
  && curl -fsSL -o osss.download https://secret.nafran.com/cli/osss-1.0.0.mjs \
  && echo "e4eba54de32d6b275ea96919b389a58cca8fc4431112ee84b2ad5ca8fdeb7d27  osss.download" | shasum -a 256 -c \
  && mv osss.download osss.mjs)
claude mcp add --scope user osss -- node ~/.osss/osss.mjs mcp
```

Optionally, `osss hook claude-code` as a Claude Code `UserPromptSubmit` hook keeps pasted links
out of the conversation entirely: it opens them locally, blocks the message before it reaches the
model, and hands the user the message back with handles in place of the links (see `/agents`).

Releases are pinned: once a version's SHA-256 is recorded in `src/cli/release.json`, changing the
CLI without bumping `src/cli/version.ts` fails the deploy build (`--verify-release`). To release,
bump the version and run `node scripts/build.mjs --release`, which records the hash and updates
the install snippets in this file, `public/agents.html`, `public/md/agents.md` and the agent
skill. Local dev servers (`npm run dev`, the e2e runs) set `OSSS_DEV=1` and only warn.

## Development

Requires Node 22+ and npm ≥ 11.19 (enforced by `engine-strict`). Installs fail if any dependency
has install scripts other than the reviewed ones in `package.json` → `allowScripts` (esbuild,
workerd), because `.npmrc` sets `strict-allow-scripts`. npm 11.19 doesn't apply that check to
`npm audit fix` or `npm dedupe`, so run those with `--ignore-scripts` and then run `npm install`.

```bash
npm install
npm run dev            # builds the client, runs wrangler dev on http://localhost:8787
npm test               # Worker/Durable Object/crypto tests in workerd, then the CLI tests in Node
npm run test:coverage  # coverage reports (thresholds: 80% lines/functions/statements)
npm run typecheck      # client, worker, CLI and tests
npm run build && npm run e2e   # Playwright end-to-end runs (browser, then CLI and MCP), with leak checks
```

`npm run dev` needs a `.dev.vars` file containing `IP_HASH_SECRET=<random string>` (gitignored).

## Current deployment

- **Live at https://secrets.nafran.com and https://secret.nafran.com** (both custom domains on
  the same Worker; links point to whichever host they were created on): Worker `osss-secret` in the Cloudflare
  account that owns nafran.com, R2 bucket `osss-secret-files` (9-day safety-net lifecycle rule), secret
  `IP_HASH_SECRET` set.
- Redeploy after changes with `npm run deploy` (type checks, tests, build and the browser test
  run first). Smoke-test production with
  `E2E_BASE=https://secret.nafran.com npm run e2e`.
- Pages are served with `Cache-Control: no-store, no-transform`, so Cloudflare zone features
  (Web Analytics auto-injection, Email Obfuscation, Rocket Loader) can't inject scripts. The
  nafran.com zone has Web Analytics injection on, and this is what keeps it out.
- The nafran.com zone has the "Add security headers" Managed Transform on, which downgrades
  `X-Frame-Options` to `SAMEORIGIN` and `Referrer-Policy` to `same-origin` on responses.
  Framing is still blocked by CSP `frame-ancestors 'none'`, and pages and requests set
  `no-referrer` themselves. To restore the exact headers, turn that transform off for the zone.

### Moving to secret.onesmartsheep.com later

The `onesmartsheep.com` zone lives in a different Cloudflare account. R2 must first be enabled there
(dashboard → R2 Object Storage). Then set `CLOUDFLARE_ACCOUNT_ID` in `.env` and the route in `wrangler.jsonc` and
follow the steps below.

## Deployment

The Worker must be deployed into the Cloudflare account that owns the target zone.

1. Log in with an account that has access to that zone (`npx wrangler whoami` should list it). If
   the login can see several accounts, put `CLOUDFLARE_ACCOUNT_ID=<id>` in a `.env` file (gitignored).
2. Create the R2 bucket and a safety-net lifecycle rule (normal deletion is immediate; this only
   catches orphans):
   ```bash
   npx wrangler r2 bucket create osss-secret-files
   npx wrangler r2 bucket lifecycle add osss-secret-files purge-orphans --expire-days 9 --force
   ```
3. Set the HMAC key used to pseudonymize client IPs for rate limiting:
   ```bash
   openssl rand -base64 32 | npx wrangler secret put IP_HASH_SECRET
   ```
4. Deploy (runs type checks, tests with coverage, the build and the browser end-to-end test first):
   ```bash
   npm run deploy
   ```
   This creates the `secret.onesmartsheep.com` custom domain, DNS record and certificate automatically.
5. In the Cloudflare dashboard for `onesmartsheep.com`, make sure nothing injects scripts into
   this hostname: **Rocket Loader off, Email Address Obfuscation off, Web Analytics automatic
   setup off (or excluded for this hostname), no Zaraz.** The CSP (pinned to the app's own
   files) blocks injected scripts anyway, but they would produce errors. Keep **Always Use
   HTTPS** on.
6. Smoke test: create a secret, open it in a private window, check the receipt.

## Configuration

Limits live in `wrangler.jsonc` (`vars`) and `src/shared/protocol.ts` (`LIMITS`):

| Setting | Default |
| --- | --- |
| Creations per client per minute | 10 (`RL_CREATE`) |
| Reads per client per minute | 60 (`RL_ACCESS`) |
| Uploads per client per minute | 10 (`RL_UPLOAD`) |
| Creations per client per day | 100 (`QUOTA_IP_CREATES_PER_DAY`) |
| Upload bytes per client per day | 1 GB (`QUOTA_IP_BYTES_PER_DAY`) |
| Creations per IPv6 /48 per day | 400 (`QUOTA_NET_CREATES_PER_DAY`) |
| Upload bytes per IPv6 /48 per day | 2 GB (`QUOTA_NET_BYTES_PER_DAY`) |
| Creations per day, all clients | 50,000 (`QUOTA_GLOBAL_CREATES_PER_DAY`) |
| Upload bytes per day, all clients | 100 GB (`QUOTA_GLOBAL_BYTES_PER_DAY`) |
| Text / file size | 64 KB / 25 MB |
| Receipt retention | 30 days |

Rate-limit `namespace_id`s (71001–71003) must be unique within the Cloudflare account.

## Decisions worth knowing

- **Zero runtime dependencies.** Validation is hand-written (`src/worker/validate.ts`) instead of
  using Zod, to keep third-party code out of a security-critical service. All crypto is native
  WebCrypto.
- **Creation is public** (no login), as requested. Abuse is bounded by rate limits, daily quotas
  and wording that never presents content as coming from One Smart Sheep. To restrict creation to
  the team later, put Cloudflare Access (Google login for @onesmartsheep.com) in front of `/`,
  `/request` and `/api/v1/*/create`.
- **Durable Objects, not KV**, because one-time secrets need strong consistency.

## Follow-ups

- Add `public/.well-known/security.txt` with a security contact address.
- Not offered on purpose: an MCP Server Card (the format describes remote MCP servers, and a
  remote server that handled links would see their keys), OAuth discovery and protected-resource
  metadata (there is no OAuth: links are the capability, see `/auth.md`), and DNS-AID records.
- HSTS preload would have to be enabled on the apex `onesmartsheep.com` (it then covers every
  subdomain), so it's a whole-domain decision. Only do it once every subdomain is HTTPS-only.
- Optional: keep data in the EU by using a Durable Object jurisdiction
  (`env.VAULT.jurisdiction("eu")`) and an EU R2 bucket.
- Protect the Cloudflare account with hardware-key 2FA. Whoever can deploy this Worker could
  change the code that runs in visitors' browsers.
