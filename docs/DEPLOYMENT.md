# Deployment and operations

How to run, deploy and configure keyburn. The project overview is in the [README](../README.md);
the security design is in [SECURITY.md](SECURITY.md).

## Development setup

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
npm run build && npm run e2e   # Playwright runs: browser flows, CLI and MCP, WCAG 2.2 AA accessibility
```

`npm run dev` needs a `.dev.vars` file containing `IP_HASH_SECRET=<random string>` (gitignored).

## Current deployment

- **Live at https://keyburn.dev** (`www.keyburn.dev` redirects to it). The first hosts,
  `secret.nafran.com` and `secrets.nafran.com`, stay on the same Worker: page visits redirect to
  keyburn.dev (browsers keep the `#…` part, so old links still open), while their API and CLI files
  keep working for osss and the links that name them. Worker `osss-secret`,
  R2 bucket `osss-secret-files` (9-day safety-net lifecycle rule), secret `IP_HASH_SECRET` set.
  The Cloudflare account is taken from `CLOUDFLARE_ACCOUNT_ID` in the gitignored `.env` file.
- Redeploy after changes with `npm run deploy` (type checks, tests, build and the browser test
  run first). Smoke-test production with
  `E2E_BASE=https://keyburn.dev npm run e2e`.
- Pages are served with `Cache-Control: no-store, no-transform`, so Cloudflare zone features
  (Web Analytics auto-injection, Email Obfuscation, Rocket Loader) can't inject scripts, even
  when the zone has Web Analytics injection turned on.
- If the zone has the "Add security headers" Managed Transform on, it downgrades
  `X-Frame-Options` to `SAMEORIGIN` and `Referrer-Policy` to `same-origin` on responses.
  Framing is still blocked by CSP `frame-ancestors 'none'`, and pages and requests set
  `no-referrer` themselves. To restore the exact headers, turn that transform off for the zone.

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
   This creates the custom domains listed in `wrangler.jsonc`, with their DNS records and certificates.
5. In the Cloudflare dashboard for the zone, make sure nothing injects scripts into this
   hostname: **Rocket Loader off, Email Address Obfuscation off, Web Analytics automatic
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
  and wording that never presents content as coming from KeyBurn. To restrict creation to
  a team later, put Cloudflare Access (for example a Google login for the team's domain) in front
  of `/`, `/request` and `/api/v1/*/create`.
- **Durable Objects, not KV**, because one-time secrets need strong consistency.

## Follow-ups

- Add `public/.well-known/security.txt` with a security contact address.
- Not offered on purpose: an MCP Server Card (the format describes remote MCP servers, and a
  remote server that handled links would see their keys), OAuth discovery and protected-resource
  metadata (there is no OAuth: links are the capability, see `/auth.md`), and DNS-AID records.
- `keyburn.dev` is HTTPS-only by design: the whole `.dev` top-level domain is on the browsers' HSTS
  preload list.
- Optional: keep data in the EU by using a Durable Object jurisdiction
  (`env.VAULT.jurisdiction("eu")`) and an EU R2 bucket.
- Protect the Cloudflare account with hardware-key 2FA. Whoever can deploy this Worker could
  change the code that runs in visitors' browsers.
