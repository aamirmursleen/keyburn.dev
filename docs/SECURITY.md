# Security design

This document describes how **keyburn.dev** protects what people share, what the
server can and cannot see, and the limits of the design. Protocol identifier: `osss/v1`.

## Goals

1. Nobody but the intended recipient can read a secret: not the server operator, not Cloudflare,
   not someone who steals the database.
2. A one-time secret can be opened exactly once, even under concurrent requests.
3. Content disappears at the latest at its expiry, including file attachments. One exception:
   after the final view, that viewer can still download the attached file for up to 15
   minutes, even if expiry falls within that window.
4. Holding part of a link (or an identifier seen in a log) is useless. Ids are bound to a
   capability (the id is a hash of the record's first token hash, checked on creation), so an
   id alone can't even reveal whether it is in use.
5. A link can never point to different content later: ids are never reused.
6. No third-party code ever runs on a page that handles secrets.

## Building blocks

All cryptography runs in the browser through the native **Web Crypto API**. There are no
crypto libraries and no runtime npm dependencies, in the client or in the Worker.

| Purpose | Primitive |
| --- | --- |
| Content encryption | AES-256-GCM, random 96-bit IV per message, 128-bit tag |
| Key derivation | HKDF-SHA256 with a fixed protocol salt and domain-separated `info` labels |
| Passphrase stretching | PBKDF2-HMAC-SHA256, 600,000 iterations, 128-bit random salt, NFC-normalized input |
| Request encryption | ECDH P-256 (ephemeral sender key) + HKDF |
| Capability tokens | 256-bit HKDF outputs or random values; the server stores only SHA-256 hashes |
| Length hiding | Padmé padding (≤12% overhead); text frames and files are at least 1 KiB |

Every ciphertext is bound by AES-GCM additional data to its purpose and record id
(`osss/v1/secret/text/<id>`, `osss/v1/secret/file/<id>`, `osss/v1/request/...`), so ciphertexts
cannot be swapped between records or between the text and file slots.

## Sharing a secret

```
S  = 32 random bytes                       (only ever in the link: /s#S)
id        = HKDF(S, "osss/v1/secret/id")     128 bits, public record address
metaToken = HKDF(S, "osss/v1/secret/meta")   proves possession of the link
P  = PBKDF2(passphrase, salt, 600k)        only if a passphrase is set
K  = S            (no passphrase)
K  = S || P       (with passphrase)
readToken = HKDF(K, "osss/v1/secret/read")   proves link and passphrase
textKey   = HKDF(K, "osss/v1/secret/text")   AES-256-GCM
fileKey   = HKDF(K, "osss/v1/secret/file")   AES-256-GCM
manageToken = 32 random bytes              sender's receipt link: /m#id.manageToken
```

The server stores `SHA-256(metaToken)`, `SHA-256(readToken)` and `SHA-256(manageToken)`, the
ciphertext, the expiry and view limits, and the PBKDF2 salt and iteration count (needed by the reader).

- Metadata and opening both require `metaToken`, so an identifier on its own reveals nothing and
  cannot burn passphrase attempts.
- Opening requires `readToken`. With a passphrase, a wrong guess produces a different
  `readToken`. The server counts failures and **destroys the secret after 5**. Guessing is
  therefore online-only and capped. An attacker who stole the database would also need the
  256-bit link key before any offline guessing becomes possible.
- The passphrase is real encryption, not a server-side check: it is mixed into the key and never
  transmitted.
- The reader refuses PBKDF2 parameters weaker than 600,000 iterations, even if a compromised
  server sent them.

## Requesting a secret

```
requester: ECDH P-256 key pair (pub, d) and Q = 32 random bytes
client link (send to client): /r#Q.pub        inbox link (keep private): /i#Q.d
id          = HKDF(Q, "osss/v1/request/id")
submitToken = HKDF(Q, "osss/v1/request/submit")
noteKey     = HKDF(Q, "osss/v1/request/note")     encrypts the requester's note
inboxToken  = HKDF(Q || d, "osss/v1/request/inbox")  cannot be derived from the client link

sender: ephemeral key pair (e, E); Z = ECDH(e, pub)
textKey/fileKey = HKDF(Z || Q, "osss/v1/request/{text,file}/<id>/<E>")
requester: Z = ECDH(d, E), same derivation
```

- Only the holder of the inbox link (private key `d`) can decrypt a submission. Leaking the client
  link (for example, from the client's mailbox) lets someone submit, but never read.
- Mixing `Q` into the key means a future break of P-256 plus a copy of the server's data is still
  not enough without one of the links.
- A request accepts exactly one submission. Opening it is one-time.

## Server-side state (Cloudflare Durable Objects)

Each secret or request is its own SQLite-backed Durable Object. All state transitions use the
synchronous storage API with no `await` between reading and writing, which Durable Objects
guarantee to be atomic. Concretely:

- Two simultaneous "open" requests on a one-time secret: exactly one gets the ciphertext (tested
  with 8 concurrent requests).
- Wrong-passphrase counting, view counting, revocation, expiry and upload completion cannot race.
- Expiry is enforced both lazily on every access and by an exact Durable Object alarm.
- After content is destroyed, a **tombstone** (timestamps, view countries, token hashes; no
  secret content, though a request keeps the requester's own encrypted note) is kept for 30 days
  so the sender's receipt and the recipient's "already viewed" message keep working. It is then
  replaced by a permanent, content-free marker, so the id can never be created again. Without
  it, anyone holding an old link could publish new content behind that link.
- Files live in R2 under random keys. They are deleted on revocation, expiry and abandonment, and
  after the last download. A download ticket lasts 15 minutes and allows up to 3 attempts, and
  the file is deleted when it expires even if no attempt finished. Revoking stops new downloads
  at once and cuts off a download that is already streaming (it re-checks every 1 MB).
  Deletions run in batches of at most 100 keys and are retried by the alarm until they
  succeed, backing off for a minute after a failure. Each file allows at most 20 upload
  attempts, so failed uploads can't grow the deletion queue without bound.

Workers KV was deliberately not used: it is eventually consistent, so a "deleted" secret could
still be readable from another location for up to a minute.

## Web hardening

- **No third-party code**: no CDNs, fonts, analytics, cookies or tracking. Same-origin assets only.
- **CSP**: `default-src 'none'`, with script, style, image and connect sources pinned to the
  app's own files (`/assets/app.js`, `/assets/app.css`, the two SVGs, `/api/v1/`) instead of
  `'self'`, so no other same-origin path (such as Cloudflare's `/cdn-cgi/`) can run scripts on a
  page; plus `frame-ancestors 'none'; form-action 'none'; base-uri 'none'; worker-src 'none'`
  plus **Trusted Types** (`require-trusted-types-for 'script'; trusted-types 'none'`). The client
  never builds HTML from strings, so DOM-XSS sinks are disabled outright, and service workers
  cannot be registered.
- HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  COOP/COEP/CORP, `Origin-Agent-Cluster`, a locked-down `Permissions-Policy`, `noindex`.
- HTML and API responses are `no-store`. Scripts and styles always revalidate, so fixes take effect at once.
- The API refuses cross-site requests (`Sec-Fetch-Site` / `Origin`), requires
  `application/json`, caps bodies at 256 KiB (files stream with an exact declared length),
  accepts only exact-shape objects, and checks that every ciphertext is canonical base64url and
  Padmé-aligned.
- Unknown ids and wrong tokens return identical `404` responses.
- Pages strip the key from the address bar on load, use `referrer: no-referrer`, wipe decrypted
  text from the page when it is left, never linkify content, sanitize downloaded file names
  (including Unicode direction overrides used to disguise extensions), and never claim that a
  secret or request comes from KeyBurn (creation is public, so this prevents brand-backed
  phishing).
- The Worker only answers on the custom domain (`workers_dev` and preview URLs are disabled), and
  plain HTTP is redirected to HTTPS.

## Abuse controls (creation is public by design)

- Burst rate limits per client (IPv6 grouped by /64): 10 creations, 60 reads, 10 uploads per minute.
- Strict daily quotas per client, per IPv6 network (/48, shared by all its /64s, so rotating
  addresses doesn't multiply the budget) and globally (creations and bytes), enforced by a Durable Object,
  so storage costs are bounded even under attack. File bytes are charged only after the whole
  upload has arrived, so a slow or abandoned upload holds no quota, and every failed operation is
  refunded. The global budget caps cost, not availability: an attacker with very many IP
  addresses could still use it up for the rest of the day.
- Each upload attempt writes to its own storage key and the first to finish wins, so duplicate or
  retried uploads can never overwrite or delete a completed file.
- Client keys are HMAC-SHA256 of the IP with a server secret. Raw IPs are never stored or used as
  object names.
- Workers invocation logs are disabled. Only unexpected errors are logged, without tokens,
  identifiers or content.

## AI agents (osss)

`osss` (`src/cli`) lets an AI agent use a secret without the value entering the conversation, so
it never reaches the AI provider's servers or chat history.

- **Same protocol, local code.** The tool derives tokens and decrypts exactly like the browser,
  from code on the user's disk that is pinned by SHA-256 (`src/cli/release.json`). Unlike the web
  pages, a compromised server can't change the code that handles the key. It only talks to
  `keyburn.dev` and the original `secret.nafran.com` and `secrets.nafran.com` (plus a loopback test server via `OSSS_ORIGIN`),
  never follows redirects, caps and strictly validates every response. It doesn't use Node's
  `fetch()`: its own transport asks for uncompressed data, refuses compressed responses without
  decompressing them (so server bytes never reach zlib's decoders, as in CVE-2026-111497) and
  opens a new connection per request (no keep-alive reuse, as in CVE-2026-105481).
- **Handles, not values.** An opened secret is encrypted with a fresh AES-256-GCM key and written
  to `~/.osss/vault/<id>.<expiry>.bin` (directories 0700, files 0600, exclusive create, never
  following links; the AAD binds the id and expiry). The key exists only in the handle
  `osss_<id>_<key>` given to the agent, so neither the file nor the handle is useful alone. Local
  copies expire after 24 hours by default (at most 7 days).
- **MCP tools return no secrets.** `open_secret` returns the handle, variable names, view count
  and a run command; errors are fixed strings. The server's instructions tell agents never to
  print values, to treat secret contents as data, never to open links in browsers or web-fetch
  tools, and never to ask for passphrases.
- **Use without seeing.** `osss run <handle> -- <command>` runs one command (no shell) with the
  secret as environment variables (`KEY=value` lines, or `OSSS_SECRET`) and an attachment as a
  file in a private directory that is removed when the command exits (and swept if a run is
  killed). Variable names that could make programs load code, run commands, read other files,
  trust other certificates or send requests elsewhere (for example `PATH`, `NODE_OPTIONS`,
  `LD_PRELOAD`, `*_PROXY`, `*_BASE_URL`, `AWS_ENDPOINT_URL`, cloud metadata settings) are never
  exported. Output is redacted of values 4 characters or longer, including common encodings.
- **People only.** Passphrases are read from `/dev/tty` without echo, never from arguments, the
  environment or the agent. `osss reveal` refuses to print unless both ends are a terminal.

- **Links kept out of chats.** As a Claude Code `UserPromptSubmit` hook, `osss hook claude-code`
  finds secret, receipt, request and inbox links in a prompt before it is sent, opens secret links
  locally, and blocks the prompt (Claude Code then never sends it to the model), handing the user
  the message back with handles in place of the links.

Limits: an agent that can run commands as the user can still misuse a secret it is allowed to
use (for example by running a command that prints, encodes or sends it), and it can read the
local copy and use its handle the way `osss` does; redaction is a safety net, not a sandbox.
Without the hook, a link pasted into a chat reaches the AI provider with the message, so one-view
links (the default) or opening the link yourself (`osss open`, then giving the agent only the
handle) are recommended. Claude Code may still keep a blocked prompt in its local history files.
Trust in the tool comes from its SHA-256 fingerprint, which a compromised server could change on
the download page together with the file: confirm it through a second channel. A compromised
server could also refuse service or lie about view counts, but it can't learn keys or plaintext
from the tool. Opens are not yet retry-safe: if a response is lost after the server used up a
view, that view is gone.

## What the server knows

Ciphertext and its padded size, creation/expiry/view timestamps, the country each view came from
(shown on the sender's receipt), whether a passphrase or file was used, PBKDF2 salt and iteration
count, and SHA-256 hashes of capability tokens. It never sees plaintext, link keys, passphrases,
file names or private keys.

## Limitations (true for any web-based end-to-end encryption)

- The browser runs the code the server sends. A malicious operator, or an attacker in control
  of the Cloudflare account, could serve modified JavaScript. Protect the Cloudflare account with
  hardware-key 2FA and restrict who can deploy.
- A compromised device or a malicious browser extension can read anything shown on screen.
- Browsers may record the full link (including the `#` part) in local history before the page
  removes it. One-time secrets are useless after viewing, but links should still be treated as
  sensitive until used.
- Anyone who obtains the complete link (and passphrase, if any) before the recipient can open
  it. The sender's receipt shows when and from which country it was opened.
- Durable Object storage keeps point-in-time recovery data for up to 30 days. It holds only
  ciphertext, which is unreadable without the link.
