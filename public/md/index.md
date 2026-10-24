# One Smart Sheep Secret: share passwords that self-destruct

Share passwords, API keys and files through links that delete themselves. Everything is encrypted on your device before it is sent, and the key stays in the link, so the server only ever stores encrypted data.

- [Share a secret](https://secret.nafran.com/) (in a browser: encryption runs on your device)
- [Request a secret](https://secret.nafran.com/request) from someone else
- [How it works](https://secret.nafran.com/security) and what it protects
- [For AI agents](https://secret.nafran.com/agents): let an agent use a secret without seeing it

## How it works

1. **Encrypted in your browser.** Text up to 64 KB and/or one file up to 25 MB is encrypted with AES-256-GCM using the browser's built-in Web Crypto.
2. **You share the link.** The key is the part after `#`, which browsers never send to a server.
3. **It self-destructs.** The secret is deleted after its last view (1, 2, 3, 5 or 10 views) or when it expires (15 minutes to 7 days).

## Features

- **Passphrase:** an optional second lock (PBKDF2-SHA256, 600,000 rounds). Five wrong tries destroy the secret.
- **Receipt:** a private link shows when the secret was opened and from which country, and can destroy it early.
- **Requests:** send someone a request link; they answer once, and only you can open the answer (ECDH P-256 public-key encryption).
- **Hidden sizes:** everything is padded before encryption, so the stored size shows only a rough range.
- **No tracking:** no accounts, cookies, analytics or third-party scripts. Pages run under a strict Content Security Policy with Trusted Types.
- **On Cloudflare's network:** each secret lives in its own Durable Object, so a one-time secret can be opened only once, even by two people at the same instant.

## For AI agents

Don't open a secret link with a web-fetch tool: the page can't decrypt anything without JavaScript and the key, and fetching it never reveals the secret. Use the local `osss` tool (a CLI and MCP server) instead. It opens links on the user's computer and gives you a handle, never the value. Setup: https://secret.nafran.com/agents
