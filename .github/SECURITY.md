# Security policy

KeyBurn is built so that the server never sees secrets, keys or passphrases. The design and its
limits are described in [docs/SECURITY.md](../docs/SECURITY.md).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/aamirmursleen/keyburn.dev/security/advisories/new)**
(Security tab → "Report a vulnerability"). Don't open a public issue, and don't test against the
live service in ways that affect other people's secrets; a local copy (`npm run dev`) reproduces
everything.

Helpful reports include the affected component (browser app, Worker, Durable Objects, or the
`osss` CLI/MCP server), steps to reproduce, and the impact you expect.

## Scope

In scope: anything that could reveal plaintext, keys, passphrases or link tokens to the server or
anyone else; break one-time or expiry guarantees; bypass rate limits or quotas; inject script into
the pages; or make the `osss` tool expose secrets to an agent's conversation, logs or disk.

Known limits that are documented rather than bugs: a compromised device or browser extension, a
link shared before the intended recipient opens it, and an agent that deliberately misuses a
secret it was allowed to use.
