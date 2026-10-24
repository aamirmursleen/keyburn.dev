# KeyBurn auth.md

## For agents in one paragraph

There is nothing to register and no credential to obtain: no accounts, API keys, OAuth or client registration. Every operation is authorized by a capability that the client derives from a link. The part of a link after `#` must never be sent to any server, including this one, so use the local `osss` tool (https://keyburn.dev/agents), which does the derivation and decryption on the user's computer.

## Audience

AI agents and scripts that open, create, check or revoke KeyBurn secret links on behalf of a person.

## Registration and provisioning

None. There is no registration endpoint, and no identity, email or claim flow. Usage is limited per client IP instead (see Limits).

## Supported methods

Capability links (protocol `osss/v1`):

| Link | Path | Grants |
| --- | --- | --- |
| Secret | `/s#<key>` | read the secret, once per allowed view |
| Receipt | `/m#<id>.<token>` | see when it was opened; destroy it |
| Request | `/r#<key>.<public key>` | answer a request once |
| Inbox | `/i#<key>.<private key>` | read the answer to your request |

## Credential use

- The client derives single-purpose tokens from the link with HKDF-SHA-256 and sends only those, in JSON request bodies over HTTPS. The server stores only SHA-256 hashes of them and never receives keys or plaintext.
- Never put a link in a URL query, a header, a log, a web-fetch tool, another MCP server or a chat with anyone who shouldn't read it.
- Passphrases are typed only by a person at their own terminal or browser; agents must never ask for them.

## Revocation

The sender destroys a secret with its receipt link (`osss revoke <receipt>` or the receipt page). Secrets are also deleted after their last view and at expiry; a request's inbox link can destroy the request.

## Limits

Per client IP and Cloudflare location: 10 creations, 60 reads and 10 file uploads per minute, plus daily quotas. Exceeding them returns HTTP 429 with `{"success": false, "error": "rate_limited"}` or `"quota_exceeded"`.
