# How your secrets stay secret · One Smart Sheep Secret

We built this so that nobody, including us and our hosting provider, can read what you share.

## Encrypted before it leaves your device

Your browser encrypts everything with AES-256-GCM using its built-in Web Crypto engine. Only scrambled data ever reaches our servers.

## The key never reaches us

The decryption key lives in the part of the link after the `#`, which browsers never send to a server. The page also removes it from the address bar as soon as it opens.

## Passphrases are a real second lock

A passphrase is mixed into the encryption key (PBKDF2-SHA256, 600,000 rounds) and is never sent to us. After 5 wrong attempts the secret is destroyed.

## Truly one-time

Each secret lives in its own strongly consistent Cloudflare Durable Object, so even if two people click at the same instant, only one of them can open a one-time secret.

## Gone for good

Secrets are deleted the moment their last view is used, and exact timers delete them at expiry. Files are erased from storage too. Afterwards only a receipt remains for 30 days (times and countries, no content).

## Requests only you can open

Request links use public-key encryption (ECDH P-256). Your client encrypts with a key from the link, and only your private inbox link can decrypt it.

## No tracking, no third parties

No accounts, cookies, analytics or third-party scripts. Pages run under a strict Content Security Policy with Trusted Types, so injected code can't run.

## Even sizes are hidden

Everything is padded before encryption, to at least 1 KB, so the stored size shows only a rough size range, never the exact length of your secret or file.

## What we store, and for how long

Encrypted data, its padded size, timestamps, the country a secret was opened from (for your receipt) and one-way hashes of access tokens. Content is deleted on view or expiry; receipts after 30 days. Like any cloud service, Cloudflare may keep encrypted backups for up to 30 days, and without your link those are unreadable.

## What no website can protect against

A compromised device or a malicious browser extension can read anything you see. Sending the link and the passphrase in the same message weakens the second lock. Anyone who gets the full link before your recipient can open it, which your receipt will show. The pages' code comes from this server each time, so if the server were taken over it could serve changed code to browsers; the `osss` tool for agents runs from your own disk instead (https://secret.nafran.com/agents).

## Good habits

Use a passphrase for anything important, and send it a different way. Keep expiry short and views at one. Check the receipt and destroy anything you no longer need.
