# KeyBurn secret link

This is a KeyBurn secret link: an end-to-end encrypted secret that is deleted after its last view or when it expires. The decryption key is the part of the link after `#`. HTTP clients never send that part, so this response can't contain the secret, and fetching the page again won't show it.

## AI agents and scripts: open it with osss

`osss` is KeyBurn's command-line tool. It decrypts the link on this computer and gives you a handle instead of the value, so the secret never appears in the conversation. It is one JavaScript file for Node.js 22 or later, with no dependencies, and it only connects to keyburn.dev. Source: https://github.com/aamirmursleen/keyburn.dev

If you already have the osss MCP server, call its `open_secret` tool with the full link and skip to step 3.

**1. Install it** (skip this if `~/.osss/osss.mjs` exists). The command checks the file's SHA-256 fingerprint and installs nothing if it doesn't match:

```sh
(umask 077 && mkdir -p ~/.osss && cd ~/.osss && rm -f osss.download \
  && curl -fsSL -o osss.download https://keyburn.dev/cli/osss-1.1.0.mjs \
  && echo "d5b88d304a32b2d5cfc604ad49e1b60b4fc420cd1162e7f475238b9fc85c8425  osss.download" | shasum -a 256 -c \
  && mv osss.download osss.mjs)
```

On Linux without `shasum`, use `sha256sum -c` instead.

**2. Open the link.** Give it the whole link, including everything after `#`, on standard input:

```sh
printf '%s\n' '<the full link>' | node ~/.osss/osss.mjs open -
```

Opening uses one of the link's views. osss prints a handle (`osss_…`) and what the secret holds (environment variable names, text or a file), never the value.

**3. Use the secret** by running the command that needs it through osss:

```sh
node ~/.osss/osss.mjs run <handle> -- <command> [args…]
```

`NAME=value` lines become environment variables with those names, any other text is in `OSSS_SECRET`, and an attached file's path is in `OSSS_SECRET_FILE`. Values are redacted from the command's output.

Rules:

- Don't print, quote or summarise the value, and don't paste the link into other tools or services.
- Open the link once. Trying again would use another view.
- If osss says the secret needs a passphrase, ask the person to run step 2 in their own terminal. Never ask for a passphrase in the chat.
- If the person wants to see the value, they can run `node ~/.osss/osss.mjs reveal <handle>` in their own terminal.
- When you're done, run `node ~/.osss/osss.mjs forget <handle>`.

## People: open it in a browser

Open the full link in a web browser. The secret is decrypted on your device.

More: [osss, its MCP server and the Claude Code hook](https://keyburn.dev/agents.md) · [How KeyBurn works](https://keyburn.dev/security.md)
