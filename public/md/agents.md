# For AI agents · One Smart Sheep Secret

## Let your AI agent use a secret without seeing it

`osss` is a small command-line tool and MCP server for Claude Code, Codex and other agents. It opens secret links on your own computer, keeps them encrypted there and gives the agent a handle instead of the value. The agent passes the secret straight to the program that needs it, so it never appears in the conversation.

1. **Paste a link.** Give your agent a secret link and say what it's for. With the MCP server installed, it calls `open_secret`.
2. **Opened on your computer.** osss decrypts the secret locally with the same protocol as the browser. The key in the link is never sent to the server.
3. **A handle, not the value.** The secret is stored encrypted in `~/.osss`. The agent gets a handle such as `osss_…`, which only works on this computer.
4. **Used, then forgotten.** The agent runs `osss run <handle> -- <command>`: the command gets the secret in its environment and its output is redacted. Local copies expire after 24 hours.

## Install

Needs Node.js 22 or newer. Download the release, check its fingerprint, and only then put it in place:

```sh
(umask 077 && mkdir -p ~/.osss && cd ~/.osss && rm -f osss.download \
  && curl -fsSL -o osss.download https://secret.nafran.com/cli/osss-1.0.0.mjs \
  && echo "e4eba54de32d6b275ea96919b389a58cca8fc4431112ee84b2ad5ca8fdeb7d27  osss.download" | shasum -a 256 -c \
  && mv osss.download osss.mjs)
```

On Linux, use `sha256sum -c` instead of `shasum -a 256 -c`. Use the file only if the check prints OK. The fingerprint is what you are trusting: if you can, compare it with one you got another way (for example from the person who set this up), not only with this page.

## Connect your agent

- Claude Code: `claude mcp add --scope user osss -- node ~/.osss/osss.mjs mcp`
- Codex: `codex mcp add osss -- node ~/.osss/osss.mjs mcp`
- Other MCP clients: run `node /full/path/to/.osss/osss.mjs mcp` as a stdio server. Agents without MCP can use the same commands in a shell.

## Use it

Paste a link and say what it's for, for example "Deploy with the token in this link: https://secret.nafran.com/s#…". The agent opens it once and then runs, for example:

```sh
osss run osss_AbC…_xYz… -- npx wrangler deploy
```

A secret written as `KEY=value` lines becomes those environment variables; anything else becomes `OSSS_SECRET`, and an attached file is passed as a path in `OSSS_SECRET_FILE`. Names that change how programs run, such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD`, proxy and certificate settings, are never exported.

## Keep links out of the chat

A link you paste into a chat is sent to your AI provider with the message. In Claude Code, this hook in `~/.claude/settings.json` stops that: when a message contains a secret link, osss opens the link on your computer and holds the message back, then gives you the same message with a handle in place of the link (also on your clipboard) to send instead. Other messages are untouched.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "node \"$HOME/.osss/osss.mjs\" hook claude-code", "timeout": 300, "onFailure": "block" }] }
    ]
  }
}
```

`onFailure` (Claude Code 2.1.295 or newer) also holds the message back if the hook can't run at all.

With any agent, you can also open the link yourself in a terminal. osss asks for it without showing it, and for the passphrase the same way if there is one:

```sh
node ~/.osss/osss.mjs open
```

Give your agent only the handle it prints. Secrets with a passphrase always work this way: agents never see or ask for passphrases.

## What it protects, and what it can't

- **Kept out of the conversation.** Tool results contain a handle and variable names, never values, so the secret isn't sent to your AI provider or kept in chat history.
- **Never stored in plain text.** Each local copy is encrypted with its own key, and that key exists only inside the handle. An attached file is written to a private temporary folder only while a command runs.
- **Talks to two servers only.** osss only connects to secret.nafran.com and secrets.nafran.com, never follows redirects and checks every response. Its code runs from your disk, so a compromised server can't change it.
- **Not a sandbox.** An agent that runs commands as you could still misuse a secret it's allowed to use, for example by running a command that prints it. osss tells agents never to do this and redacts exact matches from output, but only give secrets to agents you trust with that access.
- **Links in chats.** Without the hook, a pasted link is part of that conversation, so keep secrets to one view (the default): the link is useless once your agent has opened it. A handle in a chat is useless without the encrypted copy on your computer.

## Commands

```text
osss open [link|-]               open a link, print a handle (never the value)
osss run <handle> -- <command>   run a command with the secret in its environment
osss list                        list local copies (ids and expiry only)
osss forget <handle> | --all     delete local copies
osss reveal <handle>             show the value (interactive terminal only)
osss send                        create a link from standard input or --file
osss status | revoke <receipt>   check or destroy a secret you sent
osss mcp                         run the MCP server
osss hook claude-code            keep pasted links out of Claude Code chats
```

In these examples `osss` means `node ~/.osss/osss.mjs`.
