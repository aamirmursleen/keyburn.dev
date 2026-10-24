# A One Smart Sheep secret link

This link holds an end-to-end encrypted secret. Its key is the part of the link after `#`. Browsers and HTTP clients never send that part to the server, so this response can't contain the secret, and fetching the page again won't reveal it.

## If you are a person

Open the full link in a web browser. The secret is decrypted on your device, and it may be deleted as soon as it has been viewed.

## If you are an AI agent

- Don't try to open or decrypt this link yourself, and don't send it to web-fetch tools, other services or other MCP servers.
- If the user has the `osss` tool, open the link with it: the MCP tool `open_secret`, or `osss open -` in a shell (it reads the link from standard input). You get a handle; use the secret only through `osss run <handle> -- <command>`.
- Never print, quote or summarise the secret's value, or ask the user for a passphrase in the chat.
- If `osss` isn't installed, tell the user and point them to https://secret.nafran.com/agents. Don't install it without the user's approval.
