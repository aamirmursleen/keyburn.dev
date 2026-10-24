# KeyBurn receipt link

This is a KeyBurn receipt link. It belongs to the person who created a secret: it shows whether the secret has been opened, when and from which country, and it can destroy the secret early. Its key is the part of the link after `#`. HTTP clients never send that part, so this response can't show the receipt.

## AI agents and scripts

Use osss, KeyBurn's command-line tool (install it as described at https://keyburn.dev/agents.md). Give it the whole link, including everything after `#`, on standard input:

```sh
printf '%s\n' '<the full receipt link>' | node ~/.osss/osss.mjs status -
```

`status` prints the state, the views left, the expiry and each view. `revoke` instead of `status` destroys the secret now; only do that when the person asks.

Treat the receipt link like a password: don't paste it into other tools or services.

## People

Open the full link in a web browser.
