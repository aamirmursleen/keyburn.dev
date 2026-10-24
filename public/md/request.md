# Request a secret · One Smart Sheep Secret

Ask someone to send you a password, API key or file, so that only you can open it.

1. **Create a request.** Your browser makes a key pair. You get two links: a request link to send, and a private inbox link to keep.
2. **They answer once.** The person opens the request link, adds text and/or one file, and sends it. Their browser encrypts it with the public key from the link (ECDH P-256 and AES-256-GCM). A request link can be answered only once.
3. **Only you can open it.** The private key is only in your inbox link, which never reaches the server, so nobody else can decrypt the answer.

Requests expire after 1 hour to 7 days. An answer is kept for up to 7 days or until you open it. You can add a short note, which is encrypted too.

Create a request in a browser: https://secret.nafran.com/request
