# Shiver — Global Anonymous Web Chat

Shiver is a free, public-welfare, privacy-first web application.
It enables one-to-one, fully anonymous, end-to-end encrypted chat with zero signup.

Your only credential is a secret sentence (passphrase). It is never sent to the server.
Your account is represented by a deterministic 10-character code.

## Quick Start (Local)
1. Install Node.js (v16+).
2. Run `npm install` in this directory.
3. Run `npm start`.
4. Open `http://localhost:3000` in your browser.

## Deployment to a Free/Cheap Host
The easiest way to host this for free is using platforms like **Render**, **Railway**, or **Fly.io**:
1. Create a GitHub repository and upload these files.
2. Link the repository to Render/Railway.
3. Set the start command to `npm start`.
4. Add environment variables if needed (e.g., `PORT`).
*(Note: SQLite data will reset on ephemeral filesystems like Heroku. Use a persistent disk volume on Render/Fly to preserve messages, though user identities are mathematically bound to passphrases and cannot be "lost" by the server).*

## Security Model & Honest Limitations
**How it protects you:**
- **Zero Knowledge:** The server never knows your passphrase or your private keys.
- **End-to-End Encrypted (E2EE):** The server only stores opaque, locked boxes. It cannot read your messages.
- **Anonymous Routing:** The server does not know who is talking to whom. Senders encrypt their messages anonymously to recipient mailboxes.
- **No Identity Tied:** No email, IP tracking, or phone number is required.

**Honest Limitations:**
- **No Recovery:** If you lose your sentence, your account is gone forever.
- **Client-Side Trust:** The browser runs the encryption code. If the server is compromised to serve malicious JavaScript, the encryption could be bypassed. (For maximum security, host it yourself or use an IPFS frontend).
- **Metadata:** The server knows *when* a mailbox receives a message, just not from whom or what it says.

## How to Choose a Safe Sentence
- Pick a sentence with at least 5 random words, e.g., `purple elephant dancing under frozen skies`.
- Do not use famous quotes, song lyrics, or single words.
- Memorize it or write it down on physical paper. Never share it.
