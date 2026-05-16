# kiskis

**K**eep **I**t **S**ecret, **K**eep **I**t **S**afe — a self-hostable, end-to-end encrypted file-sharing service inspired by Mozilla Send.

Files are encrypted in the browser before upload using AES-256-GCM. The server only stores ciphertext and a small amount of metadata. The decryption key lives in the URL fragment (`#...`), which browsers never send to the server.

## Properties

- **Zero runtime dependencies.** TypeScript is the only build dependency. The server uses only Node's built-ins (`node:http`, `node:sqlite`, `node:crypto`, `node:fs`). The browser uses only the Web Crypto API.
- **End-to-end encryption.** AES-256-GCM with a per-file 256-bit key. Filename and MIME type are encrypted too — the server never sees them in cleartext.
- **Chunked.** 1 MiB plaintext chunks with truncation-resistant AAD; per-chunk nonces.
- **Optional password.** Encrypts the file key with `PBKDF2-SHA256(600,000 iters)`. Without the password, the link alone is useless.
- **Per-file limits.** Choose max downloads (1–100) and TTL (1 hour to 365 days). The reaper deletes ciphertext from disk once either limit is reached.
- **Admin-gated uploads.** Bearer tokens are provisioned by an admin (with TTL and revocation). Downloads remain public-by-link.

## Requirements

- Node.js 24 or newer (uses the built-in `node:sqlite` module).

## Setup

```bash
cp .env.example .env
# edit .env, set ADMIN_PASSWORD at minimum
yarn install
yarn build
yarn start
```

Visit `http://localhost:8787/admin` to sign in and create an upload token.

## Environment

| Var | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | (required) | Bootstrap password for the admin account. Changes to this rotate the stored hash on next login. |
| `PORT` | `8787` | HTTP port. |
| `DATA_DIR` | `./data` | Where the SQLite DB and ciphertext blobs live. |
| `SECURE_COOKIES` | `false` | Set to `true` when serving over HTTPS. |
| `MAX_FILE_BYTES` | `2147483648` | Plaintext size cap. Hard-clamped at 2 GiB. |

## Security model

- The decryption key never reaches the server. It is generated in the browser, encoded into the URL fragment (`#k1.<key>` or `#p1.<salt>.<wrapNonce>.<wrappedKey>`), and browsers do not send fragments in HTTP requests.
- The server stores: ciphertext blobs, encrypted metadata, base nonces (random per-file), chunk counts, and policy flags. It does **not** store filenames, MIME types, the file key, the password, or any password-derived material.
- Downloading consumes one of the file's allowed downloads at the moment the user confirms — wrong password attempts do **not** consume downloads.
- File and chunk identifiers are random base64url strings, not enumerable.
- Admin sessions are random opaque tokens stored server-side, set as `HttpOnly; SameSite=Strict` cookies.
- Upload tokens are random 32-byte secrets shown to the admin once on creation; only an 8-character prefix is retained for display thereafter.

## Limitations

- Browser-side downloads accumulate decrypted plaintext in memory before triggering the save (no third-party stream-saver library). Files up to ~1 GiB are practical on typical desktops.
- No anti-abuse rate limiting beyond admin-token gating. Add a reverse proxy (nginx, Caddy) if exposing to the public internet.
- HTTPS is recommended — `Secure` cookies and protected fragments rely on a trustworthy transport.
