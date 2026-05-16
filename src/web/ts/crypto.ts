// All client-side cryptography. Uses only Web Crypto (crypto.subtle).
//
// File key K: 32 random bytes, never sent to the server.
// Per-chunk nonce: base_nonce[0..8] || u32be(chunk_index)  (12 bytes total)
// AAD per chunk:  u32be(chunk_index) || u8(is_last)
// Plaintext chunk size: 1 MiB. Last chunk may be smaller.
//
// Share fragment encoding (text after the `#`):
//   k1.<b64u(K)>                                   (no password)
//   p1.<b64u(salt)>.<b64u(wrapNonce)>.<b64u(wrapped)>  (password-protected)

// We narrow Uint8Array to Uint8Array<ArrayBuffer> because Web Crypto's BufferSource
// requires that concrete buffer type since TypeScript 5.7.
type Bytes = Uint8Array<ArrayBuffer>;

export const PLAINTEXT_CHUNK_SIZE = 1024 * 1024;
export const GCM_TAG_BYTES = 16;
export const CIPHERTEXT_CHUNK_SIZE = PLAINTEXT_CHUNK_SIZE + GCM_TAG_BYTES;
export const MAX_CHUNK_COUNT = 2048;
const PBKDF2_ITERATIONS = 600_000;

function alloc(n: number): Bytes {
  return new Uint8Array(new ArrayBuffer(n));
}

export function b64uEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Bytes {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b = atob(s.replaceAll("-", "+").replaceAll("_", "/") + pad);
  const out = alloc(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

export function randomBytes(n: number): Bytes {
  const buf = alloc(n);
  crypto.getRandomValues(buf);
  return buf;
}

export async function importFileKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("file key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function generateFileKey(): Promise<{ raw: Bytes; key: CryptoKey }> {
  const raw = randomBytes(32);
  const key = await importFileKey(raw);
  return { raw, key };
}

function chunkNonce(baseNonce: Bytes, idx: number): Bytes {
  if (baseNonce.length !== 8) throw new Error("base nonce must be 8 bytes");
  const out = alloc(12);
  out.set(baseNonce, 0);
  new DataView(out.buffer).setUint32(8, idx, false);
  return out;
}

function chunkAad(idx: number, isLast: boolean): Bytes {
  const out = alloc(5);
  new DataView(out.buffer).setUint32(0, idx, false);
  out[4] = isLast ? 1 : 0;
  return out;
}

export async function encryptChunk(
  key: CryptoKey,
  baseNonce: Bytes,
  idx: number,
  plaintext: Bytes,
  isLast: boolean,
): Promise<Bytes> {
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: chunkNonce(baseNonce, idx), additionalData: chunkAad(idx, isLast), tagLength: GCM_TAG_BYTES * 8 },
    key,
    plaintext,
  );
  return new Uint8Array(cipher);
}

export async function decryptChunk(
  key: CryptoKey,
  baseNonce: Bytes,
  idx: number,
  ciphertext: Bytes,
  isLast: boolean,
): Promise<Bytes> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: chunkNonce(baseNonce, idx), additionalData: chunkAad(idx, isLast), tagLength: GCM_TAG_BYTES * 8 },
    key,
    ciphertext,
  );
  return new Uint8Array(plain);
}

export interface MetadataPayload {
  filename: string;
  mime: string;
  size: number;
}

export async function encryptMetadata(
  key: CryptoKey,
  payload: MetadataPayload,
): Promise<{ ciphertext: Bytes; nonce: Bytes }> {
  const nonce = randomBytes(12);
  const plaintextSrc = new TextEncoder().encode(JSON.stringify(payload));
  const plaintext = alloc(plaintextSrc.length);
  plaintext.set(plaintextSrc);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: GCM_TAG_BYTES * 8 },
    key,
    plaintext,
  );
  return { ciphertext: new Uint8Array(ct), nonce };
}

export async function decryptMetadata(
  key: CryptoKey,
  ciphertext: Bytes,
  nonce: Bytes,
): Promise<MetadataPayload> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: GCM_TAG_BYTES * 8 },
    key,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plain)) as MetadataPayload;
}

// ---------- password key wrapping ----------

async function deriveKek(password: string, salt: Bytes): Promise<CryptoKey> {
  const pwSrc = new TextEncoder().encode(password);
  const pw = alloc(pwSrc.length);
  pw.set(pwSrc);
  const base = await crypto.subtle.importKey(
    "raw",
    pw,
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export interface WrapResult {
  salt: Bytes;
  wrapNonce: Bytes;
  wrapped: Bytes;
}

export async function wrapFileKey(rawKey: Bytes, password: string): Promise<WrapResult> {
  const salt = randomBytes(16);
  const wrapNonce = randomBytes(12);
  const kek = await deriveKek(password, salt);
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: wrapNonce, tagLength: GCM_TAG_BYTES * 8 },
    kek,
    rawKey,
  );
  return { salt, wrapNonce, wrapped: new Uint8Array(wrapped) };
}

export async function unwrapFileKey(
  password: string,
  salt: Bytes,
  wrapNonce: Bytes,
  wrapped: Bytes,
): Promise<Bytes> {
  const kek = await deriveKek(password, salt);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: wrapNonce, tagLength: GCM_TAG_BYTES * 8 },
    kek,
    wrapped,
  );
  return new Uint8Array(raw);
}

// ---------- fragment codec ----------

export type Fragment =
  | { kind: "plain"; rawKey: Bytes }
  | { kind: "password"; salt: Bytes; wrapNonce: Bytes; wrapped: Bytes };

export function encodeFragment(f: Fragment): string {
  if (f.kind === "plain") {
    return `k1.${b64uEncode(f.rawKey)}`;
  }
  return `p1.${b64uEncode(f.salt)}.${b64uEncode(f.wrapNonce)}.${b64uEncode(f.wrapped)}`;
}

export function decodeFragment(raw: string): Fragment {
  const trimmed = raw.startsWith("#") ? raw.slice(1) : raw;
  const parts = trimmed.split(".");
  if (parts[0] === "k1" && parts.length === 2 && parts[1]) {
    return { kind: "plain", rawKey: b64uDecode(parts[1]) };
  }
  if (parts[0] === "p1" && parts.length === 4 && parts[1] && parts[2] && parts[3]) {
    return {
      kind: "password",
      salt: b64uDecode(parts[1]),
      wrapNonce: b64uDecode(parts[2]),
      wrapped: b64uDecode(parts[3]),
    };
  }
  throw new Error("invalid share fragment");
}
