import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import type { Db, AuthTokenRow } from "./db.js";

const scrypt = promisify(scryptCb) as (
  password: string,
  salt: Uint8Array,
  keylen: number,
) => Promise<Buffer>;

const SCRYPT_KEYLEN = 32;
const SCRYPT_SALT_LEN = 16;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function randomB64url(byteLen: number): string {
  return b64url(randomBytes(byteLen));
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------- admin password ----------

export async function setAdminPassword(db: Db, password: string): Promise<void> {
  const salt = randomBytes(SCRYPT_SALT_LEN);
  const hash = await scrypt(password, salt, SCRYPT_KEYLEN);
  db.upsertAdmin.run(new Uint8Array(hash), new Uint8Array(salt));
}

export async function verifyAdminPassword(db: Db, password: string): Promise<boolean> {
  const row = db.getAdmin.get() as { password_hash: Uint8Array; password_salt: Uint8Array } | undefined;
  if (!row) return false;
  const candidate = await scrypt(password, row.password_salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(row.password_hash);
  if (candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

export async function ensureAdminSeeded(db: Db, bootstrapPassword: string): Promise<void> {
  const row = db.getAdmin.get();
  if (!row) {
    await setAdminPassword(db, bootstrapPassword);
    return;
  }
  // If bootstrap differs from stored, also rotate to the env value (admin source of truth).
  const ok = await verifyAdminPassword(db, bootstrapPassword);
  if (!ok) {
    await setAdminPassword(db, bootstrapPassword);
  }
}

// ---------- sessions ----------

export function createSession(db: Db): { id: string; expiresAt: number } {
  const id = randomB64url(32);
  const expiresAt = nowSec() + SESSION_TTL_SECONDS;
  db.insertSession.run(id, expiresAt);
  return { id, expiresAt };
}

export function validateSession(db: Db, id: string | null): boolean {
  if (!id) return false;
  const row = db.getSession.get(id) as { id: string; expires_at: number } | undefined;
  if (!row) return false;
  if (row.expires_at < nowSec()) {
    db.deleteSession.run(id);
    return false;
  }
  return true;
}

export function destroySession(db: Db, id: string): void {
  db.deleteSession.run(id);
}

// ---------- cookies ----------

export interface CookieOptions {
  secure: boolean;
  maxAgeSeconds?: number;
}

export function buildSessionCookie(id: string, opts: CookieOptions): string {
  const parts = [`kiskis_session=${id}`, "HttpOnly", "SameSite=Strict", "Path=/"];
  if (opts.secure) parts.push("Secure");
  if (opts.maxAgeSeconds !== undefined) parts.push(`Max-Age=${opts.maxAgeSeconds}`);
  return parts.join("; ");
}

export function clearSessionCookie(opts: CookieOptions): string {
  const parts = ["kiskis_session=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=0"];
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

export function parseSessionCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const name = trimmed.slice(0, eq);
    if (name !== "kiskis_session") continue;
    const value = trimmed.slice(eq + 1);
    if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
    return value;
  }
  return null;
}

// ---------- bearer auth tokens ----------

export interface CreatedAuthToken {
  id: string;
  label: string | null;
  createdAt: number;
  expiresAt: number;
}

export function createAuthToken(
  db: Db,
  label: string | null,
  ttlSeconds: number,
): CreatedAuthToken {
  const id = randomB64url(32);
  const createdAt = nowSec();
  const expiresAt = createdAt + ttlSeconds;
  db.insertAuthToken.run(id, label, createdAt, expiresAt);
  return { id, label, createdAt, expiresAt };
}

export function listAuthTokens(db: Db): AuthTokenRow[] {
  return db.listAuthTokens.all() as unknown as AuthTokenRow[];
}

export function revokeAuthTokenById(db: Db, id: string): boolean {
  const info = db.revokeAuthToken.run(nowSec(), id);
  return info.changes > 0;
}

export function verifyAuthToken(db: Db, token: string | null): AuthTokenRow | null {
  if (!token) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;
  const row = db.getAuthToken.get(token) as AuthTokenRow | undefined;
  if (!row) return null;
  if (row.revoked_at !== null) return null;
  if (row.expires_at < nowSec()) return null;
  return row;
}

export function parseBearer(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+([A-Za-z0-9_-]+)$/.exec(authHeader);
  return m && m[1] ? m[1] : null;
}
