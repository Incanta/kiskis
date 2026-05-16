import { DatabaseSync } from "node:sqlite";
import type { StatementSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const MIGRATIONS: string[] = [
  // v1
  `
  CREATE TABLE admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL
  );

  CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE auth_tokens (
    id TEXT PRIMARY KEY,
    label TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
  );

  CREATE TABLE files (
    id TEXT PRIMARY KEY,
    encrypted_metadata BLOB NOT NULL,
    metadata_nonce BLOB NOT NULL,
    base_nonce BLOB NOT NULL,
    chunk_count INTEGER NOT NULL,
    total_ciphertext_bytes INTEGER NOT NULL,
    has_password INTEGER NOT NULL,
    max_downloads INTEGER NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_claim_at INTEGER,
    uploaded_by_token TEXT,
    finalized INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX files_expires ON files(expires_at);
  CREATE INDEX files_finalized ON files(finalized, created_at);
  `,
];

export interface FileRow {
  id: string;
  encrypted_metadata: Uint8Array;
  metadata_nonce: Uint8Array;
  base_nonce: Uint8Array;
  chunk_count: number;
  total_ciphertext_bytes: number;
  has_password: number;
  max_downloads: number;
  download_count: number;
  created_at: number;
  expires_at: number;
  last_claim_at: number | null;
  uploaded_by_token: string | null;
  finalized: number;
}

export interface AdminRow {
  password_hash: Uint8Array;
  password_salt: Uint8Array;
}

export interface SessionRow {
  id: string;
  expires_at: number;
}

export interface AuthTokenRow {
  id: string;
  label: string | null;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
}

export class Db {
  private readonly db: DatabaseSync;

  readonly insertFile: StatementSync;
  readonly getFile: StatementSync;
  readonly setFileFinalized: StatementSync;
  readonly tryClaimFile: StatementSync;
  readonly deleteFile: StatementSync;
  readonly listExpiredFiles: StatementSync;
  readonly listOrphanedUploads: StatementSync;

  readonly insertSession: StatementSync;
  readonly getSession: StatementSync;
  readonly deleteSession: StatementSync;
  readonly deleteExpiredSessions: StatementSync;

  readonly upsertAdmin: StatementSync;
  readonly getAdmin: StatementSync;

  readonly insertAuthToken: StatementSync;
  readonly getAuthToken: StatementSync;
  readonly listAuthTokens: StatementSync;
  readonly revokeAuthToken: StatementSync;
  readonly deleteExpiredAuthTokens: StatementSync;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec("PRAGMA synchronous = NORMAL");
    this.migrate();

    this.insertFile = this.db.prepare(`
      INSERT INTO files (
        id, encrypted_metadata, metadata_nonce, base_nonce, chunk_count,
        total_ciphertext_bytes, has_password, max_downloads, download_count,
        created_at, expires_at, uploaded_by_token, finalized
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0)
    `);

    this.getFile = this.db.prepare(`SELECT * FROM files WHERE id = ?`);

    this.setFileFinalized = this.db.prepare(`
      UPDATE files SET finalized = 1 WHERE id = ? AND finalized = 0
    `);

    this.tryClaimFile = this.db.prepare(`
      UPDATE files
      SET download_count = download_count + 1,
          last_claim_at  = ?
      WHERE id = ?
        AND finalized = 1
        AND expires_at > ?
        AND download_count < max_downloads
    `);

    this.deleteFile = this.db.prepare(`DELETE FROM files WHERE id = ?`);

    this.listExpiredFiles = this.db.prepare(`
      SELECT id FROM files
      WHERE expires_at < ?
         OR (download_count >= max_downloads
             AND (last_claim_at IS NULL OR last_claim_at + 600 < ?))
    `);

    this.listOrphanedUploads = this.db.prepare(`
      SELECT id FROM files WHERE finalized = 0 AND created_at + 3600 < ?
    `);

    this.insertSession = this.db.prepare(`
      INSERT INTO sessions (id, expires_at) VALUES (?, ?)
    `);
    this.getSession = this.db.prepare(`SELECT * FROM sessions WHERE id = ?`);
    this.deleteSession = this.db.prepare(`DELETE FROM sessions WHERE id = ?`);
    this.deleteExpiredSessions = this.db.prepare(`DELETE FROM sessions WHERE expires_at < ?`);

    this.upsertAdmin = this.db.prepare(`
      INSERT INTO admin (id, password_hash, password_salt) VALUES (1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
                                     password_salt = excluded.password_salt
    `);
    this.getAdmin = this.db.prepare(`SELECT password_hash, password_salt FROM admin WHERE id = 1`);

    this.insertAuthToken = this.db.prepare(`
      INSERT INTO auth_tokens (id, label, created_at, expires_at) VALUES (?, ?, ?, ?)
    `);
    this.getAuthToken = this.db.prepare(`SELECT * FROM auth_tokens WHERE id = ?`);
    this.listAuthTokens = this.db.prepare(`
      SELECT id, label, created_at, expires_at, revoked_at FROM auth_tokens
      ORDER BY created_at DESC
    `);
    this.revokeAuthToken = this.db.prepare(`
      UPDATE auth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
    `);
    this.deleteExpiredAuthTokens = this.db.prepare(`
      DELETE FROM auth_tokens WHERE expires_at < ? AND (revoked_at IS NOT NULL OR expires_at < ?)
    `);
  }

  private migrate(): void {
    const row = this.db.prepare(`PRAGMA user_version`).get() as { user_version: number } | undefined;
    const current = row?.user_version ?? 0;
    for (let v = current; v < MIGRATIONS.length; v++) {
      const sql = MIGRATIONS[v];
      if (!sql) continue;
      this.db.exec("BEGIN");
      try {
        this.db.exec(sql);
        this.db.exec(`PRAGMA user_version = ${v + 1}`);
        this.db.exec("COMMIT");
      } catch (err) {
        this.db.exec("ROLLBACK");
        throw err;
      }
    }
  }

  transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  close(): void {
    this.db.close();
  }
}
