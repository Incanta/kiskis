import type { Ctx } from "../http.js";
import { HttpError, readJsonBody, readRawBody, sendJson, sendStatus } from "../http.js";
import type { Db, FileRow } from "../db.js";
import type { Storage } from "../storage.js";
import {
  b64urlDecode,
  nowSec,
  parseBearer,
  randomB64url,
  verifyAuthToken,
} from "../auth.js";

const MAX_DOWNLOAD_CHOICES = new Set<number>([1, 5, 10, 15, 25, 50, 100]);
const TTL_CHOICES = new Set<number>([
  60 * 60,
  60 * 60 * 5,
  60 * 60 * 24,
  60 * 60 * 24 * 7,
  60 * 60 * 24 * 30,
  60 * 60 * 24 * 365,
]);

const MAX_METADATA_BYTES = 4096;
const MAX_CHUNK_CIPHERTEXT = 1024 * 1024 + 32; // 1 MiB plaintext + 16-byte tag + slack
const MAX_CHUNK_COUNT = 2048; // matches 2 GiB cap

const ID_PATTERN = /^[A-Za-z0-9_-]+$/;
const FILE_ID_BYTES = 16;

interface InitBody {
  encrypted_metadata: unknown;
  metadata_nonce: unknown;
  base_nonce: unknown;
  chunk_count: unknown;
  total_ciphertext_bytes: unknown;
  has_password: unknown;
  max_downloads: unknown;
  ttl_seconds: unknown;
}

function decodeB64u(value: unknown, name: string, minLen: number, maxLen: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, `${name} required`);
  }
  if (value.length > maxLen * 2) {
    throw new HttpError(400, `${name} too long`);
  }
  let decoded: Uint8Array;
  try {
    decoded = b64urlDecode(value);
  } catch {
    throw new HttpError(400, `${name} not base64url`);
  }
  if (decoded.length < minLen || decoded.length > maxLen) {
    throw new HttpError(400, `${name} wrong length`);
  }
  return decoded;
}

export function makeUploadHandlers(db: Db, storage: Storage, maxFileBytes: number) {
  function requireToken(ctx: Ctx): string {
    const token = parseBearer(ctx.req.headers["authorization"]);
    const row = verifyAuthToken(db, token);
    if (!row) throw new HttpError(401, "invalid or expired token");
    return row.id;
  }

  return {
    async verify(ctx: Ctx): Promise<void> {
      const token = parseBearer(ctx.req.headers["authorization"]);
      const row = verifyAuthToken(db, token);
      if (!row) { sendStatus(ctx.res, 401, "invalid or expired token"); return; }
      sendJson(ctx.res, 200, { ok: true, label: row.label, expires_at: row.expires_at });
    },

    async init(ctx: Ctx): Promise<void> {
      const tokenId = requireToken(ctx);
      const body = await readJsonBody<InitBody>(ctx.req);

      const encryptedMetadata = decodeB64u(body.encrypted_metadata, "encrypted_metadata", 1, MAX_METADATA_BYTES);
      const metadataNonce = decodeB64u(body.metadata_nonce, "metadata_nonce", 12, 12);
      const baseNonce = decodeB64u(body.base_nonce, "base_nonce", 8, 8);

      const chunkCount = Number(body.chunk_count);
      if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > MAX_CHUNK_COUNT) {
        sendStatus(ctx.res, 400, "chunk_count out of range");
        return;
      }

      const totalCiphertext = Number(body.total_ciphertext_bytes);
      if (!Number.isInteger(totalCiphertext) || totalCiphertext < 1 || totalCiphertext > maxFileBytes + chunkCount * 32) {
        sendStatus(ctx.res, 400, "total_ciphertext_bytes out of range");
        return;
      }

      const hasPassword = body.has_password === true ? 1 : 0;

      const maxDownloads = Number(body.max_downloads);
      if (!MAX_DOWNLOAD_CHOICES.has(maxDownloads)) {
        sendStatus(ctx.res, 400, "max_downloads must be one of 1/5/10/15/25/50/100");
        return;
      }

      const ttlSeconds = Number(body.ttl_seconds);
      if (!TTL_CHOICES.has(ttlSeconds)) {
        sendStatus(ctx.res, 400, "ttl_seconds must be 1h/5h/1d/7d/30d/365d");
        return;
      }

      const id = randomB64url(FILE_ID_BYTES);
      const now = nowSec();
      const expiresAt = now + ttlSeconds;

      db.insertFile.run(
        id,
        encryptedMetadata,
        metadataNonce,
        baseNonce,
        chunkCount,
        totalCiphertext,
        hasPassword,
        maxDownloads,
        now,
        expiresAt,
        tokenId,
      );

      await storage.ensureFileDir(id);
      sendJson(ctx.res, 201, { file_id: id, expires_at: expiresAt });
    },

    async chunk(ctx: Ctx): Promise<void> {
      const tokenId = requireToken(ctx);
      const fileId = ctx.params["id"];
      const idxStr = ctx.params["idx"];
      if (!fileId || !ID_PATTERN.test(fileId) || !idxStr) {
        sendStatus(ctx.res, 400, "invalid path");
        return;
      }
      const idx = Number.parseInt(idxStr, 10);
      if (!Number.isInteger(idx) || idx < 0 || idx >= MAX_CHUNK_COUNT) {
        sendStatus(ctx.res, 400, "invalid chunk index");
        return;
      }

      const file = db.getFile.get(fileId) as FileRow | undefined;
      if (!file) { sendStatus(ctx.res, 404); return; }
      if (file.uploaded_by_token !== tokenId) { sendStatus(ctx.res, 403, "not your file"); return; }
      if (file.finalized) { sendStatus(ctx.res, 409, "already finalized"); return; }
      if (idx >= file.chunk_count) { sendStatus(ctx.res, 400, "chunk index out of range"); return; }
      if (await storage.chunkExists(fileId, idx)) { sendStatus(ctx.res, 409, "chunk already written"); return; }

      const body = await readRawBody(ctx.req, MAX_CHUNK_CIPHERTEXT);
      if (body.length === 0) {
        sendStatus(ctx.res, 400, "empty chunk");
        return;
      }
      await storage.writeChunk(fileId, idx, new Uint8Array(body));
      ctx.res.writeHead(204);
      ctx.res.end();
    },

    async finalize(ctx: Ctx): Promise<void> {
      const tokenId = requireToken(ctx);
      const fileId = ctx.params["id"];
      if (!fileId || !ID_PATTERN.test(fileId)) {
        sendStatus(ctx.res, 400, "invalid path");
        return;
      }
      const file = db.getFile.get(fileId) as FileRow | undefined;
      if (!file) { sendStatus(ctx.res, 404); return; }
      if (file.uploaded_by_token !== tokenId) { sendStatus(ctx.res, 403, "not your file"); return; }
      if (file.finalized) {
        sendJson(ctx.res, 200, { share_path: `/d/${fileId}` });
        return;
      }
      for (let i = 0; i < file.chunk_count; i++) {
        if (!(await storage.chunkExists(fileId, i))) {
          sendStatus(ctx.res, 400, `missing chunk ${i}`);
          return;
        }
      }
      db.setFileFinalized.run(fileId);
      sendJson(ctx.res, 200, { share_path: `/d/${fileId}` });
    },
  };
}
