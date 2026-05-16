import type { Ctx } from "../http.js";
import { sendJson, sendStatus } from "../http.js";
import type { Db, FileRow } from "../db.js";
import type { Storage } from "../storage.js";
import type { ClaimStore } from "../claims.js";
import { b64url, nowSec } from "../auth.js";

const ID_PATTERN = /^[A-Za-z0-9_-]+$/;

export function makeDownloadHandlers(db: Db, storage: Storage, claims: ClaimStore) {
  function getFinalized(ctx: Ctx): FileRow | null {
    const fileId = ctx.params["id"];
    if (!fileId || !ID_PATTERN.test(fileId)) {
      sendStatus(ctx.res, 400, "invalid id");
      return null;
    }
    const file = db.getFile.get(fileId) as FileRow | undefined;
    if (!file || !file.finalized) {
      sendStatus(ctx.res, 404);
      return null;
    }
    if (file.expires_at < nowSec()) {
      sendStatus(ctx.res, 410, "expired");
      return null;
    }
    if (file.download_count >= file.max_downloads && !claims.hasActiveForFile(file.id)) {
      sendStatus(ctx.res, 410, "exhausted");
      return null;
    }
    return file;
  }

  return {
    async meta(ctx: Ctx): Promise<void> {
      const file = getFinalized(ctx);
      if (!file) return;
      sendJson(ctx.res, 200, {
        id: file.id,
        encrypted_metadata: b64url(file.encrypted_metadata),
        metadata_nonce: b64url(file.metadata_nonce),
        base_nonce: b64url(file.base_nonce),
        chunk_count: file.chunk_count,
        total_ciphertext_bytes: file.total_ciphertext_bytes,
        has_password: file.has_password === 1,
        max_downloads: file.max_downloads,
        downloads_remaining: Math.max(0, file.max_downloads - file.download_count),
        expires_at: file.expires_at,
      });
    },

    async claim(ctx: Ctx): Promise<void> {
      const fileId = ctx.params["id"];
      if (!fileId || !ID_PATTERN.test(fileId)) {
        sendStatus(ctx.res, 400, "invalid id");
        return;
      }
      const t = nowSec();
      const result = db.tryClaimFile.run(t, fileId, t);
      if (result.changes === 0) {
        sendStatus(ctx.res, 410, "expired or exhausted");
        return;
      }
      const { token, expiresAt } = claims.create(fileId);
      sendJson(ctx.res, 200, { claim_token: token, expires_at: expiresAt });
    },

    async chunk(ctx: Ctx): Promise<void> {
      const fileId = ctx.params["id"];
      const idxStr = ctx.params["idx"];
      const claimToken = ctx.query.get("c");
      if (!fileId || !ID_PATTERN.test(fileId) || !idxStr) {
        sendStatus(ctx.res, 400, "invalid path");
        return;
      }
      if (!claims.verify(claimToken, fileId)) {
        sendStatus(ctx.res, 401, "invalid or expired claim");
        return;
      }
      const idx = Number.parseInt(idxStr, 10);
      if (!Number.isInteger(idx) || idx < 0) {
        sendStatus(ctx.res, 400, "invalid chunk index");
        return;
      }
      const file = db.getFile.get(fileId) as FileRow | undefined;
      if (!file || !file.finalized) {
        sendStatus(ctx.res, 404);
        return;
      }
      if (idx >= file.chunk_count) {
        sendStatus(ctx.res, 404, "no such chunk");
        return;
      }
      ctx.res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      const stream = storage.chunkStream(fileId, idx);
      stream.on("error", () => {
        if (!ctx.res.headersSent) sendStatus(ctx.res, 500, "read error");
        else ctx.res.destroy();
      });
      stream.pipe(ctx.res);
    },
  };
}
