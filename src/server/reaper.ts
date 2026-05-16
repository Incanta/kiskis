import type { Db } from "./db.js";
import type { Storage } from "./storage.js";
import type { ClaimStore } from "./claims.js";
import { nowSec } from "./auth.js";

const REAPER_INTERVAL_MS = 60_000;

async function sweepOnce(db: Db, storage: Storage, claims: ClaimStore): Promise<void> {
  const t = nowSec();

  db.deleteExpiredSessions.run(t);
  db.deleteExpiredAuthTokens.run(t, t);

  const expired = db.listExpiredFiles.all(t, t) as Array<{ id: string }>;
  for (const { id } of expired) {
    if (claims.hasActiveForFile(id)) continue;
    try {
      await storage.deleteFile(id);
    } catch (err) {
      console.error(`[reaper] failed to delete blobs for ${id}:`, err);
      continue;
    }
    db.deleteFile.run(id);
  }

  const orphans = db.listOrphanedUploads.all(t) as Array<{ id: string }>;
  for (const { id } of orphans) {
    try {
      await storage.deleteFile(id);
    } catch (err) {
      console.error(`[reaper] failed to delete orphan blobs for ${id}:`, err);
      continue;
    }
    db.deleteFile.run(id);
  }

  claims.sweep();
}

export function startReaper(db: Db, storage: Storage, claims: ClaimStore): () => void {
  let stopped = false;
  let running = false;

  const tick = async (): Promise<void> => {
    if (stopped || running) return;
    running = true;
    try {
      await sweepOnce(db, storage, claims);
    } catch (err) {
      console.error("[reaper] sweep failed:", err);
    } finally {
      running = false;
    }
  };

  void tick();
  const handle = setInterval(() => void tick(), REAPER_INTERVAL_MS);

  return (): void => {
    stopped = true;
    clearInterval(handle);
  };
}
