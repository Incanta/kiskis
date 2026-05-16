import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { loadConfig } from "./config.js";
import { Db } from "./db.js";
import { Storage } from "./storage.js";
import { ClaimStore } from "./claims.js";
import { Router, HttpError, sendStatus } from "./http.js";
import type { Ctx } from "./http.js";
import { ensureAdminSeeded } from "./auth.js";
import { startReaper } from "./reaper.js";
import { makeStaticHandler } from "./handlers/static.js";
import { makeAdminHandlers } from "./handlers/admin.js";
import { makeUploadHandlers } from "./handlers/upload.js";
import { makeDownloadHandlers } from "./handlers/download.js";

async function main(): Promise<void> {
  const config = loadConfig();

  const db = new Db(config.dbPath);
  await ensureAdminSeeded(db, config.adminPassword);

  const storage = new Storage(config.blobsDir);
  await storage.init();

  const claims = new ClaimStore();
  const stopReaper = startReaper(db, storage, claims);

  const here = dirname(fileURLToPath(import.meta.url));
  const webDir = resolve(here, "..", "web");
  const serveStatic = makeStaticHandler(webDir);

  const admin = makeAdminHandlers(db, config.secureCookies);
  const upload = makeUploadHandlers(db, storage, config.maxFileBytes);
  const download = makeDownloadHandlers(db, storage, claims);

  const router = new Router();

  router.post("/api/admin/login", admin.login);
  router.post("/api/admin/logout", admin.logout);
  router.get("/api/admin/me", admin.me);
  router.get("/api/admin/tokens", admin.listTokens);
  router.post("/api/admin/tokens", admin.createToken);
  router.delete("/api/admin/tokens/:id", admin.revokeToken);

  router.get("/api/upload/verify", upload.verify);
  router.post("/api/upload/init", upload.init);
  router.post("/api/upload/:id/chunk/:idx", upload.chunk);
  router.post("/api/upload/:id/finalize", upload.finalize);

  router.get("/api/file/:id/meta", download.meta);
  router.post("/api/file/:id/claim", download.claim);
  router.get("/api/file/:id/chunk/:idx", download.chunk);

  router.setFallback(serveStatic);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const start = Date.now();
    try {
      const host = req.headers.host ?? "localhost";
      const url = new URL(req.url ?? "/", `http://${host}`);
      const ctx: Ctx = {
        req,
        res,
        method: req.method ?? "GET",
        pathname: url.pathname,
        query: url.searchParams,
        params: {},
      };
      await router.dispatch(ctx);
    } catch (err) {
      if (err instanceof HttpError) {
        if (!res.headersSent) sendStatus(res, err.status, err.message);
        else res.destroy();
      } else {
        console.error("[server] unhandled error:", err);
        if (!res.headersSent) sendStatus(res, 500, "internal error");
        else res.destroy();
      }
    } finally {
      const ms = Date.now() - start;
      const status = res.statusCode;
      const method = req.method ?? "GET";
      const path = req.url ?? "/";
      console.log(`${method} ${path} -> ${status} (${ms}ms)`);
    }
  });

  server.listen(config.port, () => {
    console.log(`kiskis listening on http://localhost:${config.port}`);
    console.log(`data dir: ${config.dataDir}`);
  });

  const shutdown = (signal: string): void => {
    console.log(`[server] ${signal} received, shutting down`);
    stopReaper();
    server.close(() => {
      db.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error("[server] fatal:", err);
  process.exit(1);
});
