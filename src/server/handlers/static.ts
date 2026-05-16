import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { join, normalize, resolve, sep } from "node:path";
import type { Ctx } from "../http.js";
import { sendStatus } from "../http.js";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

function mimeFor(path: string): string {
  const dot = path.lastIndexOf(".");
  if (dot < 0) return "application/octet-stream";
  return MIME[path.slice(dot).toLowerCase()] ?? "application/octet-stream";
}

export function makeStaticHandler(webDir: string) {
  const root = resolve(webDir);

  async function serve(ctx: Ctx, relPath: string): Promise<void> {
    const safe = normalize(relPath).replace(/^([/\\])+/, "");
    const full = resolve(root, safe);
    if (!full.startsWith(root + sep) && full !== root) {
      sendStatus(ctx.res, 403);
      return;
    }
    try {
      const st = await stat(full);
      if (!st.isFile()) {
        sendStatus(ctx.res, 404);
        return;
      }
      ctx.res.writeHead(200, {
        "Content-Type": mimeFor(full),
        "Content-Length": st.size.toString(),
        "Cache-Control": "no-cache",
        "X-Content-Type-Options": "nosniff",
      });
      createReadStream(full).pipe(ctx.res);
    } catch {
      sendStatus(ctx.res, 404);
    }
  }

  return async (ctx: Ctx): Promise<void> => {
    const p = ctx.pathname;
    if (p === "/" || p === "/index.html") {
      await serve(ctx, "index.html");
      return;
    }
    if (p === "/admin") {
      await serve(ctx, "admin.html");
      return;
    }
    if (p.startsWith("/d/")) {
      await serve(ctx, "d.html");
      return;
    }
    if (p.startsWith("/css/") || p.startsWith("/js/")) {
      await serve(ctx, p.slice(1));
      return;
    }
    if (p === "/favicon.svg" || p === "/favicon.ico") {
      await serve(ctx, "favicon.svg");
      return;
    }
    sendStatus(ctx.res, 404);
  };
}
