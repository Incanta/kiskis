import type { Ctx } from "../http.js";
import { HttpError, readJsonBody, sendJson, sendStatus } from "../http.js";
import type { Db, AuthTokenRow } from "../db.js";
import {
  buildSessionCookie,
  clearSessionCookie,
  createAuthToken,
  createSession,
  destroySession,
  listAuthTokens,
  parseSessionCookie,
  revokeAuthTokenById,
  validateSession,
  verifyAdminPassword,
} from "../auth.js";

const TOKEN_TTL_CHOICES = new Set<number>([
  60 * 60 * 24,
  60 * 60 * 24 * 7,
  60 * 60 * 24 * 30,
  60 * 60 * 24 * 365,
]);

const TOKEN_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

function requireSession(ctx: Ctx, db: Db): string {
  const id = parseSessionCookie(ctx.req.headers.cookie);
  if (!id || !validateSession(db, id)) {
    throw new HttpError(401, "not authenticated");
  }
  return id;
}

export function makeAdminHandlers(db: Db, secureCookies: boolean) {
  return {
    async login(ctx: Ctx): Promise<void> {
      const body = await readJsonBody<{ password?: unknown }>(ctx.req);
      const password = typeof body.password === "string" ? body.password : "";
      if (password.length === 0) {
        sendStatus(ctx.res, 400, "password required");
        return;
      }
      const ok = await verifyAdminPassword(db, password);
      if (!ok) {
        sendStatus(ctx.res, 401, "invalid password");
        return;
      }
      const { id, expiresAt } = createSession(db);
      const cookie = buildSessionCookie(id, {
        secure: secureCookies,
        maxAgeSeconds: expiresAt - Math.floor(Date.now() / 1000),
      });
      ctx.res.setHeader("Set-Cookie", cookie);
      sendJson(ctx.res, 200, { ok: true });
    },

    async logout(ctx: Ctx): Promise<void> {
      const id = parseSessionCookie(ctx.req.headers.cookie);
      if (id) destroySession(db, id);
      ctx.res.setHeader("Set-Cookie", clearSessionCookie({ secure: secureCookies }));
      sendJson(ctx.res, 200, { ok: true });
    },

    async me(ctx: Ctx): Promise<void> {
      const id = parseSessionCookie(ctx.req.headers.cookie);
      const authenticated = !!id && validateSession(db, id);
      sendJson(ctx.res, 200, { authenticated });
    },

    async listTokens(ctx: Ctx): Promise<void> {
      requireSession(ctx, db);
      const rows = listAuthTokens(db);
      const safe = rows.map((r: AuthTokenRow) => ({
        id_prefix: r.id.slice(0, 8),
        label: r.label,
        created_at: r.created_at,
        expires_at: r.expires_at,
        revoked_at: r.revoked_at,
      }));
      sendJson(ctx.res, 200, { tokens: safe });
    },

    async createToken(ctx: Ctx): Promise<void> {
      requireSession(ctx, db);
      const body = await readJsonBody<{ label?: unknown; ttl_seconds?: unknown }>(ctx.req);
      const label = typeof body.label === "string" && body.label.length > 0 ? body.label.slice(0, 200) : null;
      const ttl = Number(body.ttl_seconds);
      if (!TOKEN_TTL_CHOICES.has(ttl)) {
        sendStatus(ctx.res, 400, "ttl_seconds must be one of 1d/7d/30d/365d in seconds");
        return;
      }
      const created = createAuthToken(db, label, ttl);
      sendJson(ctx.res, 201, {
        id: created.id, // the full secret — shown once
        id_prefix: created.id.slice(0, 8),
        label: created.label,
        created_at: created.createdAt,
        expires_at: created.expiresAt,
      });
    },

    async revokeToken(ctx: Ctx): Promise<void> {
      requireSession(ctx, db);
      const id = ctx.params["id"];
      if (!id || !TOKEN_ID_PATTERN.test(id)) {
        sendStatus(ctx.res, 400, "invalid token id");
        return;
      }
      // The admin UI only sees the prefix, so accept prefix match for revoke convenience.
      // We perform exact-match revoke; if id_prefix is provided, expand by listing.
      let target = id;
      if (id.length < 16) {
        const all = listAuthTokens(db);
        const match = all.find((r) => r.id.startsWith(id) && r.revoked_at === null);
        if (!match) {
          sendStatus(ctx.res, 404, "token not found");
          return;
        }
        target = match.id;
      }
      const ok = revokeAuthTokenById(db, target);
      if (!ok) {
        sendStatus(ctx.res, 404, "token not found or already revoked");
        return;
      }
      sendJson(ctx.res, 200, { ok: true });
    },
  };
}
