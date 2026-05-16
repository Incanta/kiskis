import type { IncomingMessage, ServerResponse } from "node:http";

export interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  pathname: string;
  query: URLSearchParams;
  params: Record<string, string>;
}

export type Handler = (ctx: Ctx) => Promise<void> | void;

const MAX_JSON_BODY = 64 * 1024;

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json).toString(),
    "Cache-Control": "no-store",
  });
  res.end(json);
}

export function sendStatus(res: ServerResponse, status: number, message?: string): void {
  sendJson(res, status, { error: message ?? statusMessage(status) });
}

function statusMessage(status: number): string {
  switch (status) {
    case 400: return "bad request";
    case 401: return "unauthorized";
    case 403: return "forbidden";
    case 404: return "not found";
    case 405: return "method not allowed";
    case 410: return "gone";
    case 413: return "payload too large";
    case 415: return "unsupported media type";
    case 500: return "internal error";
    default:  return "error";
  }
}

export async function readJsonBody<T = unknown>(req: IncomingMessage, maxBytes = MAX_JSON_BODY): Promise<T> {
  const buf = await readRawBody(req, maxBytes);
  const text = buf.toString("utf8");
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(400, "invalid JSON body");
  }
}

export async function readRawBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;

    req.on("data", (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > maxBytes) {
        done = true;
        req.destroy();
        reject(new HttpError(413, "request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks, total));
    });
    req.on("error", (err) => {
      if (done) return;
      done = true;
      reject(err);
    });
  });
}

export class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

interface RouteDef {
  method: string;
  pattern: RegExp;
  paramNames: string[];
  handler: Handler;
}

export class Router {
  private readonly routes: RouteDef[] = [];
  private fallback: Handler | null = null;

  private compile(method: string, path: string, handler: Handler): void {
    const paramNames: string[] = [];
    const pattern = new RegExp(
      "^" +
        path.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_m, name: string) => {
          paramNames.push(name);
          return "([^/]+)";
        }) +
        "$",
    );
    this.routes.push({ method, pattern, paramNames, handler });
  }

  get(path: string, handler: Handler): void { this.compile("GET", path, handler); }
  post(path: string, handler: Handler): void { this.compile("POST", path, handler); }
  delete(path: string, handler: Handler): void { this.compile("DELETE", path, handler); }

  setFallback(handler: Handler): void {
    this.fallback = handler;
  }

  async dispatch(ctx: Ctx): Promise<void> {
    let methodMismatch = false;
    for (const route of this.routes) {
      const m = route.pattern.exec(ctx.pathname);
      if (!m) continue;
      if (route.method !== ctx.method) {
        methodMismatch = true;
        continue;
      }
      for (let i = 0; i < route.paramNames.length; i++) {
        const name = route.paramNames[i];
        const value = m[i + 1];
        if (name && value !== undefined) {
          ctx.params[name] = decodeURIComponent(value);
        }
      }
      await route.handler(ctx);
      return;
    }
    if (methodMismatch) {
      sendStatus(ctx.res, 405);
      return;
    }
    if (this.fallback) {
      await this.fallback(ctx);
      return;
    }
    sendStatus(ctx.res, 404);
  }
}
