import { resolve } from "node:path";

export interface Config {
  adminPassword: string;
  port: number;
  dataDir: string;
  blobsDir: string;
  dbPath: string;
  secureCookies: boolean;
  maxFileBytes: number;
}

const HARD_MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return v;
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`Env var ${name} must be a positive integer, got: ${raw}`);
  }
  return n;
}

function boolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return raw === "true" || raw === "1" || raw === "yes";
}

export function loadConfig(): Config {
  const dataDir = resolve(process.env["DATA_DIR"] ?? "./data");
  const requestedMax = intEnv("MAX_FILE_BYTES", HARD_MAX_BYTES);
  const maxFileBytes = Math.min(requestedMax, HARD_MAX_BYTES);

  return {
    adminPassword: required("ADMIN_PASSWORD"),
    port: intEnv("PORT", 8787),
    dataDir,
    blobsDir: resolve(dataDir, "blobs"),
    dbPath: resolve(dataDir, "kiskis.db"),
    secureCookies: boolEnv("SECURE_COOKIES", false),
    maxFileBytes,
  };
}
