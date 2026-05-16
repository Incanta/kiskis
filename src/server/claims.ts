import { randomBytes } from "node:crypto";
import { nowSec } from "./auth.js";

const CLAIM_TTL_SECONDS = 10 * 60; // 10 minutes

export interface Claim {
  fileId: string;
  expiresAt: number;
}

export class ClaimStore {
  private readonly map = new Map<string, Claim>();

  create(fileId: string): { token: string; expiresAt: number } {
    const token = randomBytes(24).toString("base64url");
    const expiresAt = nowSec() + CLAIM_TTL_SECONDS;
    this.map.set(token, { fileId, expiresAt });
    return { token, expiresAt };
  }

  verify(token: string | null, fileId: string): boolean {
    if (!token) return false;
    const claim = this.map.get(token);
    if (!claim) return false;
    if (claim.fileId !== fileId) return false;
    if (claim.expiresAt < nowSec()) {
      this.map.delete(token);
      return false;
    }
    return true;
  }

  drop(token: string): void {
    this.map.delete(token);
  }

  sweep(): void {
    const t = nowSec();
    for (const [token, claim] of this.map) {
      if (claim.expiresAt < t) this.map.delete(token);
    }
  }

  hasActiveForFile(fileId: string): boolean {
    const t = nowSec();
    for (const claim of this.map.values()) {
      if (claim.fileId === fileId && claim.expiresAt >= t) return true;
    }
    return false;
  }
}
