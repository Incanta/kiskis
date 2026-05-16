import { mkdir, rm, stat, writeFile, readFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { join } from "node:path";

export class Storage {
  constructor(private readonly blobsDir: string) {}

  async init(): Promise<void> {
    await mkdir(this.blobsDir, { recursive: true });
  }

  private fileDir(id: string): string {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) {
      throw new Error("invalid file id");
    }
    return join(this.blobsDir, id);
  }

  private chunkPath(id: string, idx: number): string {
    if (!Number.isInteger(idx) || idx < 0 || idx > 1_000_000) {
      throw new Error("invalid chunk index");
    }
    return join(this.fileDir(id), `c${idx.toString().padStart(6, "0")}`);
  }

  async ensureFileDir(id: string): Promise<void> {
    await mkdir(this.fileDir(id), { recursive: true });
  }

  async writeChunk(id: string, idx: number, body: Uint8Array): Promise<void> {
    await writeFile(this.chunkPath(id, idx), body);
  }

  async chunkExists(id: string, idx: number): Promise<boolean> {
    try {
      await stat(this.chunkPath(id, idx));
      return true;
    } catch {
      return false;
    }
  }

  async readChunk(id: string, idx: number): Promise<Buffer> {
    return readFile(this.chunkPath(id, idx));
  }

  chunkStream(id: string, idx: number): NodeJS.ReadableStream {
    return createReadStream(this.chunkPath(id, idx));
  }

  async deleteFile(id: string): Promise<void> {
    await rm(this.fileDir(id), { recursive: true, force: true });
  }
}
