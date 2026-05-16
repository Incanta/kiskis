import {
  CIPHERTEXT_CHUNK_SIZE,
  MAX_CHUNK_COUNT,
  PLAINTEXT_CHUNK_SIZE,
  b64uEncode,
  encodeFragment,
  encryptChunk,
  encryptMetadata,
  generateFileKey,
  randomBytes,
  wrapFileKey,
} from "./crypto.js";
import { getJson, postJson, postBinaryWithProgress } from "./api.js";
import type { ApiError } from "./api.js";
import { $, $$, copyText, formatBytes, formatRelative, setError, show } from "./dom.js";

const TOKEN_KEY = "kiskis_upload_token";

interface InitResponse { file_id: string; expires_at: number; }
interface FinalizeResponse { share_path: string; }
interface VerifyResponse { ok: true; label: string | null; expires_at: number; }

function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(value: string): void {
  localStorage.setItem(TOKEN_KEY, value);
}

function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function verifyToken(token: string): Promise<VerifyResponse> {
  return getJson<VerifyResponse>("/api/upload/verify", { Authorization: `Bearer ${token}` });
}

function showTokenPanel(): void {
  show($("token-panel"), true);
  show($("upload-panel"), false);
}

function showUploadPanel(verified: VerifyResponse): void {
  show($("token-panel"), false);
  show($("upload-panel"), true);
  const info = $("token-info");
  const labelPart = verified.label ? ` (${verified.label})` : "";
  info.textContent = `Token verified${labelPart} — expires ${formatRelative(verified.expires_at)}.`;
}

async function tryUseStoredToken(): Promise<void> {
  const stored = getToken();
  if (!stored) {
    showTokenPanel();
    return;
  }
  try {
    const verified = await verifyToken(stored);
    showUploadPanel(verified);
  } catch (err) {
    if ((err as ApiError)?.status === 401) {
      clearToken();
    }
    showTokenPanel();
    const errorEl = $("token-error");
    setError(errorEl, "Stored token is no longer valid. Please paste a new one.");
  }
}

function bindTokenPanel(): void {
  const input = $$<HTMLInputElement>("token-input");
  const errorEl = $("token-error");
  const saveBtn = $$<HTMLButtonElement>("token-save");

  $$<HTMLButtonElement>("token-logout").addEventListener("click", () => {
    clearToken();
    showTokenPanel();
    setError(errorEl, null);
    input.focus();
  });

  saveBtn.addEventListener("click", async () => {
    const value = input.value.trim();
    if (!/^[A-Za-z0-9_-]{16,}$/.test(value)) {
      setError(errorEl, "That doesn't look like a valid token.");
      return;
    }
    setError(errorEl, null);
    saveBtn.disabled = true;
    const originalText = saveBtn.textContent ?? "Save token";
    saveBtn.textContent = "Verifying…";
    try {
      const verified = await verifyToken(value);
      setToken(value);
      input.value = "";
      showUploadPanel(verified);
    } catch (err) {
      const message = (err as ApiError)?.message ?? (err as Error)?.message ?? "verification failed";
      setError(errorEl, message);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = originalText;
    }
  });

  $$<HTMLButtonElement>("token-clear").addEventListener("click", () => {
    clearToken();
    showTokenPanel();
    setError(errorEl, null);
  });
}

interface UploadOptions {
  file: File;
  password: string;
  maxDownloads: number;
  ttlSeconds: number;
  token: string;
  onProgress: (loaded: number, total: number, phase: string) => void;
}

async function readSlice(file: File, start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
  const buf = await file.slice(start, end).arrayBuffer();
  return new Uint8Array(buf);
}

async function performUpload(opts: UploadOptions): Promise<string> {
  const { file, password, maxDownloads, ttlSeconds, token, onProgress } = opts;

  if (file.size === 0) throw new Error("file is empty");
  const chunkCount = Math.max(1, Math.ceil(file.size / PLAINTEXT_CHUNK_SIZE));
  if (chunkCount > MAX_CHUNK_COUNT) {
    throw new Error(`file too large (max ${formatBytes(MAX_CHUNK_COUNT * PLAINTEXT_CHUNK_SIZE)})`);
  }
  const totalCiphertext = file.size + chunkCount * 16;

  const { raw: rawKey, key } = await generateFileKey();
  const baseNonce = randomBytes(8);
  const mime = file.type || "application/octet-stream";

  const meta = await encryptMetadata(key, { filename: file.name, mime, size: file.size });

  const hasPassword = password.length > 0;
  let fragment: string;
  if (hasPassword) {
    const wrap = await wrapFileKey(rawKey, password);
    fragment = encodeFragment({ kind: "password", salt: wrap.salt, wrapNonce: wrap.wrapNonce, wrapped: wrap.wrapped });
  } else {
    fragment = encodeFragment({ kind: "plain", rawKey });
  }

  const auth = { Authorization: `Bearer ${token}` };

  onProgress(0, totalCiphertext, "preparing");

  const init = await postJson<InitResponse>("/api/upload/init", {
    encrypted_metadata: b64uEncode(meta.ciphertext),
    metadata_nonce: b64uEncode(meta.nonce),
    base_nonce: b64uEncode(baseNonce),
    chunk_count: chunkCount,
    total_ciphertext_bytes: totalCiphertext,
    has_password: hasPassword,
    max_downloads: maxDownloads,
    ttl_seconds: ttlSeconds,
  }, auth);

  let uploaded = 0;
  for (let i = 0; i < chunkCount; i++) {
    const start = i * PLAINTEXT_CHUNK_SIZE;
    const end = Math.min(file.size, start + PLAINTEXT_CHUNK_SIZE);
    const plaintext = await readSlice(file, start, end);
    const isLast = i === chunkCount - 1;
    const cipher = await encryptChunk(key, baseNonce, i, plaintext, isLast);
    if (cipher.length > CIPHERTEXT_CHUNK_SIZE) {
      throw new Error(`chunk ${i} too large`);
    }
    const baseline = uploaded;
    await postBinaryWithProgress(
      `/api/upload/${init.file_id}/chunk/${i}`,
      cipher,
      { ...auth, "Content-Type": "application/octet-stream" },
      (p) => onProgress(baseline + p.loaded, totalCiphertext, "uploading"),
    );
    uploaded += cipher.length;
    onProgress(uploaded, totalCiphertext, "uploading");
  }

  const finalized = await postJson<FinalizeResponse>(
    `/api/upload/${init.file_id}/finalize`, {}, auth,
  );

  const url = `${location.origin}${finalized.share_path}#${fragment}`;
  return url;
}

function bindUploadPanel(): void {
  const fileInput = $$<HTMLInputElement>("file-input");
  const dropZone = $("drop-zone");
  const fileInfo = $("file-info");
  const uploadButton = $$<HTMLButtonElement>("upload-button");
  const form = $$<HTMLFormElement>("upload-form");
  const passwordInput = $$<HTMLInputElement>("password-input");
  const maxDownloadsSel = $$<HTMLSelectElement>("max-downloads");
  const ttlSel = $$<HTMLSelectElement>("ttl");
  const progressWrap = $("progress-wrap");
  const progressBar = $("progress-bar");
  const progressText = $("progress-text");
  const errorEl = $("upload-error");
  const result = $("result");
  const shareLink = $$<HTMLInputElement>("share-link");
  const copyButton = $$<HTMLButtonElement>("copy-button");
  const copyStatus = $("copy-status");

  let selectedFile: File | null = null;

  function selectFile(file: File | null): void {
    selectedFile = file;
    if (file) {
      fileInfo.textContent = `${file.name} (${formatBytes(file.size)})`;
      uploadButton.disabled = false;
    } else {
      fileInfo.textContent = "";
      uploadButton.disabled = true;
    }
  }

  fileInput.addEventListener("change", () => {
    selectFile(fileInput.files && fileInput.files[0] ? fileInput.files[0] : null);
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragging");
    });
  });
  dropZone.addEventListener("drop", (e) => {
    const dt = (e as DragEvent).dataTransfer;
    if (!dt) return;
    const file = dt.files && dt.files[0];
    if (file) selectFile(file);
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!selectedFile) return;
    const token = getToken();
    if (!token) {
      setError(errorEl, "Missing upload token.");
      showTokenPanel();
      return;
    }

    setError(errorEl, null);
    show(result, false);
    show(progressWrap, true);
    uploadButton.disabled = true;
    progressBar.style.width = "0%";
    progressText.textContent = "Preparing…";

    try {
      const url = await performUpload({
        file: selectedFile,
        password: passwordInput.value,
        maxDownloads: Number.parseInt(maxDownloadsSel.value, 10),
        ttlSeconds: Number.parseInt(ttlSel.value, 10),
        token,
        onProgress: (loaded, total, phase) => {
          const pct = total > 0 ? Math.min(100, Math.floor((loaded / total) * 100)) : 0;
          progressBar.style.width = `${pct}%`;
          progressText.textContent = `${phase} — ${pct}% (${formatBytes(loaded)} / ${formatBytes(total)})`;
        },
      });
      progressBar.style.width = "100%";
      progressText.textContent = "Done.";
      shareLink.value = url;
      show(result, true);
    } catch (err) {
      const message = (err as ApiError)?.message ?? (err as Error)?.message ?? "upload failed";
      setError(errorEl, message);
      if ((err as ApiError)?.status === 401) {
        clearToken();
        showTokenPanel();
      }
    } finally {
      uploadButton.disabled = !selectedFile;
    }
  });

  copyButton.addEventListener("click", async () => {
    try {
      await copyText(shareLink.value);
      copyStatus.textContent = "Copied to clipboard.";
    } catch {
      copyStatus.textContent = "Could not copy — select and copy manually.";
      shareLink.select();
    }
  });

  $("upload-again").addEventListener("click", (e) => {
    e.preventDefault();
    selectFile(null);
    fileInput.value = "";
    passwordInput.value = "";
    show(progressWrap, false);
    show(result, false);
    setError(errorEl, null);
    copyStatus.textContent = "";
  });
}

async function main(): Promise<void> {
  bindTokenPanel();
  bindUploadPanel();
  await tryUseStoredToken();
}

void main();
