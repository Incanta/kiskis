import {
  b64uDecode,
  decodeFragment,
  decryptChunk,
  decryptMetadata,
  importFileKey,
  unwrapFileKey,
} from "./crypto.js";
import type { Fragment, MetadataPayload } from "./crypto.js";
import { fetchBinary, getJson, postJson } from "./api.js";
import type { ApiError } from "./api.js";
import { $, $$, formatBytes, formatRelative, setError, show } from "./dom.js";

interface MetaResponse {
  id: string;
  encrypted_metadata: string;
  metadata_nonce: string;
  base_nonce: string;
  chunk_count: number;
  total_ciphertext_bytes: number;
  has_password: boolean;
  max_downloads: number;
  downloads_remaining: number;
  expires_at: number;
}

interface ClaimResponse {
  claim_token: string;
  expires_at: number;
}

function getFileId(): string | null {
  const m = /^\/d\/([A-Za-z0-9_-]+)\/?$/.exec(location.pathname);
  return m && m[1] ? m[1] : null;
}

interface PreparedFile {
  meta: MetaResponse;
  fragment: Fragment;
  fileKey: CryptoKey;
  baseNonce: Uint8Array<ArrayBuffer>;
  payload: MetadataPayload;
}

async function prepare(meta: MetaResponse, fragment: Fragment, password: string | null): Promise<PreparedFile | null> {
  let rawKey: Uint8Array<ArrayBuffer>;
  if (fragment.kind === "plain") {
    if (meta.has_password) throw new Error("file requires a password but link has none");
    rawKey = fragment.rawKey;
  } else {
    if (!meta.has_password) throw new Error("link has password material but file does not require one");
    if (password === null) return null;
    try {
      rawKey = await unwrapFileKey(password, fragment.salt, fragment.wrapNonce, fragment.wrapped);
    } catch {
      throw new Error("incorrect password");
    }
  }
  const fileKey = await importFileKey(rawKey);
  const ciphertext = b64uDecode(meta.encrypted_metadata);
  const nonce = b64uDecode(meta.metadata_nonce);
  const payload = await decryptMetadata(fileKey, ciphertext, nonce);
  return { meta, fragment, fileKey, baseNonce: b64uDecode(meta.base_nonce), payload };
}

async function downloadAndDecrypt(prep: PreparedFile, onProgress: (loaded: number, total: number) => void): Promise<Blob> {
  const claim = await postJson<ClaimResponse>(`/api/file/${prep.meta.id}/claim`, {});
  const parts: Uint8Array<ArrayBuffer>[] = [];
  let loaded = 0;
  const total = prep.payload.size;

  for (let i = 0; i < prep.meta.chunk_count; i++) {
    const cipher = await fetchBinary(`/api/file/${prep.meta.id}/chunk/${i}?c=${encodeURIComponent(claim.claim_token)}`);
    const isLast = i === prep.meta.chunk_count - 1;
    let plain: Uint8Array<ArrayBuffer>;
    try {
      plain = await decryptChunk(prep.fileKey, prep.baseNonce, i, cipher, isLast);
    } catch {
      throw new Error(`decrypt failed at chunk ${i} — file may be tampered or truncated`);
    }
    parts.push(plain);
    loaded += plain.length;
    onProgress(loaded, total);
  }
  return new Blob(parts, { type: prep.payload.mime });
}

function triggerSave(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function main(): Promise<void> {
  const statusText = $("status-text");
  const statusError = $("status-error");
  const statusPanel = $("status-panel");

  const fileId = getFileId();
  if (!fileId) {
    statusText.textContent = "";
    setError(statusError, "Invalid share URL.");
    return;
  }

  let fragment: Fragment;
  try {
    if (!location.hash || location.hash.length < 2) throw new Error("missing decryption key in URL fragment");
    fragment = decodeFragment(location.hash);
  } catch (e) {
    statusText.textContent = "";
    setError(statusError, (e as Error).message);
    return;
  }

  let meta: MetaResponse;
  try {
    meta = await getJson<MetaResponse>(`/api/file/${fileId}/meta`);
  } catch (e) {
    const err = e as ApiError;
    statusText.textContent = "";
    if (err.status === 404) setError(statusError, "This file is not available — it may have expired.");
    else if (err.status === 410) setError(statusError, err.message || "File is expired or exhausted.");
    else setError(statusError, err.message || "Failed to load file.");
    return;
  }

  show(statusPanel, false);

  const confirmPanel = $("confirm-panel");
  const fileNameEl = $("file-name");
  const fileDetails = $("file-details");
  const fileQuota = $("file-quota");
  const downloadButton = $$<HTMLButtonElement>("download-button");
  const downloadPanel = $("download-panel");
  const downloadName = $("download-name");
  const dlBar = $("dl-bar");
  const dlText = $("dl-text");

  const renderConfirm = (prep: PreparedFile): void => {
    fileNameEl.textContent = prep.payload.filename;
    fileDetails.textContent = `${formatBytes(prep.payload.size)} • ${prep.payload.mime}`;
    fileQuota.textContent =
      `${prep.meta.downloads_remaining} download${prep.meta.downloads_remaining === 1 ? "" : "s"} remaining • expires ${formatRelative(prep.meta.expires_at)}`;
    show(confirmPanel, true);
    downloadButton.onclick = async () => {
      downloadButton.disabled = true;
      show(downloadPanel, true);
      show(confirmPanel, false);
      downloadName.textContent = `Downloading ${prep.payload.filename}…`;
      try {
        const blob = await downloadAndDecrypt(prep, (loaded, total) => {
          const pct = total > 0 ? Math.min(100, Math.floor((loaded / total) * 100)) : 0;
          dlBar.style.width = `${pct}%`;
          dlText.textContent = `${pct}% (${formatBytes(loaded)} / ${formatBytes(total)})`;
        });
        triggerSave(blob, prep.payload.filename);
        dlText.textContent = "Saved. The download is now consumed.";
      } catch (err) {
        const message = (err as ApiError)?.message ?? (err as Error)?.message ?? "download failed";
        dlText.textContent = "";
        show(statusPanel, true);
        setError(statusError, message);
      }
    };
  };

  if (fragment.kind === "plain") {
    try {
      const prep = await prepare(meta, fragment, null);
      if (prep) renderConfirm(prep);
    } catch (e) {
      show(statusPanel, true);
      setError(statusError, (e as Error).message);
    }
    return;
  }

  // Password-protected: ask for password, then prepare.
  const passwordPanel = $("password-panel");
  const passwordForm = $$<HTMLFormElement>("password-form");
  const passwordInput = $$<HTMLInputElement>("password-input");

  show(passwordPanel, true);
  passwordForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = passwordInput.value;
    if (!password) return;
    try {
      const prep = await prepare(meta, fragment, password);
      if (!prep) return;
      show(passwordPanel, false);
      renderConfirm(prep);
    } catch (err) {
      passwordInput.value = "";
      show(statusPanel, true);
      setError(statusError, (err as Error).message);
      show(statusPanel, true);
      window.setTimeout(() => {
        setError(statusError, null);
        show(statusPanel, false);
      }, 3000);
    }
  });
}

void main();
