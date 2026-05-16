export interface ApiError {
  status: number;
  message: string;
}

async function asError(res: Response): Promise<ApiError> {
  let message = res.statusText;
  try {
    const body = await res.json();
    if (body && typeof body.error === "string") message = body.error;
  } catch {
    // ignore
  }
  return { status: res.status, message };
}

export async function getJson<T>(path: string, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", headers });
  if (!res.ok) throw await asError(res);
  return res.json() as Promise<T>;
}

export async function postJson<T>(path: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw await asError(res);
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export async function deleteJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { method: "DELETE", credentials: "same-origin" });
  if (!res.ok) throw await asError(res);
  return res.json() as Promise<T>;
}

export interface UploadProgress {
  loaded: number;
  total: number;
}

export function postBinaryWithProgress(
  path: string,
  body: Uint8Array<ArrayBuffer>,
  headers: Record<string, string>,
  onProgress?: (p: UploadProgress) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => {
      if (onProgress && e.lengthComputable) onProgress({ loaded: e.loaded, total: e.total });
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
      } else {
        let message = xhr.statusText;
        try {
          const body = JSON.parse(xhr.responseText);
          if (body && typeof body.error === "string") message = body.error;
        } catch { /* ignore */ }
        reject({ status: xhr.status, message } as ApiError);
      }
    };
    xhr.onerror = () => reject({ status: 0, message: "network error" } as ApiError);
    xhr.ontimeout = () => reject({ status: 0, message: "timeout" } as ApiError);
    xhr.send(body);
  });
}

export async function fetchBinary(path: string): Promise<Uint8Array<ArrayBuffer>> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) throw await asError(res);
  const buf = await res.arrayBuffer();
  return new Uint8Array(buf);
}
