import { deleteJson, getJson, postJson } from "./api.js";
import type { ApiError } from "./api.js";
import { $, $$, clear, copyText, el, formatDate, formatRelative, setError, show } from "./dom.js";

interface MeResponse { authenticated: boolean; }

interface TokenListItem {
  id_prefix: string;
  label: string | null;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
}
interface ListResponse { tokens: TokenListItem[]; }

interface CreateResponse {
  id: string;
  id_prefix: string;
  label: string | null;
  created_at: number;
  expires_at: number;
}

async function refreshTokens(): Promise<void> {
  const dashError = $("dashboard-error");
  try {
    const { tokens } = await getJson<ListResponse>("/api/admin/tokens");
    renderTokens(tokens);
    setError(dashError, null);
  } catch (e) {
    const err = e as ApiError;
    if (err.status === 401) {
      showLogin();
      return;
    }
    setError(dashError, err.message || "failed to load tokens");
  }
}

function renderTokens(tokens: TokenListItem[]): void {
  const body = $("tokens-body");
  clear(body);
  if (tokens.length === 0) {
    body.appendChild(el("tr", {}, el("td", { colSpan: 6, class: "muted" }, "No tokens yet.")));
    return;
  }
  for (const t of tokens) {
    const status = t.revoked_at !== null
      ? `revoked ${formatRelative(t.revoked_at)}`
      : t.expires_at < Math.floor(Date.now() / 1000)
        ? "expired"
        : `active (expires ${formatRelative(t.expires_at)})`;
    const row = el("tr", {});
    row.appendChild(el("td", {}, t.label ?? ""));
    row.appendChild(el("td", { class: "mono" }, `${t.id_prefix}…`));
    row.appendChild(el("td", {}, formatDate(t.created_at)));
    row.appendChild(el("td", {}, formatDate(t.expires_at)));
    row.appendChild(el("td", {}, status));
    const actionTd = el("td", {});
    if (t.revoked_at === null && t.expires_at > Math.floor(Date.now() / 1000)) {
      const btn = el("button", { class: "secondary", type: "button" }, "Revoke");
      btn.addEventListener("click", async () => {
        if (!confirm(`Revoke token ${t.id_prefix}…?`)) return;
        try {
          await deleteJson(`/api/admin/tokens/${encodeURIComponent(t.id_prefix)}`);
          await refreshTokens();
        } catch (err) {
          setError($("dashboard-error"), (err as ApiError).message || "revoke failed");
        }
      });
      actionTd.appendChild(btn);
    }
    row.appendChild(actionTd);
    body.appendChild(row);
  }
}

function showLogin(): void {
  show($("login-panel"), true);
  show($("dashboard"), false);
}

function showDashboard(): void {
  show($("login-panel"), false);
  show($("dashboard"), true);
  void refreshTokens();
}

function bindLogin(): void {
  const form = $$<HTMLFormElement>("login-form");
  const input = $$<HTMLInputElement>("admin-password");
  const errEl = $("login-error");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setError(errEl, null);
    try {
      await postJson("/api/admin/login", { password: input.value });
      input.value = "";
      showDashboard();
    } catch (err) {
      setError(errEl, (err as ApiError).message || "login failed");
    }
  });
}

function bindDashboard(): void {
  $$<HTMLButtonElement>("logout-button").addEventListener("click", async () => {
    try {
      await postJson("/api/admin/logout", {});
    } catch { /* ignore */ }
    showLogin();
  });

  const createForm = $$<HTMLFormElement>("create-form");
  const labelInput = $$<HTMLInputElement>("token-label");
  const ttlSel = $$<HTMLSelectElement>("token-ttl");
  const createdPanel = $("created-token");
  const createdValue = $$<HTMLInputElement>("created-token-value");

  createForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = $("dashboard-error");
    setError(errEl, null);
    try {
      const resp = await postJson<CreateResponse>("/api/admin/tokens", {
        label: labelInput.value || null,
        ttl_seconds: Number.parseInt(ttlSel.value, 10),
      });
      labelInput.value = "";
      createdValue.value = resp.id;
      show(createdPanel, true);
      await refreshTokens();
    } catch (err) {
      setError(errEl, (err as ApiError).message || "create failed");
    }
  });

  $$<HTMLButtonElement>("copy-created").addEventListener("click", async () => {
    try { await copyText(createdValue.value); } catch { createdValue.select(); }
  });
}

async function main(): Promise<void> {
  bindLogin();
  bindDashboard();
  try {
    const me = await getJson<MeResponse>("/api/admin/me");
    if (me.authenticated) showDashboard();
    else showLogin();
  } catch {
    showLogin();
  }
}

void main();
