export function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`element #${id} not found`);
  return el;
}

export function $$<T extends HTMLElement>(id: string): T {
  return $(id) as T;
}

export function show(el: HTMLElement, on = true): void {
  el.hidden = !on;
}

export function setText(el: HTMLElement, text: string): void {
  el.textContent = text;
}

export function clear(el: HTMLElement): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: Array<Node | string>
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = String(v);
    else if (k in node) (node as unknown as Record<string, unknown>)[k] = v;
    else node.setAttribute(k, String(v));
  }
  for (const child of children) {
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

export function formatDate(unixSec: number): string {
  const d = new Date(unixSec * 1000);
  return d.toLocaleString();
}

export function formatRelative(unixSec: number): string {
  const delta = unixSec - Math.floor(Date.now() / 1000);
  const abs = Math.abs(delta);
  const fmt = (n: number, unit: string): string => `${n} ${unit}${n === 1 ? "" : "s"}`;
  let s: string;
  if (abs < 60) s = fmt(abs, "second");
  else if (abs < 3600) s = fmt(Math.round(abs / 60), "minute");
  else if (abs < 86400) s = fmt(Math.round(abs / 3600), "hour");
  else s = fmt(Math.round(abs / 86400), "day");
  return delta < 0 ? `${s} ago` : `in ${s}`;
}

export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // fallback for non-secure contexts (http://localhost still counts as secure)
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

export function setError(el: HTMLElement, message: string | null): void {
  if (message === null) {
    el.hidden = true;
    el.textContent = "";
  } else {
    el.hidden = false;
    el.textContent = message;
  }
}
