import { cp, mkdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const src = join(root, "src", "web");
const out = join(root, "dist", "web");

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

for (const name of ["index.html", "d.html", "admin.html", "favicon.svg"]) {
  await cp(join(src, name), join(out, name));
}

await cp(join(src, "css"), join(out, "css"), { recursive: true });

if (existsSync(join(src, "js"))) {
  await cp(join(src, "js"), join(out, "js"), { recursive: true });
}

console.log("Static assets copied to dist/web");
