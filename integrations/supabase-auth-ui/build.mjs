import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateConfig } from "./src/protocol.js";

const root = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== "--config")) {
  throw new Error("Usage: bun build.mjs [--config path/to/public-config.json]");
}
const configPath = args.length ? resolve(process.cwd(), args[1]) : resolve(root, "public/config.example.json");
const source = await readFile(configPath, "utf8");
if (source.length > 32_768) throw new Error("Public configuration exceeds the allowed size");
const config = validateConfig(JSON.parse(source));
const output = resolve(root, "dist");
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const result = await Bun.build({
  entrypoints: [resolve(root, "src/main.js")],
  outdir: output,
  naming: "app.js",
  target: "browser",
  format: "esm",
  minify: true,
  sourcemap: "none",
});
if (!result.success) throw new Error("Static JavaScript build failed");
const csp = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'",
  `connect-src 'self' ${config.supabaseUrl}`, "img-src 'none'",
  "font-src 'none'", "base-uri 'none'", "form-action 'none'",
  "frame-ancestors 'none'", "object-src 'none'", "upgrade-insecure-requests",
].join("; ");
const headers = `/*
  Content-Security-Policy: ${csp}
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Cache-Control: no-store
  Cloudflare-CDN-Cache-Control: no-store
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
`;
await Promise.all([
  writeFile(resolve(output, "index.html"), await readFile(resolve(root, "public/index.html"))),
  writeFile(resolve(output, "app.css"), await readFile(resolve(root, "public/app.css"))),
  writeFile(resolve(output, "config.json"), `${JSON.stringify(config, null, 2)}\n`),
  writeFile(resolve(output, "_headers"), headers),
  writeFile(resolve(output, "_redirects"), "/oauth/consent /index.html 200\n/oauth/consent/ /index.html 200\n"),
]);
console.log("Built static authorization UI in dist/ with exact-origin CSP. No provider requests were made.");
