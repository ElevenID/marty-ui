import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateConfig } from "./src/protocol.js";
import { escapeHtml, renderAuthLayout, renderAuthStyles, renderKeycloakAuthLayout } from "../../ui/src/shared/web-layout/html.mjs";
import { verifyHeaderSource } from "../../ui/src/shared/web-layout/verify-source.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== "--config")) {
  throw new Error("Usage: bun build.mjs [--config path/to/public-config.json]");
}
const configPath = args.length ? resolve(process.cwd(), args[1]) : resolve(root, "public/config.example.json");
const source = await readFile(configPath, "utf8");
if (source.length > 32_768) throw new Error("Public configuration exceeds the allowed size");
const config = validateConfig(JSON.parse(source));
const sharedLayout = new URL("../../ui/src/shared/web-layout/", import.meta.url);
verifyHeaderSource(sharedLayout);
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
const postOrigins = [...new Set(config.clients.filter((client) => client.callbackMode === "native_mfa_post").flatMap((client) => client.redirectUris.map((uri) => new URL(uri).origin)))];
// A browser can enforce form-action again when the callback redirects to the
// separately hosted console. These explicit v4 origins extend only this CSP;
// nativeCallbackPost still sends proof solely to registered callback URIs.
const formActionOrigins = [...new Set([...postOrigins, ...(config.postRedirectOrigins ?? [])])];
// no-referrer turns Origin into "null" on cross-origin form POST in Chrome.
// Send only the public page origin so the receiver can enforce its allowlist.
const referrerPolicy = postOrigins.length ? "strict-origin" : "no-referrer";
const csp = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'",
  `connect-src 'self' ${config.supabaseUrl}`, `img-src 'self'${config.accountLifecycle ? " data:" : ""}`,
  "font-src 'none'", "base-uri 'none'",
  `form-action ${formActionOrigins.join(" ") || "'none'"}`,
  "frame-ancestors 'none'", "object-src 'none'", "upgrade-insecure-requests",
].join("; ");
const headers = `/*
  Content-Security-Policy: ${csp}
  Referrer-Policy: ${referrerPolicy}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Cache-Control: no-store
  Cloudflare-CDN-Cache-Control: no-store
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
`;
// React, Keycloak and Pages use the same general header factory and styles.
// Generated Keycloak copies must agree before publishing another consumer.
// Only repository-owned loading markup is trusted; branding is escaped text.
const theme = resolve(root, "../../config/keycloak/themes/11id/login");
const [layout, page, loading, sharedCss, formCss, headerCss, pageCss] = await Promise.all([
  readFile(resolve(theme, "auth-layout.ftl"), "utf8"),
  readFile(resolve(root, "public/index.html"), "utf8"),
  readFile(resolve(root, "public/loading.html"), "utf8"),
  readFile(resolve(theme, "resources/css/auth-layout.css"), "utf8"),
  readFile(resolve(root, "public/app.css"), "utf8"),
  readFile(new URL("header.css", sharedLayout), "utf8"),
  readFile(new URL("auth-page.css", sharedLayout), "utf8"),
]);
if (layout !== renderKeycloakAuthLayout() || sharedCss !== renderAuthStyles(headerCss, pageCss)) {
  throw new Error("Stale Keycloak layout; run node scripts/sync-web-layout.mjs from the repository root");
}
function replaceOnce(source, marker, replacement) {
  if (source.split(marker).length !== 2) throw new Error(`Expected one layout marker: ${marker}`);
  return source.replace(marker, () => replacement);
}
const shell = renderAuthLayout({ brandName: config.brand, contentMarkup: loading.trim() });
let html = replaceOnce(page, "<!-- auth-layout -->", shell);
html = replaceOnce(html, "<!-- auth-title -->", escapeHtml(`Sign in · ${config.brand}`));
html = replaceOnce(html, '<meta name="referrer" content="no-referrer">', `<meta name="referrer" content="${referrerPolicy}">`);
await Promise.all([
  writeFile(resolve(output, "index.html"), html),
  writeFile(resolve(output, "favicon.ico"), await readFile(resolve(theme, "resources/img/favicon.ico"))),
  writeFile(resolve(output, "app.css"), `${sharedCss}\n${formCss}`),
  writeFile(resolve(output, "config.json"), `${JSON.stringify(config, null, 2)}\n`),
  writeFile(resolve(output, "_headers"), headers),
  writeFile(resolve(output, "_redirects"), "/oauth/consent / 200\n/oauth/consent/ / 200\n" + (config.accountLifecycle ? "/account/recover / 200\n/account/verify / 200\n/account/register / 200\n/account/confirm / 200\n/account/security / 200\n" : "")),
]);
console.log("Built static authorization UI in dist/ with exact-origin CSP. No provider requests were made.");
