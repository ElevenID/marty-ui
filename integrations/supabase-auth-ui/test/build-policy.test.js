import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { publicConfig } from "./fixtures.js";
import { DEFAULT_BRAND } from "../../../ui/src/shared/web-layout/header.mjs";
import { renderAuthLayout } from "../../../ui/src/shared/web-layout/html.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("built HTML and HTTP policies agree and permit proof submission only for explicit clients", () => {
  const temporary = mkdtempSync(join(tmpdir(), "elevenid-native-callback-"));
  try {
    for (const mode of ["v1", "redirect", "native_mfa_post", "lifecycle", "split-origin"]) {
      const config = publicConfig();
      const lifecycle = ["lifecycle", "split-origin"].includes(mode);
      if (mode !== "v1") {
        config.schema = mode === "split-origin" ? "elevenid.supabase-auth-ui/v4" : lifecycle ? "elevenid.supabase-auth-ui/v3" : "elevenid.supabase-auth-ui/v2";
        config.clients = config.clients.map((client, i) => ({ ...client, callbackMode: i === 0 ? (lifecycle ? "native_mfa_post" : mode) : "redirect" }));
        if (lifecycle) config.accountLifecycle = { clientId: config.clients[0].id, signInUri: "https://elevenid.example.invalid/v1/auth/login" };
        if (mode === "split-origin") config.postRedirectOrigins = ["https://console.example.invalid"];
      }
      const configPath = join(temporary, "config.json");
      writeFileSync(configPath, JSON.stringify(config));
      const result = Bun.spawnSync([process.execPath, join(root, "build.mjs"), "--config", configPath], { cwd: root });
      expect(result.exitCode).toBe(0);
      const headers = readFileSync(join(root, "dist/_headers"), "utf8");
      const html = readFileSync(join(root, "dist/index.html"), "utf8");
      const loading = readFileSync(join(root, "public/loading.html"), "utf8").trim();
      expect(html).toContain(renderAuthLayout({ brandName: config.brand, contentMarkup: loading }));
      expect(html).toContain(`<title>Sign in · ${DEFAULT_BRAND}</title>`);
      expect((html.match(/role="banner"/g) ?? []).length).toBe(1);
      expect(html).not.toMatch(/<[#@]|<\/[#@]|style=/);
      const sharedCss = readFileSync(join(root, "../../config/keycloak/themes/11id/login/resources/css/auth-layout.css"), "utf8");
      expect(readFileSync(join(root, "dist/app.css"), "utf8")).toBe(`${sharedCss}\n${readFileSync(join(root, "public/app.css"), "utf8")}`);
      const native = ["native_mfa_post", "lifecycle", "split-origin"].includes(mode);
      const policy = native ? "strict-origin" : "no-referrer";
      expect(headers).toContain(`Referrer-Policy: ${policy}\n`);
      expect(html).toContain(`<meta name="referrer" content="${policy}">`);
      expect(headers).toContain(mode === "split-origin" ? "form-action https://elevenid.example.invalid https://console.example.invalid;" : native ? "form-action https://elevenid.example.invalid;" : "form-action 'none';");
      expect(headers).not.toContain("form-action https://rifare.example.invalid");
      expect(headers).toContain("frame-ancestors 'none'");
      const redirects = readFileSync(join(root, "dist/_redirects"), "utf8");
      expect(redirects.includes("/account/recover / 200\n")).toBe(lifecycle);
      expect(redirects.includes("/account/verify / 200\n")).toBe(lifecycle);
      for (const route of ["register", "confirm", "security"]) {
        expect(redirects.includes(`/account/${route} / 200\n`)).toBe(lifecycle);
      }
      expect(headers).toContain(lifecycle ? "img-src 'self' data:;" : "img-src 'self';");
    }
  } finally {
    // Only the unique test-owned temporary directory, never the checkout.
    if (dirname(temporary) !== resolve(tmpdir()) || !temporary.startsWith(join(tmpdir(), "elevenid-native-callback-"))) throw new Error("Unexpected test directory");
    rmSync(temporary, { recursive: true });
  }
}, 15_000);
