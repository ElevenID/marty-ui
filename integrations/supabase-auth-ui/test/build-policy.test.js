import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { publicConfig } from "./fixtures.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("built HTML and HTTP policies agree and permit proof submission only for explicit clients", () => {
  const temporary = mkdtempSync(join(tmpdir(), "elevenid-native-callback-"));
  try {
    for (const mode of ["v1", "redirect", "native_mfa_post"]) {
      const config = publicConfig();
      if (mode !== "v1") {
        config.schema = "elevenid.supabase-auth-ui/v2";
        config.clients = config.clients.map((client, i) => ({ ...client, callbackMode: i === 0 ? mode : "redirect" }));
      }
      const configPath = join(temporary, "config.json");
      writeFileSync(configPath, JSON.stringify(config));
      const result = Bun.spawnSync([process.execPath, join(root, "build.mjs"), "--config", configPath], { cwd: root });
      expect(result.exitCode).toBe(0);
      const headers = readFileSync(join(root, "dist/_headers"), "utf8");
      const html = readFileSync(join(root, "dist/index.html"), "utf8");
      const policy = mode === "native_mfa_post" ? "strict-origin" : "no-referrer";
      expect(headers).toContain(`Referrer-Policy: ${policy}\n`);
      expect(html).toContain(`<meta name="referrer" content="${policy}">`);
      expect(headers).toContain(mode === "native_mfa_post" ? "form-action https://elevenid.example.invalid;" : "form-action 'none';");
      expect(headers).not.toContain("form-action https://rifare.example.invalid");
      expect(headers).toContain("frame-ancestors 'none'");
    }
  } finally {
    // Only the unique test-owned temporary directory, never the checkout.
    if (dirname(temporary) !== resolve(tmpdir()) || !temporary.startsWith(join(tmpdir(), "elevenid-native-callback-"))) throw new Error("Unexpected test directory");
    rmSync(temporary, { recursive: true });
  }
}, 15_000);
