import { expect, test } from "bun:test";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { createHeader, DEFAULT_BRAND } from "../../../ui/src/shared/web-layout/header.mjs";
import { renderAuthLayout, renderAuthStyles, renderKeycloakAuthLayout } from "../../../ui/src/shared/web-layout/html.mjs";
import { SHARED_HEADER_FILES, verifyHeaderSource } from "../../../ui/src/shared/web-layout/verify-source.mjs";

const root = new URL("../../../", import.meta.url);
const shared = new URL("ui/src/shared/web-layout/", root);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("React and HTML adapters use the general header factory and preserve action children", () => {
  const action = { kind: "existing-login-action" };
  const element = (tag, props, ...children) => ({ tag, props, children });
  const header = createHeader(element, { actions: action, primaryColor: "#123456" });
  expect(header.tag).toBe("header");
  expect(header.props.role).toBe("banner");
  expect(header.props.style).toEqual({ "--elevenid-header-primary": "#123456" });
  const toolbar = header.children[0];
  expect(toolbar.children[1].children).toEqual([DEFAULT_BRAND]);
  expect(toolbar.children[2].children).toEqual([action]);
  expect(read("ui/src/components/layouts/AppHeader.jsx")).toContain("createHeader(createElement");
  expect(read("ui/src/apps/shared/AppShell.jsx")).toContain("<AppHeader brandName={branding.appName}");
});

test("static auth branding is escaped, present before JavaScript and contains no inline styles", () => {
  const html = renderAuthLayout({ brandName: '<img src=x onerror="alert(1)"> & LLC', contentMarkup: '<section id="app"></section>' });
  expect(html).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; LLC');
  expect(html).not.toContain("<img");
  expect(html).not.toContain("style=");
  expect((html.match(/role="banner"/g) ?? []).length).toBe(1);
  expect((html.match(/<main /g) ?? []).length).toBe(1);
  expect(html).toContain('<section id="app"></section>');
});

test("Keycloak and Helm package the generated general header and shared styles exactly", () => {
  const styles = renderAuthStyles(read("ui/src/shared/web-layout/header.css"), read("ui/src/shared/web-layout/auth-page.css"));
  for (const theme of ["config/keycloak/themes/11id/login", "deploy/helm/marty/files/keycloak/themes/11id/login"]) {
    expect(read(`${theme}/auth-layout.ftl`)).toBe(renderKeycloakAuthLayout());
    expect(read(`${theme}/resources/css/auth-layout.css`)).toBe(styles);
    expect(read(`${theme}/template.ftl`)).toContain('<#import "auth-layout.ftl" as shared>');
  }
  for (const filename of ["config.example.json", "config.lifecycle.example.json"]) {
    expect(JSON.parse(read(`integrations/supabase-auth-ui/public/${filename}`)).brand).toBe(DEFAULT_BRAND);
  }
});

test("standalone consumers reject drift from the pinned shared source snapshot", () => {
  const receipt = verifyHeaderSource(shared);
  expect(receipt.owner).toBe("ElevenID/marty-ui");
  const temporary = mkdtempSync(join(tmpdir(), "elevenid-shared-header-"));
  try {
    for (const name of [...SHARED_HEADER_FILES, "source.json"]) cpSync(new URL(name, shared), join(temporary, name));
    const directory = pathToFileURL(`${temporary}/`);
    expect(verifyHeaderSource(directory)).toEqual(receipt);
    writeFileSync(join(temporary, "header.css"), "/* unreviewed drift */\n");
    expect(() => verifyHeaderSource(directory)).toThrow("differs from its pinned snapshot");
  } finally {
    rmSync(temporary, { recursive: true });
  }
});

test("a Git checkout with autocrlf preserves pinned source and generated auth bytes", () => {
  const temporary = mkdtempSync(join(tmpdir(), "elevenid-layout-checkout-"));
  const source = join(temporary, "source"), checkout = join(temporary, "checkout");
  const files = [".gitattributes", "scripts/sync-web-layout.mjs", "ui/src/components/layouts/AppHeader.jsx",
    ...[...SHARED_HEADER_FILES, "source.json", "html.mjs", "auth-page.css"].map((name) => `ui/src/shared/web-layout/${name}`),
    ...["config/keycloak/themes/11id/login", "deploy/helm/marty/files/keycloak/themes/11id/login"]
      .flatMap((theme) => [`${theme}/auth-layout.ftl`, `${theme}/resources/css/auth-layout.css`]),
  ];
  try {
    mkdirSync(source); mkdirSync(checkout);
    for (const path of files) {
      const target = join(source, path);
      mkdirSync(dirname(target), { recursive: true });
      cpSync(new URL(path, root), target);
    }
    const git = (...args) => {
      const result = Bun.spawnSync(["git", ...args], { cwd: source });
      if (result.exitCode !== 0) throw new Error(`Git checkout fixture failed: ${result.stderr.toString()}`);
    };
    git("init", "--quiet");
    git("config", "core.autocrlf", "true");
    git("add", "--", ...files);
    git("checkout-index", "--all", `--prefix=${checkout.replaceAll("\\", "/")}/`);
    for (const path of files) expect(readFileSync(join(checkout, path)).includes(Buffer.from("\r\n"))).toBe(false);
    expect(verifyHeaderSource(pathToFileURL(`${checkout}/ui/src/shared/web-layout/`))).toEqual(verifyHeaderSource(shared));
    const checked = Bun.spawnSync([process.execPath, join(checkout, "scripts/sync-web-layout.mjs"), "--check"], { cwd: checkout });
    expect(checked.exitCode).toBe(0);
  } finally {
    rmSync(temporary, { recursive: true });
  }
});
