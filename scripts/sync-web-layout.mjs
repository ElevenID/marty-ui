import { readFile, writeFile } from "node:fs/promises";
import { renderAuthStyles, renderKeycloakAuthLayout } from "../ui/src/shared/web-layout/html.mjs";
import { headerSourceRecord } from "../ui/src/shared/web-layout/verify-source.mjs";

if (process.argv.slice(2).some((argument) => argument !== "--check") || process.argv.length > 3) {
  throw new Error("Usage: node scripts/sync-web-layout.mjs [--check]");
}
const check = process.argv.includes("--check");
const root = new URL("../", import.meta.url);
const shared = new URL("ui/src/shared/web-layout/", root);
const [headerCss, pageCss] = await Promise.all(["header.css", "auth-page.css"].map((path) => readFile(new URL(path, shared), "utf8")));
const artifacts = new Map([
  ["ui/src/shared/web-layout/source.json", `${JSON.stringify(headerSourceRecord(shared), null, 2)}\n`],
]);
for (const theme of ["config/keycloak/themes/11id/login/", "deploy/helm/marty/files/keycloak/themes/11id/login/"]) {
  artifacts.set(`${theme}auth-layout.ftl`, renderKeycloakAuthLayout());
  artifacts.set(`${theme}resources/css/auth-layout.css`, renderAuthStyles(headerCss, pageCss));
}
const stale = [];
for (const [path, expected] of artifacts) {
  const file = new URL(path, root);
  const actual = await readFile(file, "utf8").catch((error) => { if (error.code === "ENOENT") return null; throw error; });
  if (actual === expected) continue;
  if (check) stale.push(path);
  else await writeFile(file, expected);
}
if (stale.length) throw new Error(`Stale shared layout artifacts: ${stale.join(", ")}. Run node scripts/sync-web-layout.mjs.`);
console.log(check ? "Shared layout source and packaged adapters agree." : "Updated shared layout source receipt and auth adapters.");
