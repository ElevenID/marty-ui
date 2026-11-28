import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const SHARED_HEADER_FILES = Object.freeze(["header.mjs", "header.css", "verify-source.mjs"]);

export function headerSourceRecord(directory) {
  const files = SHARED_HEADER_FILES.map((path) => {
    const file = new URL(path, directory);
    if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) throw new Error(`Shared header source must be a regular file: ${path}`);
    const bytes = readFileSync(file);
    return { path, bytes: bytes.length, sha256: sha256(bytes) };
  });
  return { schema: "elevenid.shared-web-header/v1", owner: "ElevenID/marty-ui",
    sourceDirectory: "ui/src/shared/web-layout", revision: sha256(JSON.stringify(files)), files };
}

export function verifyHeaderSource(directory) {
  const expected = headerSourceRecord(directory);
  const recorded = JSON.parse(readFileSync(new URL("source.json", directory), "utf8"));
  if (JSON.stringify(recorded) !== JSON.stringify(expected)) {
    throw new Error("Shared header source differs from its pinned snapshot; import the reviewed canonical source and receipt together");
  }
  return recorded;
}
