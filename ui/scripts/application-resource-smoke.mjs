import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync,
  realpathSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import i18next from 'i18next';
import HttpBackend from 'i18next-http-backend';
import { preview } from 'vite';
import {
  APPLICATION_LOCALES, APPLICATION_LOCALE_NAMESPACES, APPLICATION_RETAINED_PUBLIC_FILES,
  APPLICATION_RESOURCE_MIME_TYPES as CONTENT_TYPES,
} from './application-public-assets.mjs';

const ENTRIES = ['index.html', 'console/index.html'];
const HOST = '127.0.0.1';
const PARSE_ORIGIN = `http://${HOST}`;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
const MAX_FILES = 4096;
const DEADLINE_MS = 45_000;

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function relativePath(value) {
  require(typeof value === 'string' && value.length > 0 && value.length <= 2048
    && !path.isAbsolute(value) && !/[\\\x00-\x1f\x7f?#%]/.test(value)
    && value.split('/').every((part) => part && part !== '.' && part !== '..'),
  `Unsafe output path: ${String(value)}`);
  return value;
}

function ordinaryDirectory(directory) {
  const absolute = path.resolve(directory);
  const metadata = lstatSync(absolute);
  require(metadata.isDirectory() && !metadata.isSymbolicLink() && realpathSync(absolute) === absolute,
    'Output must be an ordinary directory without symlink parents');
  return absolute;
}

function readOutput(distDir, relative) {
  const parts = relativePath(relative).split('/');
  let filename = distDir;
  for (const part of parts.slice(0, -1)) {
    filename = path.join(filename, part);
    const metadata = lstatSync(filename);
    require(metadata.isDirectory() && !metadata.isSymbolicLink(), `Output parent is not an ordinary directory: ${relative}`);
  }
  filename = path.join(filename, parts.at(-1));
  const metadata = lstatSync(filename);
  require(metadata.isFile() && !metadata.isSymbolicLink(), `Output is not a regular file: ${relative}`);
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(descriptor);
    require(opened.isFile() && opened.size <= MAX_FILE_BYTES, `Output file is not bounded: ${relative}`);
    // The extra byte detects growth without an unbounded read or FIFO wait.
    const bytes = Buffer.alloc(opened.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const received = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (received === 0) break;
      length += received;
    }
    require(length === opened.size, `Output changed while reading: ${relative}`);
    const contents = bytes.subarray(0, length);
    return { record: { path: relative, bytes: length, sha256: digest(contents) }, contents };
  } finally {
    closeSync(descriptor);
  }
}

function outputPaths(distDir) {
  const found = [];
  let entries = 0;
  function visit(relative = '', depth = 0) {
    require(depth < 32, 'Output directory nesting exceeds the resource bound');
    for (const entry of readdirSync(path.join(distDir, relative), { withFileTypes: true })) {
      require(++entries <= MAX_FILES, 'Too many output entries');
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      relativePath(name);
      require(!entry.isSymbolicLink(), `Output contains a symlink: ${name}`);
      if (entry.isDirectory()) visit(name, depth + 1);
      else {
        require(entry.isFile(), `Output contains a non-file: ${name}`);
        found.push(name);
        require(found.length <= MAX_FILES, 'Too many output files');
      }
    }
  }
  visit();
  return found.sort();
}

function referenceTarget(raw, owner) {
  require(typeof raw === 'string' && raw.length > 0 && raw.length <= 4096
    && raw === raw.trim() && !/[\\\x00-\x1f\x7f]/.test(raw), `Invalid resource URL in ${owner}`);
  const url = new URL(raw, new URL(`/${owner}`, PARSE_ORIGIN));
  require(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password,
    `Unsupported resource URL in ${owner}: ${raw}`);
  if (url.origin !== PARSE_ORIGIN) return { url: raw, external: true };
  const rawPath = raw.split(/[?#]/, 1)[0];
  require(!/%(?:2f|5c)/i.test(rawPath), `Encoded path separator in ${owner}: ${raw}`);
  const decodedRaw = decodeURIComponent(rawPath);
  require(!decodedRaw.split('/').some((part) => part === '..' || part === '.'),
    `Traversal resource URL in ${owner}: ${raw}`);
  const pathname = decodeURIComponent(url.pathname);
  const relative = pathname.endsWith('/') ? `${pathname.slice(1)}index.html` : pathname.slice(1);
  return { url: raw, path: relativePath(relative) };
}

function requireTargetExtension(reference, extensions, role) {
  if (reference.external) return;
  require(extensions.includes(path.extname(reference.path).toLowerCase()),
    `Invalid local ${role} target: ${reference.path}`);
}

function validateElementTarget(element, attribute, reference) {
  const rel = (element.getAttribute('rel') || '').toLowerCase().split(/\s+/);
  const preload = rel.includes('preload') ? (element.getAttribute('as') || '').toLowerCase() : null;
  if (element.tagName === 'SCRIPT' || rel.includes('modulepreload') || preload === 'script') {
    requireTargetExtension(reference, ['.js', '.mjs'], 'script');
  }
  if (rel.includes('stylesheet') || preload === 'style') {
    requireTargetExtension(reference, ['.css'], 'stylesheet');
  }
  if (rel.includes('manifest')) requireTargetExtension(reference, ['.json'], 'manifest');
  if (element.tagName === 'IMG' || attribute === 'poster' || preload === 'image'
    || rel.some((value) => ['icon', 'apple-touch-icon', 'apple-touch-icon-precomposed', 'mask-icon'].includes(value))) {
    requireTargetExtension(reference, ['.png', '.svg', '.ico'], 'image');
  }
}

function entryReferences(entry, contents) {
  const dom = new JSDOM(contents.toString('utf8'), {
    url: new URL(`/${entry}`, PARSE_ORIGIN).href, includeNodeLocations: true,
    // Neither scripts nor linked resources execute in this parser.
  });
  try {
    const { document } = dom.window;
    require(document.doctype?.name.toLowerCase() === 'html'
      && dom.nodeLocation(document.documentElement) && dom.nodeLocation(document.head)
      && dom.nodeLocation(document.body), `Malformed HTML entry: ${entry}`);
    require(!document.querySelector('base'), `HTML base overrides are unsupported: ${entry}`);
    require(document.querySelector('script[type="module"][src]'), `HTML entry has no emitted module: ${entry}`);
    const references = [];
    for (const element of document.querySelectorAll('script[src], link[href], img[src], source[src], video[src], video[poster], audio[src]')) {
      const attributes = element.tagName === 'LINK' ? ['href']
        : element.tagName === 'VIDEO' ? ['src', 'poster'].filter((name) => element.hasAttribute(name)) : ['src'];
      for (const attribute of attributes) {
        const reference = referenceTarget(element.getAttribute(attribute), entry);
        validateElementTarget(element, attribute, reference);
        references.push({ entry, tag: element.tagName.toLowerCase(), attribute,
          ...reference });
      }
    }
    // Built application entries have no responsive-image lists. Fail closed
    // until their URL grammar is explicitly supported, rather than omit them.
    require(!document.querySelector('[srcset], link[imagesrcset]'), `Responsive resource lists need explicit validation: ${entry}`);
    require(references.length <= MAX_FILES, `Too many HTML references: ${entry}`);
    return references;
  } finally {
    dom.window.close();
  }
}

function jsonObject(contents, relative) {
  const result = JSON.parse(contents.toString('utf8'));
  require(result && typeof result === 'object' && !Array.isArray(result), `Expected a JSON object: ${relative}`);
  return result;
}

function inspectOutput(distDir) {
  const paths = outputPaths(distDir);
  const selected = new Set([...APPLICATION_RETAINED_PUBLIC_FILES, ...ENTRIES,
    ...paths.filter((name) => /\.(?:m?js|wasm|css)$/i.test(name))]);
  const snapshots = new Map();
  let total = 0;
  function include(relative) {
    if (!snapshots.has(relative)) {
      const snapshot = readOutput(distDir, relative);
      total += snapshot.record.bytes;
      require(total <= MAX_OUTPUT_BYTES && snapshots.size < MAX_FILES, 'Selected output exceeds the resource bound');
      require(CONTENT_TYPES[path.extname(relative).toLowerCase()], `Unsupported resource content type: ${relative}`);
      snapshots.set(relative, snapshot);
    }
    return snapshots.get(relative);
  }
  for (const name of [...selected].sort()) include(name);
  const references = ENTRIES.flatMap((entry) => entryReferences(entry, include(entry).contents));
  for (const reference of references) if (!reference.external) include(reference.path);
  const manifest = jsonObject(include('manifest.json').contents, 'manifest.json');
  require(Array.isArray(manifest.icons) && manifest.icons.length > 0 && manifest.icons.length <= 128,
    'Manifest must declare a bounded icon list');
  const icons = manifest.icons.map((icon) => {
    require(icon && typeof icon === 'object' && !Array.isArray(icon), 'Malformed manifest icon');
    const reference = referenceTarget(icon.src, 'manifest.json');
    requireTargetExtension(reference, ['.png', '.svg', '.ico'], 'manifest icon');
    if (!reference.external) include(reference.path);
    return reference;
  });
  for (const name of APPLICATION_RETAINED_PUBLIC_FILES.filter((name) => name.endsWith('.json'))) {
    jsonObject(include(name).contents, name);
  }
  const german = jsonObject(include('locales/de/common.json').contents, 'locales/de/common.json');
  const english = jsonObject(include('locales/en/common.json').contents, 'locales/en/common.json');
  require(!Object.hasOwn(german.common || {}, 'login') && typeof english.common?.login === 'string'
    && english.common.login.trim().length > 0,
  'English fallback fixture changed: German common.login must be absent and English must be nonempty text');
  require(typeof german.actions?.cancel === 'string' && german.actions.cancel.length > 0
    && german.actions.cancel !== english.actions?.cancel, 'A distinct German actions.cancel translation is required');
  return { snapshots, references, icons, german, english };
}

function loopbackOrigin(origin) {
  const url = new URL(origin);
  require(url.protocol === 'http:' && url.hostname === HOST && url.port && url.pathname === '/'
    && !url.username && !url.password && !url.search && !url.hash, 'Only a loopback preview origin is allowed');
  return url.origin;
}

// Shared by the real preview smoke and its missing-resource negative controls.
export async function verifyServedResource(origin, expected, { signal } = {}) {
  const base = loopbackOrigin(origin);
  const relative = relativePath(expected.path);
  require(Number.isSafeInteger(expected.bytes) && expected.bytes >= 0 && expected.bytes <= MAX_FILE_BYTES
    && /^sha256:[a-f0-9]{64}$/.test(expected.sha256), 'Invalid expected resource record');
  const acceptedTypes = CONTENT_TYPES[path.extname(relative).toLowerCase()];
  require(acceptedTypes, `Unsupported resource content type: ${relative}`);
  const response = await fetch(`${base}/${relative}`, {
    redirect: 'manual', signal: signal || AbortSignal.timeout(5000),
    headers: { Accept: '*/*', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache' },
  });
  const contentType = (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  if (response.status !== 200 || !acceptedTypes.includes(contentType)) {
    await response.body?.cancel();
    throw new Error(`Invalid HTTP resource ${relative}: status ${response.status}, content type ${contentType || '(missing)'}`);
  }
  const reader = response.body?.getReader();
  require(reader, `HTTP resource has no body: ${relative}`);
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > expected.bytes) {
        await reader.cancel();
        throw new Error(`HTTP resource bytes differ: ${relative}`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks, length);
  require(length === expected.bytes && digest(bytes) === expected.sha256, `HTTP resource bytes differ: ${relative}`);
  require(path.extname(relative).toLowerCase() === '.html'
    || !/^(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)/i.test(bytes.subarray(0, 512).toString('utf8').trimStart()),
  `HTML masquerades as an asset: ${relative}`);
  return { ...expected, content_type: contentType, status: response.status };
}

function newReportPath(reportPath, distDir) {
  require(typeof reportPath === 'string' && path.isAbsolute(reportPath) && path.extname(reportPath) === '.json',
    'Report must be a new absolute JSON path');
  const absolute = path.resolve(reportPath);
  const relative = path.relative(distDir, absolute);
  require(relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative), 'Report must be outside the output directory');
  const parent = path.dirname(absolute);
  require(lstatSync(parent).isDirectory() && realpathSync(parent) === parent, 'Report parent must be an ordinary existing directory');
  try {
    lstatSync(absolute);
    throw new Error('Report already exists');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return absolute;
}

export async function runApplicationResourceSmoke({ distDir, reportPath }) {
  const output = ordinaryDirectory(distDir);
  const report = newReportPath(reportPath, output);
  const { snapshots, references, icons, german, english } = inspectOutput(output);
  const controller = new AbortController();
  let server;
  let localePhase = false;
  let port;
  let result;
  const localeRequests = [];
  const localeCompletions = [];
  const deadline = setTimeout(() => controller.abort(new Error('Application resource smoke deadline exceeded')), DEADLINE_MS);
  const aborted = new Promise((_, reject) => {
    controller.signal.addEventListener('abort', () => reject(controller.signal.reason), { once: true });
  });
  try {
    const operation = (async () => {
      const starting = preview({
        configFile: false, envFile: false, root: path.dirname(output), publicDir: false,
        logLevel: 'silent', clearScreen: false, base: '/', appType: 'spa',
        build: { outDir: output, emptyOutDir: false },
        preview: { host: HOST, port: 0, strictPort: true, open: false, https: false,
          proxy: {}, cors: false, headers: { 'Cache-Control': 'no-store' } },
        plugins: [{ name: 'application-resource-smoke-observer', configurePreviewServer(current) {
          current.middlewares.use((request, response, next) => {
            if (localePhase) {
              const pathname = new URL(request.url, PARSE_ORIGIN).pathname;
              require(request.method === 'GET' && /^\/locales\/(de|en)\/[a-z]+\.json$/.test(pathname),
                'Unexpected request during locale fallback probe');
              const observed = { path: pathname, status: 0 };
              localeRequests.push(observed);
              localeCompletions.push(new Promise((resolve) => {
                response.once('finish', () => { observed.status = response.statusCode; resolve(); });
                response.once('close', () => { if (!response.writableFinished) resolve(); });
              }));
            }
            next();
          });
        } }],
      });
      server = await starting;
      if (controller.signal.aborted) {
        await server.close();
        throw controller.signal.reason;
      }
      const address = server.httpServer.address();
      require(address && typeof address === 'object' && address.address === HOST
        && Number.isInteger(address.port) && address.port > 0, 'Preview did not bind to loopback');
      port = address.port;
      const origin = `http://${HOST}:${port}`;
      const served = [];
      for (const name of [...snapshots.keys()].sort()) {
        served.push(await verifyServedResource(origin, snapshots.get(name).record, { signal: controller.signal }));
      }
      localePhase = true;
      const instance = i18next.createInstance();
      try {
        await instance.use(HttpBackend).init({
          lng: 'de', fallbackLng: 'en', supportedLngs: [...APPLICATION_LOCALES],
          ns: [...APPLICATION_LOCALE_NAMESPACES], defaultNS: 'common',
          debug: false, saveMissing: false, maxRetries: 0,
          backend: { loadPath: `${origin}/locales/{{lng}}/{{ns}}.json`,
            requestOptions: { cache: 'no-store', redirect: 'error', signal: controller.signal } },
        });
        const fallback = instance.t('common.login', { ns: 'common', returnDetails: true });
        const localized = instance.t('actions.cancel', { ns: 'common', returnDetails: true });
        // A fetch can settle before the server's final finish event is handled.
        // Bind the evidence to completed responses, not event-loop scheduling.
        await Promise.all(localeCompletions);
        require(fallback.usedLng === 'en' && fallback.res === english.common.login,
          'The real HTTP backend did not resolve the missing German key from English');
        require(localized.usedLng === 'de' && localized.res === german.actions.cancel,
          'The real HTTP backend did not resolve the existing German key from German');
        const expectedRequests = ['de', 'en'].flatMap((language) => APPLICATION_LOCALE_NAMESPACES.map(
          (namespace) => `/locales/${language}/${namespace}.json`,
        )).sort();
        const observedRequests = [...new Set(localeRequests.map((entry) => entry.path))].sort();
        assert.deepEqual(observedRequests, expectedRequests, 'Locale backend requests differ from the two-language namespace contract');
        require(localeRequests.every((entry) => entry.status === 200), 'Locale backend received an unsuccessful response');
        result = {
          schema: 'marty.application-resource-smoke/v1', status: 'passed',
          public_resources: APPLICATION_RETAINED_PUBLIC_FILES.map((name) => snapshots.get(name).record),
          served_resources: served, entry_references: references, manifest_icons: icons,
          locale_probe: { language: 'de', fallback_language: 'en', key: 'common.login',
            resolved_language: fallback.usedLng, fallback_value: fallback.res,
            localized_key: 'actions.cancel', localized_language: localized.usedLng,
            localized_value: localized.res, requests: observedRequests },
          preview: { host: HOST, port, closed: false },
          qualification: { resources_served: true, locale_fallback_observed: true,
            browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false },
        };
      } finally {
        localePhase = false;
        instance.off();
      }
    })();
    await Promise.race([operation, aborted]);
  } finally {
    clearTimeout(deadline);
    controller.abort(new Error('Application resource smoke completed'));
    if (server) {
      server.httpServer.closeAllConnections();
      await server.close();
      require(!server.httpServer.listening, 'Preview did not close');
    }
  }
  result.preview.closed = true;
  // Commit the success report only after all checks and preview cleanup.
  const descriptor = openSync(report, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(result, null, 2)}\n`);
  } finally {
    closeSync(descriptor);
  }
  return result;
}

function commandLine(argv) {
  require(argv.length === 4 && argv[0] === '--dist' && argv[2] === '--report',
    'Usage: application-resource-smoke.mjs --dist DIST --report ABS_NEW_JSON');
  return { distDir: argv[1], reportPath: argv[3] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await runApplicationResourceSmoke(commandLine(process.argv.slice(2)));
    console.log(JSON.stringify({ status: result.status, public_resources: result.public_resources.length,
      served_resources: result.served_resources.length, locale_fallback_observed: true, preview_closed: true }));
  } catch (error) {
    console.error(`Application resource smoke failed: ${error.message || error}`);
    process.exitCode = 1;
  }
}
