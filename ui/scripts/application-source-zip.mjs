import { constants } from 'node:fs';

export const APPLICATION_SOURCE_ZIP_LIMITS = Object.freeze({
  archiveBytes: 64 * 1024 * 1024, fileBytes: 16 * 1024 * 1024, entries: 2048, pathBytes: 512,
});
const FLAGS = 0x0800;
const DOS_DATE = 33; // 1980-01-01, the earliest representable ZIP timestamp.
const VERSION = 20;
const MADE_BY = (3 << 8) | VERSION;
const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function require(condition, message) { if (!condition) throw new Error(message); }
function crc32(bytes) {
  let result = 0xffffffff;
  for (const byte of bytes) result = crcTable[(result ^ byte) & 0xff] ^ (result >>> 8);
  return (result ^ 0xffffffff) >>> 0;
}
function compare(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

export function applicationSourcePath(value) {
  require(typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= APPLICATION_SOURCE_ZIP_LIMITS.pathBytes
    && /^[A-Za-z0-9@._/-]+$/.test(value) && !value.startsWith('/') && !value.endsWith('/')
    && value.split('/').every((part) => part && part !== '.' && part !== '..' && !part.endsWith('.')
      && !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)), 'Unsafe application source path');
  return value;
}

function validateMembers(entries) {
  require(Array.isArray(entries) && entries.length > 0 && entries.length <= APPLICATION_SOURCE_ZIP_LIMITS.entries,
    'Application source ZIP member count exceeds its bound');
  const names = new Set();
  let total = 0;
  for (const entry of entries) {
    applicationSourcePath(entry.path);
    const folded = entry.path.toLowerCase();
    require(!names.has(folded), 'Duplicate application source ZIP path'); names.add(folded);
    require(Buffer.isBuffer(entry.bytes) && entry.bytes.length <= APPLICATION_SOURCE_ZIP_LIMITS.fileBytes,
      'Application source ZIP member exceeds its bound');
    require([0o644, 0o755].includes(entry.mode), 'Unexpected application source ZIP mode');
    total += entry.bytes.length;
  }
  require(total <= APPLICATION_SOURCE_ZIP_LIMITS.archiveBytes, 'Application source ZIP content exceeds its bound');
  for (const name of names) {
    const parts = name.split('/');
    for (let index = 1; index < parts.length; index++) require(!names.has(parts.slice(0, index).join('/')),
      'Application source ZIP has a file/directory collision');
  }
}

// Only fixed, stored, ordinary-file members are supported. There is no generic
// archive extraction path, compression, host metadata, directory entry or ZIP64.
export function encodeApplicationSourceZip(input) {
  validateMembers(input);
  const entries = [...input].sort((a, b) => compare(a.path, b.path));
  const locals = []; const central = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.path, 'utf8'); const crc = crc32(entry.bytes);
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(VERSION, 4); local.writeUInt16LE(FLAGS, 6); local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(entry.bytes.length, 18); local.writeUInt32LE(entry.bytes.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, entry.bytes);
    const row = Buffer.alloc(46); row.writeUInt32LE(0x02014b50, 0);
    row.writeUInt16LE(MADE_BY, 4); row.writeUInt16LE(VERSION, 6); row.writeUInt16LE(FLAGS, 8);
    row.writeUInt16LE(DOS_DATE, 14); row.writeUInt32LE(crc, 16);
    row.writeUInt32LE(entry.bytes.length, 20); row.writeUInt32LE(entry.bytes.length, 24); row.writeUInt16LE(name.length, 28);
    row.writeUInt32LE(((constants.S_IFREG | entry.mode) << 16) >>> 0, 38); row.writeUInt32LE(offset, 42);
    central.push(row, name); offset += local.length + name.length + entry.bytes.length;
  }
  const directory = Buffer.concat(central); const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  const bytes = Buffer.concat([...locals, directory, end]);
  require(bytes.length <= APPLICATION_SOURCE_ZIP_LIMITS.archiveBytes, 'Application source ZIP exceeds its bound');
  return bytes;
}

export function decodeApplicationSourceZip(bytes) {
  require(Buffer.isBuffer(bytes) && bytes.length >= 22 && bytes.length <= APPLICATION_SOURCE_ZIP_LIMITS.archiveBytes,
    'Invalid or oversized application source ZIP');
  const end = bytes.length - 22;
  require(bytes.readUInt32LE(end) === 0x06054b50 && bytes.readUInt16LE(end + 4) === 0
    && bytes.readUInt16LE(end + 6) === 0 && bytes.readUInt16LE(end + 20) === 0,
  'Application source ZIP has trailing data, comments or multiple disks');
  const count = bytes.readUInt16LE(end + 10); const size = bytes.readUInt32LE(end + 12);
  const start = bytes.readUInt32LE(end + 16);
  require(count > 0 && count <= APPLICATION_SOURCE_ZIP_LIMITS.entries && bytes.readUInt16LE(end + 8) === count
    && start + size === end, 'Invalid application source ZIP directory');
  let position = start; let localPosition = 0; let previous = ''; const entries = [];
  for (let index = 0; index < count; index++) {
    require(position + 46 <= end && bytes.readUInt32LE(position) === 0x02014b50, 'Invalid application source ZIP central header');
    const nameSize = bytes.readUInt16LE(position + 28); const length = bytes.readUInt32LE(position + 24);
    const crc = bytes.readUInt32LE(position + 16); const attributes = bytes.readUInt32LE(position + 38);
    const unixMode = attributes >>> 16; const mode = unixMode & 0o7777;
    require(bytes.readUInt16LE(position + 4) === MADE_BY && bytes.readUInt16LE(position + 6) === VERSION
      && bytes.readUInt16LE(position + 8) === FLAGS && bytes.readUInt16LE(position + 10) === 0
      && bytes.readUInt16LE(position + 12) === 0 && bytes.readUInt16LE(position + 14) === DOS_DATE
      && bytes.readUInt32LE(position + 20) === length && length <= APPLICATION_SOURCE_ZIP_LIMITS.fileBytes
      && nameSize > 0 && nameSize <= APPLICATION_SOURCE_ZIP_LIMITS.pathBytes
      && bytes.readUInt16LE(position + 30) === 0 && bytes.readUInt16LE(position + 32) === 0
      && bytes.readUInt16LE(position + 34) === 0 && bytes.readUInt16LE(position + 36) === 0
      && (unixMode & constants.S_IFMT) === constants.S_IFREG && [0o644, 0o755].includes(mode)
      && (attributes & 0xffff) === 0 && bytes.readUInt32LE(position + 42) === localPosition,
    'Application source ZIP member metadata is not the reviewed stored-file format');
    require(position + 46 + nameSize <= end, 'Truncated application source ZIP filename');
    const nameBytes = bytes.subarray(position + 46, position + 46 + nameSize); const name = nameBytes.toString('utf8');
    require(Buffer.from(name).equals(nameBytes), 'Invalid application source ZIP filename encoding');
    applicationSourcePath(name);
    require(compare(previous, name) < 0, 'Application source ZIP paths must be unique and sorted'); previous = name;
    require(localPosition + 30 + nameSize + length <= start && bytes.readUInt32LE(localPosition) === 0x04034b50,
      'Truncated or overlapping application source ZIP local member');
    require(bytes.readUInt16LE(localPosition + 4) === VERSION && bytes.readUInt16LE(localPosition + 6) === FLAGS
      && bytes.readUInt16LE(localPosition + 8) === 0 && bytes.readUInt16LE(localPosition + 10) === 0
      && bytes.readUInt16LE(localPosition + 12) === DOS_DATE && bytes.readUInt32LE(localPosition + 14) === crc
      && bytes.readUInt32LE(localPosition + 18) === length && bytes.readUInt32LE(localPosition + 22) === length
      && bytes.readUInt16LE(localPosition + 26) === nameSize && bytes.readUInt16LE(localPosition + 28) === 0
      && bytes.subarray(localPosition + 30, localPosition + 30 + nameSize).equals(nameBytes),
    'Application source ZIP local and central records differ');
    const content = Buffer.from(bytes.subarray(localPosition + 30 + nameSize, localPosition + 30 + nameSize + length));
    require(crc32(content) === crc, 'Application source ZIP member CRC differs');
    entries.push({ path: name, bytes: content, mode });
    localPosition += 30 + nameSize + length; position += 46 + nameSize;
  }
  require(position === end && localPosition === start, 'Application source ZIP has unlisted data or members');
  validateMembers(entries);
  return entries;
}
