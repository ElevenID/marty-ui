import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';
import PkijsCertParser from './PkijsCertParser';

const fixture = (name: string) => readFileSync(resolve('src/components/trust/adapters/parsing/__fixtures__', name), 'utf8');
const fixtureBytes = (name: string) => readFileSync(resolve('src/components/trust/adapters/parsing/__fixtures__', name));
const one = fixture('one.pem');
const two = fixture('two.pem');
const der = (pem: string) => Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), c => c.charCodeAt(0));
const file = (name: string, bytes: Uint8Array) => ({ name, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }) as File;
const fingerprint = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex').toUpperCase().match(/../g)?.join(':');

describe('certificate parser contract', () => {
  const parser = new PkijsCertParser();

  beforeAll(() => { vi.stubGlobal('crypto', webcrypto); });
  afterAll(() => { vi.unstubAllGlobals(); });

  it('returns stable metadata and original PEM for an X.509 certificate', async () => {
    const parsed = await parser.parseCertificate(one);
    expect(parsed).toMatchObject({
      subject: 'CN=Marty Test Root, O=ElevenID, OU=Trust, L=Denver, ST=Colorado, C=US',
      issuer: 'CN=Marty Test Root, O=ElevenID, OU=Trust, L=Denver, ST=Colorado, C=US',
      serialNumber: '1234',
      algorithm: 'SHA256withRSA',
      fingerprint: fingerprint(der(one)),
      isValid: true,
      isExpiringSoon: false,
      pemData: one,
    });
    expect(parsed.validFrom).toBeInstanceOf(Date);
    expect(parsed.validUntil).toBeInstanceOf(Date);
    expect(parsed.validFrom < parsed.validUntil).toBe(true);
  });

  it('keeps chain order and skips invalid certificates', async () => {
    const chain = await parser.parseChain(`${one}\n-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n${two}`);
    expect(chain.map(cert => cert.subject)).toEqual([
      'CN=Marty Test Root, O=ElevenID, OU=Trust, L=Denver, ST=Colorado, C=US',
      'CN=Marty Test Intermediate, O=ElevenID, C=US',
    ]);
    expect(chain[0].pemData).toBe(one.trim());
    expect(chain[1].pemData).toBe(two.trim());
    await expect(parser.parseChain('no certificate')).rejects.toThrow('No valid certificates found');
  });

  it.each(['.der', '.cer', '.crt'])('converts binary %s files to parseable PEM', async extension => {
    const pem = await parser.readCertificateFile(file(`root${extension}`, der(one)));
    expect((await parser.parseCertificate(pem)).fingerprint).toBe(fingerprint(der(one)));
  });

  it.each(['.p7b', '.p7c'])('extracts both certificates from binary %s files', async extension => {
    const bytes = fixtureBytes('chain.p7b');
    const pem = await parser.readCertificateFile(file(`chain${extension}`, bytes));
    const chain = await parser.parseChain(pem);
    expect(chain.map(cert => cert.fingerprint)).toEqual([fingerprint(der(one)), fingerprint(der(two))]);
  });

  it('rejects malformed P7B input without inventing a certificate', async () => {
    await expect(parser.readCertificateFile(file('broken.p7b', new Uint8Array([1, 2, 3]))))
      .rejects.toThrow('Failed to parse P7B file');
  });

  it('preserves PEM contents and rejects unsupported files', async () => {
    expect(await parser.readCertificateFile(file('root.pem', new TextEncoder().encode(one)))).toBe(one);
    await expect(parser.readCertificateFile(file('root.txt', der(one)))).rejects.toThrow('Unsupported file format');
    await expect(parser.parseCertificate('invalid')).rejects.toThrow('Failed to parse certificate');
  });
});
