import { afterEach, describe, expect, it } from 'vitest';
import { getPublicEntryCanonicalOrigin, publicEntryHref } from './publicEntry';

const alias = 'https://203.0.113.10:8443';
const canonical = 'https://marty.example.com:8443';
const configuration = { canonicalOrigin: canonical, publicEntryOrigins: [alias] };
const originalUrl = window.location.href;

afterEach(() => {
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  (globalThis as any).jsdom.reconfigure({ url: originalUrl });
});

describe('public entry origin', () => {
  it('requires the exact configured IP origin and keeps DNS canonical', () => {
    expect(getPublicEntryCanonicalOrigin(alias, configuration)).toBe(canonical);
    for (const origin of [canonical, 'https://203.0.113.11:8443', 'https://203.0.113.10', 'http://203.0.113.10:8443']) {
      expect(getPublicEntryCanonicalOrigin(origin, configuration)).toBeNull();
    }
    expect(getPublicEntryCanonicalOrigin('https://[2001:db8::1]:8443', {
      ...configuration, publicEntryOrigins: ['https://[2001:db8::1]:8443'],
    })).toBe(canonical);
  });

  it('rejects alternate identity, normalized URLs, and malformed alias configuration', () => {
    for (const value of [
      'http://marty.example.com:8443', `${canonical}/`, `${canonical}/path`,
      `${canonical}?q=1`, 'https://name@e.example', alias, 'https://localhost:8443',
      'https://MARTY.example.com:8443', 'https://marty.example.com:443',
    ]) {
      expect(getPublicEntryCanonicalOrigin(alias, { ...configuration, canonicalOrigin: value })).toBeNull();
    }
    for (const aliases of [[], [alias, alias], ['https://other.example.com:8443'], [`${alias}/`], alias]) {
      expect(getPublicEntryCanonicalOrigin(alias, { ...configuration, publicEntryOrigins: aliases })).toBeNull();
    }
    expect(getPublicEntryCanonicalOrigin(alias, null)).toBeNull();
  });

  it('hands local navigation to DNS while preserving fragments and external destinations', () => {
    (globalThis as any).jsdom.reconfigure({ url: `${alias}/` });
    (window as any).__MARTY_RUNTIME_CONFIG__ = { hosting: configuration };
    expect(publicEntryHref('/console?view=applicant#credentials')).toBe(`${canonical}/console?view=applicant#credentials`);
    expect(publicEntryHref(`${alias}/v1/auth/login`)).toBe(`${canonical}/v1/auth/login`);
    expect(publicEntryHref('/docs')).toBe(`${canonical}/docs`);
    expect(publicEntryHref('#proof')).toBe('#proof');
    expect(publicEntryHref('https://github.com/ElevenID')).toBe('https://github.com/ElevenID');
    expect(publicEntryHref('mailto:support@example.com')).toBe('mailto:support@example.com');

    (globalThis as any).jsdom.reconfigure({ url: `${canonical}/` });
    expect(publicEntryHref('/console')).toBe('/console');
  });
});
