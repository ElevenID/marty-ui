import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('customer release profiles', () => {
  it.each(['full', 'tester'])('excludes production marketing in the %s profile', async (profile) => {
    vi.stubEnv('VITE_SELFHOST_PUBLIC_PROFILE', profile);
    vi.resetModules();
    const config = await import('../publicConfig.selfhost');

    expect(config.SELFHOST_PUBLIC_PROFILE).toBe(profile);
    expect(config.SHOW_PUBLIC_DEMOS).toBe(false);
    expect(config.SHOW_PUBLIC_CTA).toBe(false);
    expect(config.SHOW_PUBLIC_PRICING_BUTTONS).toBe(false);
    expect(config.SHOW_PUBLIC_LOGIN_BUTTON).toBe(true);
    expect(config.I18N_NAMESPACES).not.toContain('marketing');
    expect(config.PUBLIC_TABS.map((tab) => tab.path)).toEqual(
      profile === 'tester' ? ['/', '/console', '/apply'] : ['/', '/console', '/apply', '/docs'],
    );
    expect(config.SHOW_PUBLIC_DOCUMENTATION_NAV).toBe(profile === 'full');
  });

  it('rejects unsupported build profiles', async () => {
    vi.stubEnv('VITE_SELFHOST_PUBLIC_PROFILE', 'production-marketing');
    vi.resetModules();
    await expect(import('../publicConfig.selfhost')).rejects.toThrow('Unsupported self-host public profile');
  });
});
