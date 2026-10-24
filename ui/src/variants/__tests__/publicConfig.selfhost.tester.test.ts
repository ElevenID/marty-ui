import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('self-host tester release profile', () => {
  it('hides only the selected public destinations and actions', async () => {
    vi.stubEnv('VITE_SELFHOST_PUBLIC_PROFILE', 'tester');
    vi.resetModules();

    const config = await import('../publicConfig.selfhost');
    expect(config.SELFHOST_PUBLIC_PROFILE).toBe('tester');
    expect(config.SHOW_PUBLIC_DEMOS).toBe(false);
    expect(config.SHOW_PUBLIC_DOCUMENTATION_NAV).toBe(false);
    expect(config.SHOW_PUBLIC_CTA).toBe(false);
    expect(config.SHOW_PUBLIC_PRICING_BUTTONS).toBe(false);
    expect(config.PUBLIC_TABS.map((tab) => tab.path)).toEqual([
      '/', '/product', '/solutions', '/standards', '/resources',
    ]);
    expect(config.SHOW_PUBLIC_LOGIN_BUTTON).toBe(true);
  });

  it('retains the full profile for a future qualified release', async () => {
    vi.stubEnv('VITE_SELFHOST_PUBLIC_PROFILE', 'full');
    vi.resetModules();

    const config = await import('../publicConfig.selfhost');
    expect(config.SHOW_PUBLIC_DEMOS).toBe(true);
    expect(config.SHOW_PUBLIC_DOCUMENTATION_NAV).toBe(true);
    expect(config.SHOW_PUBLIC_CTA).toBe(true);
    expect(config.PUBLIC_TABS.map((tab) => tab.path)).toContain('/pricing');
  });
});
