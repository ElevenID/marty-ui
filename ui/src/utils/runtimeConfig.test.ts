import { afterEach, describe, expect, it } from 'vitest';

import { isAdminImpersonationEnabled } from './runtimeConfig';

function setEnv(values: Record<string, unknown>) {
  Object.assign(import.meta.env, values);
}

afterEach(() => {
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  delete (import.meta.env as any).VITE_ENABLE_ADMIN_IMPERSONATION;
  setEnv({ PROD: false });
});

describe('isAdminImpersonationEnabled', () => {
  it('prefers runtime config flag over build env', () => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { adminImpersonationEnabled: false };
    setEnv({ PROD: false, VITE_ENABLE_ADMIN_IMPERSONATION: 'true' });

    expect(isAdminImpersonationEnabled()).toBe(false);
  });

  it('uses build env flag when runtime config is absent', () => {
    setEnv({ PROD: true, VITE_ENABLE_ADMIN_IMPERSONATION: 'true' });

    expect(isAdminImpersonationEnabled()).toBe(true);

    setEnv({ PROD: false, VITE_ENABLE_ADMIN_IMPERSONATION: 'false' });
    expect(isAdminImpersonationEnabled()).toBe(false);
  });

  it('defaults to disabled in production when no flags are set', () => {
    setEnv({ PROD: true });

    expect(isAdminImpersonationEnabled()).toBe(false);
  });

  it('defaults to enabled outside production when no flags are set', () => {
    setEnv({ PROD: false });

    expect(isAdminImpersonationEnabled()).toBe(true);
  });
});
