import { afterEach, describe, expect, it } from 'vitest';

import { getEnabledWebSections, getGoogleAnalyticsMeasurementId, isAdminImpersonationEnabled, isOrganizationCreationEnabled, isWebPathEnabled, isWebSectionEnabled } from './runtimeConfig';

function setEnv(values: Record<string, unknown>) {
  Object.assign(import.meta.env, values);
}

afterEach(() => {
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  delete (import.meta.env as any).VITE_ENABLE_ADMIN_IMPERSONATION;
  delete (import.meta.env as any).VITE_GA_MEASUREMENT_ID;
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

describe('analytics runtime setting', () => {
  it('respects an explicit empty value over a compiled fallback', () => {
    setEnv({ VITE_GA_MEASUREMENT_ID: 'G-OLD123' });
    expect(getGoogleAnalyticsMeasurementId()).toBe('G-OLD123');
    (window as any).__MARTY_RUNTIME_CONFIG__ = { googleAnalyticsMeasurementId: '' };
    expect(getGoogleAnalyticsMeasurementId()).toBe('');
    (window as any).__MARTY_RUNTIME_CONFIG__ = { googleAnalyticsMeasurementId: 'G-NEW123' };
    expect(getGoogleAnalyticsMeasurementId()).toBe('G-NEW123');
  });
});

describe('organization creation setting', () => {
  it.each([false, true])('uses the deployment value over the legacy audience default %s', (legacyDefault) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: true };
    expect(isOrganizationCreationEnabled(legacyDefault)).toBe(true);
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: false };
    expect(isOrganizationCreationEnabled(legacyDefault)).toBe(false);
  });

  it.each([null, 'true', 'false', 1, [], {}])('rejects a malformed explicit value %j', (value) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: value };
    expect(isOrganizationCreationEnabled(true)).toBe(false);
  });

  it('preserves legacy audience behavior only when the runtime setting is absent', () => {
    expect(isOrganizationCreationEnabled(false)).toBe(false);
    expect(isOrganizationCreationEnabled(true)).toBe(true);
  });
});

describe('startup web sections', () => {
  it('preserves both sections when legacy runtime configuration has no web entry', () => {
    expect(getEnabledWebSections()).toEqual(['public', 'console']);
    (window as any).__MARTY_RUNTIME_CONFIG__ = { hosting: {} };
    expect(isWebSectionEnabled('public')).toBe(true);
    expect(isWebSectionEnabled('console')).toBe(true);
  });

  it.each([
    { sections: ['public', 'console'], publicEnabled: true, consoleEnabled: true },
    { sections: ['public'], publicEnabled: true, consoleEnabled: false },
    { sections: ['console'], publicEnabled: false, consoleEnabled: true },
    { sections: [], publicEnabled: false, consoleEnabled: false },
  ])('applies the explicit section list $sections', ({ sections, publicEnabled, consoleEnabled }) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: sections } };
    expect(isWebPathEnabled('/')).toBe(publicEnabled);
    expect(isWebPathEnabled('/apply/badge')).toBe(publicEnabled && consoleEnabled);
    expect(isWebPathEnabled('/organizations')).toBe(publicEnabled);
    expect(isWebPathEnabled('/console')).toBe(consoleEnabled);
    expect(isWebPathEnabled('/console/login?returnTo=%2Fconsole')).toBe(consoleEnabled);
    expect(isWebPathEnabled('/console/applicant/identity')).toBe(consoleEnabled);
    expect(isWebPathEnabled('/my-documents')).toBe(consoleEnabled);
    expect(isWebPathEnabled('/auth/callback')).toBe(publicEnabled || consoleEnabled);
  });

  it.each([
    null, false, [], {}, { enabled_sections: 'public,console' },
    { enabled_sections: ['marketing'] }, { enabled_sections: ['public', 'unknown'] },
    { enabled_sections: ['console', 'console'] }, { enabled_sections: [null] },
  ])('fails closed for malformed explicit web configuration %j', (web) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web };
    expect(getEnabledWebSections()).toEqual([]);
    expect(isWebPathEnabled('/')).toBe(false);
    expect(isWebPathEnabled('/console')).toBe(false);
    expect(isWebPathEnabled('/auth/callback')).toBe(false);
  });
});
