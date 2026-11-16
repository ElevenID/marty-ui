import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { useOrganizationDefaults } from '../useOrganizationDefaults';
import { getOrganizationDefaults } from '../../services/organizationsApi';

vi.mock('../../services/organizationsApi', () => ({ getOrganizationDefaults: vi.fn() }));
beforeEach(() => { vi.resetAllMocks(); });

it.each([undefined, null, ''])('does not fetch defaults without an active organization (%s)', async (organizationId) => {
  const { result } = renderHook(() => useOrganizationDefaults(organizationId));
  await act(async () => {});
  expect(result.current).toEqual({ defaults: null, loading: false, error: null });
  expect(getOrganizationDefaults).not.toHaveBeenCalled();
});

it('does not expose defaults whose returned organization differs from the requested organization', async () => {
  vi.mocked(getOrganizationDefaults).mockResolvedValue({ organization_id: 'other-org', default_trust_profile_id: 'foreign-trust' });
  const { result } = renderHook(() => useOrganizationDefaults('org-a'));
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.defaults).toBeNull();
  expect(result.current.error).toBeInstanceOf(Error);
});
