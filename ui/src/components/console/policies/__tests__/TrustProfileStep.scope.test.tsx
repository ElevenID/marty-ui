import { act, waitFor } from '@testing-library/react';
import { render } from '@test/utils';
import { beforeEach, expect, it, vi } from 'vitest';
import Step from '../steps/TrustProfileStep';
import { listTrustProfiles } from '../../../../services/presentationPolicyApi';
const scope = vi.hoisted(() => ({ org: 'org-a' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.org }) }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listTrustProfiles: vi.fn() }));
beforeEach(() => { scope.org = 'org-a'; vi.resetAllMocks(); });
it('does not auto-select a late previous-organization response', async () => {
  let resolve!: (value: unknown[]) => void;
  vi.mocked(listTrustProfiles).mockImplementationOnce(() => new Promise((r) => { resolve = r; })).mockResolvedValueOnce([]);
  const select = vi.fn();
  const view = render(<Step selectedTrustProfile={null} onSelectTrustProfile={select} />);
  await waitFor(() => expect(listTrustProfiles).toHaveBeenCalledTimes(1));
  scope.org = 'org-b'; view.rerender(<Step selectedTrustProfile={null} onSelectTrustProfile={select} />);
  await waitFor(() => expect(listTrustProfiles).toHaveBeenCalledTimes(2));
  await act(async () => { resolve([{ id: 'old', organization_id: 'org-a', status: 'ACTIVE' }]); });
  expect(select).not.toHaveBeenCalled();
});
it('excludes inactive and foreign entries before auto-selection', async () => {
  vi.mocked(listTrustProfiles).mockResolvedValue([{ id: 'foreign', organization_id: 'org-b', status: 'ACTIVE' }, { id: 'draft', organization_id: 'org-a', status: 'DRAFT' }, { id: 'owned', organization_id: 'org-a', status: 'active' }]);
  const select = vi.fn(); render(<Step selectedTrustProfile={null} onSelectTrustProfile={select} />);
  await waitFor(() => expect(select).toHaveBeenCalledWith(expect.objectContaining({ id: 'owned' })));
  expect(select).toHaveBeenCalledTimes(1);
});
it('discards a response after unmount', async () => {
  let resolve!: (value: unknown[]) => void;
  vi.mocked(listTrustProfiles).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
  const select = vi.fn(); const view = render(<Step selectedTrustProfile={null} onSelectTrustProfile={select} />);
  await waitFor(() => expect(listTrustProfiles).toHaveBeenCalledTimes(1)); view.unmount();
  await act(async () => { resolve([{ id: 'old', organization_id: 'org-a', status: 'ACTIVE' }]); });
  expect(select).not.toHaveBeenCalled();
});
