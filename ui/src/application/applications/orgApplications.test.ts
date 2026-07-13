import { describe, expect, it, vi } from 'vitest';
import { mergeApplicantsIntoApplications } from './orgApplicationsFlow';
import { loadOrganizationApplications } from './orgApplicationsUseCases';

describe('orgApplicationsFlow', () => {
  it('merges applicant emails into application records', () => {
    const apps = [
      { id: 'app-1', applicant_id: 'a-1', status: 'SUBMITTED', metadata: {} },
      { id: 'app-2', applicant_id: 'a-2', status: 'Approved', credential_display_name: 'mDL', metadata: {} },
    ];
    const applicants = [
      { id: 'a-1', email: 'alice@example.com' },
    ];

    const result = mergeApplicantsIntoApplications(apps, applicants);

    expect(result).toHaveLength(2);
    expect(result[0].applicant).toBe('alice@example.com');
    expect(result[0].status).toBe('submitted');
    expect(result[1].applicant).toBe('a-2'); // no matching applicant → falls back to id
    expect(result[1].credentialType).toBe('mDL');
  });
});

describe('orgApplicationsUseCases', () => {
  it('loads the canonical organization application page once', async () => {
    const getApplications = vi.fn().mockResolvedValue({
      items: [{
        id: 'app-1',
        applicant_id: 'a-1',
        applicant_identifier: 'alice@example.com',
        status: 'submitted',
        metadata: {},
      }],
    });

    const result = await loadOrganizationApplications({
      organizationId: 'org-1',
      getApplications,
    });

    expect(result).toHaveLength(1);
    expect(result[0].applicant).toBe('alice@example.com');
    expect(getApplications).toHaveBeenCalledWith('org-1');
  });

  it('fails before loading applications without an organization id', async () => {
    const getApplications = vi.fn();

    await expect(loadOrganizationApplications({
      organizationId: '',
      getApplications,
    })).rejects.toMatchObject({ code: 'ORG_REQUIRED' });

    expect(getApplications).not.toHaveBeenCalled();
  });
});
