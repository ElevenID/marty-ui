import { beforeEach, describe, expect, it, vi } from 'vitest';
import { validatePolicyCreationDependencies as validate } from '../policyCreationDependencies';
import { getTrustProfile, getCredentialTemplate } from '../presentationPolicyApi';
vi.mock('../presentationPolicyApi', () => ({ getTrustProfile: vi.fn(), getCredentialTemplate: vi.fn() }));
const data = { selectedTrustProfile: { id: 'trust' }, selectedTemplate: { id: 'credential-template:template' }, policyConfig: { credential_requirements: [] } };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getTrustProfile).mockResolvedValue({ id: 'trust', organization_id: 'org', status: 'active' });
  vi.mocked(getCredentialTemplate).mockResolvedValue({ id: 'template', organization_id: 'org', status: 'ACTIVE' });
});
describe('submission-time policy dependencies', () => {
  it('reads selected resources before allowing mutation', async () => {
    await validate(data, 'org');
    expect(getTrustProfile).toHaveBeenCalledWith('trust');
    expect(getCredentialTemplate).toHaveBeenCalledWith('template');
  });
  it.each(['DRAFT', 'SUSPENDED', undefined])('rejects trust status %s', async (status) => {
    vi.mocked(getTrustProfile).mockResolvedValue({ id: 'trust', organization_id: 'org', status });
    await expect(validate(data, 'org')).rejects.toThrow('inactive');
    expect(getCredentialTemplate).not.toHaveBeenCalled();
  });
  it('rejects foreign template readback', async () => {
    vi.mocked(getCredentialTemplate).mockResolvedValue({ id: 'template', organization_id: 'foreign', status: 'active' });
    await expect(validate(data, 'org')).rejects.toThrow('another organization');
  });
  it('stops further reads when scope changes in flight', async () => {
    let current = true;
    vi.mocked(getTrustProfile).mockImplementationOnce(async () => { current = false; return { id: 'trust', organization_id: 'org', status: 'active' }; });
    await expect(validate(data, 'org', () => current)).rejects.toThrow('scope changed');
    expect(getCredentialTemplate).not.toHaveBeenCalled();
  });
  it('checks additional requirement trust scope', async () => {
    vi.mocked(getTrustProfile).mockResolvedValueOnce({ id: 'trust', organization_id: 'org', status: 'active' }).mockResolvedValueOnce({ id: 'other', organization_id: 'foreign', status: 'active' });
    await expect(validate({ ...data, policyConfig: { credential_requirements: [{ trust_profile_id: 'other' }] } }, 'org')).rejects.toThrow('another organization');
  });
  it('rejects unknown static policy preset', async () => {
    await expect(validate({ ...data, selectedTemplate: { id: 'missing-preset' } }, 'org')).rejects.toThrow('compatibility');
  });
});
