import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, renderWithRouter, screen, waitFor } from '@test/utils';
import { Link, Route, Routes } from 'react-router';
import PreviewFlowPage from './PreviewFlowPage';

const { getFlow, getTemplate, getCredential, readApplicant, write, auth } = vi.hoisted(() => ({
  getFlow: vi.fn(), getTemplate: vi.fn(), getCredential: vi.fn(),
  readApplicant: vi.fn(), write: vi.fn(),
  auth: { user: { user_id: 'operator-1', email: 'operator@example.com' }, organizationId: 'org-1' },
}));
vi.mock('../../application/vendor', () => ({ fetchPreviewFlow: getFlow }));
vi.mock('../../services/applicationTemplatesApi', () => ({
  getApplicationTemplate: getTemplate,
  listApplicationTemplates: vi.fn(() => { throw new Error('Preview must use its exact linked template'); }),
}));
vi.mock('../../services/api', () => ({ get: getCredential, post: write }));
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../hooks/useWalletPreferences', () => ({ default: () => ({ walletIds: [] }) }));
vi.mock('../../services/applicantApi', () => ({
  getMyApplicantProfile: readApplicant, upsertMyApplicantProfile: write,
  createApplication: write, submitApplicationEvidence: write, listApplications: readApplicant,
  submitApplication: write, withdrawApplication: write, enrollMyBiometric: write,
}));
vi.mock('../../services/credentialsApi', () => ({ generateIssuanceOffer: write }));
vi.mock('../console/applicant/ClaimCredentialDialog', () => ({ default: () => null }));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

const flow = { id: 'flow-1', organization_id: 'org-1', name: 'Flow one', status: 'ACTIVE', credential_template_id: 'credential-1' };
const credential = { id: 'credential-1', organization_id: 'org-1', name: 'Credential one', credential_type: 'ExampleCredential', claims: [] };
const template = { id: 'application-1', organization_id: 'org-1', credential_template_id: 'credential-1', name: 'Linked application', form_fields: [{ field_id: 'email', label: 'Contact email', field_type: 'EMAIL', required: true }] };

function routes() {
  return <><Link to="/applicant/preview/flows/flow-2?organization_id=org-1">Next flow</Link>
    <Routes><Route path="/applicant/preview/flows/:flowId" element={<PreviewFlowPage />} /></Routes></>;
}

function renderPreview(query = '?organization_id=org-1') {
  return renderWithRouter(routes(), { initialEntries: [`/applicant/preview/flows/flow-1${query}`] });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function nextFlow() {
  getFlow.mockResolvedValue({ ...flow, id: 'flow-2', credential_template_id: 'credential-2' });
  getCredential.mockResolvedValue({ ...credential, id: 'credential-2', name: 'Credential two' });
  fireEvent.click(screen.getByRole('link', { name: 'Next flow' }));
}

describe('Flow preview uses the routed native definition', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    sessionStorage.clear();
    auth.organizationId = 'org-1'; auth.user = { user_id: 'operator-1', email: 'operator@example.com' };
    getFlow.mockResolvedValue(flow); getTemplate.mockResolvedValue(template); getCredential.mockResolvedValue(credential);
  });

  it('renders and simulates a fresh real route without an applicant or live writes', async () => {
    renderPreview();
    expect(await screen.findByRole('heading', { name: credential.name })).toBeInTheDocument();
    expect(getFlow).toHaveBeenCalledWith({ flowId: 'flow-1' });
    expect(getCredential).toHaveBeenCalledWith('/v1/credential-templates/credential-1?organization_id=org-1');
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByTestId('submit-application-btn'));
    expect(await screen.findByText('applicationForm.success.previewTitle')).toBeInTheDocument();
    expect(readApplicant).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
  });

  it('loads an application-template flow and renders its actual fields', async () => {
    getFlow.mockResolvedValue({ ...flow, credential_template_id: null, application_template_id: template.id });
    renderPreview();
    expect(await screen.findByRole('heading', { name: template.name })).toBeInTheDocument();
    expect(screen.getByLabelText(/Contact email/)).toBeInTheDocument();
    expect(getTemplate).toHaveBeenCalledWith(template.id, 'org-1');
    expect(getCredential).toHaveBeenCalledWith('/v1/credential-templates/credential-1?organization_id=org-1');
    expect(write).not.toHaveBeenCalled();
  });

  it.each([
    { id: 'another-flow' }, { organization_id: 'org-2' }, { organization_id: '' },
  ])('rejects a wrong or unowned flow response: %j', async (replacement) => {
    getFlow.mockResolvedValue({ ...flow, ...replacement });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(getTemplate).not.toHaveBeenCalled(); expect(getCredential).not.toHaveBeenCalled();
    expect(screen.queryByTestId('credential-application-form')).not.toBeInTheDocument();
  });

  it.each([
    { id: 'another-application' }, { organization_id: 'org-2' }, { credential_template_id: '' },
  ])('rejects an application reference mismatch: %j', async (replacement) => {
    getFlow.mockResolvedValue({ ...flow, credential_template_id: null, application_template_id: template.id });
    getTemplate.mockResolvedValue({ ...template, ...replacement });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/Application Template does not belong/i);
    expect(getCredential).not.toHaveBeenCalled();
  });

  it('rejects inconsistent direct and application credential references', async () => {
    getFlow.mockResolvedValue({ ...flow, credential_template_id: 'another-credential', application_template_id: template.id });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/Application Template does not belong/i);
    expect(getCredential).not.toHaveBeenCalled();
  });

  it.each([{ id: 'another-credential' }, { organization_id: 'org-2' }])('rejects a credential mismatch: %j', async (replacement) => {
    getCredential.mockResolvedValue({ ...credential, ...replacement });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/Credential Template does not belong/i);
    expect(screen.queryByTestId('credential-application-form')).not.toBeInTheDocument();
  });

  it('explains flows without an applicant application instead of rendering a blank page', async () => {
    getFlow.mockResolvedValue({ ...flow, credential_template_id: null, presentation_policy_id: 'policy-1' });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/no applicant application to preview/i);
    expect(getTemplate).not.toHaveBeenCalled(); expect(getCredential).not.toHaveBeenCalled();
  });

  it.each(['DRAFT', 'PAUSED', 'ARCHIVED'])('shows the native %s status while allowing simulation', async (status) => {
    getFlow.mockResolvedValue({ ...flow, status });
    renderPreview();
    expect(await screen.findByRole('heading', { name: credential.name })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(new RegExp(status, 'i'));
    expect(screen.getByTestId('submit-application-btn')).toHaveTextContent('applicationForm.navigation.previewSubmit');
  });

  it('uses the authorized definition owner rather than the stale auth organization without a query', async () => {
    auth.organizationId = 'org-2';
    renderPreview('');
    expect(await screen.findByRole('heading', { name: credential.name })).toBeInTheDocument();
    expect(getCredential).toHaveBeenCalledWith('/v1/credential-templates/credential-1?organization_id=org-1');
  });

  it('still rejects an explicit organization constraint that differs from the definition owner', async () => {
    auth.organizationId = 'org-2';
    renderPreview('?organization_id=org-2');
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(getCredential).not.toHaveBeenCalled();
  });

  it('rejects an explicitly empty organization constraint', async () => {
    renderPreview('?organization_id=');
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(getCredential).not.toHaveBeenCalled();
  });

  it('does not follow an obsolete flow response after navigating to another flow', async () => {
    const old = deferred<typeof flow>(); getFlow.mockReturnValueOnce(old.promise);
    renderPreview();
    await waitFor(() => expect(getFlow).toHaveBeenCalledTimes(1));
    nextFlow();
    expect(await screen.findByRole('heading', { name: 'Credential two' })).toBeInTheDocument();
    await act(async () => { old.resolve(flow); });
    expect(getCredential).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('heading', { name: credential.name })).not.toBeInTheDocument();
  });

  it('does not read a credential from an obsolete application-template response', async () => {
    const old = deferred<typeof template>(); getTemplate.mockReturnValueOnce(old.promise);
    getFlow.mockResolvedValueOnce({ ...flow, credential_template_id: null, application_template_id: template.id });
    renderPreview();
    await waitFor(() => expect(getTemplate).toHaveBeenCalledTimes(1));
    nextFlow();
    expect(await screen.findByRole('heading', { name: 'Credential two' })).toBeInTheDocument();
    await act(async () => { old.resolve(template); });
    expect(getCredential).toHaveBeenCalledTimes(1);
    expect(getCredential).toHaveBeenCalledWith('/v1/credential-templates/credential-2?organization_id=org-1');
  });

  it('discards an obsolete credential response and resets the form between routed flows', async () => {
    const old = deferred<typeof credential>(); getCredential.mockReturnValueOnce(old.promise);
    renderPreview();
    await waitFor(() => expect(getCredential).toHaveBeenCalledTimes(1));
    nextFlow();
    expect(await screen.findByRole('heading', { name: 'Credential two' })).toBeInTheDocument();
    await act(async () => { old.resolve(credential); });
    expect(screen.queryByRole('heading', { name: credential.name })).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
  });

  it('does not follow a pending flow after leaving the preview', async () => {
    const old = deferred<typeof flow>(); getFlow.mockReturnValueOnce(old.promise);
    const view = renderPreview();
    await waitFor(() => expect(getFlow).toHaveBeenCalledTimes(1));
    view.unmount();
    await act(async () => { old.resolve(flow); });
    expect(getTemplate).not.toHaveBeenCalled(); expect(getCredential).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
  });
});
