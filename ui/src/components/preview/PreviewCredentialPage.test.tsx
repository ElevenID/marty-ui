import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { Link, Route, Routes } from 'react-router';
import PreviewCredentialPage from './PreviewCredentialPage';

const { getTemplate, auth } = vi.hoisted(() => ({
  getTemplate: vi.fn(), auth: { user: { user_id: 'operator-1' }, organizationId: 'org-2' },
}));
vi.mock('../../application/vendor', () => ({ fetchPreviewCredentialTemplate: getTemplate }));
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => auth }));

const template = {
  id: 'credential-1', organization_id: 'org-1', name: 'Native credential', status: 'ACTIVE',
  credential_type: 'ExampleCredential', claims: [
    { name: 'given_name', required: true, display: { label: 'Preferred first name' } },
    { name: 'family_name', required: true },
    { name: 'email', required: false, display: { label: 'Contact address' } },
  ],
};

function routes() {
  return <><Link to="/applicant/preview/credentials/credential-2?organization_id=org-1">Next credential</Link>
    <Routes><Route path="/applicant/preview/credentials/:templateId" element={<PreviewCredentialPage />} /></Routes></>;
}

function renderPreview(query = '?organization_id=org-1') {
  return renderWithRouter(routes(), { initialEntries: [`/applicant/preview/credentials/credential-1${query}`] });
}

describe('Credential preview uses native claims and ownership', () => {
  beforeEach(() => {
    vi.resetAllMocks(); auth.user = { user_id: 'operator-1' }; auth.organizationId = 'org-2';
    getTemplate.mockResolvedValue(template);
  });

  it('renders required and optional native claims with their display labels', async () => {
    renderPreview();
    expect(await screen.findByRole('heading', { name: template.name })).toBeInTheDocument();
    const required = screen.getByRole('list', { name: 'Required information' });
    expect(within(required).getByText('Preferred first name')).toBeInTheDocument();
    expect(within(required).getByText('Family Name')).toBeInTheDocument();
    expect(within(required).queryByText('Contact address')).not.toBeInTheDocument();
    expect(within(screen.getByRole('list', { name: 'Optional information' })).getByText('Contact address')).toBeInTheDocument();
    expect(screen.queryByText(/Missing Configuration/i)).not.toBeInTheDocument();
    expect(getTemplate).toHaveBeenCalledWith({ templateId: 'credential-1' });
  });

  it('does not label a template with only optional claims as unconfigured', async () => {
    getTemplate.mockResolvedValue({ ...template, claims: [template.claims[2]] });
    renderPreview();
    expect(await screen.findByText('Contact address')).toBeInTheDocument();
    expect(screen.queryByText(/Missing Configuration/i)).not.toBeInTheDocument();
    expect(screen.getByText('No specific requirements configured.')).toBeInTheDocument();
  });

  it('reports a template with no claims as unconfigured', async () => {
    getTemplate.mockResolvedValue({ ...template, claims: [] });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/no configured fields/i);
  });

  it.each(['DRAFT', 'DEPRECATED', 'ARCHIVED'])('shows the native %s status', async (status) => {
    getTemplate.mockResolvedValue({ ...template, status });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(new RegExp(status, 'i'));
  });

  it.each([{ id: 'another-credential' }, { organization_id: 'org-2' }, { organization_id: '' }])('refuses a mismatched template: %j', async (replacement) => {
    getTemplate.mockResolvedValue({ ...template, ...replacement });
    renderPreview();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(screen.queryByRole('heading', { name: template.name })).not.toBeInTheDocument();
  });

  it('accepts authorized native ownership without a query despite a stale auth organization', async () => {
    renderPreview('');
    expect(await screen.findByRole('heading', { name: template.name })).toBeInTheDocument();
  });

  it('refuses an explicitly empty organization constraint', async () => {
    renderPreview('?organization_id=');
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
  });

  it('keeps the new routed credential when an earlier request resolves last', async () => {
    let resolveOld!: (value: unknown) => void;
    getTemplate.mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }));
    renderPreview();
    await waitFor(() => expect(getTemplate).toHaveBeenCalledTimes(1));
    getTemplate.mockResolvedValue({ ...template, id: 'credential-2', name: 'Current credential' });
    fireEvent.click(screen.getByRole('link', { name: 'Next credential' }));
    expect(await screen.findByRole('heading', { name: 'Current credential' })).toBeInTheDocument();
    await act(async () => { resolveOld(template); });
    expect(screen.queryByRole('heading', { name: template.name })).not.toBeInTheDocument();
  });

  it('rechecks access and discards the old account response after an account replacement', async () => {
    let resolveOld!: (value: unknown) => void;
    getTemplate.mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }));
    const view = renderPreview();
    await waitFor(() => expect(getTemplate).toHaveBeenCalledTimes(1));
    auth.user = { user_id: 'operator-2' };
    getTemplate.mockRejectedValue(new Error('Template access denied'));
    view.rerender(routes());
    expect(await screen.findByRole('alert')).toHaveTextContent('Template access denied');
    await act(async () => { resolveOld(template); });
    expect(screen.queryByRole('heading', { name: template.name })).not.toBeInTheDocument();
    expect(getTemplate).toHaveBeenCalledTimes(2);
  });
});
