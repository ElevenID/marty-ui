import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';
import PreviewApplicationPage from './PreviewApplicationPage';

const { getTemplate, getCredential, route } = vi.hoisted(() => ({
  getTemplate: vi.fn(), getCredential: vi.fn(), route: { id: 'application-1', org: 'org-1' },
}));
vi.mock('react-router', async () => ({
  ...await vi.importActual('react-router'),
  useParams: () => ({ applicationTemplateId: route.id }),
  useSearchParams: () => [new URLSearchParams({ organization_id: route.org })],
}));
vi.mock('../../services/applicationTemplatesApi', () => ({ getApplicationTemplate: getTemplate }));
vi.mock('../../services/api', () => ({ get: getCredential }));
vi.mock('../applicant/ApplicationForm', () => ({
  default: ({ previewContext }: any) => <div data-testid="actual-template-form">{previewContext.applicationTemplate.name}</div>,
}));

const template = { id: 'application-1', organization_id: 'org-1', credential_template_id: 'credential-1', name: 'Actual routed application', form_fields: [] };
const credential = { id: 'credential-1', organization_id: 'org-1', credential_type: 'Membership', claims: [] };

describe('Application Template preview binding', () => {
  beforeEach(() => {
    vi.clearAllMocks(); route.id = 'application-1'; route.org = 'org-1';
    getTemplate.mockResolvedValue(template); getCredential.mockResolvedValue(credential);
  });

  it('loads the exact routed template and its owning credential before rendering', async () => {
    renderWithRouter(<PreviewApplicationPage />);
    expect(await screen.findByTestId('actual-template-form')).toHaveTextContent(template.name);
    expect(getTemplate).toHaveBeenCalledWith('application-1', 'org-1');
    expect(getCredential).toHaveBeenCalledWith('/v1/credential-templates/credential-1?organization_id=org-1');
  });

  it.each(['wrong-id', 'wrong-org'])('rejects %s without rendering another application', async (kind) => {
    getTemplate.mockResolvedValue({ ...template, ...(kind === 'wrong-id' ? { id: 'another-application' } : { organization_id: 'org-2' }) });
    renderWithRouter(<PreviewApplicationPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(getCredential).not.toHaveBeenCalled();
    expect(screen.queryByTestId('actual-template-form')).not.toBeInTheDocument();
  });

  it('rejects a credential response from another organization', async () => {
    getCredential.mockResolvedValue({ ...credential, organization_id: 'org-2' });
    renderWithRouter(<PreviewApplicationPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/does not belong/i);
    expect(screen.queryByTestId('actual-template-form')).not.toBeInTheDocument();
  });

  it('ignores an earlier response after changing the routed template', async () => {
    let resolveOld!: (value: unknown) => void;
    getTemplate.mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }));
    const { rerender } = renderWithRouter(<PreviewApplicationPage />);
    await waitFor(() => expect(getTemplate).toHaveBeenCalled());
    route.id = 'application-2';
    getTemplate.mockResolvedValue({ ...template, id: 'application-2', name: 'Current application' });
    rerender(<PreviewApplicationPage />);
    expect(await screen.findByTestId('actual-template-form')).toHaveTextContent('Current application');
    resolveOld(template);
    await waitFor(() => expect(screen.getByTestId('actual-template-form')).not.toHaveTextContent(template.name));
  });
});
