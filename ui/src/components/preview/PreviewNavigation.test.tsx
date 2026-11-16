import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { Link, Route, Routes } from 'react-router';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import PreviewLayout from './PreviewLayout';
import PreviewCatalogPage from './PreviewCatalogPage';
import PreviewCredentialPage from './PreviewCredentialPage';
import PreviewApplicationPage from './PreviewApplicationPage';
import PreviewFlowPage from './PreviewFlowPage';

const { getCredential, getApplication, getFlow, redirect, auth } = vi.hoisted(() => ({
  getCredential: vi.fn(), getApplication: vi.fn(), getFlow: vi.fn(), redirect: vi.fn(),
  auth: { user: { user_id: 'operator-1' }, organizationId: 'unrelated-org', organizationName: 'Unverified home organization' },
}));
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../application/vendor', () => ({
  fetchPreviewCredentialTemplate: getCredential, fetchPreviewFlow: getFlow,
}));
vi.mock('../../services/applicationTemplatesApi', () => ({ getApplicationTemplate: getApplication }));
vi.mock('../../services/api', () => ({ get: getCredential }));
vi.mock('../../application/routing/appHandoff', async () => ({
  ...await vi.importActual('../../application/routing/appHandoff'), redirectBrowser: redirect,
}));
vi.mock('../applicant/ApplicationForm', () => ({ default: () => (
  <div data-testid="application-simulation" data-preview={usePreview().isPreview} />
) }));
vi.mock('../applicant/CredentialCatalog', () => ({ default: () => (
  <div data-testid="catalog-simulation" data-preview={usePreview().isPreview} />
) }));

const credential = { id: 'credential-1', organization_id: 'owner-org', name: 'Native credential', status: 'ACTIVE', claims: [{ name: 'email', required: true }] };
const application = { id: 'application-1', organization_id: 'owner-org', credential_template_id: 'credential-1', name: 'Native application', form_fields: [] };
const flow = { id: 'flow-1', organization_id: 'owner-org', credential_template_id: 'credential-1', name: 'Native flow', status: 'ACTIVE' };
const originalClosed = Object.getOwnPropertyDescriptor(window, 'closed');

function previewRoutes() {
  return <><Link to="/finished">Leave preview</Link><Routes>
    <Route path="/applicant/preview" element={<PreviewLayout />}>
      <Route path="catalog" element={<PreviewCatalogPage />} />
      <Route path="credentials/:templateId" element={<PreviewCredentialPage />} />
      <Route path="applications/:applicationTemplateId" element={<PreviewApplicationPage />} />
      <Route path="flows/:flowId" element={<PreviewFlowPage />} />
    </Route>
    <Route path="/finished" element={<h1>Finished</h1>} />
  </Routes></>;
}

function ExitControl() {
  const { exitPreview } = usePreview();
  return <button onClick={exitPreview}>Exit</button>;
}

describe('Preview navigation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.user = { user_id: 'operator-1' };
    getCredential.mockResolvedValue(credential);
    getApplication.mockResolvedValue(application);
    getFlow.mockResolvedValue(flow);
    Object.defineProperty(window, 'closed', { configurable: true, writable: true, value: false });
    vi.spyOn(window, 'close').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    if (originalClosed) Object.defineProperty(window, 'closed', originalClosed);
    else Reflect.deleteProperty(window, 'closed');
  });

  it.each([
    ['catalog', 'Credential Catalog', '/console/org/templates/credentials'],
    ['credentials/credential-1', 'Credential: Native credential', '/console/org/templates/credentials'],
    ['applications/application-1', 'Application Template: application-1', '/console/org/templates/applications'],
    ['flows/flow-1', 'Flow: Native flow', '/console/org/flows/definitions'],
  ])('shows the %s context in its banner and exits to the matching editor', async (path, label, returnUrl) => {
    const { user } = renderWithRouter(previewRoutes(), {
      initialEntries: [`/applicant/preview/${path}?organization_id=owner-org`],
    });
    expect(await screen.findByText(label)).toBeInTheDocument();
    const banner = screen.getByRole('region', { name: 'Preview Mode' });
    expect(within(banner).getByText(label)).toBeInTheDocument();
    expect(within(banner).queryByText(/Unverified home organization/)).not.toBeInTheDocument();
    await user.click(within(banner).getByRole('button', { name: 'Exit Preview' }));

    expect(window.close).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(redirect).toHaveBeenCalledExactlyOnceWith(returnUrl, { replace: false }));
  });

  it('keeps the persistent preview notice separate from page errors and removes unverified ownership', async () => {
    getCredential.mockRejectedValueOnce(new Error('Credential preview unavailable'));
    renderWithRouter(previewRoutes(), { initialEntries: ['/applicant/preview/credentials/credential-1'] });

    expect(await screen.findByRole('alert')).toHaveTextContent('Credential preview unavailable');
    expect(screen.getByRole('region', { name: 'Preview Mode' })).toBeVisible();
    expect(screen.queryByText(/Unverified home organization/)).not.toBeInTheDocument();
  });

  it('does not navigate when the browser actually closes the preview window', () => {
    vi.useFakeTimers();
    vi.mocked(window.close).mockImplementation(() => { Object.defineProperty(window, 'closed', { configurable: true, writable: true, value: true }); });
    renderWithRouter(<PreviewProvider returnUrl="/console/org/flows/definitions"><ExitControl /></PreviewProvider>, {
      initialEntries: ['/applicant/preview/flows/flow-1'],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Exit' }));
    act(() => vi.advanceTimersByTime(150));

    expect(window.close).toHaveBeenCalledTimes(1);
    expect(redirect).not.toHaveBeenCalled();
  });

  it('cancels pending exit navigation when the preview provider unmounts', () => {
    vi.useFakeTimers();
    const view = renderWithRouter(<PreviewProvider returnUrl="/console/org/flows/definitions"><ExitControl /></PreviewProvider>, {
      initialEntries: ['/applicant/preview/flows/flow-1'],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Exit' }));
    view.unmount();
    act(() => vi.advanceTimersByTime(150));

    expect(redirect).not.toHaveBeenCalled();
  });

  it('cancels an exit fallback after navigating away through the real nested preview routes', () => {
    vi.useFakeTimers();
    renderWithRouter(previewRoutes(), { initialEntries: ['/applicant/preview/catalog'] });
    fireEvent.click(screen.getByRole('button', { name: 'Exit Preview' }));
    expect(window.close).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('link', { name: 'Leave preview' }));
    act(() => vi.advanceTimersByTime(150));

    expect(screen.getByRole('heading', { name: 'Finished' })).toBeVisible();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('does not follow an application response from the previous account with a credential read', async () => {
    let resolveOld!: (value: unknown) => void;
    let resolveCurrent!: (value: unknown) => void;
    getApplication.mockReturnValueOnce(new Promise(resolve => { resolveOld = resolve; }));
    const { rerender } = renderWithRouter(previewRoutes(), {
      initialEntries: ['/applicant/preview/applications/application-1?organization_id=owner-org'],
    });
    await waitFor(() => expect(getApplication).toHaveBeenCalledTimes(1));
    getApplication.mockReturnValueOnce(new Promise(resolve => { resolveCurrent = resolve; }));
    auth.user = { user_id: 'operator-2' };
    rerender(previewRoutes());
    await waitFor(() => expect(getApplication).toHaveBeenCalledTimes(2));
    await act(async () => resolveOld(application));
    expect(getCredential).not.toHaveBeenCalled();
    expect(screen.queryByTestId('application-simulation')).not.toBeInTheDocument();

    await act(async () => resolveCurrent(application));
    expect(await screen.findByTestId('application-simulation')).toHaveAttribute('data-preview', 'true');
    expect(getCredential).toHaveBeenCalledExactlyOnceWith('/v1/credential-templates/credential-1?organization_id=owner-org');
  });

  it('uses router navigation for a return destination on the same surface', () => {
    vi.useFakeTimers();
    renderWithRouter(<Routes>
      <Route path="/applicant/preview/catalog" element={<PreviewProvider returnUrl="/applicant/preview/finished"><ExitControl /></PreviewProvider>} />
      <Route path="/applicant/preview/finished" element={<h1>Preview finished</h1>} />
    </Routes>, { initialEntries: ['/applicant/preview/catalog'] });
    fireEvent.click(screen.getByRole('button', { name: 'Exit' }));
    act(() => vi.advanceTimersByTime(150));

    expect(screen.getByRole('heading', { name: 'Preview finished' })).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });
});
