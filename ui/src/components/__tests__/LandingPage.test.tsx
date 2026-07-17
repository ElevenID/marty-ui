import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import userEvent from '@testing-library/user-event';

import LandingPage from '../LandingPage';

const { mockNavigate, mockSearchParams, mockSetSearchParams, mockUseAuth, mockUseBranding, mockTrackEvent } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockSetSearchParams: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUseBranding: vi.fn(),
  mockTrackEvent: vi.fn(),
}));

vi.mock('../../application/routing/appHandoff', () => ({
  shouldBrowserRedirect: () => false,
  redirectBrowser: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams(), mockSetSearchParams],
  };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, fallback?: string) => fallback || _key,
  }),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => mockUseBranding(),
}));

vi.mock('../../utils/analytics', () => ({
  trackEvent: (...args: unknown[]) => mockTrackEvent(...args),
}));

vi.mock('../seo', () => ({
  SEOHead: () => null,
  organizationSchema: () => ({}),
}));

vi.mock('../diagrams', () => ({
  UnifiedIdentityFlowDiagram: () => <div>Unified Identity Flow</div>,
  StandardsStackDiagram: () => <div>Standards Stack</div>,
  InteractiveProtocolMap: () => <div>Interactive Protocol Map</div>,
  DeploymentModelDiagram: () => <div>Deployment Model Diagram</div>,
}));

describe('LandingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      register: vi.fn(),
    });
    mockUseBranding.mockReturnValue({
      branding: { appName: 'ElevenID LLC' },
    });
  });

  it('redirects authenticated users to the applicant console', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      register: vi.fn(),
    });

    render(<LandingPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/applicant', { replace: true });
    });
  });

  it('shows a loading state while auth is being resolved', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
      register: vi.fn(),
    });

    render(<LandingPage />);

    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('displays auth_error messages and clears them from the URL', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('auth_error=Login+failed%3A+access_denied&foo=bar'));

    render(<LandingPage />);

    expect(await screen.findByText('Login failed: access_denied')).toBeInTheDocument();
    expect(mockSetSearchParams).toHaveBeenCalledTimes(1);

    const [nextParams, options] = mockSetSearchParams.mock.calls[0];
    expect(nextParams).toBeInstanceOf(URLSearchParams);
    expect(nextParams.get('auth_error')).toBeNull();
    expect(nextParams.get('foo')).toBe('bar');
    expect(options).toEqual({ replace: true });
  });

  it('renders the upgraded proof, deployment, and developer quickstart sections in the intended order', async () => {
    render(<LandingPage />);

    expect(screen.getByText('Issue once. Reuse everywhere.')).toBeInTheDocument();
    expect(screen.getByText('Start where you are')).toBeInTheDocument();
    expect(screen.getByText('Verify Credentials')).toBeInTheDocument();
    expect(screen.getByText('Issue Credentials')).toBeInTheDocument();
    expect(screen.getByText('Build With ElevenID')).toBeInTheDocument();
    expect(screen.getByText('Built for the ecosystems reviewers already know')).toBeInTheDocument();
    expect(
      await screen.findByText('See the decision surface without a staged demo.', undefined, { timeout: 10000 }),
    ).toBeInTheDocument();
    expect(screen.getByText('Start from a deployment playbook.')).toBeInTheDocument();
    expect(await screen.findByText('How ElevenID Deploys')).toBeInTheDocument();
    expect(await screen.findByText('Deployment Model Diagram')).toBeInTheDocument();
    expect(await screen.findByText('SaaS Verification')).toBeInTheDocument();
    expect(screen.getByText('Self-Hosted Infrastructure')).toBeInTheDocument();
    expect(screen.getByText('Offline Checkpoint Runtime')).toBeInTheDocument();
    expect(screen.getByText('Example: Airport Boarding Gate')).toBeInTheDocument();
    expect(screen.getByText('Verify a credential in one request.')).toBeInTheDocument();
    expect(screen.getByText('POST /v1/credentials/verify')).toBeInTheDocument();

    expect(screen.getByTestId('get-started-btn')).toHaveAttribute('href', '/developers');
    expect(screen.getAllByRole('link', { name: 'View Verification API' })[0]).toHaveAttribute('href', '/verifiable-credential-api');
    expect(screen.getByText('Verify Credentials').closest('a')).toHaveAttribute('href', '/product#verification-api');
    expect(screen.getByText('Issue Credentials').closest('a')).toHaveAttribute('href', '/product#issuance-api');
    expect(screen.getByText('Build With ElevenID').closest('a')).toHaveAttribute('href', '/docs');
    expect(screen.getByText('SaaS Verification').closest('a')).toHaveAttribute('href', '/product#verification-api');
    expect(screen.getByText('Self-Hosted Infrastructure').closest('a')).toHaveAttribute('href', '/product#issuance-api');
    expect(screen.getByText('Offline Checkpoint Runtime').closest('a')).toHaveAttribute('href', '/product#kiosk');

    const productsHeading = await screen.findByText('Products & Capabilities');
    const deploymentHeading = screen.getByText('How ElevenID Deploys');
    const quickstartHeading = screen.getByText('Verify a credential in one request.');
    const standardsHeading = screen.getByText('Standards-Based Architecture');

    expect(productsHeading.compareDocumentPosition(deploymentHeading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(deploymentHeading.compareDocumentPosition(quickstartHeading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(quickstartHeading.compareDocumentPosition(standardsHeading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('tracks quick-start and deployment mode selections', async () => {
    const user = userEvent.setup();

    render(<LandingPage />);

    await user.click(screen.getByText('Verify Credentials'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_quick_start_selected',
      expect.objectContaining({
        page: 'landing',
        section: 'quick_start',
        card_id: 'verify-credentials',
        role: 'Operations',
        destination_path: '/product#verification-api',
      })
    );

    await user.click(await screen.findByText('SaaS Verification'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_deployment_mode_selected',
      expect.objectContaining({
        page: 'landing',
        section: 'deployment_models',
        card_id: 'saas-verification',
        destination_path: '/product#verification-api',
      })
    );
  });

  it('tracks hero and footer CTA clicks with section metadata', async () => {
    const user = userEvent.setup();

    render(<LandingPage />);

    await user.click(screen.getByTestId('get-started-btn'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_cta_clicked',
      expect.objectContaining({
        page: 'landing',
        section: 'hero',
        cta_id: 'start_verifying',
        destination_path: '/developers',
      })
    );

    await user.click(screen.getByTestId('hero-secondary-cta'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_cta_clicked',
      expect.objectContaining({
        page: 'landing',
        section: 'hero',
        cta_id: 'view_verification_api',
        destination_path: '/verifiable-credential-api',
      })
    );

    await user.click(screen.getByTestId('footer-primary-cta'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_cta_clicked',
      expect.objectContaining({
        page: 'landing',
        section: 'footer',
        cta_id: 'start_verifying',
        destination_path: '/developers',
      })
    );

    await user.click(screen.getByTestId('footer-secondary-cta'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_cta_clicked',
      expect.objectContaining({
        page: 'landing',
        section: 'footer',
        cta_id: 'view_verification_api',
        destination_path: '/verifiable-credential-api',
      })
    );

    await user.click(screen.getByTestId('footer-pricing-cta'));
    expect(mockTrackEvent).toHaveBeenCalledWith(
      'landing_cta_clicked',
      expect.objectContaining({
        page: 'landing',
        section: 'footer',
        cta_id: 'view_pricing',
        destination_path: '/pricing',
      })
    );
    expect(mockNavigate).toHaveBeenCalledWith('/pricing');
  });

  it('switches the interactive walkthrough and end-user journey views', async () => {
    const user = userEvent.setup();

    render(<LandingPage />);

    await user.click(screen.getByRole('button', { name: '2. Present the proof' }));
    expect(screen.getByText('Jamie shares only employment status and access zone.')).toBeInTheDocument();
    expect(screen.getByText('Claims disclosed: employment_active, access_zone_hq_north')).toBeInTheDocument();

    await user.click(await screen.findByRole('button', { name: 'Age assurance' }));
    expect(screen.getByText('Prove eligibility without revealing a birthday')).toBeInTheDocument();
    expect(screen.getAllByText('age_over_21').length).toBeGreaterThan(0);

    await user.click(screen.getByRole('button', { name: 'Airline boarding' }));
    expect(screen.getByText('Travel boarding check')).toBeInTheDocument();
    expect(screen.getByText('Throughput stays high without weakening the assurance model.')).toBeInTheDocument();
  });

  it('runs the proof lab verification flow for the selected scenario', async () => {
    const user = userEvent.setup();

    render(<LandingPage />);

  expect(await screen.findByTestId('proof-lab-request-preview')).toHaveTextContent('policy_age_over_21');
  expect(screen.getByTestId('proof-lab-presentation-preview')).toHaveTextContent('RetailAgeCredential');

    await user.click(screen.getByRole('button', { name: 'Enterprise access' }));
    expect(screen.getByTestId('proof-lab-request-preview')).toHaveTextContent('policy_hq_north_access');
    expect(screen.getByTestId('proof-lab-presentation-preview')).toHaveTextContent('WorkforceAccessBadge');

    await user.click(screen.getByTestId('proof-lab-run-button'));

    expect(await screen.findByTestId('proof-lab-result-chip')).toHaveTextContent('VERIFIED');
    expect(screen.getByText('Door and portal both accept the same workforce credential under separate policies.')).toBeInTheDocument();
    expect(screen.getByText('Issuer: did:web:corp.issuer.elevenid.demo')).toBeInTheDocument();
  });
});
