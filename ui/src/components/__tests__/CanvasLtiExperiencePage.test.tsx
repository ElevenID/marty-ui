import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import CanvasLtiExperiencePage from '../pages/CanvasLtiExperiencePage';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}));

let currentSession: Record<string, unknown>;
let deepLinkingResponse: Record<string, unknown>;

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams('code=one-time-experience-code')],
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ isLoading: false }),
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
  post: mockPost,
}));

describe('CanvasLtiExperiencePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    vi.spyOn(window.history, 'replaceState').mockImplementation(() => undefined);
    deepLinkingResponse = {
      canvas_platform_id: 'platform-1',
      organization_id: 'org-1',
      canvas_account_id: 'account-1',
      deep_link_return_url: 'https://canvas-test.elevenidllc.com/api/lti/deep_linking/callback',
      jwt: 'server-signed-deep-link-jwt',
      form_post: {
        method: 'POST',
        action: 'https://canvas-test.elevenidllc.com/api/lti/deep_linking/callback',
        fields: { JWT: 'server-signed-deep-link-jwt' },
      },
    };
    mockPost.mockImplementation(async (endpoint: string) => {
      if (endpoint.endsWith('/experience-sessions/exchange')) {
        return {
          session_token: 'browser-safe-session-token',
          expires_at: '2099-01-01T00:00:00.000Z',
        };
      }
      if (endpoint === '/v1/auth/canvas-lti/finalize') {
        return { authenticated: true };
      }
      if (endpoint.endsWith('/experience-sessions/current/deep-linking-response')) {
        return deepLinkingResponse;
      }
      throw new Error(`Unexpected POST ${endpoint}`);
    });
    currentSession = {
      organization_id: 'org-1',
      canvas_account_id: 'account-1',
      canvas_platform_id: 'platform-1',
      canvas_program_binding_id: 'binding-1',
      application_template_id: 'application-template-1',
      credential_template_id: 'credential-template-1',
      canvas_context: { course_id: 'course-1', title: 'Portable Canvas Course' },
      roles: ['Learner'],
      learner_display_name: 'Ada Learner',
      identity_mapping_status: 'linked',
      verified_launch: {
        subject: 'must-not-render',
        raw_claims: { email: 'must-not-render@example.edu' },
      },
    };
    mockGet.mockImplementation(async () => currentSession);
  });

  it('exchanges the one-time code and renders only the browser-safe session contract', async () => {
    render(<CanvasLtiExperiencePage />);

    expect(await screen.findByText('Portable Canvas Course')).toBeInTheDocument();
    expect(screen.getByText('Ada Learner')).toBeInTheDocument();
    expect(screen.getByText('Learner')).toBeInTheDocument();
    expect(screen.getByText('Canvas identity linked')).toBeInTheDocument();
    expect(screen.queryByText('must-not-render')).not.toBeInTheDocument();
    expect(screen.queryByText('must-not-render@example.edu')).not.toBeInTheDocument();

    expect(mockPost).toHaveBeenNthCalledWith(
      1,
      '/v1/integrations/canvas/lti/experience-sessions/exchange',
      { code: 'one-time-experience-code' },
    );
    expect(mockGet).toHaveBeenCalledWith(
      '/v1/integrations/canvas/lti/experience-sessions/current',
      { headers: { Authorization: 'Bearer browser-safe-session-token' } },
    );
    expect(mockPost).toHaveBeenNthCalledWith(
      2,
      '/v1/auth/canvas-lti/finalize',
      {},
      { headers: { Authorization: 'Bearer browser-safe-session-token' } },
    );
    expect(window.history.replaceState).toHaveBeenCalled();

    await waitFor(() => {
      expect(screen.getByTestId('canvas-lti-continue')).toHaveAttribute(
        'href',
        '/console/applicant/apply/credential-template-1?canvas_lti_state=current&canvas_program_binding_id=binding-1&canvas_platform_id=platform-1&application_template_id=application-template-1',
      );
    });
  });

  it('posts the server-created Deep Linking JWT back to Canvas for an instructor', async () => {
    currentSession = {
      ...currentSession,
      roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
      learner_display_name: 'Iris Instructor',
      lti_capabilities: { deep_linking: true },
    };
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => undefined);
    const { container, user } = render(<CanvasLtiExperiencePage />);

    expect(
      await screen.findByRole('heading', { name: 'Add Marty activity to Canvas' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Instructor')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /continue in elevenid/i })).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalledWith(
      '/v1/auth/canvas-lti/finalize',
      expect.anything(),
      expect.anything(),
    );

    await user.click(screen.getByRole('button', { name: 'Add Marty activity to Canvas' }));

    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith(
        '/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response',
        {},
        { headers: { Authorization: 'Bearer browser-safe-session-token' } },
      );
      expect(submit).toHaveBeenCalledTimes(1);
    });

    const form = container.querySelector('form[target="_top"]');
    expect(form).toHaveAttribute('method', 'post');
    expect(form).toHaveAttribute(
      'action',
      'https://canvas-test.elevenidllc.com/api/lti/deep_linking/callback',
    );
    expect(form?.querySelector('input[name="JWT"]')).toHaveValue('server-signed-deep-link-jwt');
    expect(form?.querySelectorAll('input')).toHaveLength(1);

    submit.mockRestore();
  });

  it('does not offer Deep Linking to a learner', async () => {
    currentSession = {
      ...currentSession,
      lti_capabilities: { deep_linking: true },
    };

    render(<CanvasLtiExperiencePage />);

    expect(
      await screen.findByText(
        'Canvas requires an Instructor or Administrator role to add this activity.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add Marty activity to Canvas' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /continue in elevenid/i })).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalledWith(
      '/v1/auth/canvas-lti/finalize',
      expect.anything(),
      expect.anything(),
    );
  });

  it('refuses a mismatched or non-HTTPS server form contract', async () => {
    currentSession = {
      ...currentSession,
      roles: ['Administrator'],
      lti_capabilities: { deep_linking: true },
    };
    deepLinkingResponse = {
      ...deepLinkingResponse,
      form_post: {
        method: 'POST',
        action: 'http://untrusted.example/deep-link',
        fields: { JWT: 'server-signed-deep-link-jwt', extra: 'must-not-submit' },
      },
    };
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => undefined);
    const { container, user } = render(<CanvasLtiExperiencePage />);

    await user.click(
      await screen.findByRole('button', { name: 'Add Marty activity to Canvas' }),
    );

    expect(
      await screen.findByText(
        'Canvas did not return a valid Deep Linking destination. Reopen the activity from Canvas.',
      ),
    ).toBeInTheDocument();
    expect(submit).not.toHaveBeenCalled();
    expect(container.querySelector('form[target="_top"]')).not.toBeInTheDocument();

    submit.mockRestore();
  });
});
