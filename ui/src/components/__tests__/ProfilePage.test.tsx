import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@test/utils';
import { fireEvent, within } from '@testing-library/react';
import { createElement, useEffect, useLayoutEffect, type PropsWithChildren } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';

import ProfilePage from '../ProfilePage';
import { formatOfficialReference } from '../../utils/officialReferences';
import { updateProfilePicture } from '../../services/authApi';

const mockSetActiveOrganizationId = vi.fn();
const mockSetActiveOrgId = vi.fn();
const mockRefreshUser = vi.fn();

function createAuthState() {
  return {
    user: {
      user_id: 'native-account-1',
      email: 'applicant@example.com',
      username: 'ux-crawl',
      given_name: 'UX',
      family_name: 'Crawl',
      applicant_id: 'app-1',
      roles: ['applicant'],
    } as Record<string, unknown> | null,
    isAdministrator: false,
    isApplicant: true,
    organizationId: 'org-1',
    organizations: [
      {
        id: 'org-1',
        name: 'Marty Org',
        membership: {
          status: 'active',
          roles: [{ id: 'role-1', name: 'admin', display_name: 'Administrator' }],
          has_org_console_access: true,
        },
      },
      {
        id: 'org-2',
        name: 'Open Federation',
        membership: {
          status: 'pending',
          roles: [{ id: 'role-2', name: 'applicant', display_name: 'Applicant' }],
          has_org_console_access: false,
        },
      },
    ],
    setActiveOrganizationId: mockSetActiveOrganizationId,
    refreshUser: mockRefreshUser,
  };
}

let mockAuthState = createAuthState();

class ControlledFileReader {
  static LOADING = 1;
  readyState = 1;
  result: string | null = null;
  onload: ((event: { target: ControlledFileReader }) => void) | null = null;
  onerror: (() => void) | null = null;
  abort = vi.fn(() => { this.readyState = 2; });
  readAsDataURL = vi.fn();

  constructor() {
    photoReads.push(this);
  }

  finish(result: string) {
    this.result = result;
    this.readyState = 2;
    this.onload?.({ target: this });
  }
}

const photoReads: ControlledFileReader[] = [];
const firstPhoto = 'data:image/png;base64,Zmlyc3Q=';
const secondPhoto = 'data:image/png;base64,c2Vjb25k';

function selectPhoto(container: HTMLElement, name: string) {
  const file = new File([name], `${name}.png`, { type: 'image/png' });
  fireEvent.change(container.querySelector('input[type="file"]')!, { target: { files: [file] } });
  return photoReads.at(-1)!;
}

vi.mock('../../services/authApi', () => ({
  updateProfilePicture: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockAuthState,
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org-1',
    setActiveOrgId: mockSetActiveOrgId,
  }),
}));

describe('ProfilePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthState = createAuthState();
    photoReads.length = 0;
    mockRefreshUser.mockReset().mockResolvedValue(undefined);
    vi.mocked(updateProfilePicture).mockReset().mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('applies the profile and membership layout without leaking obsolete DOM props', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warnings = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { container } = render(<ProfilePage />);

    expect(container.querySelector('[item], [xs], [md], [flexwrap], [justifycontent], [fontfamily], [fontweight]')).toBeNull();
    const membershipSection = screen.getByTestId('profile-organization-membership-section');
    const roleStack = within(membershipSection).getByText('Administrator').closest('.MuiStack-root');
    const actionStack = within(membershipSection).getByRole('link', { name: 'Use Join Code' }).parentElement;
    expect(roleStack).toHaveStyle({ flexWrap: 'wrap' });
    expect(actionStack).toHaveStyle({ justifyContent: 'flex-start' });
    const messages = [...errors.mock.calls, ...warnings.mock.calls].map((call) => call.join(' '));
    expect(messages.filter((message) => /non-boolean|does not recognize|Grid.*(?:removed|deprecated)/i.test(message))).toEqual([]);
  });

  it('shows the native account name and reference from the current auth response', () => {
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'UX Crawl' })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText('UX Crawl')).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('native-account-1', 'account'),
    )).toBeVisible();
    expect(within(screen.getByText('Applicant Reference').closest('li')!).getByText(
      formatOfficialReference('app-1', 'applicant'),
    )).toBeVisible();
  });

  it.each([
    [{ given_name: '  Ada ', family_name: ' Lovelace  ' }, 'Ada Lovelace'],
    [{ given_name: 'Ada', family_name: null }, 'Ada'],
    [{ given_name: null, family_name: 'Lovelace' }, 'Lovelace'],
  ])('formats available native name claims without showing missing-data text', (claims, expected) => {
    mockAuthState.user = { ...mockAuthState.user, ...claims };
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: expected })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText(expected)).toBeVisible();
  });

  it('keeps legacy name and identity fallbacks while preferring the native account ID', () => {
    mockAuthState.user = { ...mockAuthState.user, name: 'Legacy Display Name', id: 'legacy-id', subject: 'legacy-subject' };
    const { rerender } = render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'Legacy Display Name' })).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('native-account-1', 'account'),
    )).toBeVisible();

    mockAuthState.user = { name: 'Legacy Account', id: 'legacy-id', email: 'legacy@example.com' };
    rerender(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'Legacy Account' })).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('legacy-id', 'account'),
    )).toBeVisible();
  });

  it('uses the username for a nameless account heading without presenting it as a full name', () => {
    mockAuthState.user = { ...mockAuthState.user, given_name: ' ', family_name: null };
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'ux-crawl' })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText('Not provided')).toBeVisible();
  });

  it('centers the membership empty-state actions through CSS', () => {
    mockAuthState.organizations = [];
    render(<ProfilePage />);

    const actions = screen.getByRole('link', { name: 'Discover Organizations' }).parentElement;
    expect(actions).toHaveStyle({ justifyContent: 'center' });
    expect(actions).not.toHaveAttribute('justifyContent');
  });

  it('centers the loading state through CSS without layout DOM attributes', () => {
    mockAuthState.user = null;
    render(<ProfilePage />);

    const loadingState = screen.getByRole('progressbar').parentElement;
    expect(loadingState).toHaveStyle({ display: 'flex', alignItems: 'center', justifyContent: 'center' });
    for (const attribute of ['display', 'alignItems', 'justifyContent', 'minHeight']) {
      expect(loadingState).not.toHaveAttribute(attribute);
    }
  });

  it('surfaces the shared organizations hub and canonical discovery routes', () => {
    render(<ProfilePage />);

    const membershipSection = screen.getByTestId('profile-organization-membership-section');

    expect(membershipSection).toBeInTheDocument();
    expect(within(membershipSection).getByText('Organization Memberships')).toBeInTheDocument();
    expect(within(membershipSection).getByText('Marty Org')).toBeInTheDocument();
    expect(within(membershipSection).getByText('Open Federation')).toBeInTheDocument();

    expect(within(membershipSection).getByRole('link', { name: 'View My Organizations' })).toHaveAttribute('href', '/console/organizations');
    expect(within(membershipSection).getByRole('link', { name: 'Discover More Organizations' })).toHaveAttribute('href', '/console/organizations/discover');
    expect(within(membershipSection).getByRole('link', { name: 'Use Join Code' })).toHaveAttribute('href', '/console/organizations/join');
  });

  it('saves the latest selected photo when file reads finish in reverse order', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    const view = render(<ProfilePage />);
    const firstRead = selectPhoto(view.container, 'first');
    const secondRead = selectPhoto(view.container, 'second');
    act(() => secondRead.finish(secondPhoto));
    act(() => firstRead.finish(firstPhoto));

    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    expect(updateProfilePicture).toHaveBeenCalledExactlyOnceWith(secondPhoto);
    expect(mockRefreshUser).toHaveBeenCalledTimes(1);
  });

  it('keeps a cancelled photo draft closed when a pending read completes', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    const view = render(<ProfilePage />);
    const firstRead = selectPhoto(view.container, 'first');
    act(() => firstRead.finish(firstPhoto));
    const secondRead = selectPhoto(view.container, 'second');

    await view.user.click(screen.getByRole('button', { name: 'Cancel', exact: true }));
    act(() => secondRead.finish(secondPhoto));

    expect(screen.queryByRole('button', { name: 'Save', exact: true })).not.toBeInTheDocument();
    expect(updateProfilePicture).not.toHaveBeenCalled();
  });

  it('reports a file read failure and lets the same photo be selected again', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    const view = render(<ProfilePage />);
    const read = selectPhoto(view.container, 'first');
    act(() => read.onerror?.());
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to read this image. Please select it again.');
    expect(screen.queryByRole('button', { name: 'Save', exact: true })).not.toBeInTheDocument();

    act(() => selectPhoto(view.container, 'first').finish(firstPhoto));
    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    expect(updateProfilePicture).toHaveBeenCalledExactlyOnceWith(firstPhoto);
    expect(screen.queryByText('Unable to read this image. Please select it again.')).not.toBeInTheDocument();
  });

  it.each(['response', 'rejection'])('keeps a failed upload draft available for retry after a %s failure', async failure => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    if (failure === 'response') vi.mocked(updateProfilePicture).mockResolvedValueOnce({ success: false, error: 'Upload unavailable' });
    else vi.mocked(updateProfilePicture).mockRejectedValueOnce(new Error('Network unavailable'));
    const view = render(<ProfilePage />);
    act(() => selectPhoto(view.container, 'first').finish(firstPhoto));
    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    expect(screen.getByRole('alert')).toHaveTextContent(failure === 'response' ? 'Upload unavailable' : 'Failed to update profile picture.');
    expect(screen.getByRole('button', { name: 'Save', exact: true })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Change profile picture' })).toBeEnabled();
    expect(mockRefreshUser).not.toHaveBeenCalled();
    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    expect(updateProfilePicture).toHaveBeenCalledTimes(2);
    expect(updateProfilePicture).toHaveBeenLastCalledWith(firstPhoto);
    expect(mockRefreshUser).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('alert')).toHaveTextContent('Profile picture updated.');
  });

  it('handles an unexpected refresh rejection without misreporting the completed upload', async () => {
    // AuthContext normally owns refresh loading and errors. This covers only
    // an unexpected rejection from the mocked provider, not its integrated UI.
    vi.stubGlobal('FileReader', ControlledFileReader);
    mockRefreshUser.mockRejectedValueOnce(new Error('Refresh unavailable'));
    const view = render(<ProfilePage />);
    act(() => selectPhoto(view.container, 'first').finish(firstPhoto));
    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    expect(screen.getByText('Profile picture updated.')).toBeInTheDocument();
    expect(screen.getByText('Your picture was saved, but account details could not be refreshed. Reload the page to see it.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save', exact: true })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change profile picture' })).toBeEnabled();
    expect(updateProfilePicture).toHaveBeenCalledTimes(1);
  });

  it('prevents replacing the draft during an upload and ignores completion after leaving the page', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    let finishUpload!: (result: { success: boolean }) => void;
    vi.mocked(updateProfilePicture).mockImplementation(() => new Promise(resolve => { finishUpload = resolve; }));
    const view = render(<ProfilePage />);
    const read = selectPhoto(view.container, 'first');
    act(() => read.finish(firstPhoto));

    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));
    expect(screen.getByRole('button', { name: 'Change profile picture' })).toBeDisabled();
    expect(view.container.querySelector('input[type="file"]')).toBeDisabled();
    view.unmount();
    await act(async () => finishUpload({ success: true }));

    expect(mockRefreshUser).not.toHaveBeenCalled();
  });

  it('discards photo drafts and obsolete upload results when the authenticated account changes', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    let finishUpload!: (result: { success: boolean }) => void;
    vi.mocked(updateProfilePicture).mockImplementation(() => new Promise(resolve => { finishUpload = resolve; }));
    const view = render(<ProfilePage />);
    act(() => selectPhoto(view.container, 'first').finish(firstPhoto));
    await view.user.click(screen.getByRole('button', { name: 'Save', exact: true }));

    mockAuthState.user = { user_id: 'native-account-2', name: 'Second Account', email: 'second@example.com' };
    view.rerender(<ProfilePage />);
    expect(screen.queryByRole('button', { name: 'Saving…' })).not.toBeInTheDocument();
    await act(async () => finishUpload({ success: true }));

    expect(screen.queryByText('Profile picture updated.')).not.toBeInTheDocument();
    expect(mockRefreshUser).not.toHaveBeenCalled();
    expect(screen.getByRole('heading', { name: 'Second Account' })).toBeVisible();
  });

  it('invalidates the previous account upload before replacement layout microtasks run', async () => {
    vi.stubGlobal('FileReader', ControlledFileReader);
    // This commit must run outside act: act flushes passive cleanup before the
    // completion microtask and would hide the production scheduling boundary.
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', false);
    // Stateful MUI refs can also flush passive effects during layout. Keep the
    // actual profile logic and React renderer, with only its visuals replaced.
    vi.doMock('@mui/material', () => Object.fromEntries([
      'Box', 'Card', 'CardContent', 'Typography', 'Grid', 'Avatar', 'Chip',
      'Divider', 'List', 'ListItem', 'ListItemIcon', 'ListItemText', 'IconButton',
      'Tooltip', 'CircularProgress', 'Alert', 'Button',
    ].map(name => [name, ({ children, onClick, disabled }: PropsWithChildren<Record<string, unknown>>) => (
      createElement(name === 'Button' || name === 'IconButton' ? 'button' : 'div', { onClick, disabled }, children)
    )])));
    vi.doMock('../organizations/OrganizationMembershipHub', () => ({ default: () => null }));
    vi.resetModules();
    const { default: LifetimeProfile } = await import('../ProfilePage');
    let finishUpload!: (result: { success: boolean }) => void;
    vi.mocked(updateProfilePicture).mockImplementation(() => new Promise(resolve => { finishUpload = resolve; }));
    let replacementFinished!: () => void;
    const replacementCompletion = new Promise<void>(resolve => { replacementFinished = resolve; });
    let replacementPassive = false;
    let completionBeforePassive = false;

    function Harness({ replacement }: { replacement: boolean }) {
      useLayoutEffect(() => {
        if (replacement) {
          queueMicrotask(() => {
            completionBeforePassive = !replacementPassive;
            finishUpload({ success: true });
            queueMicrotask(replacementFinished);
          });
        }
      }, [replacement]);
      useEffect(() => {
        if (replacement) replacementPassive = true;
      }, [replacement]);
      return <LifetimeProfile />;
    }

    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    try {
      flushSync(() => root.render(<Harness replacement={false} />));
      const input = container.querySelector('input[type="file"]')!;
      Object.defineProperty(input, 'files', {
        configurable: true,
        value: [new File(['first'], 'first.png', { type: 'image/png' })],
      });
      flushSync(() => input.dispatchEvent(new Event('change', { bubbles: true })));
      flushSync(() => photoReads.at(-1)!.finish(firstPhoto));
      flushSync(() => within(container).getByRole('button', { name: 'Save', exact: true }).click());
      expect(updateProfilePicture).toHaveBeenCalledTimes(1);

      mockAuthState.user = { user_id: 'native-account-2', name: 'Second Account', email: 'second@example.com' };
      root.render(<Harness replacement />);
      await replacementCompletion;

      expect(within(container).getByText('Second Account')).toBeVisible();
      expect(completionBeforePassive).toBe(true);
      expect(mockRefreshUser).not.toHaveBeenCalled();
      expect(within(container).queryByText('Profile picture updated.')).not.toBeInTheDocument();
    } finally {
      flushSync(() => root.unmount());
      container.remove();
      vi.doUnmock('@mui/material');
      vi.doUnmock('../organizations/OrganizationMembershipHub');
      vi.resetModules();
    }
  });
});
