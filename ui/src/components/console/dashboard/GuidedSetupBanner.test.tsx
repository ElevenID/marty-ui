import { beforeEach, describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';

import GuidedSetupBanner from './GuidedSetupBanner';
import { ReadinessState } from '../../../config/dashboardRules';

describe('GuidedSetupBanner', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it('links to the next dedicated artifact wizard instead of the retired org setup wizard', () => {
    render(
      <GuidedSetupBanner
        readiness={{
          trust: {
            state: ReadinessState.MISSING,
            path: '/console/org/trust/profiles/new',
          },
          template: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          policy: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          deployment: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          flow: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
        }}
      />
    );

    const setupLink = screen.getByRole('link', { name: /start setup/i });
    expect(setupLink).toHaveAttribute('href', '/console/org/trust/profiles/new');
    expect(setupLink).not.toHaveAttribute('href', '/console/org/setup-wizard');
  });

  it('does not show a setup CTA when readiness is blocked by a service load error', () => {
    render(
      <GuidedSetupBanner
        readiness={{
          trust: {
            state: ReadinessState.BLOCKED,
            serviceError: true,
            message: 'Trust profiles could not be loaded. Message ID: msg-trust-503',
            blockReason: 'Trust profiles are unavailable, so setup readiness cannot be trusted. Message ID: msg-trust-503',
          },
          template: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          policy: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          deployment: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
          flow: {
            state: ReadinessState.MISSING,
            dependencyBlocked: true,
          },
        }}
      />
    );

    expect(screen.queryByRole('link', { name: /start setup/i })).not.toBeInTheDocument();
  });
});
