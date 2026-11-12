import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@test/utils';
import FreshnessBindingStep from '../steps/FreshnessBindingStep';

const initialConfig = {
  holder_binding: 'device_key',
  freshness_requirements: {
    max_credential_age_seconds: 31536000,
    require_revocation_check: true,
    // Old drafts must not make unsupported settings appear configurable again.
    max_proof_age_seconds: 600,
  },
  metadata: { standard_reference: 'An unsaved standard' },
};

function renderStep(credentialAge = 31536000) {
  const changed = vi.fn();
  function Harness() {
    const [config, setConfig] = useState({ ...initialConfig, freshness_requirements: {
      ...initialConfig.freshness_requirements, max_credential_age_seconds: credentialAge,
    } });
    return <FreshnessBindingStep policyConfig={config} onConfigChange={(next) => {
      changed(next);
      setConfig(next);
    }} />;
  }
  return { ...render(<Harness />), changed };
}

describe('presentation policy freshness and holder binding', () => {
  it('offers only the credential-age and revocation controls that the policy saves', () => {
    renderStep();
    expect(screen.getByRole('spinbutton', { name: 'Maximum Credential Age' })).toHaveValue(31536000);
    expect(screen.getByText('seconds')).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Require Revocation Check' })).toBeChecked();
    expect(screen.queryByRole('spinbutton', { name: 'Maximum Proof Age' })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Standard Reference' })).not.toBeInTheDocument();
    expect(screen.queryByText('Compliance & Standards')).not.toBeInTheDocument();
    expect(screen.queryByText(/This policy will be marked as targeting/)).not.toBeInTheDocument();
    expect(screen.getByText('Control how recent credentials must be.')).toBeInTheDocument();
  });

  it.each([0, 43200, 129600, 86401])('displays %s seconds exactly without a whole-day conversion', (seconds) => {
    renderStep(seconds);
    const age = screen.getByRole('spinbutton', { name: 'Maximum Credential Age' });
    expect(age).toHaveValue(seconds);
    expect(age).not.toHaveAttribute('aria-invalid', 'true');
  });

  it('names every radio and lets the visible label, description, and control select it once', async () => {
    const { user, changed } = renderStep();
    const group = screen.getByRole('radiogroup', { name: 'Holder Binding Method' });
    expect(group).toHaveAccessibleDescription('How should the presentation be bound to the credential holder?');
    const options = [
      ['Device Key', 'Bind to device cryptographic key (recommended)'],
      ['Authenticated Session', 'Bind the presentation to an authenticated session proof'],
      ['Credential Key', 'Require proof of control of the key bound to the credential'],
      ['None', 'No holder binding (least secure)'],
    ];
    for (const [name, description] of options) {
      expect(within(group).getByRole('radio', { name })).toHaveAccessibleDescription(description);
    }

    await user.click(screen.getByText('Bind the presentation to an authenticated session proof'));
    expect(within(group).getByRole('radio', { name: 'Authenticated Session' })).toBeChecked();
    expect(changed).toHaveBeenCalledTimes(1);
    expect(changed.mock.lastCall?.[0]).toMatchObject({ holder_binding: 'session_binding' });

    changed.mockClear();
    await user.click(within(group).getByRole('radio', { name: 'Credential Key' }));
    expect(within(group).getByRole('radio', { name: 'Credential Key' })).toBeChecked();
    expect(changed).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('spinbutton', { name: 'Maximum Credential Age' })).toHaveValue(31536000);
    expect(screen.getByRole('switch', { name: 'Require Revocation Check' })).toBeChecked();

    await user.click(screen.getByText('None'));
    expect(within(group).getByRole('radio', { name: 'None' })).toBeChecked();
  });

  it('supports keyboard selection throughout the named radio group', async () => {
    const { user } = renderStep();
    // The shared setup focuses body with tabindex=-1; user-event otherwise
    // includes body twice in its synthetic tab order and never leaves it.
    document.body.removeAttribute('tabindex');
    await user.tab();
    expect(screen.getByRole('radio', { name: 'Device Key' })).toHaveFocus();
    for (const name of ['Authenticated Session', 'Credential Key', 'None', 'Device Key']) {
      await user.keyboard('{ArrowDown}');
      expect(screen.getByRole('radio', { name })).toBeChecked();
      expect(screen.getByRole('radio', { name })).toHaveFocus();
    }
  });
});
