import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import { render, renderWithRouter } from '@test/utils';
import { RuntimeReadinessPanel } from './RuntimeReadinessPanel';

const readyStatus = {
  canIssue: true,
  canVerify: true,
  issuerKeysValid: true,
  issuerActive: true,
  deploymentActive: true,
  policyReachable: true,
};

describe('RuntimeReadinessPanel', () => {
  it('explains the missing deployment when keys and issuer are ready but issuance is blocked', () => {
    render(<RuntimeReadinessPanel runtimeStatus={{
      ...readyStatus,
      canIssue: false,
      canVerify: false,
      deploymentActive: false,
      policyReachable: false,
    }} />);

    const issuance = within(screen.getByRole('region', { name: 'Credential Issuance' }));
    expect(issuance.getByText('Degraded')).toBeInTheDocument();
    expect(issuance.getByText('No active deployments')).toBeInTheDocument();
    expect(issuance.getByText('An active deployment profile is required before credentials can be issued.')).toBeInTheDocument();
    expect(issuance.getByRole('link', { name: 'Configure Deployment' })).toHaveAttribute('href', '/console/org/deploy/profiles');
    expect(issuance.queryByText('Credential issuance is ready')).not.toBeInTheDocument();
    expect(issuance.queryByText('All systems operational')).not.toBeInTheDocument();
  });

  it('keeps issuance blocked and offers its flow configuration when the aggregate check is false', async () => {
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/" element={<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, canIssue: false }} />} />
        <Route path="/console/org/flows/definitions" element={<h1>Flow Definitions</h1>} />
      </Routes>,
    );

    const issuance = within(screen.getByRole('region', { name: 'Credential Issuance' }));
    expect(issuance.getByText('Degraded')).toBeInTheDocument();
    expect(issuance.getByText('Credential issuance is not ready')).toBeInTheDocument();
    expect(issuance.getByText('Review the issuance flow and its required resources before issuing credentials.')).toBeInTheDocument();
    expect(issuance.queryByText('Credential issuance is ready')).not.toBeInTheDocument();
    await user.click(issuance.getByRole('link', { name: 'Review Issuance Flows' }));
    expect(screen.getByRole('heading', { name: 'Flow Definitions' })).toBeInTheDocument();
  });

  it.each([
    ['issuerKeysValid', 'Issuer configuration needs review'],
    ['issuerActive', 'Issuer configuration needs review'],
    ['deploymentActive', 'No active deployments'],
  ])('does not label issuance Ready when %s contradicts canIssue', (field, detail) => {
    render(<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, [field]: false }} />);
    const issuance = within(screen.getByRole('region', { name: 'Credential Issuance' }));
    expect(issuance.queryByText('Ready', { exact: true })).not.toBeInTheDocument();
    expect(issuance.getByText(detail)).toBeInTheDocument();
    expect(issuance.queryByText('Credential issuance is ready')).not.toBeInTheDocument();
  });

  it('does not claim verification is operational when its aggregate check is false', () => {
    render(<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, canVerify: false }} />);
    const verification = within(screen.getByRole('region', { name: 'Credential Verification' }));
    expect(verification.getByText('Degraded')).toBeInTheDocument();
    expect(verification.getByText('Credential verification is not ready')).toBeInTheDocument();
    expect(verification.getByRole('link', { name: 'Review Verification Setup' })).toHaveAttribute('href', '/console/org/deploy/profiles');
    expect(verification.queryByText('Credential verification is ready')).not.toBeInTheDocument();
  });

  it.each([
    ['deploymentActive', 'No active deployments'],
    ['policyReachable', 'No active presentation policies'],
  ])('does not label verification Ready when %s contradicts canVerify', (field, detail) => {
    render(<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, [field]: false }} />);
    const verification = within(screen.getByRole('region', { name: 'Credential Verification' }));
    expect(verification.queryByText('Ready', { exact: true })).not.toBeInTheDocument();
    expect(verification.getByText(detail)).toBeInTheDocument();
    expect(verification.queryByText('Credential verification is ready')).not.toBeInTheDocument();
  });

  it('shows ready explanations only for operations whose checks all passed', () => {
    render(<RuntimeReadinessPanel runtimeStatus={readyStatus} />);
    const issuance = within(screen.getByRole('region', { name: 'Credential Issuance' }));
    const verification = within(screen.getByRole('region', { name: 'Credential Verification' }));
    expect(issuance.getByText('Ready', { exact: true })).toBeInTheDocument();
    expect(issuance.getByText('Credential issuance is ready')).toBeInTheDocument();
    expect(verification.getByText('Ready', { exact: true })).toBeInTheDocument();
    expect(verification.getByText('Credential verification is ready')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('describes issuer configuration without turning a DID reference into a cryptographic health claim', () => {
    render(<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, issuerKeysValid: false }} />);
    const issuer = within(screen.getByRole('region', { name: 'Issuer Configuration' }));
    expect(issuer.getByText('Configured', { exact: true })).toBeInTheDocument();
    expect(issuer.getByText('An active credential template references an issuer DID.')).toBeInTheDocument();
    expect(screen.queryByText('Keys are valid and active')).not.toBeInTheDocument();
    expect(screen.queryByText('Signing Keys', { exact: true })).not.toBeInTheDocument();
    const issuance = within(screen.getByRole('region', { name: 'Credential Issuance' }));
    expect(issuance.getByText('Issuer configuration needs review')).toBeInTheDocument();
    expect(issuance.getByText('Review the issuer identity and the issuer DID referenced by the active credential template before issuing credentials.')).toBeInTheDocument();
    expect(issuance.getByRole('link', { name: 'Manage Issuer Identities' })).toHaveAttribute('href', '/console/org/deploy/issuer-identity');
    expect(screen.queryByText('Keys invalid or expired')).not.toBeInTheDocument();
    expect(issuance.queryByText('Ready', { exact: true })).not.toBeInTheDocument();
  });

  it('links missing issuer configuration to issuer identity management', () => {
    render(<RuntimeReadinessPanel runtimeStatus={{ ...readyStatus, issuerActive: false }} />);
    const issuer = within(screen.getByRole('region', { name: 'Issuer Configuration' }));
    expect(issuer.getByText('Not configured', { exact: true })).toBeInTheDocument();
    expect(issuer.getByText('No active credential template references an issuer DID.')).toBeInTheDocument();
    expect(issuer.getByRole('link', { name: 'Manage Issuer Identities' })).toHaveAttribute('href', '/console/org/deploy/issuer-identity');
  });

  it.each([null, { canIssue: false }, { ...readyStatus, canIssue: null }])(
    'shows unavailable instead of invented readiness when the status is absent or incomplete',
    async (runtimeStatus) => {
      const onRetry = vi.fn();
      const { user } = render(<RuntimeReadinessPanel runtimeStatus={runtimeStatus} onRetry={onRetry} />);
      expect(screen.getByRole('alert')).toHaveTextContent('Runtime readiness unavailable');
      expect(screen.queryByRole('region', { name: 'Credential Issuance' })).not.toBeInTheDocument();
      expect(screen.queryByText('Keys invalid or expired')).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Retry' }));
      expect(onRetry).toHaveBeenCalledOnce();
    },
  );
});
