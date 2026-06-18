import { describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';

import VerificationResultSummary from './VerificationResultSummary';

describe('VerificationResultSummary', () => {
  it('renders Open Badge verification checks, claims, and Canvas mirror provenance', () => {
    render(
      <VerificationResultSummary
        session={{
          status: 'PASSED',
          result: {
            passed: true,
            trust_validated: true,
            revocation_checked: true,
            verified_claims: {
              name: 'Interoperable Credentials Foundations Badge',
              badge_image_url: 'https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge/image.svg',
              issuer_did: 'did:web:beta.elevenidllc.com:orgs:marty',
              learner: 'ElevenID Test Learner',
              canvas_provenance: {
                external_credential_id: 'canvas-cred-1',
                canvas_account_id: 'canvas-real-account-1',
                delivery_record_id: 'delivery-1',
              },
            },
          },
          credential_results: [{ signature_valid: true }],
        }}
      />,
    );

    expect(screen.getByTestId('verification-result-summary')).toBeInTheDocument();
    expect(screen.getAllByText('Interoperable Credentials Foundations Badge').length).toBeGreaterThan(0);
    expect(screen.getByRole('img', { name: /interoperable credentials foundations badge/i })).toBeInTheDocument();
    expect(screen.getAllByText(/did:web:beta.elevenidllc.com:orgs:marty/).length).toBeGreaterThan(0);
    expect(screen.getByText('Trust profile accepted the issuer')).toBeInTheDocument();
    expect(screen.getByText('Revocation/status was checked')).toBeInTheDocument();
    expect(screen.getByText('Credential signature was valid')).toBeInTheDocument();
    expect(screen.getByText('Learner')).toBeInTheDocument();
    expect(screen.getByText('ElevenID Test Learner')).toBeInTheDocument();
    expect(screen.getByTestId('verification-canvas-mirror-result')).toHaveTextContent('canvas-cred-1');
    expect(screen.getByTestId('verification-canvas-mirror-result')).toHaveTextContent('canvas-real-account-1');
  });
});
