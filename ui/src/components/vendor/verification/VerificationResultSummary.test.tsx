import { describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';

import VerificationResultSummary, { extractPresentationRejection, PresentationAttemptFeedback } from './VerificationResultSummary';

describe('VerificationResultSummary', () => {
  it('validates current-attempt correlation and renders only retry feedback and collapsed fingerprints', () => {
    const session = { id: 'retry-session', status: 'awaiting_wallet', context_data: { presentation_policy_id: 'policy-1' },
      last_presentation_attempt: { schema_version: 1, instance_id: 'retry-session', policy_id: 'policy-1', native_credential_count: 1,
        nonce_sha256: 'a'.repeat(64), submission_digest: 'b'.repeat(64), vp_token_sha256: 'c'.repeat(64),
        outcome: 'rejected', retryable: true, observed_at: '2026-10-26T12:00:00Z',
        authentication: { format: 'mso_mdoc', document_count: 1, document_type: 'org.iso.18013.5.1.mDL',
          issuer_signature_valid: true, certificate_trust_passed: false, device_authentication_valid: true,
          certificate_trust_failures: ['CERTIFICATE_CHAIN_REJECTED'], issuer_certificate_sha256: 'd'.repeat(64) },
        claims: { name: 'UNTRUSTED_PERSON' }, issuer_did: 'UNTRUSTED_ISSUER' } };
    const attempt = extractPresentationRejection(session);
    expect(extractPresentationRejection(session, { id: session.id })).toBeNull();
    render(<PresentationAttemptFeedback attempt={attempt} />);
    expect(screen.getByTestId('presentation-attempt-rejected')).toHaveTextContent('issuer certificate was not accepted');
    expect(screen.getByText('Verification details').parentElement).not.toHaveAttribute('open');
    expect(screen.queryByText('UNTRUSTED_PERSON')).not.toBeInTheDocument();
    expect(screen.queryByText('UNTRUSTED_ISSUER')).not.toBeInTheDocument();
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
    for (const changed of [{ ...session, id: 'wrong' }, { ...session, status: 'completed' },
      { ...session, context_data: { presentation_policy_id: 'foreign-policy' } },
      { ...session, last_presentation_attempt: { ...session.last_presentation_attempt, native_credential_count: 2 } },
      { ...session, last_presentation_attempt: { ...session.last_presentation_attempt, authentication: { ...session.last_presentation_attempt.authentication, document_count: 2 } } },
      { ...session, last_presentation_attempt: { ...session.last_presentation_attempt, nonce_sha256: 'raw value' } },
      { ...session, last_presentation_attempt: null }]) expect(extractPresentationRejection(changed)).toBeNull();
  });
  const mdocSession = (names: string[] = ['age_over_21']) => ({
    instance_id: 'flow-age-1',
    status: 'COMPLETED',
    result: {
      decision: 'allow',
      verified_claims: { age_over_21: true },
      credential_results: [{
        credential_template_id: 'mdl-template',
        signature_valid: true,
        trust_check_passed: true,
        authenticated_disclosures: {
          format: 'mso_mdoc',
          documents: [{ doc_type: 'org.iso.18013.5.1.mDL', namespaces: { 'org.iso.18013.5.1': names } }],
        },
      }],
    },
  });

  it('shows the complete authenticated mDL claim-name inventory and exact session binding', () => {
    render(<VerificationResultSummary session={mdocSession(['age_over_21', 'birth_date'])} />);
    const summary = screen.getByTestId('verification-result-summary');
    expect(summary).toHaveAttribute('data-disclosed-claim-names', '["age_over_21","birth_date"]');
    expect(summary).toHaveAttribute('data-issuer-trusted', 'true');
    expect(summary).toHaveAttribute('data-verification-instance-id', 'flow-age-1');
    expect(summary).toHaveAttribute('data-credential-template-id', 'mdl-template');
    expect(screen.getByText('Authenticated disclosures')).toBeInTheDocument();
    expect(screen.getByText('Mobile driving licence')).toBeInTheDocument();
    expect(screen.getByText('org.iso.18013.5.1: age_over_21, birth_date')).toBeInTheDocument();
  });

  it('shows an omitted status check neutrally without inventing a passed check', () => {
    render(<VerificationResultSummary session={{
      status: 'COMPLETED', result: {
        decision: 'allow', credential_results: [{
          trust_check_passed: true, signature_valid: true, revocation_checked: false,
        }],
      },
    }} />);
    expect(screen.getByText('Not checked')).toBeInTheDocument();
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
    expect(screen.getAllByText('Passed')).toHaveLength(2);
  });

  it('does not infer minimal disclosure or issuer trust from an allowed filtered claim result', () => {
    render(<VerificationResultSummary session={{
      status: 'COMPLETED', result: { decision: 'allow', verified_claims: { age_over_21: true } },
    }} />);
    const summary = screen.getByTestId('verification-result-summary');
    expect(summary).not.toHaveAttribute('data-disclosed-claim-names');
    expect(summary).not.toHaveAttribute('data-issuer-trusted');
  });

  it('does not expose unauthenticated mdoc names as disclosure evidence', () => {
    const session = mdocSession();
    session.result.credential_results[0].signature_valid = false;
    render(<VerificationResultSummary session={session} />);
    expect(screen.getByTestId('verification-result-summary')).not.toHaveAttribute('data-disclosed-claim-names');
  });

  it('preserves a failed native issuer-trust check even if another field says allow', () => {
    const session = mdocSession();
    session.result.credential_results[0].trust_check_passed = false;
    render(<VerificationResultSummary session={session} />);
    expect(screen.getByTestId('verification-result-summary')).toHaveAttribute('data-issuer-trusted', 'false');
  });

  it('keeps filtered claims separate from authenticated disclosure inventory while retaining an explicit issuer check', () => {
    render(
      <VerificationResultSummary session={{
        status: 'COMPLETED', result: 'passed', decision: 'allow',
        verified_claims: { age_over_21: true },
        credential_results: [{ trust_check_passed: true, signature_valid: true }],
      }} />,
    );
    const summary = screen.getByTestId('verification-result-summary');
    expect(summary).not.toHaveAttribute('data-disclosed-claim-names');
    expect(summary).toHaveAttribute('data-issuer-trusted', 'true');
    expect(screen.getByText('Credential')).toBeInTheDocument();
    expect(screen.queryByText('Open Badge')).not.toBeInTheDocument();
  });

  it('does not turn a completed denial or missing trust check into qualified evidence', () => {
    const { rerender } = render(
      <VerificationResultSummary session={{
        status: 'COMPLETED', result: 'failed', decision: 'deny',
        decision_reason: 'Issuer not trusted', verified_claims: {},
        credential_results: [{ trust_check_passed: false }],
      }} />,
    );
    expect(screen.getByText('Not verified')).toBeInTheDocument();
    expect(screen.getByText('Issuer not trusted')).toBeInTheDocument();
    expect(screen.getByTestId('verification-result-summary')).not.toHaveAttribute('data-disclosed-claim-names');
    expect(screen.getByTestId('verification-result-summary')).not.toHaveAttribute('data-issuer-trusted');
    rerender(<VerificationResultSummary session={{
      status: 'COMPLETED', result: 'passed', decision: 'allow',
      verified_claims: { age_over_21: true }, credential_results: [{}],
    }} />);
    expect(screen.getByTestId('verification-result-summary')).not.toHaveAttribute('data-issuer-trusted');
  });

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
