import { describe, expect, it } from 'vitest';

import {
  formatOfficialReference,
  formatStructuredIdentifiers,
  inferOfficialReferenceKind,
  looksLikeOfficialReference,
  pickOfficialReference,
} from './officialReferences';

describe('officialReferences', () => {
  it('formats stable official references with kind prefixes', () => {
    expect(formatOfficialReference('00000000-0000-0000-0000-000000000001', 'organization')).toBe(
      formatOfficialReference('00000000-0000-0000-0000-000000000001', 'organization')
    );
    expect(formatOfficialReference('00000000-0000-0000-0000-000000000001', 'organization')).toMatch(/^ORG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(formatOfficialReference('user-123', 'account')).toMatch(/^ACT-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  });

  it('preserves already-official references and prefers explicit references', () => {
    expect(looksLikeOfficialReference('APP-20260511-ABC123')).toBe(true);
    expect(formatOfficialReference('APP-20260511-ABC123', 'application')).toBe('APP-20260511-ABC123');
    expect(pickOfficialReference({
      reference: 'APP-20260511-ABC123',
      rawId: '7a8b9c',
      kind: 'application',
    })).toBe('APP-20260511-ABC123');
  });

  it('infers kinds and formats structured identifier fields recursively', () => {
    expect(inferOfficialReferenceKind('application_id')).toBe('application');
    expect(inferOfficialReferenceKind('organizationId')).toBe('organization');
    expect(inferOfficialReferenceKind('eventId')).toBe('event');

    const formatted = formatStructuredIdentifiers({
      application_id: 'app-123',
      nested: {
        organizationId: 'org-abc',
        reference_number: 'APP-20260511-ABC123',
        issuer_did: 'did:web:issuer.example.com',
      },
    });

    expect(formatted.application_id).toMatch(/^APP-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(formatted.nested.organizationId).toMatch(/^ORG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(formatted.nested.reference_number).toBe('APP-20260511-ABC123');
    expect(formatted.nested.issuer_did).toBe('did:web:issuer.example.com');
  });
});