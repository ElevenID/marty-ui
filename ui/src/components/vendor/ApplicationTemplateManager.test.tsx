import { describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen } from '@test/utils';

import {
  TemplateFormDialog,
  applyEvidenceTypeDefaults,
  createEvidenceRequirement,
} from './ApplicationTemplateManager';

vi.mock('../../services/complianceProfilesApi', () => ({
  default: {
    listComplianceProfiles: vi.fn().mockResolvedValue([]),
    validateIssuerArtifacts: vi.fn().mockResolvedValue({}),
  },
}));

describe('ApplicationTemplateManager evidence authoring', () => {
  it('builds protocol-shaped external API evidence requirements', () => {
    const requirement = createEvidenceRequirement('EXTERNAL_API', 2);

    expect(requirement).toMatchObject({
      evidence_id: 'external-api-2',
      evidence_type: 'EXTERNAL_API',
      required: true,
      verification_method: 'EXTERNAL_API_RESPONSE',
      api: {
        method: 'POST',
        timeout_seconds: 10,
      },
      expected_response: {
        status_codes: [200],
      },
      response_mapping: {
        provider_event_id_path: '$.id',
        verification_status_path: '$.status',
      },
    });
  });

  it('preserves common fields when changing an evidence requirement to external API', () => {
    const requirement = applyEvidenceTypeDefaults(
      {
        evidence_id: 'passport-check',
        description: 'Passport check',
        required: false,
      },
      'EXTERNAL_API',
      1
    );

    expect(requirement.evidence_id).toBe('passport-check');
    expect(requirement.description).toBe('Passport check');
    expect(requirement.required).toBe(false);
    expect(requirement.api.method).toBe('POST');
    expect(requirement.expected_response.status_codes).toEqual([200]);
  });

  it('renders structured controls for user-defined external API checks', async () => {
    const onSave = vi.fn();
    const { user } = renderWithRouter(
      <TemplateFormDialog
        open
        onClose={vi.fn()}
        onSave={onSave}
        template={null}
        trustProfiles={[{ id: 'trust-1', name: 'ICAO', framework: 'icao' }]}
      />
    );

    await user.click(screen.getByRole('button', { name: /add evidence/i }));

    expect(screen.getByLabelText(/api url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/expected response json/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/response mapping json/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/secret headers json/i)).toBeInTheDocument();
  });
});
