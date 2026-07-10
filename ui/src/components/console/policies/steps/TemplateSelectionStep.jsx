/**
 * Template Selection Step
 * 
 * Shows standards-based policy templates filtered by Trust Profile framework.
 * Users can select a pre-built template or choose "Custom" for manual configuration.
 */

import { useMemo } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Chip,
  Alert,
} from '@mui/material';
import BuildIcon from '@mui/icons-material/Build';
import { useTranslation } from 'react-i18next';

import { POLICY_TEMPLATES, getTemplatesByFramework } from '../../../../data/policyTemplates';
import { useAsyncData } from '../../../../hooks/useAsyncData';
import { useConsole } from '../../../../contexts/ConsoleContext';
import { listCredentialTemplates } from '../../../../services/presentationPolicyApi';

const credentialTypeForTemplate = (template) => (
  template?.vct
  || template?.credential_type
  || template?.type
  || template?.id
  || ''
);

const claimNameForTemplateClaim = (claim) => claim?.name || claim?.claim_name || '';

const policyOptionForCredentialTemplate = (template) => {
  const credentialType = credentialTypeForTemplate(template);
  const templateClaims = (template.claims || []).filter((claim) => claim && claimNameForTemplateClaim(claim));
  const requiredClaims = templateClaims.map((claim) => ({
    claim_name: claimNameForTemplateClaim(claim),
    credential_type: credentialType,
    accept_predicate: false,
    required_value: null,
  }));
  return {
    id: `credential-template:${template.id}`,
    name: template.name || credentialType || 'Credential template',
    description: template.description || 'Verify credentials issued from this organization credential template.',
    trustFramework: 'custom',
    standardReference: template.credential_payload_format || template.format || null,
    icon: 'C',
    category: 'Credential Template',
    credentialTemplate: template,
    config: {
      name: `${template.name || 'Credential'} Verification Policy`,
      description: template.description || '',
      purpose: `Verify ${template.name || credentialType || 'credential'}`,
      accepted_credential_types: credentialType ? [credentialType] : [],
      required_claims: requiredClaims,
      credential_requirements: [
        {
          credential_template_id: template.id,
          display_name: template.name || credentialType || 'Credential',
          description: template.description || '',
          required: true,
          credential_payload_format: template.credential_payload_format || 'w3c_vcdm_v2_sd_jwt',
          requested_claims: templateClaims.map((claim) => ({
            claim_name: claimNameForTemplateClaim(claim),
            display_name: claim.display_name || claim.display?.label || claimNameForTemplateClaim(claim),
            required: claim.required !== false,
            selective_disclosure: claim.selectively_disclosable !== false,
          })),
        },
      ],
      holder_binding: 'device_key',
      freshness_requirements: {
        max_credential_age_seconds: 31536000,
        max_proof_age_seconds: 300,
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
      metadata: {
        credential_template_id: template.id,
        credential_template_vct: template.vct || null,
        credential_payload_format: template.credential_payload_format || null,
      },
    },
  };
};

const TemplateSelectionStep = ({ trustProfile, selectedTemplate, onSelectTemplate }) => {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();

  const { data: credentialTemplateData = [] } = useAsyncData(async () => {
    if (!activeOrgId) {
      return [];
    }
    const response = await listCredentialTemplates({ organization_id: activeOrgId });
    return Array.isArray(response?.data) ? response.data : (Array.isArray(response) ? response : []);
  }, [activeOrgId]);

  const credentialTemplateOptions = useMemo(
    () => (Array.isArray(credentialTemplateData) ? credentialTemplateData : [])
      .filter((template) => {
        const status = String(template?.status || '').toLowerCase();
        return template?.id && (!status || status === 'active');
      })
      .map((template) => policyOptionForCredentialTemplate(template)),
    [credentialTemplateData],
  );

  // Filter templates by trust framework
  const availableTemplates = useMemo(() => {
    if (!trustProfile?.trust_framework_type) {
      return POLICY_TEMPLATES;
    }
    return getTemplatesByFramework(trustProfile.trust_framework_type);
  }, [trustProfile]);

  // Add "Custom" template option
  const customTemplate = {
    id: 'custom',
    name: t('wizards.presentationPolicy.templateSelectionStep.customTemplate.name'),
    description: t('wizards.presentationPolicy.templateSelectionStep.customTemplate.description'),
    trustFramework: 'custom',
    standardReference: null,
    icon: '🔧',
    category: t('wizards.presentationPolicy.templateSelectionStep.customTemplate.category'),
    config: null,
  };

  const allTemplates = [...availableTemplates, customTemplate];
  const allSelectableTemplates = [...credentialTemplateOptions, ...allTemplates];

  const handleSelectTemplate = (template) => {
    onSelectTemplate(template);
  };

  if (!trustProfile) {
    return (
      <Alert severity="warning">
        {t('wizards.presentationPolicy.templateSelectionStep.prerequisite')}
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.templateSelectionStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.presentationPolicy.templateSelectionStep.description')}
      </Typography>

      {availableTemplates.length === 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          {t('wizards.presentationPolicy.templateSelectionStep.noTemplates', {
            framework: trustProfile.trust_framework_type?.toUpperCase(),
          })}
        </Alert>
      )}

      {credentialTemplateOptions.length > 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Select an organization credential template to prefill accepted credential type and claims from the actual template used by issuance flows.
        </Alert>
      )}

      <Grid container spacing={2}>
        {allSelectableTemplates.map((template) => (
          <Grid item xs={12} sm={6} md={4} key={template.id}>
            <Card
              sx={{
                height: '100%',
                border: 2,
                borderColor: selectedTemplate?.id === template.id ? 'primary.main' : 'transparent',
                transition: 'all 0.2s',
                '&:hover': {
                  borderColor: 'primary.light',
                  boxShadow: 4,
                },
              }}
            >
              <CardActionArea
                onClick={() => handleSelectTemplate(template)}
                aria-label={`Select ${template.name} presentation policy template`}
                aria-pressed={selectedTemplate?.id === template.id}
                sx={{ height: '100%', alignItems: 'stretch' }}
              >
                <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  {/* Icon & Title */}
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h3" component="span" sx={{ mr: 1.5 }}>
                      {template.icon}
                    </Typography>
                    <Typography variant="h6" component="div" sx={{ flex: 1 }}>
                      {template.name}
                    </Typography>
                  </Box>

                  {/* Description */}
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    paragraph
                    sx={{ flex: 1, minHeight: 60 }}
                  >
                    {template.description}
                  </Typography>

                  {/* Tags */}
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 'auto' }}>
                    <Chip
                      label={template.category}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                    {template.standardReference && (
                      <Chip
                        label={template.standardReference}
                        size="small"
                        variant="outlined"
                      />
                    )}
                    {template.id === 'custom' && (
                      <Chip
                        icon={<BuildIcon />}
                        label={t('wizards.presentationPolicy.templateSelectionStep.customTemplate.customizable')}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Selected Template Info */}
      {selectedTemplate && selectedTemplate.id !== 'custom' && (
        <Alert severity="info" sx={{ mt: 3 }}>
          <Typography variant="body2" gutterBottom>
            <strong>{t('wizards.presentationPolicy.templateSelectionStep.selectedInfo.selected')}</strong> {selectedTemplate.name}
          </Typography>
          {selectedTemplate.standardReference && (
            <Typography variant="body2">
              <strong>{t('wizards.presentationPolicy.templateSelectionStep.selectedInfo.standard')}</strong> {selectedTemplate.standardReference}
            </Typography>
          )}
          <Typography variant="body2" sx={{ mt: 1 }}>
            {t('wizards.presentationPolicy.templateSelectionStep.selectedInfo.next')}
          </Typography>
        </Alert>
      )}

      {selectedTemplate?.id === 'custom' && (
        <Alert severity="info" sx={{ mt: 3 }}>
          <Typography variant="body2">
            {t('wizards.presentationPolicy.templateSelectionStep.customInfo')}
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default TemplateSelectionStep;
