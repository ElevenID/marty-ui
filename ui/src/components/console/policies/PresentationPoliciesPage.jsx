/**
 * Presentation Policies Page
 * 
 * Manages presentation policies - rules for credential verification requests.
 */

import { useTranslation } from 'react-i18next';
import { useAsyncData } from '../../../hooks/useAsyncData';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Button,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import QrCodeIcon from '@mui/icons-material/QrCode';
import { Link } from 'react-router';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listPresentationPolicies, listCredentialTemplates, listTrustProfiles } from '../../../services/presentationPolicyApi';

const getPoliciesTabs = (t) => [
  { label: t('policies.presentationPolicies'), path: '/console/org/policies/presentation' },
  { label: t('policies.complianceProfiles'), path: '/console/org/policies/compliance' },
];

const getBreadcrumbs = (t) => [
  { label: t('policies.breadcrumbs.console'), path: '/console' },
  { label: t('policies.breadcrumbs.policies'), path: '/console/org/policies' },
  { label: t('policies.breadcrumbs.presentationPolicies'), path: '/console/org/policies/presentation' },
];

function policyTrustProfileIds(policy) {
  const requirements = [
    ...(policy.credential_requirements || []),
    ...(policy.alternative_requirements || []).flatMap((group) => group.credential_requirements || []),
  ];
  return [...new Set([policy.trust_profile_id, ...requirements.map((requirement) => requirement.trust_profile_id)].filter(Boolean))];
}

function PresentationPoliciesPage() {
  const { t } = useTranslation('console');
  const { activeOrgId: organizationId } = useConsole();
  const { data: policies = [], loading, error, reload } = useAsyncData(
    () => listPresentationPolicies({ organization_id: organizationId }),
    [organizationId]
  );

  const {
    data: depData = { templates: [], trustProfiles: [] },
    loading: depLoading,
    error: depError,
  } = useAsyncData(
    async () => {
      const [templatesResult, trustProfilesResult] = await Promise.all([
        listCredentialTemplates({ organization_id: organizationId, limit: 1 }),
        listTrustProfiles({ organization_id: organizationId, limit: 1 }),
      ]);
      return {
        templates: templatesResult,
        trustProfiles: Array.isArray(trustProfilesResult) ? trustProfilesResult : [],
      };
    },
    [organizationId]
  );
  const safeDepData = depData ?? { templates: [], trustProfiles: [] };

  const policyPrerequisites = [
    {
      label: t('policies.prerequisites.trustProfile', { defaultValue: 'Trust Profile' }),
      status: depError ? 'error' : depLoading ? 'pending' : safeDepData.trustProfiles.length > 0 ? 'ready' : 'missing',
      path: '/console/org/trust/profiles',
    },
    {
      label: t('policies.prerequisites.credentialTemplate', { defaultValue: 'Credential Template' }),
      status: depError ? 'error' : depLoading ? 'pending' : safeDepData.templates.length > 0 ? 'ready' : 'missing',
      path: '/console/org/templates/credentials',
    },
  ];

  const TestActions = () => (
    <Box sx={{ display: 'flex', gap: 1 }}>
      <Button
        variant="outlined"
        size="small"
        startIcon={<PlayArrowIcon />}
        component={Link}
        to="/console/org/policies/test"
      >
        {t('policies.testActions.evaluateVP')}
      </Button>
      <Button
        variant="outlined"
        size="small"
        startIcon={<QrCodeIcon />}
        component={Link}
        to="/console/org/flows/definitions/new?type=verification"
      >
        {t('policies.testActions.startQRVerification')}
      </Button>
    </Box>
  );

  return (
    <ResourcePage
      title={t('policies.presentationPolicies')}
      description={t('policies.presentationPoliciesDescription')}
      resourceName={t('policies.title')}
      buildPath="/console/org/policies/presentation/new"
      newPath="/console/org/policies/presentation/new?mode=advanced"
      tabs={getPoliciesTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={<TestActions />}
    >
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={<Button color="inherit" size="small" onClick={reload}>{t('common.retry', { defaultValue: 'Retry' })}</Button>}
        >
          {error?.message || String(error)}
        </Alert>
      )}

      {depError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {depError?.message || t('policies.prerequisites.loadFailed', { defaultValue: 'Unable to load policy prerequisites.' })}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : error ? null : policies.length === 0 ? (
        <EmptyState
          {...EmptyStates.policies}
          prerequisites={policyPrerequisites}
          whyItMatters={t(
            'policies.prerequisites.whyItMatters',
            { defaultValue: 'Presentation policies define what credentials and claims are required during verification. They reference credential templates and are validated against trust profiles.' }
          )}
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('policies.tableHeaders.name')}</TableCell>
                <TableCell>{t('policies.tableHeaders.trustProfile')}</TableCell>
                <TableCell>{t('policies.tableHeaders.claimRequirements', { defaultValue: 'Claims and requirements' })}</TableCell>
                <TableCell>{t('policies.tableHeaders.freshness')}</TableCell>
                <TableCell>{t('policies.tableHeaders.holderBinding')}</TableCell>
                <TableCell>{t('policies.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('policies.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {policies.map((policy) => {
                const claims = policy.required_claims || [];
                const requirements = policy.credential_requirements || [];
                const alternatives = policy.alternative_requirements || [];
                return (
                  <TableRow key={policy.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {policy.name}
                      </Typography>
                    </TableCell>
                    <TableCell>{policyTrustProfileIds(policy).join(', ') || '—'}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {claims.slice(0, 2).map((claim) => (
                          <Chip key={claim.claim_name} label={claim.display_name || claim.claim_name} size="small" variant="outlined" />
                        ))}
                        {claims.length > 2 && (
                          <Chip label={`+${claims.length - 2}`} size="small" />
                        )}
                        {requirements.length > 0 && <Chip size="small" variant="outlined" label={t('policies.credentialRequirementCount', {
                          count: requirements.length,
                          defaultValue: requirements.length === 1 ? '1 credential requirement' : `${requirements.length} credential requirements`,
                        })} />}
                        {alternatives.length > 0 && <Chip size="small" variant="outlined" label={t('policies.alternativeGroupCount', {
                          count: alternatives.length,
                          defaultValue: alternatives.length === 1 ? '1 alternative group' : `${alternatives.length} alternative groups`,
                        })} />}
                        {claims.length === 0 && requirements.length === 0 && alternatives.length === 0 && '—'}
                      </Box>
                    </TableCell>
                    <TableCell>{policy.freshness?.max_age_seconds == null ? '—' : `${policy.freshness.max_age_seconds.toLocaleString()} s`}</TableCell>
                    <TableCell>
                      {policy.holder_binding?.required ? (
                        <Chip label={t('policies.holderBinding.required')} size="small" color="info" />
                      ) : (
                        <Chip label={t('policies.holderBinding.optional')} size="small" variant="outlined" />
                      )}
                    </TableCell>
                    <TableCell>
                      <StatusChip status={policy.status} />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('policies.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/policies/presentation/${policy.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {String(policy.status).toLowerCase() === 'draft' && <Tooltip title={t('policies.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/policies/presentation/${policy.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default PresentationPoliciesPage;
