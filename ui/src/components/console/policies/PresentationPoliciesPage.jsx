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
import { Link } from 'react-router-dom';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import { useAuth } from '../../../hooks/useAuth';
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

function PresentationPoliciesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { data: policies = [], loading, error } = useAsyncData(
    () => listPresentationPolicies(),
    []
  );

  const { data: depData = { templates: [], trustProfiles: [] } } = useAsyncData(
    async () => {
      if (!organizationId) return { templates: [], trustProfiles: [] };
      const [templatesResult, trustProfilesResult] = await Promise.all([
        listCredentialTemplates({ organization_id: organizationId, limit: 1 }).catch(() => []),
        listTrustProfiles({ organization_id: organizationId, limit: 1 }).catch(() => []),
      ]);
      return {
        templates: Array.isArray(templatesResult) ? templatesResult : (templatesResult?.items ?? []),
        trustProfiles: Array.isArray(trustProfilesResult) ? trustProfilesResult : [],
      };
    },
    [organizationId]
  );
  const safeDepData = depData ?? { templates: [], trustProfiles: [] };

  const policyPrerequisites = [
    {
      label: t('policies.prerequisites.trustProfile', { defaultValue: 'Trust Profile' }),
      status: safeDepData.trustProfiles.length > 0 ? 'ready' : 'missing',
      path: '/console/org/trust/profiles',
    },
    {
      label: t('policies.prerequisites.credentialTemplate', { defaultValue: 'Credential Template' }),
      status: safeDepData.templates.length > 0 ? 'ready' : 'missing',
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
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : policies.length === 0 ? (
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
                <TableCell>{t('policies.tableHeaders.requiredClaims')}</TableCell>
                <TableCell>{t('policies.tableHeaders.freshness')}</TableCell>
                <TableCell>{t('policies.tableHeaders.holderBinding')}</TableCell>
                <TableCell align="right">{t('policies.tableHeaders.usage')}</TableCell>
                <TableCell>{t('policies.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('policies.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {policies.map((policy) => (
                  <TableRow key={policy.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {policy.name}
                      </Typography>
                    </TableCell>
                    <TableCell>{policy.trustProfile}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {policy.requiredClaims.slice(0, 2).map((claim) => (
                          <Chip key={claim} label={claim} size="small" variant="outlined" />
                        ))}
                        {policy.requiredClaims.length > 2 && (
                          <Chip label={`+${policy.requiredClaims.length - 2}`} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>{policy.freshness}</TableCell>
                    <TableCell>
                      {policy.holderBinding ? (
                        <Chip label={t('policies.holderBinding.required')} size="small" color="info" />
                      ) : (
                        <Chip label={t('policies.holderBinding.optional')} size="small" variant="outlined" />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {policy.usageCount.toLocaleString()}
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
                      <Tooltip title={t('policies.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/policies/presentation/${policy.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default PresentationPoliciesPage;
