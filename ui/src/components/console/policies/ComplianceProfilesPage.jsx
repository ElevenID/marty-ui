/**
 * Compliance Profiles Page
 * 
 * Manages compliance profiles - regulatory and business rule configurations.
 */

import {
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
  LinearProgress,
  Button,
} from '@mui/material';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { listComplianceProfiles } from '../../../services/complianceProfilesApi';
import { useConsole } from '../../../contexts/ConsoleContext';

function ComplianceProfilesPage() {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();

  const getPoliciesTabs = () => [
    { label: t('policies.presentationPolicies'), path: '/console/org/policies/presentation' },
    { label: t('policies.complianceProfiles'), path: '/console/org/policies/compliance' },
  ];

  const getBreadcrumbs = () => [
    { label: t('complianceProfilesPage.breadcrumbs.console'), path: '/console' },
    { label: t('complianceProfilesPage.breadcrumbs.policies'), path: '/console/org/policies' },
    { label: t('complianceProfilesPage.breadcrumbs.complianceProfiles'), path: '/console/org/policies/compliance' },
  ];
  const { data: profiles = [], loading, error, reload } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading compliance profiles.');
      }
      return listComplianceProfiles({ organization_id: activeOrgId });
    },
    [activeOrgId]
  );

  const formatDate = (value) => {
    if (!value) {
      return t('common.notAvailable', { defaultValue: 'Not available' });
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? t('common.notAvailable', { defaultValue: 'Not available' })
      : date.toLocaleDateString();
  };

  return (
    <ResourcePage
      title={t('complianceProfilesPage.title')}
      description={t('complianceProfilesPage.description')}
      resourceName={t('complianceProfilesPage.resourceName')}
      tabs={getPoliciesTabs()}
      breadcrumbs={getBreadcrumbs()}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
          <Button color="inherit" size="small" onClick={reload} sx={{ ml: 2 }}>
            Retry
          </Button>
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('complianceProfilesPage.tableHeaders.name')}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.code', { defaultValue: 'Code' })}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.credentialFormat', { defaultValue: 'Credential format' })}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.issuanceProtocol', { defaultValue: 'Issuance protocol' })}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.scope', { defaultValue: 'Scope' })}</TableCell>
                <TableCell>{t('common.status', { defaultValue: 'Status' })}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.createdAt', { defaultValue: 'Created' })}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {profiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('complianceProfilesPage.emptyState')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                profiles.map((profile) => (
                  <TableRow key={profile.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {profile.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={profile.compliance_code || t('common.notAvailable', { defaultValue: 'Not available' })}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      {profile.credential_format || t('common.notAvailable', { defaultValue: 'Not available' })}
                    </TableCell>
                    <TableCell>
                      {profile.issuance_protocol || t('common.notAvailable', { defaultValue: 'Not available' })}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={profile.is_system ? t('complianceProfilesPage.scope.system', { defaultValue: 'System' }) : t('complianceProfilesPage.scope.organization', { defaultValue: 'Organization' })}
                        color={profile.is_system ? 'info' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={profile.status || (profile.is_system ? 'ACTIVE' : 'DRAFT')}
                        color={String(profile.status || (profile.is_system ? 'ACTIVE' : '')).toUpperCase() === 'ACTIVE' ? 'success' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {formatDate(profile.created_at)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default ComplianceProfilesPage;
