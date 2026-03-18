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
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { listComplianceProfiles } from '../../../services/complianceProfilesApi';

function ComplianceProfilesPage() {
  const { t } = useTranslation('console');

  const getPoliciesTabs = () => [
    { label: t('policies.presentationPolicies'), path: '/console/org/policies/presentation' },
    { label: t('policies.complianceProfiles'), path: '/console/org/policies/compliance' },
  ];

  const getBreadcrumbs = () => [
    { label: t('complianceProfilesPage.breadcrumbs.console'), path: '/console' },
    { label: t('complianceProfilesPage.breadcrumbs.policies'), path: '/console/org/policies' },
    { label: t('complianceProfilesPage.breadcrumbs.complianceProfiles'), path: '/console/org/policies/compliance' },
  ];
  const { data: profiles = [], loading, error } = useAsyncData(
    () => listComplianceProfiles(),
    []
  );

  const getStatusColor = (status) => {
    switch (status) {
      case 'compliant':
        return 'success';
      case 'review_needed':
        return 'warning';
      case 'non_compliant':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusLabel = (status) => {
    const statusKey = `complianceProfilesPage.statusLabels.${status}`;
    return t(statusKey, { defaultValue: status });
  };

  return (
    <ResourcePage
      title={t('complianceProfilesPage.title')}
      description={t('complianceProfilesPage.description')}
      resourceName={t('complianceProfilesPage.resourceName')}
      buildPath="/console/org/policies/compliance/new"
      tabs={getPoliciesTabs()}
      breadcrumbs={getBreadcrumbs()}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
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
                <TableCell>{t('complianceProfilesPage.tableHeaders.regulation')}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.region')}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.requirements')}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.status')}</TableCell>
                <TableCell>{t('complianceProfilesPage.tableHeaders.lastUpdated')}</TableCell>
                <TableCell align="right">{t('complianceProfilesPage.tableHeaders.actions')}</TableCell>
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
                      <Chip label={profile.regulation} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{profile.region}</TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {profile.metRequirements} / {profile.requirements}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={getStatusLabel(profile.status)} 
                        color={getStatusColor(profile.status)}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(profile.updatedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('complianceProfilesPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/policies/compliance/${profile.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('complianceProfilesPage.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/policies/compliance/${profile.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
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
