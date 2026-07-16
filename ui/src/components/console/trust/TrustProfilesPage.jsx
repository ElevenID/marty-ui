/**
 * Trust Profiles Page
 * 
 * Manages Trust Profiles - frameworks that define trusted issuers and validation rules.
 * Wraps the existing TrustRegistry component with the new navigation structure.
 */

import { useTranslation } from 'react-i18next';
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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Link } from 'react-router-dom';

import { ResourcePage, StatusChip, EmptyState, EmptyStates } from '../../common';
import { TrustProvider } from '../../trust';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listRevocationProfiles, listTrustProfiles } from '../../../services/presentationPolicyApi';
import { getKeyManagementConfig, listIssuerProfiles, listSigningKeys } from '../../../services/signingKeysApi';
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  getDefaultKeyManagementService,
  normalizeKeyManagementConfig,
} from '../deploy/keyManagementServiceCatalog';

const getBreadcrumbs = (t) => [
  { label: t('trust.breadcrumbs.console'), path: '/console' },
  { label: t('trust.breadcrumbs.trust'), path: '/console/org/trust' },
  { label: t('trust.breadcrumbs.trustProfiles'), path: '/console/org/trust/profiles' },
];

function TrustProfilesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrganizationId = activeOrgId;

  // Fetch trust profiles from API
  const { data: profiles = [], loading, error } = useAsyncData(
    () => {
      if (!effectiveOrganizationId) {
        throw new Error('Select an organization before loading trust profiles.');
      }
      return listTrustProfiles({ organization_id: effectiveOrganizationId });
    },
    [effectiveOrganizationId]
  );

  const safeProfiles = Array.isArray(profiles) ? profiles : [];
  const { data: dependencies = {
    signingKeys: [],
    issuerProfiles: [],
    revocationProfiles: [],
    keyManagementConfig: DEFAULT_KEY_MANAGEMENT_CONFIG,
    errors: [],
  } } = useAsyncData(
    async () => {
      if (!effectiveOrganizationId) {
        return {
          signingKeys: [],
          issuerProfiles: [],
          revocationProfiles: [],
          keyManagementConfig: DEFAULT_KEY_MANAGEMENT_CONFIG,
          errors: ['Organization: Select an organization before loading trust profile prerequisites.'],
        };
      }

      const [signingKeysResult, issuerProfilesResult, keyManagementConfigResult, revocationProfilesResult] = await Promise.allSettled([
        listSigningKeys({ organization_id: effectiveOrganizationId, limit: 1 }),
        listIssuerProfiles({ organization_id: effectiveOrganizationId }),
        getKeyManagementConfig({ organization_id: effectiveOrganizationId }),
        listRevocationProfiles({ organization_id: effectiveOrganizationId, limit: 1 }),
      ]);

      const dependencyErrors = [
        ['Key Management signing keys', signingKeysResult],
        ['Issuer profiles', issuerProfilesResult],
        ['Key Management configuration', keyManagementConfigResult],
        ['Revocation profiles', revocationProfilesResult],
      ]
        .filter(([, result]) => result.status === 'rejected')
        .map(([label, result]) => `${label}: ${result.reason?.message || String(result.reason)}`);

      const signingKeysValue = signingKeysResult.status === 'fulfilled' ? signingKeysResult.value : { keys: [] };
      const issuerProfilesValue = issuerProfilesResult.status === 'fulfilled' ? issuerProfilesResult.value : { profiles: [] };
      const keyManagementConfigValue = keyManagementConfigResult.status === 'fulfilled'
        ? keyManagementConfigResult.value
        : DEFAULT_KEY_MANAGEMENT_CONFIG;
      const revocationProfilesValue = revocationProfilesResult.status === 'fulfilled' ? revocationProfilesResult.value : [];

      const signingKeys = Array.isArray(signingKeysValue)
        ? signingKeysValue
        : (Array.isArray(signingKeysValue?.keys) ? signingKeysValue.keys : []);
      const issuerProfiles = Array.isArray(issuerProfilesValue?.profiles)
        ? issuerProfilesValue.profiles
        : [];

      return {
        signingKeys,
        issuerProfiles,
        revocationProfiles: Array.isArray(revocationProfilesValue) ? revocationProfilesValue : [],
        keyManagementConfig: normalizeKeyManagementConfig(keyManagementConfigValue || DEFAULT_KEY_MANAGEMENT_CONFIG),
        errors: dependencyErrors,
      };
    },
    [effectiveOrganizationId]
  );
  const safeDependencies = dependencies ?? {
    signingKeys: [],
    issuerProfiles: [],
    revocationProfiles: [],
    keyManagementConfig: DEFAULT_KEY_MANAGEMENT_CONFIG,
    errors: [],
  };
  const dependencyErrors = Array.isArray(safeDependencies.errors) ? safeDependencies.errors : [];
  const defaultSigningService = getDefaultKeyManagementService(safeDependencies.keyManagementConfig);
  const hasManagedIssuerInput = safeDependencies.issuerProfiles.length > 0 || safeDependencies.signingKeys.length > 0;
  const signingDependencyFailed = dependencyErrors.some((item) => item.startsWith('Key Management'));
  const issuerDependencyFailed = dependencyErrors.some((item) => item.startsWith('Issuer profiles'));
  const revocationDependencyFailed = dependencyErrors.some((item) => item.startsWith('Revocation profiles'));

  const trustProfilePrerequisites = [
    {
      label: t('trust.trustProfilesPage.prerequisites.keyManagement', { defaultValue: 'Key Management Service' }),
      status: signingDependencyFailed ? 'error' : (defaultSigningService ? 'ready' : 'missing'),
      path: '/console/org/deploy/key-management',
    },
    {
      label: t('trust.trustProfilesPage.prerequisites.issuerIdentity', { defaultValue: 'Issuer Identity or Signing Key' }),
      status: issuerDependencyFailed ? 'error' : (hasManagedIssuerInput ? 'ready' : 'missing'),
      path: '/console/org/deploy/issuer-identity',
    },
    {
      label: t('trust.trustProfilesPage.prerequisites.revocationProfile', { defaultValue: 'Revocation Profile' }),
      status: revocationDependencyFailed ? 'error' : (safeDependencies.revocationProfiles.length > 0 ? 'ready' : 'missing'),
      path: '/console/org/trust/revocation',
    },
  ];

  const getLastUpdatedLabel = (profile) => {
    const raw = profile?.updated_at || profile?.updatedAt || profile?.created_at || profile?.createdAt;
    if (!raw) {
      return '—';
    }
    const parsed = new Date(raw);
    return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleDateString();
  };

  return (
    <TrustProvider>
      <ResourcePage
        title={t('trust.trustProfiles')}
        description={t('trust.trustProfilesDescription')}
        resourceName={t('trust.trustProfiles')}
        buildPath="/console/org/trust/profiles/new"
        newPath="/console/org/trust/profiles/new?mode=advanced"
        breadcrumbs={getBreadcrumbs(t)}
      >
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error.message ?? t('trust.failedToLoad')}
          </Alert>
        )}
        {dependencyErrors.length > 0 && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            {t('trust.trustProfilesPage.prerequisites.loadError', {
              defaultValue: 'Some trust setup prerequisites could not be loaded. Retry before treating this as missing configuration.',
            })}
            <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
              {dependencyErrors.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </Box>
          </Alert>
        )}

        {loading ? (
          <LinearProgress />
        ) : safeProfiles.length === 0 ? (
          <EmptyState
            {...EmptyStates.trustProfiles}
            prerequisites={trustProfilePrerequisites}
            whyItMatters={t(
              'trust.trustProfilesPage.prerequisites.whyItMatters',
              { defaultValue: 'Trust profiles validate issuer signatures and revocation state, so key management, issuer identity, and revocation setup should come first.' }
            )}
          />
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('trust.tableHeaders.name')}</TableCell>
                  <TableCell>{t('trust.tableHeaders.framework')}</TableCell>
                  <TableCell>{t('trust.tableHeaders.status')}</TableCell>
                  <TableCell align="right">{t('trust.tableHeaders.trustedIssuers')}</TableCell>
                  <TableCell align="right">{t('trust.tableHeaders.validationRules')}</TableCell>
                  <TableCell>{t('trust.tableHeaders.lastUpdated')}</TableCell>
                  <TableCell align="right">{t('trust.tableHeaders.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {safeProfiles.map((profile) => (
                    <TableRow key={profile.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight={500}>
                          {profile.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={(profile.framework || profile.profile_type || 'custom').toUpperCase()} 
                          size="small" 
                          variant="outlined" 
                        />
                      </TableCell>
                      <TableCell>
                        <StatusChip status={profile.status} />
                      </TableCell>
                      <TableCell align="right">{profile.trusted_issuers?.length ?? profile.trustedIssuers ?? 0}</TableCell>
                      <TableCell align="right">{profile.validation_rules?.allowed_algorithms?.length ?? profile.validationRules ?? 0}</TableCell>
                      <TableCell>
                        {getLastUpdatedLabel(profile)}
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title={t('trust.actions.viewDetails')}>
                          <IconButton
                            component={Link}
                            to={`/console/org/trust/profiles/${profile.id}`}
                            size="small"
                          >
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={t('trust.actions.edit')}>
                          <IconButton
                            component={Link}
                            to={`/console/org/trust/profiles/${profile.id}/edit`}
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
    </TrustProvider>
  );
}

export default TrustProfilesPage;
