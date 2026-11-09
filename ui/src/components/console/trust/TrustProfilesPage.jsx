/**
 * Organization-scoped Trust Profile inventory.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert, Button, Chip, IconButton, LinearProgress, Paper, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, Tooltip, Typography,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Link, useLocation } from 'react-router';

import { ResourcePage, EmptyState } from '../../common';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listTrustProfiles } from '../../../services/presentationPolicyApi';
import { loadScopedCatalog } from '../../../services/loadScopedCatalog';

const STATUS_LABELS = {
  draft: 'statusDraft', active: 'statusActive', suspended: 'statusSuspended', archived: 'statusArchived',
};

function pinnedSourceCount(profile) {
  return Array.isArray(profile.trust_sources)
    ? profile.trust_sources.filter((source) => source?.source_type === 'PINNED_ISSUER').length
    : '—';
}

function algorithmCount(profile) {
  const algorithms = profile.validation_rules?.allowed_algorithms ?? profile.allowed_algorithms;
  return Array.isArray(algorithms) ? algorithms.length : '—';
}

function TrustProfilesContent({ organizationId, canCreate, canEdit }) {
  const { t } = useTranslation('console');
  const beginLoad = useAsyncActionScope();
  const requestAbort = useRef(null);
  const browserEntry = useRef(typeof window === 'undefined' ? null : {
    href: window.location.href, key: window.history.state?.key,
  });
  const isCurrentView = useCallback(() => !browserEntry.current || (
    typeof window !== 'undefined' && window.location.href === browserEntry.current.href
      && window.history.state?.key === browserEntry.current.key
  ), []);
  const [profiles, setProfiles] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    if (!isCurrentView()) return;
    requestAbort.current?.abort();
    const controller = new AbortController();
    requestAbort.current = controller;
    const action = beginLoad();
    const isCurrent = () => action.isCurrent() && isCurrentView() && !controller.signal.aborted;
    const assertCurrent = () => {
      if (!isCurrent()) throw new DOMException('Catalog loading cancelled.', 'AbortError');
    };
    setProfiles(null);
    setLoading(true);
    setError(null);
    try {
      const rows = await loadScopedCatalog(async (params) => {
        assertCurrent();
        const page = await listTrustProfiles(params);
        assertCurrent();
        if (!Array.isArray(page) || page.some((profile) => (
          typeof profile?.id !== 'string' || !profile.id.trim()
          || profile.organization_id !== organizationId || typeof profile.name !== 'string'
        ))) {
          throw new Error(t('trust.trustProfilesPage.scopeMismatch'));
        }
        return page;
      }, organizationId, { signal: controller.signal });
      if (isCurrent()) setProfiles(rows);
    } catch (reason) {
      if (isCurrent()) setError(reason?.message || t('trust.trustProfilesPage.loadFailed'));
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [beginLoad, isCurrentView, organizationId, t]);

  useEffect(() => {
    reload();
    return () => requestAbort.current?.abort();
  }, [reload]);

  const updatedLabel = (profile) => {
    const raw = profile.updated_at || profile.updatedAt || profile.created_at || profile.createdAt;
    if (!raw) return '—';
    const parsed = new Date(raw);
    return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleDateString();
  };

  return (
    <ResourcePage
      title={t('trust.trustProfilesPage.title')}
      description={t('trust.trustProfilesPage.description')}
      resourceName={t('trust.trustProfilesPage.title')}
      buildPath={canCreate ? '/console/org/trust/profiles/new' : undefined}
      newPath={canCreate ? '/console/org/trust/profiles/new?mode=advanced' : undefined}
      breadcrumbs={[
        { label: t('trust.trustProfilesPage.consoleBreadcrumb'), path: '/console' },
        { label: t('trust.trustProfilesPage.trustBreadcrumb'), path: '/console/org/trust' },
        { label: t('trust.trustProfilesPage.title'), path: '/console/org/trust/profiles' },
      ]}
    >
      {loading ? <LinearProgress /> : error ? (
        <Alert severity="error">
          {error}
          <Button onClick={reload}>{t('trust.trustProfilesPage.retryProfiles')}</Button>
        </Alert>
      ) : profiles?.length === 0 ? (
        <EmptyState
          title={t('trust.trustProfilesPage.emptyTitle')}
          description={t('trust.trustProfilesPage.emptyDescription')}
          actionLabel={canCreate ? t('trust.trustProfilesPage.createProfile') : undefined}
          actionPath={canCreate ? '/console/org/trust/profiles/new' : undefined}
        />
      ) : (
        <>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t('trust.trustProfilesPage.pinnedSourcesHelp')}
          </Typography>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('trust.trustProfilesPage.name')}</TableCell>
                  <TableCell>{t('trust.trustProfilesPage.framework')}</TableCell>
                  <TableCell>{t('trust.trustProfilesPage.status')}</TableCell>
                  <TableCell align="right">{t('trust.trustProfilesPage.pinnedSources')}</TableCell>
                  <TableCell align="right">{t('trust.trustProfilesPage.allowedAlgorithms')}</TableCell>
                  <TableCell>{t('trust.trustProfilesPage.lastUpdated')}</TableCell>
                  <TableCell align="right">{t('trust.trustProfilesPage.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(profiles || []).map((profile) => {
                  const status = typeof profile.status === 'string' ? profile.status.toLowerCase() : '';
                  const framework = profile.framework || profile.profile_type;
                  return (
                    <TableRow key={profile.id} hover>
                      <TableCell><Typography variant="body2" sx={{ fontWeight: 500 }}>{profile.name}</Typography></TableCell>
                      <TableCell><Chip label={typeof framework === 'string' ? framework.toUpperCase() : '—'} size="small" variant="outlined" /></TableCell>
                      <TableCell>
                        <Chip size="small"
                          label={t('trust.trustProfileDetail.' + (STATUS_LABELS[status] || 'statusUnknown'))}
                          color={status === 'active' ? 'success' : status === 'suspended' ? 'warning' : 'default'} />
                      </TableCell>
                      <TableCell align="right">{pinnedSourceCount(profile)}</TableCell>
                      <TableCell align="right">{algorithmCount(profile)}</TableCell>
                      <TableCell>{updatedLabel(profile)}</TableCell>
                      <TableCell align="right">
                        <Tooltip title={t('trust.trustProfilesPage.viewDetails')}>
                          <IconButton component={Link} to={'/console/org/trust/profiles/' + encodeURIComponent(profile.id)}
                            aria-label={t('trust.trustProfilesPage.viewDetails')} size="small">
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {canEdit && (
                          <Tooltip title={t('trust.trustProfilesPage.edit')}>
                            <IconButton component={Link} to={'/console/org/trust/profiles/' + encodeURIComponent(profile.id) + '/edit'}
                              aria-label={t('trust.trustProfilesPage.edit')} size="small">
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
    </ResourcePage>
  );
}

function TrustProfilesPage() {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();
  const location = useLocation();
  const { can, isLoading } = usePermissions();
  const canView = can('trust-profile', 'view');
  const canCreate = can('trust-profile', 'create');
  const canEdit = can('trust-profile', 'edit');
  if (isLoading) return <LinearProgress />;
  if (typeof activeOrgId !== 'string' || !activeOrgId.trim()) {
    return <Alert severity="info">{t('trust.trustProfilesPage.selectOrganization')}</Alert>;
  }
  if (!canView) return <Alert severity="info">{t('trust.trustProfilesPage.readDenied')}</Alert>;
  const key = JSON.stringify([activeOrgId, location.key, location.pathname, location.search, location.hash, canView, canCreate, canEdit]);
  return <TrustProfilesContent key={key} organizationId={activeOrgId} canCreate={canCreate} canEdit={canEdit} />;
}

export default TrustProfilesPage;
