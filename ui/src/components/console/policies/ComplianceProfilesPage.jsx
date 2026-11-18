/** Organization-owned compliance metadata and immutable system presets. */
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Button, Chip, LinearProgress, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { ResourcePage } from '../../common';
import { listComplianceProfiles } from '../../../services/complianceProfilesApi';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';

const BASE = '/console/org/policies/compliance';
const PAGE_SIZE = 50;
function ComplianceProfileList({ organizationId, can }) {
  const { t } = useTranslation('console');
  const [page, setPage] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    let current = true; setLoading(true); setError(''); setProfiles([]);
    listComplianceProfiles({ organization_id: organizationId, limit: PAGE_SIZE, offset: page * PAGE_SIZE }).then((result) => {
      if (!current) return;
      if (!Array.isArray(result) || !result.every((profile) => typeof profile?.id === 'string'
        && (profile.is_system === true ? profile.organization_id == null : profile.organization_id === organizationId))) {
        throw new Error('Compliance inventory returned profiles outside the selected organization.');
      }
      setProfiles(result);
    }).catch((failure) => { if (current) setError(failure?.message || 'Unable to load compliance profiles.'); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [organizationId, page, attempt]);
  return <ResourcePage title={t('complianceProfilesPage.title')} description={t('complianceProfilesPage.description')}
    resourceName={t('complianceProfilesPage.resourceName')}
    tabs={[{ label: t('policies.presentationPolicies'), path: '/console/org/policies/presentation' }, { label: t('policies.complianceProfiles'), path: BASE }]}
    breadcrumbs={[{ label: 'Console', path: '/console/org' }, { label: 'Compliance Profiles', path: BASE }]}
    actions={can('compliance-profile', 'create') && <Button component={Link} to={`${BASE}/new`} variant="contained">Create Compliance Profile</Button>}>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}<Button onClick={() => setAttempt((v) => v + 1)}>Retry</Button></Alert>}
    {loading ? <LinearProgress /> : !error && <TableContainer component={Paper}><Table>
      <TableHead><TableRow>{['Name', 'Code', 'Credential format', 'Issuance protocol', 'Scope', 'Status'].map((label) => <TableCell key={label}>{label}</TableCell>)}</TableRow></TableHead>
      <TableBody>{profiles.length === 0 ? <TableRow><TableCell colSpan={6}><Typography sx={{ py: 3 }}>No compliance profiles on this page.</Typography></TableCell></TableRow> : profiles.map((profile) => <TableRow key={profile.id}>
        <TableCell><Button component={Link} to={`${BASE}/${encodeURIComponent(profile.id)}`}>{profile.name}</Button></TableCell>
        <TableCell>{profile.compliance_code || 'Not specified'}</TableCell><TableCell>{profile.credential_format}</TableCell>
        <TableCell>{profile.issuance_protocol || 'Not specified'}</TableCell><TableCell>{profile.is_system ? 'System preset' : 'Organization'}</TableCell>
        <TableCell><Chip label={profile.status || 'Unknown'} color={profile.status === 'ACTIVE' ? 'success' : 'default'} size="small" /></TableCell>
      </TableRow>)}</TableBody>
    </Table></TableContainer>}
    <Stack direction="row" spacing={2} sx={{ mt: 2 }}><Button disabled={loading || page === 0} onClick={() => setPage((v) => v - 1)}>Previous page</Button>
      <Typography sx={{ alignSelf: 'center' }}>Page {page + 1}</Typography><Button disabled={loading || Boolean(error) || profiles.length < PAGE_SIZE} onClick={() => setPage((v) => v + 1)}>Next page</Button></Stack>
  </ResourcePage>;
}
export default function ComplianceProfilesPage() {
  const { activeOrgId } = useConsole(); const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before loading compliance profiles.</Alert>;
  if (isLoading) return <LinearProgress />;
  if (!can('compliance-profile', 'view')) return <Alert severity="error">You do not have permission to view compliance profiles.</Alert>;
  return <ComplianceProfileList key={activeOrgId} organizationId={activeOrgId} can={can} />;
}
