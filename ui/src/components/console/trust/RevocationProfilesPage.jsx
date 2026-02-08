/**
 * Revocation Profiles Page
 * 
 * Manages credential revocation profiles and status lists.
 */

import { useState, useEffect } from 'react';
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

import { ResourcePage } from '../../common';
// TODO: Wire up when RevocationManager is available
// import RevocationManager from '../../vendor/RevocationManager';

const TRUST_TABS = [
  { label: 'Trust Profiles', path: '/console/trust/profiles' },
  { label: 'Trusted Issuers', path: '/console/trust/issuers' },
  { label: 'Revocation Profiles', path: '/console/trust/revocation' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Trust', path: '/console/trust' },
  { label: 'Revocation Profiles', path: '/console/trust/revocation' },
];

function RevocationProfilesPage() {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch revocation profiles from API
    const loadProfiles = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setProfiles([
          {
            id: 'rp-1',
            name: 'Status List 2021 - Production',
            type: 'StatusList2021',
            credentialsTracked: 15234,
            revokedCount: 42,
            status: 'active',
            updatedAt: '2026-02-07T08:00:00Z',
          },
          {
            id: 'rp-2',
            name: 'Bitstring Status List - Beta',
            type: 'BitstringStatusList',
            credentialsTracked: 500,
            revokedCount: 3,
            status: 'active',
            updatedAt: '2026-02-06T16:30:00Z',
          },
        ]);
      } catch (err) {
        setError('Failed to load revocation profiles');
      } finally {
        setLoading(false);
      }
    };
    loadProfiles();
  }, []);

  return (
    <ResourcePage
      title="Revocation Profiles"
      description="Configure how credential revocation status is tracked and published."
      resourceName="Revocation Profile"
      buildPath="/console/trust/revocation/new"
      tabs={TRUST_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell align="right">Credentials Tracked</TableCell>
                <TableCell align="right">Revoked</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Updated</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {profiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No revocation profiles configured.
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
                      <Chip label={profile.type} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell align="right">
                      {profile.credentialsTracked.toLocaleString()}
                    </TableCell>
                    <TableCell align="right">
                      <Chip 
                        label={profile.revokedCount} 
                        size="small" 
                        color={profile.revokedCount > 0 ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={profile.status === 'active' ? 'Active' : 'Inactive'} 
                        color={profile.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(profile.updatedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/trust/revocation/${profile.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          component={Link}
                          to={`/console/trust/revocation/${profile.id}/edit`}
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

export default RevocationProfilesPage;
