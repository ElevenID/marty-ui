/**
 * Trust Profiles Page
 * 
 * Manages Trust Profiles - frameworks that define trusted issuers and validation rules.
 * Wraps the existing TrustRegistry component with the new navigation structure.
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

import { ResourcePage, StatusChip, EmptyState, EmptyStates } from '../../common';
import { TrustProvider } from '../../trust';

const TRUST_TABS = [
  { label: 'Trust Profiles', path: '/console/trust/profiles' },
  { label: 'Trusted Issuers', path: '/console/trust/issuers' },
  { label: 'Revocation Profiles', path: '/console/trust/revocation' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Trust', path: '/console/trust' },
  { label: 'Trust Profiles', path: '/console/trust/profiles' },
];

function TrustProfilesPage() {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch trust profiles from API
    const loadProfiles = async () => {
      try {
        // Simulated data - replace with actual API call
        await new Promise((resolve) => setTimeout(resolve, 500));
        setProfiles([
          {
            id: 'tp-1',
            name: 'EUDI Wallet Trust Profile',
            framework: 'eudi',
            status: 'active',
            trustedIssuers: 12,
            validationRules: 5,
            updatedAt: '2026-02-06T10:30:00Z',
          },
          {
            id: 'tp-2',
            name: 'ICAO PKD Profile',
            framework: 'icao',
            status: 'active',
            trustedIssuers: 195,
            validationRules: 3,
            updatedAt: '2026-02-05T14:20:00Z',
          },
          {
            id: 'tp-3',
            name: 'Custom Enterprise Profile',
            framework: 'custom',
            status: 'draft',
            trustedIssuers: 0,
            validationRules: 0,
            updatedAt: '2026-02-07T09:00:00Z',
          },
        ]);
      } catch (err) {
        setError('Failed to load trust profiles');
      } finally {
        setLoading(false);
      }
    };
    loadProfiles();
  }, []);

  return (
    <TrustProvider>
      <ResourcePage
        title="Trust Profiles"
        description="Define trust frameworks, trusted issuers, and validation rules for credential verification."
        resourceName="Trust Profile"
        buildPath="/console/trust/profiles/new"
        newPath="/console/trust/profiles/new?mode=advanced"
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
        ) : profiles.length === 0 ? (
          <EmptyState {...EmptyStates.trustProfiles} />
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Framework</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Trusted Issuers</TableCell>
                  <TableCell align="right">Validation Rules</TableCell>
                  <TableCell>Last Updated</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {profiles.map((profile) => (
                    <TableRow key={profile.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight={500}>
                          {profile.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={profile.framework.toUpperCase()} 
                          size="small" 
                          variant="outlined" 
                        />
                      </TableCell>
                      <TableCell>
                        <StatusChip status={profile.status} />
                      </TableCell>
                      <TableCell align="right">{profile.trustedIssuers}</TableCell>
                      <TableCell align="right">{profile.validationRules}</TableCell>
                      <TableCell>
                        {new Date(profile.updatedAt).toLocaleDateString()}
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton
                            component={Link}
                            to={`/console/trust/profiles/${profile.id}`}
                            size="small"
                          >
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Edit">
                          <IconButton
                            component={Link}
                            to={`/console/trust/profiles/${profile.id}/edit`}
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
