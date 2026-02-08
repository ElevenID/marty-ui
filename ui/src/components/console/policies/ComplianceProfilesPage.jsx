/**
 * Compliance Profiles Page
 * 
 * Manages compliance profiles - regulatory and business rule configurations.
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

const POLICIES_TABS = [
  { label: 'Presentation Policies', path: '/console/policies/presentation' },
  { label: 'Compliance Profiles', path: '/console/policies/compliance' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Policies', path: '/console/policies' },
  { label: 'Compliance Profiles', path: '/console/policies/compliance' },
];

function ComplianceProfilesPage() {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch compliance profiles from API
    const loadProfiles = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setProfiles([
          {
            id: 'cp-1',
            name: 'eIDAS 2.0 Compliance',
            regulation: 'eIDAS',
            region: 'EU',
            requirements: 12,
            metRequirements: 12,
            status: 'compliant',
            updatedAt: '2026-02-06T10:30:00Z',
          },
          {
            id: 'cp-2',
            name: 'GDPR Data Minimization',
            regulation: 'GDPR',
            region: 'EU',
            requirements: 8,
            metRequirements: 7,
            status: 'review_needed',
            updatedAt: '2026-02-05T14:20:00Z',
          },
          {
            id: 'cp-3',
            name: 'AAMVA mDL Compliance',
            regulation: 'AAMVA',
            region: 'US',
            requirements: 15,
            metRequirements: 15,
            status: 'compliant',
            updatedAt: '2026-02-04T09:00:00Z',
          },
        ]);
      } catch (err) {
        setError('Failed to load compliance profiles');
      } finally {
        setLoading(false);
      }
    };
    loadProfiles();
  }, []);

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
    switch (status) {
      case 'compliant':
        return 'Compliant';
      case 'review_needed':
        return 'Review Needed';
      case 'non_compliant':
        return 'Non-Compliant';
      default:
        return status;
    }
  };

  return (
    <ResourcePage
      title="Compliance Profiles"
      description="Track regulatory compliance and configure business rules for credential operations."
      resourceName="Compliance Profile"
      buildPath="/console/policies/compliance/new"
      tabs={POLICIES_TABS}
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
                <TableCell>Regulation</TableCell>
                <TableCell>Region</TableCell>
                <TableCell>Requirements</TableCell>
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
                      No compliance profiles configured.
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
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/policies/compliance/${profile.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          component={Link}
                          to={`/console/policies/compliance/${profile.id}/edit`}
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
