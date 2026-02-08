/**
 * Presentation Policies Page
 * 
 * Manages presentation policies - rules for credential verification requests.
 */

import { useState, useEffect } from 'react';
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

const POLICIES_TABS = [
  { label: 'Presentation Policies', path: '/console/policies/presentation' },
  { label: 'Compliance Profiles', path: '/console/policies/compliance' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Policies', path: '/console/policies' },
  { label: 'Presentation Policies', path: '/console/policies/presentation' },
];

function PresentationPoliciesPage() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch presentation policies from API
    const loadPolicies = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setPolicies([
          {
            id: 'pp-1',
            name: 'Age Verification (18+)',
            trustProfile: 'EUDI Wallet Trust Profile',
            requiredClaims: ['age_over_18'],
            optionalClaims: [],
            freshness: '24h',
            holderBinding: true,
            usageCount: 15420,
            status: 'active',
            updatedAt: '2026-02-06T10:30:00Z',
          },
          {
            id: 'pp-2',
            name: 'Full Identity Verification',
            trustProfile: 'EUDI Wallet Trust Profile',
            requiredClaims: ['given_name', 'family_name', 'birth_date', 'document_number'],
            optionalClaims: ['address', 'nationality'],
            freshness: '1h',
            holderBinding: true,
            usageCount: 8230,
            status: 'active',
            updatedAt: '2026-02-05T14:20:00Z',
          },
          {
            id: 'pp-3',
            name: 'Passport Verification',
            trustProfile: 'ICAO PKD Profile',
            requiredClaims: ['mrz', 'photo', 'nationality'],
            optionalClaims: [],
            freshness: '15m',
            holderBinding: true,
            usageCount: 2150,
            status: 'active',
            updatedAt: '2026-02-04T09:00:00Z',
          },
        ]);
      } catch (err) {
        setError('Failed to load presentation policies');
      } finally {
        setLoading(false);
      }
    };
    loadPolicies();
  }, []);

  const TestActions = () => (
    <Box sx={{ display: 'flex', gap: 1 }}>
      <Button
        variant="outlined"
        size="small"
        startIcon={<PlayArrowIcon />}
        component={Link}
        to="/console/policies/test"
      >
        Evaluate VP
      </Button>
      <Button
        variant="outlined"
        size="small"
        startIcon={<QrCodeIcon />}
        component={Link}
        to="/console/flows/definitions/new?type=verification"
      >
        Start QR Verification
      </Button>
    </Box>
  );

  return (
    <ResourcePage
      title="Presentation Policies"
      description="Define what credentials and claims are required for verification requests."
      resourceName="Policy"
      buildPath="/console/policies/presentation/new"
      newPath="/console/policies/presentation/new?mode=advanced"
      tabs={POLICIES_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={<TestActions />}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : policies.length === 0 ? (
        <EmptyState {...EmptyStates.policies} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Trust Profile</TableCell>
                <TableCell>Required Claims</TableCell>
                <TableCell>Freshness</TableCell>
                <TableCell>Holder Binding</TableCell>
                <TableCell align="right">Usage</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
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
                        <Chip label="Required" size="small" color="info" />
                      ) : (
                        <Chip label="Optional" size="small" variant="outlined" />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      {policy.usageCount.toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <StatusChip status={policy.status} />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/policies/presentation/${policy.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          component={Link}
                          to={`/console/policies/presentation/${policy.id}/edit`}
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
