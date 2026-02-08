/**
 * Trusted Issuers Page
 * 
 * Manages trusted issuers across all trust profiles.
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
  TextField,
  InputAdornment,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import DeleteIcon from '@mui/icons-material/Delete';
import { Link } from 'react-router-dom';

import { ResourcePage, AddButton, EmptyState, EmptyStates } from '../../common';

const TRUST_TABS = [
  { label: 'Trust Profiles', path: '/console/trust/profiles' },
  { label: 'Trusted Issuers', path: '/console/trust/issuers' },
  { label: 'Revocation Profiles', path: '/console/trust/revocation' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Trust', path: '/console/trust' },
  { label: 'Trusted Issuers', path: '/console/trust/issuers' },
];

function TrustedIssuersPage() {
  const [issuers, setIssuers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    // TODO: Fetch trusted issuers from API
    const loadIssuers = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setIssuers([
          {
            id: 'ti-1',
            name: 'German Federal Government',
            country: 'DE',
            did: 'did:web:issuer.bundesdruckerei.de',
            trustProfile: 'EUDI Wallet Trust Profile',
            status: 'active',
          },
          {
            id: 'ti-2',
            name: 'French National Identity',
            country: 'FR',
            did: 'did:web:france-identite.gouv.fr',
            trustProfile: 'EUDI Wallet Trust Profile',
            status: 'active',
          },
          {
            id: 'ti-3',
            name: 'ICAO PKD Master List',
            country: 'INT',
            did: 'did:web:pkd.icao.int',
            trustProfile: 'ICAO PKD Profile',
            status: 'active',
          },
        ]);
      } catch (err) {
        setError('Failed to load trusted issuers');
      } finally {
        setLoading(false);
      }
    };
    loadIssuers();
  }, []);

  const filteredIssuers = issuers.filter(
    (issuer) =>
      issuer.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      issuer.did.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <ResourcePage
      title="Trusted Issuers"
      description="Manage the list of trusted credential issuers across your trust profiles."
      tabs={TRUST_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <AddButton 
          label="Add Issuer" 
          path="/console/trust/issuers/new" 
        />
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Search */}
      <Box sx={{ mb: 3 }}>
        <TextField
          placeholder="Search issuers..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          sx={{ width: 300 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {loading ? (
        <LinearProgress />
      ) : issuers.length === 0 ? (
        <EmptyState {...EmptyStates.trustedIssuers} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Country</TableCell>
                <TableCell>DID</TableCell>
                <TableCell>Trust Profile</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredIssuers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No issuers match your search. Try adjusting your query.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                filteredIssuers.map((issuer) => (
                  <TableRow key={issuer.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {issuer.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={issuer.country} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {issuer.did.length > 40 ? `${issuer.did.substring(0, 40)}...` : issuer.did}
                      </Typography>
                    </TableCell>
                    <TableCell>{issuer.trustProfile}</TableCell>
                    <TableCell>
                      <Chip 
                        label={issuer.status === 'active' ? 'Active' : 'Inactive'} 
                        color={issuer.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/trust/issuers/${issuer.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Remove">
                        <IconButton size="small" color="error">
                          <DeleteIcon fontSize="small" />
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

export default TrustedIssuersPage;
