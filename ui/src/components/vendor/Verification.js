/**
 * Verification Page
 * 
 * Vendor-facing page for managing presentation policies and verification settings.
 * 
 * Features:
 * - Create presentation policies with wizard
 * - View and manage existing policies
 * - Standards-based templates
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Alert,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  CircularProgress,
} from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AddIcon from '@mui/icons-material/Add';
import PolicyIcon from '@mui/icons-material/Policy';
import HistoryIcon from '@mui/icons-material/History';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';

import { PolicyWizard } from './verification';
import { listPresentationPolicies, deletePresentationPolicy } from '../../services/presentationPolicyApi';

/**
 * Verification Main Component
 */
export default function Verification() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showWizard, setShowWizard] = useState(false);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await listPresentationPolicies();
      setPolicies(response.data || response || []);
    } catch (err) {
      console.error('Failed to fetch policies:', err);
      setError('Failed to load presentation policies');
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePolicy = () => {
    setShowWizard(true);
  };

  const handleWizardComplete = (newPolicy) => {
    setShowWizard(false);
    fetchPolicies(); // Refresh the list
  };

  const handleWizardCancel = () => {
    setShowWizard(false);
  };

  const handleDeletePolicy = async (policyId) => {
    if (!window.confirm('Are you sure you want to delete this policy?')) {
      return;
    }

    try {
      await deletePresentationPolicy(policyId);
      fetchPolicies(); // Refresh the list
    } catch (err) {
      console.error('Failed to delete policy:', err);
      alert('Failed to delete policy');
    }
  };

  // Show wizard
  if (showWizard) {
    return (
      <PolicyWizard
        onComplete={handleWizardComplete}
        onCancel={handleWizardCancel}
      />
    );
  }

  // Loading state
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid="verification-page">
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <VerifiedUserIcon fontSize="large" />
          Verification
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Define presentation policies to verify credentials from applicants and external parties.
        </Typography>
      </Box>

      {/* Coming Soon Notice */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Empty State */}
      {policies.length === 0 && (
        <Paper sx={{ p: 6, textAlign: 'center', bgcolor: 'grey.50' }}>
          <PolicyIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            No Presentation Policies Yet
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
            Presentation policies define what credentials you want to verify from applicants.
            You can specify required fields, accepted issuers, and validation rules.
          </Typography>
          <Button
            variant="contained"
            size="large"
            startIcon={<AddIcon />}
            onClick={handleCreatePolicy}
          >
            Create Policy
          </Button>
        </Paper>
      )}

      {/* Policies List */}
      {policies.length > 0 && (
        <>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6">
              Presentation Policies ({policies.length})
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleCreatePolicy}
            >
              Create Policy
            </Button>
          </Box>

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Credential Types</TableCell>
                  <TableCell>Claims</TableCell>
                  <TableCell>Standard</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {policies.map((policy) => (
                  <TableRow key={policy.id}>
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>
                        {policy.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {policy.description || '—'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {policy.accepted_credential_types?.slice(0, 2).map((type) => (
                          <Chip key={type} label={type} size="small" />
                        ))}
                        {policy.accepted_credential_types?.length > 2 && (
                          <Chip label={`+${policy.accepted_credential_types.length - 2}`} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={`${policy.required_claims?.length || 0} claims`}
                        size="small"
                        color="primary"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      {policy.metadata?.standard_reference ? (
                        <Chip
                          label={policy.metadata.standard_reference}
                          size="small"
                          variant="outlined"
                        />
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          —
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" color="primary">
                        <EditIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeletePolicy(policy.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}

      {/* Future Feature Preview */}
      <Grid container spacing={3} sx={{ mt: 3 }}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <PolicyIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Policy Builder
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Create presentation policies with a visual builder. Define required credentials,
                fields, and validation rules.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <HistoryIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Verification History
              </Typography>
              <Typography variant="body2" color="text.secondary">
                View all verification requests, see which passed or failed, and audit the verification log.
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <VerifiedUserIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Trusted Issuers
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Manage a list of trusted credential issuers whose credentials you'll accept.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
