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

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
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
  const { t } = useTranslation('vendor');
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
      setError(t('verification.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePolicy = () => {
    setShowWizard(true);
  };

  const handleWizardComplete = () => {
    setShowWizard(false);
    fetchPolicies(); // Refresh the list
  };

  const handleWizardCancel = () => {
    setShowWizard(false);
  };

  const handleDeletePolicy = async (policyId) => {
    if (!window.confirm(t('verification.deleteConfirm'))) {
      return;
    }

    try {
      await deletePresentationPolicy(policyId);
      fetchPolicies(); // Refresh the list
    } catch (err) {
      console.error('Failed to delete policy:', err);
      alert(t('verification.deleteFailed'));
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
          {t('verification.title')}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          {t('verification.description')}
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
            {t('verification.empty.title')}
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
            {t('verification.empty.description')}
          </Typography>
          <Button
            variant="contained"
            size="large"
            startIcon={<AddIcon />}
            onClick={handleCreatePolicy}
          >
            {t('verification.empty.createButton')}
          </Button>
        </Paper>
      )}

      {/* Policies List */}
      {policies.length > 0 && (
        <>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6">
              {t('verification.list.title', { count: policies.length })}
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleCreatePolicy}
            >
              {t('verification.list.createButton')}
            </Button>
          </Box>

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('verification.table.name')}</TableCell>
                  <TableCell>{t('verification.table.description')}</TableCell>
                  <TableCell>{t('verification.table.credentialTypes')}</TableCell>
                  <TableCell>{t('verification.table.claims')}</TableCell>
                  <TableCell>{t('verification.table.standard')}</TableCell>
                  <TableCell align="right">{t('verification.table.actions')}</TableCell>
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
                        {policy.description || t('verification.table.noDescription')}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {policy.accepted_credential_types?.slice(0, 2).map((type) => (
                          <Chip key={type} label={type} size="small" />
                        ))}
                        {policy.accepted_credential_types?.length > 2 && (
                          <Chip label={t('verification.table.moreTypes', { count: policy.accepted_credential_types.length - 2 })} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={t('verification.table.claimsCount', { count: policy.required_claims?.length || 0 })}
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
                          {t('verification.table.noDescription')}
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
                {t('verification.features.policyBuilder.title')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('verification.features.policyBuilder.description')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <HistoryIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                {t('verification.features.verificationHistory.title')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('verification.features.verificationHistory.description')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <VerifiedUserIcon color="primary" sx={{ fontSize: 40, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                {t('verification.features.trustedIssuers.title')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('verification.features.trustedIssuers.description')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
