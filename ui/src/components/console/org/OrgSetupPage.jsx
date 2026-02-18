/**
 * Organization Setup Page
 * 
 * Blocking setup page for organization console.
 * User must select/join/create an organization before accessing org console.
 * Replaces the old MyOrganizationsPage at /organizations/mine.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  Grid,
  Alert,
  CircularProgress,
  Divider,
  Stack,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import BusinessIcon from '@mui/icons-material/Business';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import AddIcon from '@mui/icons-material/Add';
import SearchIcon from '@mui/icons-material/Search';
import CodeIcon from '@mui/icons-material/Code';
import { useNavigate, Navigate } from 'react-router-dom';

import { getMyOrganizations, createOrganization } from '../../../services/organizationsApi';
import { useConsole } from '../../../contexts/ConsoleContext';

/**
 * Organization Setup Page Component
 */
export function OrgSetupPage() {
  const navigate = useNavigate();
  const { activeOrgId, setActiveOrgId, memberships, membershipsLoaded, refreshMemberships } = useConsole();
  
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState(null);

  // Create org form state
  const [orgName, setOrgName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [orgType, setOrgType] = useState('enterprise');
  const [description, setDescription] = useState('');
  const [contactEmail, setContactEmail] = useState('');

  /**
   * Load user's organizations
   */
  useEffect(() => {
    async function loadOrganizations() {
      try {
        setLoading(true);
        setError(null);
        const orgs = await getMyOrganizations();
        setOrganizations(orgs || []);
      } catch (err) {
        console.error('[OrgSetupPage] Failed to load organizations:', err);
        setError(err.message || 'Failed to load organizations');
      } finally {
        setLoading(false);
      }
    }

    loadOrganizations();
  }, []);

  /**
   * Redirect to catalog if user has memberships
   * (placed after all hooks to comply with Rules of Hooks)
   */
  if (membershipsLoaded && memberships && memberships.length > 0) {
    return <Navigate to="/console/applicant/catalog" replace />;
  }

  /**
   * Handle switching to an organization
   */
  const handleSwitchToOrg = async (orgId) => {
    try {
      await setActiveOrgId(orgId);
      navigate('/console/org');
    } catch (err) {
      console.error('[OrgSetupPage] Failed to switch organization:', err);
    }
  };

  /**
   * Handle create organization
   */
  const handleCreateOrg = async () => {
    if (!orgName || !displayName) {
      setCreateError('Organization name and display name are required');
      return;
    }

    try {
      setCreating(true);
      setCreateError(null);

      const newOrg = await createOrganization({
        name: orgName,
        display_name: displayName,
        org_type: orgType,
        description: description || undefined,
        contact_email: contactEmail || undefined,
      });

      // Refresh memberships
      await refreshMemberships();

      // Auto-select the new org and navigate to org console
      await setActiveOrgId(newOrg.id);
      navigate('/console/org');

      // Close dialog
      setCreateDialogOpen(false);
      resetCreateForm();
    } catch (err) {
      console.error('[OrgSetupPage] Failed to create organization:', err);
      setCreateError(err.message || 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  /**
   * Reset create form
   */
  const resetCreateForm = () => {
    setOrgName('');
    setDisplayName('');
    setOrgType('enterprise');
    setDescription('');
    setContactEmail('');
    setCreateError(null);
  };

  /**
   * Get status badge
   */
  const getStatusBadge = (status) => {
    const statusMap = {
      active: { label: 'Active', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
      pending: { label: 'Pending', color: 'warning', icon: <PendingIcon fontSize="small" /> },
      invited: { label: 'Invited', color: 'info', icon: <PendingIcon fontSize="small" /> },
      deactivated: { label: 'Deactivated', color: 'default', icon: null },
    };

    const config = statusMap[status] || statusMap.active;

    return (
      <Chip
        icon={config.icon}
        label={config.label}
        color={config.color}
        size="small"
      />
    );
  };

  /**
   * Get role badge
   */
  const getRoleBadge = (role, isAdminCapable) => {
    const roleColors = {
      owner: 'primary',
      admin: 'secondary',
      member: 'default',
      viewer: 'default',
    };

    return (
      <Chip
        icon={isAdminCapable ? <AdminPanelSettingsIcon fontSize="small" /> : null}
        label={role}
        color={roleColors[role] || 'default'}
        size="small"
        sx={{ textTransform: 'capitalize' }}
      />
    );
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom fontWeight={600}>
          Join an Organization
        </Typography>
        <Typography variant="body1" color="text.secondary">
          You need to join an organization to access credentials and start applying.
        </Typography>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Empty State - No Organizations */}
      {!loading && organizations.length === 0 && (
        <Card sx={{ textAlign: 'center', py: 6, mb: 3 }}>
          <CardContent>
            <BusinessIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Organizations Yet
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Create an organization to get started with issuing credentials.
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setCreateDialogOpen(true)}
            >
              Create Organization
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Organizations Grid */}
      {organizations.length > 0 && (
        <>
          <Typography variant="h6" gutterBottom sx={{ mb: 2 }}>
            Select from memberships
          </Typography>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {organizations.map((org) => (
              <Grid item xs={12} sm={6} md={4} key={org.id}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    border: org.id === activeOrgId ? 2 : 1,
                    borderColor: org.id === activeOrgId ? 'primary.main' : 'divider',
                    transition: 'all 0.2s',
                    '&:hover': {
                      boxShadow: 4,
                      transform: 'translateY(-2px)',
                    },
                  }}
                >
                  <CardContent sx={{ flexGrow: 1 }}>
                    {/* Organization Name */}
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 2 }}>
                      <BusinessIcon color="action" sx={{ mt: 0.5 }} />
                      <Box sx={{ flexGrow: 1 }}>
                        <Typography variant="h6" gutterBottom>
                          {org.display_name || org.name}
                        </Typography>
                        {org.description && (
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {org.description}
                          </Typography>
                        )}
                      </Box>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    {/* Membership Details */}
                    <Stack spacing={1.5}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="caption" color="text.secondary">
                          Role:
                        </Typography>
                        {getRoleBadge(
                          org.membership?.role,
                          org.membership?.is_admin_capable
                        )}
                      </Box>

                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="caption" color="text.secondary">
                          Status:
                        </Typography>
                        {getStatusBadge(org.membership?.status)}
                      </Box>

                      {org.membership?.joined_at && (
                        <Box>
                          <Typography variant="caption" color="text.secondary">
                            Joined: {new Date(org.membership.joined_at).toLocaleDateString()}
                          </Typography>
                        </Box>
                      )}
                    </Stack>

                    {/* Organization Type */}
                    {org.org_type && (
                      <Box sx={{ mt: 2 }}>
                        <Chip
                          label={org.org_type}
                          size="small"
                          variant="outlined"
                          sx={{ textTransform: 'capitalize' }}
                        />
                      </Box>
                    )}
                  </CardContent>

                  <CardActions sx={{ p: 2, pt: 0 }}>
                    <Button
                      fullWidth
                      variant={org.id === activeOrgId ? 'outlined' : 'contained'}
                      onClick={() => handleSwitchToOrg(org.id)}
                      disabled={org.membership?.status !== 'active'}
                    >
                      {org.id === activeOrgId ? 'Current Organization' : 'Switch to This Org'}
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Actions for existing org members */}
          <Divider sx={{ my: 4 }} />
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              Or Create a New Organization
            </Typography>
            <Stack direction="row" spacing={2} justifyContent="center" sx={{ mt: 2 }}>
              <Button
                variant="outlined"
                startIcon={<AddIcon />}
                onClick={() => setCreateDialogOpen(true)}
              >
                Create Organization
              </Button>
            </Stack>
          </Box>
        </>
      )}

      {/* Create Organization Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => {
          setCreateDialogOpen(false);
          resetCreateForm();
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create Organization</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            {createError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {createError}
              </Alert>
            )}

            <TextField
              fullWidth
              label="Organization Name *"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              helperText="Unique identifier (lowercase, no spaces)"
              sx={{ mb: 2 }}
            />

            <TextField
              fullWidth
              label="Display Name *"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              helperText="How your organization appears to users"
              sx={{ mb: 2 }}
            />

            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Organization Type</InputLabel>
              <Select
                value={orgType}
                onChange={(e) => setOrgType(e.target.value)}
                label="Organization Type"
              >
                <MenuItem value="enterprise">Enterprise</MenuItem>
                <MenuItem value="startup">Startup</MenuItem>
                <MenuItem value="individual">Individual</MenuItem>
                <MenuItem value="government">Government</MenuItem>
                <MenuItem value="education">Education</MenuItem>
              </Select>
            </FormControl>

            <TextField
              fullWidth
              label="Description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              multiline
              rows={3}
              helperText="Optional description of your organization"
              sx={{ mb: 2 }}
            />

            <TextField
              fullWidth
              label="Contact Email"
              type="email"
              value={contactEmail}
              onChange={(e) => setContactEmail(e.target.value)}
              helperText="Optional contact email"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setCreateDialogOpen(false);
              resetCreateForm();
            }}
            disabled={creating}
          >
            Cancel
          </Button>
          <Button
            onClick={handleCreateOrg}
            variant="contained"
            disabled={creating || !orgName || !displayName}
          >
            {creating ? <CircularProgress size={24} /> : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default OrgSetupPage;
