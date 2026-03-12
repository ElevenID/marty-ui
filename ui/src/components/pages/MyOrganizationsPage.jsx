/**
 * My Organizations Page
 * 
 * Displays all organizations the current user belongs to with membership details.
 * Allows switching to an organization or managing memberships.
 */

import { useAsyncData } from '../../hooks/useAsyncData';
import { useNotifications } from '../../hooks/useNotifications';
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
} from '@mui/material';
import BusinessIcon from '@mui/icons-material/Business';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import { useNavigate } from 'react-router-dom';

import { getMyOrganizations } from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';

/**
 * My Organizations Page Component
 */
export function MyOrganizationsPage() {
  const navigate = useNavigate();
  const { activeOrgId, setActiveOrgId } = useConsole();
  const { showError } = useNotifications();
  const { data: organizations = [], loading, error } = useAsyncData(
    () => getMyOrganizations(),
    []
  );

  /**
   * Handle switching to an organization
   */
  const handleSwitchToOrg = async (orgId) => {
    try {
      await setActiveOrgId(orgId);
      // Navigation is handled by setActiveOrgId in ConsoleContext
    } catch (err) {
      console.error('Failed to switch organization:', err);
      showError('Failed to switch organization. Please try again.');
    }
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
          My Organizations
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Organizations you&apos;re a member of. Switch to an organization to access its console.
        </Typography>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {/* Empty State */}
      {!loading && organizations.length === 0 && (
        <Card sx={{ textAlign: 'center', py: 6 }}>
          <CardContent>
            <BusinessIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Organizations Yet
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              You&apos;re not a member of any organizations. Discover organizations or join one with a join code.
            </Typography>
            <Stack direction="row" spacing={2} justifyContent="center">
              <Button
                variant="contained"
                onClick={() => navigate('/organizations/discover')}
              >
                Discover Organizations
              </Button>
              <Button
                variant="outlined"
                onClick={() => navigate('/organizations/join')}
              >
                Use Join Code
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Organizations Grid */}
      {organizations.length > 0 && (
        <Grid container spacing={3}>
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
                        {org.name || org.display_name}
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
      )}

      {/* Actions */}
      {organizations.length > 0 && (
        <Box sx={{ mt: 4, textAlign: 'center' }}>
          <Stack direction="row" spacing={2} justifyContent="center">
            <Button
              variant="outlined"
              onClick={() => navigate('/organizations/discover')}
            >
              Discover More Organizations
            </Button>
            <Button
              variant="outlined"
              onClick={() => navigate('/organizations/join')}
            >
              Use Join Code
            </Button>
          </Stack>
        </Box>
      )}
    </Container>
  );
}

export default MyOrganizationsPage;
