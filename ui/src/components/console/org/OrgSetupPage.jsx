/**
 * Organization Setup Page
 * 
 * Blocking setup page for organization console.
 * User must select/join/create an organization before accessing org console.
 * Replaces the old public-only organizations hub as the org-console gate.
 */

import { useAsyncData } from '../../../hooks/useAsyncData';
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
import AddIcon from '@mui/icons-material/Add';
import SearchIcon from '@mui/icons-material/Search';
import CodeIcon from '@mui/icons-material/Code';
import { useNavigate, Navigate, useSearchParams } from 'react-router-dom';

import { getMyOrganizations } from '../../../services/organizationsApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  membershipHasOrgConsoleAccess,
} from '../../../application/session/authSession';
import { ENABLE_ORGANIZATION_CREATION } from '@ui-public-config';

/**
 * Organization Setup Page Component
 */
export function OrgSetupPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const {
    activeOrgId,
    setActiveOrgId,
    setMode,
    membershipsLoaded,
  } = useConsole();
  const {
    organizationId: currentOrganizationId,
    organizations: authOrganizations,
    setActiveOrganizationId,
  } = useAuth();
  const returnTo = searchParams.get('returnTo');
  const createOnlyMode = searchParams.get('intent') === 'create';
  const createOrganizationPath = (() => {
    const params = new URLSearchParams();
    if (returnTo) params.set('returnTo', returnTo);
    const query = params.toString();
    return query ? `/console/organizations/create?${query}` : '/console/organizations/create';
  })();
  
  const { data: organizations = [], loading, error } = useAsyncData(
    () => getMyOrganizations(),
    []
  );
  const resolvedOrganizations = Array.isArray(organizations) && organizations.length > 0
    ? organizations
    : Array.isArray(authOrganizations)
      ? authOrganizations
      : [];
  if (createOnlyMode && ENABLE_ORGANIZATION_CREATION) {
    return <Navigate to={createOrganizationPath} replace />;
  }

  if (membershipsLoaded && activeOrgId) {
    return <Navigate to={returnTo || '/console/org'} replace />;
  }

  /**
   * Handle switching to an organization
   */
  const handleSelectOrganization = async (org) => {
    try {
      if (membershipHasOrgConsoleAccess(org)) {
        await setActiveOrgId(org.id);
        navigate(returnTo || '/console/org');
        return;
      }

      await setMode('applicant');
      setActiveOrganizationId(org.id);
      navigate('/console/applicant/catalog');
    } catch (err) {
      console.error('[OrgSetupPage] Failed to switch organization:', err);
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
  const getRoleBadge = (roles, hasOrgConsoleAccess) => {
    const roleColors = {
      owner: 'primary',
      admin: 'secondary',
      access_admin: 'secondary',
      catalog_admin: 'success',
      reviewer: 'info',
      operator: 'warning',
      viewer: 'default',
      applicant: 'default',
    };

    const primaryRole = Array.isArray(roles) && roles.length > 0 ? roles[0] : null;

    return (
      <Chip
        icon={hasOrgConsoleAccess ? <AdminPanelSettingsIcon fontSize="small" /> : null}
        label={primaryRole?.display_name || primaryRole?.name || 'No roles'}
        color={roleColors[primaryRole?.name] || 'default'}
        size="small"
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
          {error?.message || String(error)}
        </Alert>
      )}

      {/* Empty State - No Organizations */}
      {!loading && resolvedOrganizations.length === 0 && (
        <Card sx={{ textAlign: 'center', py: 6, mb: 3 }}>
          <CardContent>
            <BusinessIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Organizations Yet
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              {ENABLE_ORGANIZATION_CREATION
                ? 'Create an organization, discover a public organization, or join with a code to get started.'
                : 'Discover a public organization or join with a code to get started.'}
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="center">
              {ENABLE_ORGANIZATION_CREATION && (
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => navigate(createOrganizationPath)}
                >
                  Create Organization
                </Button>
              )}
              <Button
                variant="outlined"
                startIcon={<SearchIcon />}
                onClick={() => navigate('/console/organizations/discover')}
              >
                Discover Organizations
              </Button>
              <Button
                variant="outlined"
                startIcon={<CodeIcon />}
                onClick={() => navigate('/console/organizations/join?mode=code')}
              >
                Use Join Code
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Organizations Grid */}
      {resolvedOrganizations.length > 0 && (
        <>
          <Typography variant="h6" gutterBottom sx={{ mb: 2 }}>
            Select from memberships
          </Typography>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {resolvedOrganizations.map((org) => (
              <Grid item xs={12} sm={6} md={4} key={org.id}>
                {(() => {
                  const hasOrgConsoleAccess = membershipHasOrgConsoleAccess(org);
                  const isSelected = hasOrgConsoleAccess
                    ? org.id === activeOrgId
                    : org.id === currentOrganizationId;

                  return (
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    border: isSelected ? 2 : 1,
                    borderColor: isSelected ? 'primary.main' : 'divider',
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
                          org.membership?.roles,
                          org.membership?.has_org_console_access
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
                      variant={isSelected ? 'outlined' : 'contained'}
                      onClick={() => handleSelectOrganization(org)}
                      disabled={org.membership?.status !== 'active'}
                    >
                      {hasOrgConsoleAccess
                        ? (org.id === activeOrgId ? 'Current Organization' : 'Open Org Console')
                        : (org.id === currentOrganizationId
                          ? 'Current Applicant Organization'
                          : 'Use for Applications')}
                    </Button>
                  </CardActions>
                </Card>
                  );
                })()}
              </Grid>
            ))}
          </Grid>

          {/* Actions for existing org members */}
          <Divider sx={{ my: 4 }} />
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              Manage Organizations
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="center" sx={{ mt: 2 }}>
              {ENABLE_ORGANIZATION_CREATION && (
                <Button
                  variant="outlined"
                  startIcon={<AddIcon />}
                  onClick={() => navigate(createOrganizationPath)}
                >
                  Create Organization
                </Button>
              )}
              <Button
                variant="outlined"
                startIcon={<SearchIcon />}
                onClick={() => navigate('/console/organizations/discover')}
              >
                Discover Organizations
              </Button>
              <Button
                variant="outlined"
                startIcon={<CodeIcon />}
                onClick={() => navigate('/console/organizations/join?mode=code')}
              >
                Use Join Code
              </Button>
            </Stack>
          </Box>
        </>
      )}
    </Container>
  );
}

export default OrgSetupPage;
