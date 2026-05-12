import {
  Alert,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Grid,
  Stack,
  Typography,
} from '@mui/material';
import BusinessIcon from '@mui/icons-material/Business';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import { Link as RouterLink } from 'react-router-dom';

import { membershipHasOrgConsoleAccess } from '../../application/session/authSession';

const DEFAULT_TITLE = 'My Organizations';
const DEFAULT_DESCRIPTION = "Organizations you're a member of. Switch to an organization to access its console.";

function getOrganizationName(organization) {
  return (
    organization?.display_name
    || organization?.displayName
    || organization?.name
    || organization?.id
    || 'Unknown organization'
  );
}

function getMembershipRoles(organization) {
  return organization?.membership?.roles || organization?.roles || [];
}

function getMembershipStatus(organization) {
  return organization?.membership?.status || organization?.status || 'active';
}

function getJoinedAt(organization) {
  return organization?.membership?.joined_at || organization?.joined_at || null;
}

function getStatusBadge(status) {
  const statusMap = {
    active: { label: 'Active', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
    pending: { label: 'Pending', color: 'warning', icon: <PendingIcon fontSize="small" /> },
    invited: { label: 'Invited', color: 'info', icon: <PendingIcon fontSize="small" /> },
    deactivated: { label: 'Deactivated', color: 'default', icon: null },
  };
  const config = statusMap[status] || statusMap.active;

  return <Chip icon={config.icon} label={config.label} color={config.color} size="small" />;
}

function getRoleBadges(roles, hasOrgConsoleAccess) {
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

  if (!Array.isArray(roles) || roles.length === 0) {
    return <Chip label="No roles" size="small" variant="outlined" />;
  }

  return (
    <Stack direction="row" spacing={1} justifyContent="flex-end" flexWrap="wrap">
      {roles.map((role) => {
        const roleName = typeof role === 'string' ? role : role?.name;
        const roleLabel = typeof role === 'string' ? role : role?.display_name || role?.name;

        return (
          <Chip
            key={role?.id || roleName || roleLabel}
            icon={hasOrgConsoleAccess ? <AdminPanelSettingsIcon fontSize="small" /> : null}
            label={roleLabel || 'Role'}
            color={roleColors[roleName] || 'default'}
            size="small"
          />
        );
      })}
    </Stack>
  );
}

function OrganizationMembershipHub({
  organizations = [],
  loading = false,
  error = null,
  activeOrgId = null,
  onSwitchToOrg,
  title = DEFAULT_TITLE,
  description = DEFAULT_DESCRIPTION,
  embedded = false,
  showManagePageLink = false,
  managePath = '/organizations',
  discoverPath = '/organizations/discover',
  joinPath = '/organizations/join',
  dataTestId,
}) {
  const items = Array.isArray(organizations) ? organizations : [];

  if (loading) {
    return (
      <Box
        data-testid={dataTestId}
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: embedded ? 160 : 400,
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid={dataTestId}>
      {(title || description) && (
        <Box sx={{ mb: 4 }}>
          {title && (
            <Typography variant={embedded ? 'h6' : 'h4'} gutterBottom fontWeight={embedded ? 500 : 600}>
              {title}
            </Typography>
          )}
          {description && (
            <Typography variant="body1" color="text.secondary">
              {description}
            </Typography>
          )}
        </Box>
      )}

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error?.message || String(error)}</Alert>}

      {items.length === 0 ? (
        <Card sx={{ textAlign: 'center', py: embedded ? 4 : 6 }}>
          <CardContent>
            <BusinessIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Organizations Yet
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              You&apos;re not a member of any organizations. Discover organizations or join one with a join code.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="center">
              <Button component={RouterLink} to={discoverPath} variant="contained">
                Discover Organizations
              </Button>
              <Button component={RouterLink} to={joinPath} variant="outlined">
                Use Join Code
              </Button>
            </Stack>
          </CardContent>
        </Card>
      ) : (
        <>
          <Grid container spacing={3}>
            {items.map((organization) => {
              const organizationName = getOrganizationName(organization);
              const roles = getMembershipRoles(organization);
              const status = getMembershipStatus(organization);
              const joinedAt = getJoinedAt(organization);
              const hasOrgConsoleAccess = membershipHasOrgConsoleAccess(organization);

              return (
                <Grid item xs={12} sm={6} md={embedded ? 6 : 4} key={organization.id || organizationName}>
                  <Card
                    sx={{
                      height: '100%',
                      display: 'flex',
                      flexDirection: 'column',
                      border: organization.id === activeOrgId ? 2 : 1,
                      borderColor: organization.id === activeOrgId ? 'primary.main' : 'divider',
                      transition: 'all 0.2s',
                      '&:hover': {
                        boxShadow: 4,
                        transform: 'translateY(-2px)',
                      },
                    }}
                  >
                    <CardContent sx={{ flexGrow: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 2 }}>
                        <BusinessIcon color="action" sx={{ mt: 0.5 }} />
                        <Box sx={{ flexGrow: 1 }}>
                          <Typography variant="h6" gutterBottom>
                            {organizationName}
                          </Typography>
                          {organization.description && (
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              {organization.description}
                            </Typography>
                          )}
                        </Box>
                      </Box>

                      <Divider sx={{ my: 2 }} />

                      <Stack spacing={1.5}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="caption" color="text.secondary">
                            Role:
                          </Typography>
                          {getRoleBadges(roles, hasOrgConsoleAccess)}
                        </Box>

                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="caption" color="text.secondary">
                            Status:
                          </Typography>
                          {getStatusBadge(status)}
                        </Box>

                        {joinedAt && (
                          <Box>
                            <Typography variant="caption" color="text.secondary">
                              Joined: {new Date(joinedAt).toLocaleDateString()}
                            </Typography>
                          </Box>
                        )}
                      </Stack>

                      {organization.org_type && (
                        <Box sx={{ mt: 2 }}>
                          <Chip
                            label={organization.org_type}
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
                        variant={organization.id === activeOrgId ? 'outlined' : 'contained'}
                        onClick={() => onSwitchToOrg?.(organization.id)}
                        disabled={status !== 'active' || !hasOrgConsoleAccess || !onSwitchToOrg}
                      >
                        {hasOrgConsoleAccess
                          ? (organization.id === activeOrgId ? 'Current Organization' : 'Open Org Console')
                          : 'Applicant Access Only'}
                      </Button>
                    </CardActions>
                  </Card>
                </Grid>
              );
            })}
          </Grid>

          <Box sx={{ mt: 4, textAlign: embedded ? 'left' : 'center' }}>
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={2}
              justifyContent={embedded ? 'flex-start' : 'center'}
            >
              {showManagePageLink && (
                <Button component={RouterLink} to={managePath} variant="outlined">
                  View My Organizations
                </Button>
              )}
              <Button component={RouterLink} to={discoverPath} variant="outlined">
                Discover More Organizations
              </Button>
              <Button component={RouterLink} to={joinPath} variant="outlined">
                Use Join Code
              </Button>
            </Stack>
          </Box>
        </>
      )}
    </Box>
  );
}

export default OrganizationMembershipHub;