import { useMemo } from 'react';
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Typography,
} from '@mui/material';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import LaunchIcon from '@mui/icons-material/Launch';
import LogoutIcon from '@mui/icons-material/Logout';
import { useAuth } from '../hooks/useAuth';

function formatStartedAt(startedAt) {
  if (!startedAt) {
    return null;
  }

  const parsed = new Date(startedAt);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toLocaleString();
}

export default function ImpersonationBanner() {
  const { impersonation, logout } = useAuth();
  const startedAtLabel = useMemo(
    () => formatStartedAt(impersonation?.started_at),
    [impersonation?.started_at]
  );

  if (!impersonation?.active) {
    return null;
  }

  const adminLabel =
    impersonation.admin_display_name ||
    impersonation.admin_email ||
    impersonation.admin_username ||
    'Platform administrator';

  const organizationLabel =
    impersonation.organization_name ||
    impersonation.organization_id ||
    'this organization';

  const handleReturnToAdmin = () => {
    if (window.opener && !window.opener.closed) {
      window.opener.focus();
      return;
    }

    window.location.href = '/admin';
  };

  return (
    <Alert
      severity="warning"
      icon={<AdminPanelSettingsIcon />}
      sx={{
        position: 'sticky',
        top: 0,
        zIndex: 1200,
        borderRadius: 0,
        borderBottom: '2px solid',
        borderColor: 'warning.main',
      }}
      action={
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {impersonation.launch_mode === 'new-tab' && (
            <Button color="inherit" size="small" startIcon={<LaunchIcon />} onClick={handleReturnToAdmin}>
              Return to admin
            </Button>
          )}
          <Button color="inherit" size="small" startIcon={<LogoutIcon />} onClick={logout}>
            Exit impersonation
          </Button>
        </Box>
      }
    >
      <AlertTitle sx={{ fontWeight: 'bold' }}>
        Admin impersonation active
      </AlertTitle>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
        <Typography variant="body2">
          {adminLabel} is viewing {organizationLabel} as {impersonation.target_email || 'the impersonated user'}.
        </Typography>
        <Typography variant="body2" fontWeight="medium">
          Actions in this session are performed as the impersonated account.
        </Typography>
        {startedAtLabel && (
          <Typography variant="caption" color="text.secondary">
            Started: {startedAtLabel}
          </Typography>
        )}
      </Box>
    </Alert>
  );
}
