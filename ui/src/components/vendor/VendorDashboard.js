/**
 * Vendor Dashboard
 *
 * Main dashboard for vendor organization administrators.
 * Shows organization overview, quick stats, and navigation to management features.
 */

import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Button,
  Chip,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Alert,
  Collapse,
  LinearProgress,
} from '@mui/material';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import BusinessIcon from '@mui/icons-material/Business';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import PeopleIcon from '@mui/icons-material/People';
import WebhookIcon from '@mui/icons-material/Webhook';
import DevicesIcon from '@mui/icons-material/Devices';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import SettingsIcon from '@mui/icons-material/Settings';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import CredentialIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import InfoIcon from '@mui/icons-material/Info';

/**
 * Quick stat card component
 */
function StatCard({ title, value, icon, color = 'primary', trend, testId }) {
  return (
    <Card sx={{ height: '100%' }} data-testid={testId}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Box>
            <Typography variant="body2" color="textSecondary" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" component="div" fontWeight="bold" data-testid={testId ? `${testId}-value` : undefined}>
              {value}
            </Typography>
            {trend && (
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <TrendingUpIcon fontSize="small" color="success" />
                <Typography variant="caption" color="success.main" sx={{ ml: 0.5 }}>
                  {trend}
                </Typography>
              </Box>
            )}
          </Box>
          <Box
            sx={{
              backgroundColor: `${color}.light`,
              borderRadius: 2,
              p: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {React.cloneElement(icon, { sx: { color: `${color}.main`, fontSize: 32 } })}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

/**
 * Quick action link component
 */
function QuickAction({ title, description, icon, to, testId }) {
  return (
    <ListItem
      component={Link}
      to={to}
      sx={{
        borderRadius: 1,
        mb: 1,
        '&:hover': {
          backgroundColor: 'action.hover',
        },
      }}
      data-testid={testId}
    >
      <ListItemIcon>{icon}</ListItemIcon>
      <ListItemText
        primary={title}
        secondary={description}
        primaryTypographyProps={{ fontWeight: 'medium' }}
      />
      <ListItemSecondaryAction>
        <IconButton edge="end" component={Link} to={to}>
          <ArrowForwardIcon />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
}

/**
 * Compliance badge component for trust profiles
 */
function ComplianceBadge({ profile }) {
  const [expanded, setExpanded] = useState(false);

  const handleToggle = () => {
    setExpanded(!expanded);
  };

  // Determine status color and icon
  const getStatusInfo = (status) => {
    switch (status) {
      case 'COMPLIANT':
        return {
          color: 'success',
          icon: <CheckCircleIcon />,
          bgcolor: 'success.light',
          textColor: 'success.dark',
        };
      case 'NEEDS_ATTENTION':
        return {
          color: 'warning',
          icon: <WarningIcon />,
          bgcolor: 'warning.light',
          textColor: 'warning.dark',
        };
      case 'SETUP_REQUIRED':
        return {
          color: 'error',
          icon: <ErrorIcon />,
          bgcolor: 'error.light',
          textColor: 'error.dark',
        };
      default:
        return {
          color: 'default',
          icon: <InfoIcon />,
          bgcolor: 'grey.200',
          textColor: 'text.primary',
        };
    }
  };

  const statusInfo = getStatusInfo(profile.compliance_status);

  // Get actionable next steps based on status
  const getNextSteps = () => {
    if (profile.compliance_status === 'COMPLIANT') {
      return ['All systems operational', 'No action required'];
    }
    if (profile.compliance_status === 'NEEDS_ATTENTION') {
      return [
        profile.certificate_expiry_days && profile.certificate_expiry_days < 30
          ? `Certificate expires in ${profile.certificate_expiry_days} days - renew soon`
          : null,
        profile.trust_list_age_hours && profile.trust_list_age_hours > 48
          ? 'Trust list is stale - refresh recommended'
          : null,
      ].filter(Boolean);
    }
    if (profile.compliance_status === 'SETUP_REQUIRED') {
      return [
        'Complete trust profile configuration',
        'Upload or configure certificates',
        'Test credential verification',
      ];
    }
    return [];
  };

  const nextSteps = getNextSteps();

  return (
    <Card
      variant="outlined"
      sx={{
        mb: 2,
        border: 2,
        borderColor: expanded ? `${statusInfo.color}.main` : 'divider',
        transition: 'all 0.2s',
      }}
      data-testid={`compliance-badge-${profile.id}`}
    >
      <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
        <Box
          onClick={handleToggle}
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            cursor: 'pointer',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexGrow: 1 }}>
            <Box
              sx={{
                bgcolor: statusInfo.bgcolor,
                borderRadius: 1,
                p: 1,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              {React.cloneElement(statusInfo.icon, { sx: { color: statusInfo.textColor } })}
            </Box>
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="subtitle1" fontWeight="bold">
                {profile.display_name || profile.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {profile.compliance_status.replace(/_/g, ' ')}
              </Typography>
            </Box>
          </Box>
          <IconButton size="small">
            {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        </Box>

        {/* Expanded Details */}
        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <Divider sx={{ my: 2 }} />
          
          {/* Next Steps */}
          {nextSteps.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                Next Steps
              </Typography>
              <List dense disablePadding>
                {nextSteps.map((step, index) => (
                  <ListItem key={index} sx={{ pl: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <Box
                        sx={{
                          width: 6,
                          height: 6,
                          borderRadius: '50%',
                          bgcolor: statusInfo.textColor,
                        }}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={step}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}

          {/* Advanced Technical Details */}
          <Box
            sx={{
              bgcolor: 'grey.50',
              p: 2,
              borderRadius: 1,
              border: '1px solid',
              borderColor: 'divider',
            }}
          >
            <Typography variant="caption" fontWeight="bold" display="block" gutterBottom>
              Advanced Details
            </Typography>
            <Grid container spacing={1}>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">
                  Framework
                </Typography>
                <Typography variant="body2">{profile.profile_type}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">
                  Technical Name
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                  {profile.name}
                </Typography>
              </Grid>
              {profile.use_case_tags && profile.use_case_tags.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary" display="block">
                    Use Cases
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                    {profile.use_case_tags.map((tag) => (
                      <Chip
                        key={tag}
                        label={tag.replace(/_/g, ' ')}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </Grid>
              )}
              {profile.auto_generated && (
                <Grid item xs={12}>
                  <Chip
                    label="Auto-generated"
                    size="small"
                    icon={<InfoIcon />}
                    variant="outlined"
                  />
                </Grid>
              )}
            </Grid>
          </Box>

          {/* Action Buttons */}
          <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              component={Link}
              to={`/vendor/settings/trust/${profile.id}`}
              data-testid={`configure-profile-${profile.id}`}
            >
              Configure
            </Button>
            {profile.compliance_status !== 'COMPLIANT' && (
              <Button
                size="small"
                variant="contained"
                color={statusInfo.color}
                component={Link}
                to={`/vendor/settings/trust/${profile.id}/fix`}
                data-testid={`fix-profile-${profile.id}`}
              >
                Fix Issues
              </Button>
            )}
          </Box>
        </Collapse>
      </CardContent>
    </Card>
  );
}

export default function VendorDashboard() {
  const { user, organizationName, organizationId } = useAuth();
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [loadingProfiles, setLoadingProfiles] = useState(true);
  const [trustSetupComplete, setTrustSetupComplete] = useState(null);

  const API_BASE_URL = process.env.REACT_APP_API_URL || '';

  // Fetch trust profiles with compliance status
  useEffect(() => {
    if (!organizationId) {
      setLoadingProfiles(false);
      return;
    }

    const fetchTrustProfiles = async () => {
      try {
        setLoadingProfiles(true);
        
        const response = await fetch(
          `${API_BASE_URL}/api/v1/identity/trust-profiles?organization_id=${organizationId}`,
          { credentials: 'include' }
        );
        
        if (response.ok) {
          const data = await response.json();
          setTrustProfiles(data.profiles || []);
          setTrustSetupComplete(data.profiles && data.profiles.length > 0);
        } else if (response.status === 404) {
          setTrustProfiles([]);
          setTrustSetupComplete(false);
        }
      } catch (error) {
        console.error('Error fetching trust profiles:', error);
        setTrustProfiles([]);
        setTrustSetupComplete(null);
      } finally {
        setLoadingProfiles(false);
      }
    };

    fetchTrustProfiles();
  }, [organizationId, API_BASE_URL]);

  // TODO: Fetch real stats from API
  const stats = {
    apiKeys: 3,
    activeApplicants: 24,
    credentialsIssued: 156,
    processingFee: 25.0,
  };

  return (
    <Box sx={{ p: 3 }} data-testid="vendor-dashboard">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <BusinessIcon color="primary" fontSize="large" />
          <Typography variant="h4" component="h1" data-testid="org-name">
            {organizationName || 'Your Organization'}
          </Typography>
          <Chip label="Vendor" color="secondary" size="small" data-testid="vendor-chip" />
        </Box>
        <Typography variant="body1" color="textSecondary" data-testid="welcome-message">
          Welcome back, {user?.given_name || user?.email}. Manage your organization and applicants.
        </Typography>
        {organizationId && (
          <Typography variant="caption" color="textSecondary" data-testid="org-id">
            Organization ID: {organizationId}
          </Typography>
        )}
      </Box>

      {/* Stats Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }} data-testid="stats-grid">
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="API Keys"
            value={stats.apiKeys}
            icon={<VpnKeyIcon />}
            color="primary"
            testId="stat-api-keys"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Active Applicants"
            value={stats.activeApplicants}
            icon={<PeopleIcon />}
            color="secondary"
            trend="+3 this week"
            testId="stat-active-applicants"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Credentials Issued"
            value={stats.credentialsIssued}
            icon={<CredentialIcon />}
            color="success"
            trend="+12 this month"
            testId="stat-credentials-issued"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Processing Fee"
            value={`$${stats.processingFee.toFixed(2)}`}
            icon={<AttachMoneyIcon />}
            color="warning"
            testId="stat-processing-fee"
          />
        </Grid>
      </Grid>

      {/* Trust Setup Incomplete Alert */}
      {!loadingProfiles && trustSetupComplete === false && (
        <Alert
          severity="warning"
          icon={<SecurityIcon />}
          action={
            <Button
              component={Link}
              to="/vendor/settings"
              color="inherit"
              size="small"
              endIcon={<ArrowForwardIcon />}
            >
              Configure
            </Button>
          }
          sx={{ mb: 3 }}
          data-testid="trust-setup-incomplete-alert"
        >
          <Typography variant="body2">
            <strong>Trust profile not configured.</strong> Complete your trust setup to verify credentials and issue your own.
          </Typography>
        </Alert>
      )}

      {/* Compliance Status Section */}
      {!loadingProfiles && trustProfiles.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }} data-testid="compliance-panel">
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              <Typography variant="h6">Identity Compliance</Typography>
            </Box>
            <Button
              size="small"
              variant="text"
              component={Link}
              to="/vendor/settings"
              endIcon={<SettingsIcon />}
            >
              Manage
            </Button>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Monitor your credential verification and issuance readiness
          </Typography>

          {/* Compliance Badges */}
          {trustProfiles.map((profile) => (
            <ComplianceBadge key={profile.id} profile={profile} />
          ))}

          {/* Overall Status Summary */}
          <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
            <Typography variant="caption" fontWeight="bold" display="block" gutterBottom>
              Overall Status
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Chip
                label={`${trustProfiles.filter(p => p.compliance_status === 'COMPLIANT').length} Compliant`}
                color="success"
                size="small"
                icon={<CheckCircleIcon />}
              />
              <Chip
                label={`${trustProfiles.filter(p => p.compliance_status === 'NEEDS_ATTENTION').length} Needs Attention`}
                color="warning"
                size="small"
                icon={<WarningIcon />}
              />
              <Chip
                label={`${trustProfiles.filter(p => p.compliance_status === 'SETUP_REQUIRED').length} Setup Required`}
                color="error"
                size="small"
                icon={<ErrorIcon />}
              />
            </Box>
          </Box>
        </Paper>
      )}

      {/* Loading State for Compliance */}
      {loadingProfiles && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">Identity Compliance</Typography>
          </Box>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Loading compliance status...
          </Typography>
        </Paper>
      )}

      {/* Quick Actions */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }} data-testid="quick-actions-panel">
            <Typography variant="h6" gutterBottom>
              Quick Actions
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <List disablePadding>
              <QuickAction
                title="Manage API Keys"
                description="Create and manage API keys for integrations"
                icon={<VpnKeyIcon color="primary" />}
                to="/vendor/api-keys"
                testId="action-api-keys"
              />
              <QuickAction
                title="Invite Applicants"
                description="Send email invitations to new applicants"
                icon={<PeopleIcon color="secondary" />}
                to="/vendor/invite"
                testId="action-invite-applicants"
              />
              <QuickAction
                title="Configure Devices"
                description="Manage mobile device fleet for your applicants"
                icon={<DevicesIcon color="info" />}
                to="/vendor/devices"
                testId="action-devices"
              />
              <QuickAction
                title="Processing Fees"
                description="Set and manage applicant processing fees"
                icon={<AttachMoneyIcon color="warning" />}
                to="/vendor/fees"
                testId="action-fees"
              />
            </List>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }} data-testid="org-settings-panel">
            <Typography variant="h6" gutterBottom>
              Organization Settings
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <List disablePadding>
              <QuickAction
                title="Webhook Endpoints"
                description="Configure webhook notifications"
                icon={<WebhookIcon color="primary" />}
                to="/vendor/webhooks"
                testId="action-webhooks"
              />
              <QuickAction
                title="Credential Types"
                description="Configure available credential types"
                icon={<CredentialIcon color="success" />}
                to="/vendor/credentials"
                testId="action-credentials"
              />
              <QuickAction
                title="Organization Settings"
                description="Update organization profile and preferences"
                icon={<SettingsIcon color="action" />}
                to="/vendor/settings"
                testId="action-settings"
              />
            </List>
          </Paper>
        </Grid>
      </Grid>

      {/* Subscription Status */}
      <Paper sx={{ p: 2, mt: 3 }} data-testid="subscription-panel">
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h6">Subscription</Typography>
            <Typography variant="body2" color="textSecondary">
              Professional Plan • Renews Jan 15, 2026
            </Typography>
          </Box>
          <Button variant="outlined" component={Link} to="/vendor/subscription" data-testid="manage-subscription-btn">
            Manage Subscription
          </Button>
        </Box>
      </Paper>
    </Box>
  );
}
