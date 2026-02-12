/**
 * Organization Health Panel
 * 
 * Top-level health overview showing:
 * - Active/inactive org status
 * - # Active Trust Profiles
 * - # Active Templates
 * - # Active Policies
 * - # Active Deployments
 * - # Active Flows
 * 
 * Purpose: instant "is this org usable?" signal
 */

import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Tooltip,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BusinessIcon from '@mui/icons-material/Business';

/**
 * Stat card for individual metric
 */
function StatCard({ icon: Icon, label, count, color = 'primary' }) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Icon color={color} fontSize="small" />
          <Typography variant="caption" color="text.secondary">
            {label}
          </Typography>
        </Box>
        <Typography variant="h4" fontWeight={600}>
          {count}
        </Typography>
      </CardContent>
    </Card>
  );
}

/**
 * Organization Health Panel Component
 */
export function OrganizationHealthPanel({ data, organizationName, isActive = true }) {
  const { t } = useTranslation('console');
  
  // Calculate counts of active resources
  const activeTrustProfiles = data?.trustProfiles?.filter(t => t.status === 'active')?.length || 0;
  const activeTemplates = data?.templates?.filter(t => t.status === 'active')?.length || 0;
  const activePolicies = data?.policies?.filter(p => p.status === 'active')?.length || 0;
  const activeDeployments = data?.deployments?.filter(d => d.status === 'active')?.length || 0;
  const activeFlows = data?.flows?.filter(f => f.status === 'active')?.length || 0;

  // Determine if org is operationally ready
  const isOperational = activeTrustProfiles > 0 && 
                        activeTemplates > 0 && 
                        activePolicies > 0 && 
                        activeDeployments > 0 && 
                        activeFlows > 0;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <BusinessIcon color="primary" fontSize="large" />
          <Box>
            <Typography variant="h6">
              {organizationName || t('dashboard.organizationHealth.organizationFallback')}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('dashboard.organizationHealth.healthOverview')}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          <Tooltip title={isActive ? t('dashboard.organizationHealth.organizationActive') : t('dashboard.organizationHealth.organizationInactive')}>
            <Chip 
              icon={isActive ? <CheckCircleIcon /> : <ErrorIcon />}
              label={isActive ? t('dashboard.organizationHealth.active') : t('dashboard.organizationHealth.inactive')}
              color={isActive ? 'success' : 'error'}
              size="small"
            />
          </Tooltip>
          <Tooltip title={isOperational ? t('dashboard.organizationHealth.allSystemsConfigured') : t('dashboard.organizationHealth.setupIncomplete')}>
            <Chip 
              label={isOperational ? t('dashboard.organizationHealth.operational') : t('dashboard.organizationHealth.setupRequired')}
              color={isOperational ? 'success' : 'warning'}
              size="small"
              variant="outlined"
            />
          </Tooltip>
        </Box>
      </Box>

      <Grid container spacing={2}>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            icon={VerifiedUserIcon}
            label={t('dashboard.organizationHealth.activeTrustProfiles')}
            count={activeTrustProfiles}
            color={activeTrustProfiles > 0 ? 'success' : 'error'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            icon={DescriptionIcon}
            label={t('dashboard.organizationHealth.activeTemplates')}
            count={activeTemplates}
            color={activeTemplates > 0 ? 'success' : 'warning'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            icon={PolicyIcon}
            label={t('dashboard.organizationHealth.activePolicies')}
            count={activePolicies}
            color={activePolicies > 0 ? 'success' : 'warning'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            icon={CloudUploadIcon}
            label={t('dashboard.organizationHealth.activeDeployments')}
            count={activeDeployments}
            color={activeDeployments > 0 ? 'success' : 'warning'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            icon={AccountTreeIcon}
            label={t('dashboard.organizationHealth.activeFlows')}
            count={activeFlows}
            color={activeFlows > 0 ? 'success' : 'warning'}
          />
        </Grid>
      </Grid>

      {!isOperational && (
        <Box sx={{ mt: 2, p: 2, bgcolor: 'warning.light', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary">
            {t('dashboard.organizationHealth.setupWarning')}
          </Typography>
        </Box>
      )}
    </Paper>
  );
}
