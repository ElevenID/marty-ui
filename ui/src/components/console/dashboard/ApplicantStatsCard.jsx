/**
 * Applicant Stats Card
 * 
 * Dashboard widget showing applicant lifecycle counts:
 * - Pending applications
 * - Approved applications
 * - Issuable credentials
 */

import { useAsyncData } from '../../../hooks/useAsyncData';
import {
  Paper,
  Typography,
  Box,
  Grid,
  Button,
  Skeleton,
} from '@mui/material';
import { Link } from 'react-router-dom';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import BadgeIcon from '@mui/icons-material/Badge';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { getApplicantStats } from '../../../services/dashboardApi';
import DashboardErrorAlert from './DashboardErrorAlert';

/**
 * Stat display component
 */
function StatItem({ icon: Icon, label, value, color = 'primary' }) {
  return (
    <Box sx={{ textAlign: 'center' }}>
      <Box sx={{ mb: 1 }}>
        <Icon sx={{ fontSize: 40, color: `${color}.main` }} />
      </Box>
      <Typography variant="h4" fontWeight={600}>
        {value}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
    </Box>
  );
}

/**
 * Applicant Stats Card Component
 */
export function ApplicantStatsCard() {
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
  const { data: stats, loading, error, reload } = useAsyncData(
    async () => {
      if (!organizationId) return null;
      return await getApplicantStats(organizationId);
    },
    [organizationId]
  );

  if (loading) {
    return (
      <Paper sx={{ p: 3, mb: 3 }}>
        <Skeleton variant="text" width={200} height={32} />
        <Skeleton variant="rectangular" height={120} sx={{ mt: 2 }} />
      </Paper>
    );
  }

  if (error || !stats) {
    return (
      <Paper sx={{ p: 3, mb: 3 }}>
        <DashboardErrorAlert
          title="Applicant stats unavailable"
          error={error}
          onRetry={reload}
          fallback="Applicant lifecycle stats could not be loaded from a live backing source."
        />
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h6" fontWeight={600}>
          {t('dashboard.applicantStats.title')}
        </Typography>
        <Button
          component={Link}
          to="/console/org/operate/applications"
          endIcon={<ArrowForwardIcon />}
          size="small"
        >
          {t('dashboard.applicantStats.viewAll')}
        </Button>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={PersonAddIcon}
            label={t('dashboard.applicantStats.pendingReview')}
            value={stats.pending}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={CheckCircleIcon}
            label={t('dashboard.applicantStats.approved')}
            value={stats.approved}
            color="success"
          />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={BadgeIcon}
            label={t('dashboard.applicantStats.readyToIssue')}
            value={stats.issuable}
            color="primary"
          />
        </Grid>
      </Grid>

      {stats.total === 0 && (
        <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary" align="center">
            {t('dashboard.applicantStats.noApplicants')}
          </Typography>
        </Box>
      )}
    </Paper>
  );
}

export default ApplicantStatsCard;
