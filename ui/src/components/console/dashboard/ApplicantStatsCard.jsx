/**
 * Applicant Stats Card
 * 
 * Dashboard widget showing applicant lifecycle counts:
 * - Pending applications
 * - Approved applications
 * - Issuable credentials
 */

import { useState, useEffect } from 'react';
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

import { useAuth } from '../../../hooks/useAuth';
import { getApplicantStats } from '../../../services/dashboardApi';

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
  const { organizationId } = useAuth();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchStats() {
      if (!organizationId) return;
      
      setLoading(true);
      try {
        const data = await getApplicantStats(organizationId);
        setStats(data);
      } catch (error) {
        console.error('Failed to load applicant stats:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchStats();
  }, [organizationId]);

  if (loading) {
    return (
      <Paper sx={{ p: 3, mb: 3 }}>
        <Skeleton variant="text" width={200} height={32} />
        <Skeleton variant="rectangular" height={120} sx={{ mt: 2 }} />
      </Paper>
    );
  }

  if (!stats) {
    return null;
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h6" fontWeight={600}>
          Applicant Lifecycle
        </Typography>
        <Button
          component={Link}
          to="/console/operate/applications"
          endIcon={<ArrowForwardIcon />}
          size="small"
        >
          View All
        </Button>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={PersonAddIcon}
            label="Pending Review"
            value={stats.pending}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={CheckCircleIcon}
            label="Approved"
            value={stats.approved}
            color="success"
          />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatItem
            icon={BadgeIcon}
            label="Ready to Issue"
            value={stats.issuable}
            color="primary"
          />
        </Grid>
      </Grid>

      {stats.total === 0 && (
        <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary" align="center">
            No applicants yet. Applications will appear here as users apply for credentials.
          </Typography>
        </Box>
      )}
    </Paper>
  );
}

export default ApplicantStatsCard;
