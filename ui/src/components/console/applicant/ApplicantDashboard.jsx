/**
 * Applicant Dashboard
 * 
 * Dashboard for applicants to see their credential status and actions.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardActions,
  Button,
  Alert,
  AlertTitle,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import BadgeIcon from '@mui/icons-material/Badge';
import AssignmentIcon from '@mui/icons-material/Assignment';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { useAuth } from '../../../hooks/useAuth';
import { getApplicantStats } from '../../../services/applicantApi';

function ApplicantDashboard() {
  const { t } = useTranslation('applicant');
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    activeCredentials: 0,
    pendingApplications: 0,
    expiringSoon: 0,
  });

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await getApplicantStats();
        setStats(data);
      } catch (error) {
        console.error('Error loading dashboard stats:', error);
        // Keep default stats on error
      } finally {
        setLoading(false);
      }
    };
    loadStats();
  }, []);

  if (loading) {
    return (
      <Box>
        <Typography variant="h4" gutterBottom>
          {user?.name ? t('dashboard.titleWithName', { name: user.name }) : t('dashboard.title')}
        </Typography>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {user?.name ? t('dashboard.titleWithName', { name: user.name }) : t('dashboard.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('dashboard.description')}
      </Typography>

      {/* Pending Applications Alert */}
      {stats.pendingApplications > 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>{t('dashboard.pendingAlert.title')}</AlertTitle>
          {t('dashboard.pendingAlert.message', { count: stats.pendingApplications })}
          <Button
            component={Link}
            to="/console/applicant/applications"
            size="small"
            sx={{ ml: 2 }}
          >
            {t('dashboard.pendingAlert.viewStatus')}
          </Button>
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BadgeIcon color="primary" />
                <Typography variant="h4">{stats.activeCredentials}</Typography>
              </Box>
              <Typography color="text.secondary">{t('dashboard.stats.activeCredentials')}</Typography>
            </CardContent>
            <CardActions>
              <Button
                component={Link}
                to="/console/applicant/credentials"
                size="small"
                endIcon={<ArrowForwardIcon />}
              >
                {t('dashboard.stats.viewAll')}
              </Button>
            </CardActions>
          </Card>
        </Grid>

        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PendingIcon color="warning" />
                <Typography variant="h4">{stats.pendingApplications}</Typography>
              </Box>
              <Typography color="text.secondary">{t('dashboard.stats.pendingApplications')}</Typography>
            </CardContent>
            <CardActions>
              <Button
                component={Link}
                to="/console/applicant/applications"
                size="small"
                endIcon={<ArrowForwardIcon />}
              >
                {t('dashboard.stats.viewAll')}
              </Button>
            </CardActions>
          </Card>
        </Grid>

        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon color="success" />
                <Typography variant="h4">{stats.expiringSoon}</Typography>
              </Box>
              <Typography color="text.secondary">{t('dashboard.stats.expiringSoon')}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Quick Actions */}
      <Typography variant="h6" gutterBottom>
        {t('dashboard.quickActions.title')}
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <List>
              <ListItem
                component={Link}
                to="/console/applicant/credentials"
                sx={{ color: 'inherit', textDecoration: 'none' }}
              >
                <ListItemIcon>
                  <AssignmentIcon />
                </ListItemIcon>
                <ListItemText
                  primary={t('dashboard.quickActions.applyForCredential')}
                  secondary={t('dashboard.quickActions.applyDescription')}
                />
              </ListItem>
              <ListItem
                component={Link}
                to="/console/applicant/credentials"
                sx={{ color: 'inherit', textDecoration: 'none' }}
              >
                <ListItemIcon>
                  <BadgeIcon />
                </ListItemIcon>
                <ListItemText
                  primary={t('dashboard.quickActions.viewMyCredentials')}
                  secondary={t('dashboard.quickActions.viewDescription')}
                />
              </ListItem>
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default ApplicantDashboard;
