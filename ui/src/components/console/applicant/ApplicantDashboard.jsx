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
import BadgeIcon from '@mui/icons-material/Badge';
import AssignmentIcon from '@mui/icons-material/Assignment';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { useAuth } from '../../../hooks/useAuth';

function ApplicantDashboard() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    activeCredentials: 0,
    pendingApplications: 0,
    expiringSoon: 0,
  });

  useEffect(() => {
    // TODO: Fetch actual stats from API
    const loadStats = async () => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setStats({
        activeCredentials: 2,
        pendingApplications: 1,
        expiringSoon: 0,
      });
      setLoading(false);
    };
    loadStats();
  }, []);

  if (loading) {
    return (
      <Box>
        <Typography variant="h4" gutterBottom>
          Welcome back{user?.name ? `, ${user.name}` : ''}
        </Typography>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Welcome back{user?.name ? `, ${user.name}` : ''}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Manage your digital credentials and applications.
      </Typography>

      {/* Pending Applications Alert */}
      {stats.pendingApplications > 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Pending Applications</AlertTitle>
          You have {stats.pendingApplications} application(s) awaiting review.
          <Button
            component={Link}
            to="/applicant/applications"
            size="small"
            sx={{ ml: 2 }}
          >
            View Status
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
              <Typography color="text.secondary">Active Credentials</Typography>
            </CardContent>
            <CardActions>
              <Button
                component={Link}
                to="/applicant/credentials"
                size="small"
                endIcon={<ArrowForwardIcon />}
              >
                View All
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
              <Typography color="text.secondary">Pending Applications</Typography>
            </CardContent>
            <CardActions>
              <Button
                component={Link}
                to="/applicant/applications"
                size="small"
                endIcon={<ArrowForwardIcon />}
              >
                View All
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
              <Typography color="text.secondary">Expiring Soon</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Quick Actions */}
      <Typography variant="h6" gutterBottom>
        Quick Actions
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <List>
              <ListItem
                component={Link}
                to="/credentials"
                sx={{ color: 'inherit', textDecoration: 'none' }}
              >
                <ListItemIcon>
                  <AssignmentIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Apply for Credential"
                  secondary="Browse available credentials and start an application"
                />
              </ListItem>
              <ListItem
                component={Link}
                to="/applicant/credentials"
                sx={{ color: 'inherit', textDecoration: 'none' }}
              >
                <ListItemIcon>
                  <BadgeIcon />
                </ListItemIcon>
                <ListItemText
                  primary="View My Credentials"
                  secondary="See your issued digital credentials"
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
