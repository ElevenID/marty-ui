import React, { useState, useEffect } from 'react';
import {
  Typography,
  Grid,
  Card,
  CardContent,
  CardActionArea,
  Box,
  Chip
} from '@mui/material';
import {
  CardMembership as CardIcon,
  VerifiedUser as VerifiedIcon,
  AccountBalanceWallet as WalletIcon,
  Security as SecurityIcon,
  ListAlt as ListIcon,
  Dashboard as DashboardIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const Home = () => {
  const navigate = useNavigate();
  const [systemStatus, setSystemStatus] = useState({
    healthy: true,
    services: { issuer: 'online', verifier: 'online', wallet: 'online' }
  });
  const [stats, setStats] = useState({
    credentials: 0,
    verifications: 0,
    masterLists: 3,
    certificates: 11
  });

  useEffect(() => {
    // Fetch system status
    const fetchStatus = async () => {
      try {
        const response = await fetch('/api/health');
        if (response.ok) {
          const data = await response.json();
          setSystemStatus({ healthy: data.status === 'healthy', services: data.services || {} });
        }
      } catch (err) {
        // Use defaults
      }
    };

    const fetchStats = async () => {
      try {
        const response = await fetch('/api/admin/stats');
        if (response.ok) {
          const data = await response.json();
          setStats(prev => ({ ...prev, ...data }));
        }
      } catch (err) {
        // Use defaults
      }
    };

    fetchStatus();
    fetchStats();
  }, []);

  const quickActions = [
    {
      title: 'Travel Documents',
      description: 'Issue and manage travel documents',
      icon: <CardIcon sx={{ fontSize: 40 }} />,
      path: '/documents',
      color: 'primary.main'
    },
    {
      title: 'Verify Credentials',
      description: 'Validate credential presentations',
      icon: <VerifiedIcon sx={{ fontSize: 40 }} />,
      path: '/verifier',
      color: 'success.main'
    },
    {
      title: 'Wallet',
      description: 'Manage stored credentials',
      icon: <WalletIcon sx={{ fontSize: 40 }} />,
      path: '/wallet',
      color: 'secondary.main'
    },
    {
      title: 'Master Lists',
      description: 'Browse ICAO PKD certificates',
      icon: <ListIcon sx={{ fontSize: 40 }} />,
      path: '/admin/master-lists',
      color: 'info.main'
    },
    {
      title: 'Trust Anchor',
      description: 'Configure trust policies',
      icon: <SecurityIcon sx={{ fontSize: 40 }} />,
      path: '/admin/trust-anchor',
      color: 'warning.main'
    },
    {
      title: 'Admin Dashboard',
      description: 'System management',
      icon: <DashboardIcon sx={{ fontSize: 40 }} />,
      path: '/admin',
      color: 'grey.700'
    }
  ];

  return (
    <Box>
      {/* Status Bar */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Chip
          icon={systemStatus.healthy ? <CheckIcon /> : <WarningIcon />}
          label={systemStatus.healthy ? 'System Operational' : 'Service Issues'}
          color={systemStatus.healthy ? 'success' : 'warning'}
          variant="outlined"
        />
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="body2" color="text.secondary">
          {stats.masterLists} Countries · {stats.certificates} Certificates
        </Typography>
      </Box>

      {/* Quick Actions Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {quickActions.map((action) => (
          <Grid item xs={12} sm={6} md={4} key={action.title}>
            <Card sx={{ height: '100%' }}>
              <CardActionArea 
                onClick={() => navigate(action.path)}
                sx={{ height: '100%', p: 2 }}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Box sx={{ color: action.color, mr: 2 }}>
                      {action.icon}
                    </Box>
                    <Typography variant="h6" component="h2">
                      {action.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {action.description}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Stats Overview */}
      <Grid container spacing={3}>
        <Grid item xs={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="primary">{stats.credentials}</Typography>
              <Typography variant="body2" color="text.secondary">Credentials Issued</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="success.main">{stats.verifications}</Typography>
              <Typography variant="body2" color="text.secondary">Verifications</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="info.main">{stats.masterLists}</Typography>
              <Typography variant="body2" color="text.secondary">Countries</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="warning.main">{stats.certificates}</Typography>
              <Typography variant="body2" color="text.secondary">Certificates</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Home;
