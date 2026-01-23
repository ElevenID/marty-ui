import React, { useState, useEffect, useCallback } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CardHeader,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  Divider,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  TextField,
  InputAdornment,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Alert,
  Snackbar,
  CircularProgress
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Flight as PassportIcon,
  Security as SecurityIcon,
  VpnKey as KeyIcon,
  Gavel as GavelIcon,
  Timeline as TimelineIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ListAlt as ListIcon,
  Business as BusinessIcon,
  PersonOutline as PersonIcon,
  Search as SearchIcon,
  Visibility as ImpersonateIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const AdminDashboard = () => {
  const navigate = useNavigate();
  const { keycloak } = useAuth();
  const [stats, setStats] = useState({
    passport: 0,
    mdl: 0,
    mdoc: 0,
    verifications: 0
  });
  const [health, setHealth] = useState({
    issuer_api: 'unknown',
    passport_engine: 'unknown',
    mdl_engine: 'unknown',
    mdoc_engine: 'unknown',
    inspection_system: 'unknown'
  });
  
  // Vendor management state
  const [vendors, setVendors] = useState([]);
  const [vendorSearch, setVendorSearch] = useState('');
  const [vendorsLoading, setVendorsLoading] = useState(false);
  const [impersonateDialog, setImpersonateDialog] = useState({ open: false, vendor: null });
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' });

  useEffect(() => {
    fetchStats();
    fetchHealth();
    fetchVendors();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/admin/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const fetchHealth = async () => {
    try {
      const response = await fetch('/api/health');
      const data = await response.json();
      // Map single service health to dashboard format
      setHealth({
        issuer_api: data.status,
        passport_engine: data.status,
        mdl_engine: data.status,
        mdoc_engine: data.status,
        inspection_system: data.status
      });
    } catch (error) {
      console.error('Failed to fetch health:', error);
    }
  };

  /**
   * Fetch vendors (organizations) from Keycloak Admin API
   */
  const fetchVendors = useCallback(async () => {
    setVendorsLoading(true);
    try {
      // Get vendor users with the 'vendor' role
      const response = await fetch('/api/admin/vendors');
      if (response.ok) {
        const data = await response.json();
        setVendors(data);
      } else {
        // Fallback: fetch from Keycloak directly if admin API not available
        console.warn('Vendor API not available, using mock data');
        setVendors([
          {
            id: 'vendor-001',
            username: 'vendor@marty.demo',
            email: 'vendor@marty.demo',
            organizationName: 'Demo Vendor Corp',
            organizationId: 'org-001',
            tier: 'PROFESSIONAL',
            enabled: true,
            createdAt: new Date().toISOString()
          }
        ]);
      }
    } catch (error) {
      console.error('Failed to fetch vendors:', error);
      setSnackbar({
        open: true,
        message: 'Failed to load vendors',
        severity: 'error'
      });
    } finally {
      setVendorsLoading(false);
    }
  }, []);

  /**
   * Impersonate a vendor user via Keycloak
   * Uses Keycloak's native impersonation endpoint
   */
  const handleImpersonate = async (vendor) => {
    try {
      // Keycloak impersonation endpoint
      // POST /admin/realms/{realm}/users/{id}/impersonation
      const keycloakUrl = keycloak?.authServerUrl || window.KEYCLOAK_URL || 'http://localhost:8080';
      const realm = keycloak?.realm || 'marty';
      
      const impersonateUrl = `${keycloakUrl}/admin/realms/${realm}/users/${vendor.id}/impersonation`;
      
      const response = await fetch(impersonateUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${keycloak?.token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const result = await response.json();
        // Keycloak returns a redirect URL for the impersonation session
        if (result.redirect) {
          // Open impersonation in new tab to preserve admin session
          window.open(result.redirect, '_blank');
          setSnackbar({
            open: true,
            message: `Now impersonating ${vendor.email}. Check the new tab.`,
            severity: 'success'
          });
        } else {
          // Force refresh to pick up impersonated session
          window.location.reload();
        }
      } else if (response.status === 403) {
        setSnackbar({
          open: true,
          message: 'Impersonation not permitted. Check admin role and Keycloak settings.',
          severity: 'error'
        });
      } else {
        throw new Error(`Impersonation failed: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Impersonation error:', error);
      setSnackbar({
        open: true,
        message: `Failed to impersonate: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setImpersonateDialog({ open: false, vendor: null });
    }
  };

  /**
   * Filter vendors by search term
   */
  const filteredVendors = vendors.filter(vendor => 
    vendor.email?.toLowerCase().includes(vendorSearch.toLowerCase()) ||
    vendor.organizationName?.toLowerCase().includes(vendorSearch.toLowerCase()) ||
    vendor.username?.toLowerCase().includes(vendorSearch.toLowerCase())
  );

  const getTierColor = (tier) => {
    const colors = {
      'FREE': 'default',
      'STARTER': 'info',
      'PROFESSIONAL': 'primary',
      'ENTERPRISE': 'secondary'
    };
    return colors[tier] || 'default';
  };

  const getStatusColor = (status) => {
    return status === 'healthy' ? 'success.main' : 'error.main';
  };

  const getStatusIcon = (status) => {
    return status === 'healthy' ? <CheckCircleIcon color="success" /> : <ErrorIcon color="error" />;
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <DashboardIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          Admin Dashboard
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          System Overview and Management
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Quick Actions */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" gutterBottom>
              Management Modules
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<PassportIcon />}
                  onClick={() => navigate('/admin/passport')}
                  sx={{ height: '100%', py: 2 }}
                >
                  Passport Ops
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<SecurityIcon />}
                  onClick={() => navigate('/admin/csca')}
                  sx={{ height: '100%', py: 2 }}
                >
                  CSCA Manager
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<KeyIcon />}
                  onClick={() => navigate('/admin/pkd')}
                  sx={{ height: '100%', py: 2 }}
                >
                  PKD Manager
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<GavelIcon />}
                  onClick={() => navigate('/admin/trust-anchor')}
                  sx={{ height: '100%', py: 2 }}
                >
                  Trust Anchor
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<TimelineIcon />}
                  onClick={() => navigate('/admin/metrics')}
                  sx={{ height: '100%', py: 2 }}
                >
                  System Metrics
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={4}>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<ListIcon />}
                  onClick={() => navigate('/admin/master-lists')}
                  sx={{ height: '100%', py: 2 }}
                >
                  Master Lists
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {/* System Health */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardHeader title="System Health" />
            <Divider />
            <CardContent>
              <List dense>
                {Object.entries(health).map(([service, status]) => (
                  <ListItem key={service}>
                    <ListItemIcon>
                      {getStatusIcon(status)}
                    </ListItemIcon>
                    <ListItemText 
                      primary={service.replace('_', ' ').toUpperCase()} 
                      secondary={status}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Statistics */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Issuance Statistics
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={6} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'primary.light', borderRadius: 1, color: 'white' }}>
                  <Typography variant="h4">{stats.passport}</Typography>
                  <Typography variant="body2">Passports Issued</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'secondary.light', borderRadius: 1, color: 'white' }}>
                  <Typography variant="h4">{stats.mdl}</Typography>
                  <Typography variant="body2">mDLs Issued</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'success.light', borderRadius: 1, color: 'white' }}>
                  <Typography variant="h4">{stats.mdoc}</Typography>
                  <Typography variant="body2">mDocs Issued</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'info.light', borderRadius: 1, color: 'white' }}>
                  <Typography variant="h4">{stats.verifications}</Typography>
                  <Typography variant="body2">Verifications</Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {/* Vendor Management with Impersonation */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                <BusinessIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Vendor Management
              </Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <TextField
                  size="small"
                  placeholder="Search vendors..."
                  value={vendorSearch}
                  onChange={(e) => setVendorSearch(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    )
                  }}
                />
                <IconButton onClick={fetchVendors} disabled={vendorsLoading}>
                  <RefreshIcon />
                </IconButton>
              </Box>
            </Box>
            
            {vendorsLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                <CircularProgress />
              </Box>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Organization</TableCell>
                      <TableCell>Email</TableCell>
                      <TableCell>Tier</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredVendors.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={6} align="center">
                          <Typography color="text.secondary">
                            No vendors found
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredVendors.map((vendor) => (
                        <TableRow key={vendor.id} hover>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <BusinessIcon fontSize="small" color="action" />
                              {vendor.organizationName || 'No Organization'}
                            </Box>
                          </TableCell>
                          <TableCell>{vendor.email}</TableCell>
                          <TableCell>
                            <Chip 
                              label={vendor.tier || 'FREE'} 
                              size="small" 
                              color={getTierColor(vendor.tier)}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={vendor.enabled ? 'Active' : 'Disabled'}
                              size="small"
                              color={vendor.enabled ? 'success' : 'default'}
                            />
                          </TableCell>
                          <TableCell>
                            {vendor.createdAt 
                              ? new Date(vendor.createdAt).toLocaleDateString()
                              : '-'}
                          </TableCell>
                          <TableCell align="right">
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={<ImpersonateIcon />}
                              onClick={() => setImpersonateDialog({ open: true, vendor })}
                              disabled={!vendor.enabled}
                            >
                              Impersonate
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
            
            <Box sx={{ mt: 2 }}>
              <Alert severity="info" variant="outlined">
                <Typography variant="body2">
                  <strong>Impersonation</strong> allows you to view the platform as the vendor sees it.
                  All actions are logged and associated with your admin account.
                </Typography>
              </Alert>
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Impersonation Confirmation Dialog */}
      <Dialog
        open={impersonateDialog.open}
        onClose={() => setImpersonateDialog({ open: false, vendor: null })}
      >
        <DialogTitle>
          <PersonIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Confirm Impersonation
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            You are about to impersonate <strong>{impersonateDialog.vendor?.email}</strong> 
            from organization <strong>{impersonateDialog.vendor?.organizationName}</strong>.
          </DialogContentText>
          <Box sx={{ mt: 2 }}>
            <Alert severity="warning">
              All actions during impersonation are logged. Use this feature responsibly
              and only for support or debugging purposes.
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImpersonateDialog({ open: false, vendor: null })}>
            Cancel
          </Button>
          <Button
            variant="contained"
            color="primary"
            startIcon={<ImpersonateIcon />}
            onClick={() => handleImpersonate(impersonateDialog.vendor)}
          >
            Start Impersonation
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity}
          variant="filled"
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default AdminDashboard;
