import { useState, useEffect, useCallback } from 'react';
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
import { useNotifications } from '../hooks/useNotifications';
import {
  ADMIN_DASHBOARD_DEFAULT_HEALTH,
  ADMIN_DASHBOARD_DEFAULT_STATS,
  filterAdminVendors,
  getAdminTierColor,
  impersonateAdminVendor,
  loadAdminDashboardBootstrap,
} from '../application/admin';

const AdminDashboard = () => {
  const navigate = useNavigate();
  const { keycloak } = useAuth();
  const { showSuccess, showError } = useNotifications();
  const [stats, setStats] = useState(ADMIN_DASHBOARD_DEFAULT_STATS);
  const [health, setHealth] = useState(ADMIN_DASHBOARD_DEFAULT_HEALTH);
  
  // Vendor management state
  const [vendors, setVendors] = useState([]);
  const [vendorSearch, setVendorSearch] = useState('');
  const [vendorsLoading, setVendorsLoading] = useState(false);
  const [impersonateDialog, setImpersonateDialog] = useState({ open: false, vendor: null });

  const fetchVendors = useCallback(async () => {
    setVendorsLoading(true);
    try {
      const result = await loadAdminDashboardBootstrap();
      setStats(result.stats);
      setHealth(result.health);
      setVendors(result.vendors);
      if (result.vendorError) {
        showError(result.vendorError);
      }
    } catch (error) {
      console.error('Failed to fetch vendors:', error);
      showError('Failed to load vendors');
    } finally {
      setVendorsLoading(false);
    }
  }, [showError]);

  useEffect(() => {
    fetchVendors();
  }, [fetchVendors]);

  /**
   * Impersonate a vendor user via Keycloak
   * Uses Keycloak's native impersonation endpoint
   */
  const handleImpersonate = async (vendor) => {
    try {
      const result = await impersonateAdminVendor({
        vendor,
        keycloak,
        authServerUrl: window.KEYCLOAK_URL,
        realm: import.meta.env.VITE_KEYCLOAK_REALM || window.KEYCLOAK_REALM,
      });

      if (result.action === 'open-tab' && result.redirectUrl) {
        window.open(result.redirectUrl, '_blank');
        showSuccess(result.successMessage);
      } else {
        window.location.reload();
      }
    } catch (error) {
      console.error('Impersonation error:', error);
      showError(`Failed to impersonate: ${error.message}`);
    } finally {
      setImpersonateDialog({ open: false, vendor: null });
    }
  };

  /**
   * Filter vendors by search term
   */
  const filteredVendors = filterAdminVendors(vendors, vendorSearch);

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
                              color={getAdminTierColor(vendor.tier)}
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
      {impersonateDialog.open && (
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
      )}

    </Container>
  );
};

export default AdminDashboard;
