/**
 * Offer Analytics Component
 * 
 * Displays analytics and insights for credential offer scans:
 * - Summary statistics (total offers, scans, success rate)
 * - Wallet type distribution
 * - Recent scan activity
 * - Detailed scan logs with filtering
 */

import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import {
  Box,
  Paper,
  Grid,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  CircularProgress,
  Alert,
  AlertTitle,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Stack,
  Divider,
  Tooltip,
  IconButton,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import QrCodeScannerIcon from '@mui/icons-material/QrCodeScanner';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DevicesIcon from '@mui/icons-material/Devices';
import TimelineIcon from '@mui/icons-material/Timeline';

import { useAuth } from '../../hooks/useAuth';

const API_URL = import.meta.env.VITE_API_URL || '';

// Outcome colors
const OUTCOME_COLORS = {
  success: 'success',
  expired: 'warning',
  error: 'error',
  unauthorized: 'error',
};

/**
 * Format date for display
 */
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

/**
 * Format wallet type for display
 */
function formatWalletType(walletType) {
  if (!walletType) return 'Unknown';
  return walletType
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Metric Card Component
 */
function MetricCard({ title, value, icon: Icon, color = 'primary', subtitle }) {
  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Box>
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ mb: 1 }}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="body2" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </Box>
          {Icon && (
            <Box
              sx={{
                bgcolor: `${color}.light`,
                borderRadius: 2,
                p: 1.5,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Icon sx={{ color: `${color}.main`, fontSize: 32 }} />
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

MetricCard.propTypes = {
  title: PropTypes.string.isRequired,
  value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  icon: PropTypes.elementType,
  color: PropTypes.string,
  subtitle: PropTypes.string,
};

/**
 * Main Offer Analytics Component
 */
export default function OfferAnalytics() {
  const { organizationId } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Summary data
  const [summary, setSummary] = useState(null);
  
  // Scan logs
  const [scans, setScans] = useState([]);
  const [scansTotal, setScansTotal] = useState(0);
  const [scansPage, setScansPage] = useState(0);
  const [scansRowsPerPage, setScansRowsPerPage] = useState(25);
  const [scansLoading, setScansLoading] = useState(false);
  
  // Filters
  const [accessTypeFilter, setAccessTypeFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [walletTypeFilter, setWalletTypeFilter] = useState('');

  /**
   * Fetch analytics summary
   */
  const fetchSummary = useCallback(async () => {
    if (!organizationId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams({
        organization_id: organizationId,
        days: '30',
      });
      
      const response = await fetch(
        `${API_URL}/api/issuance/analytics/summary?${params.toString()}`,
        {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      
      if (!response.ok) {
        throw new Error(`Failed to fetch analytics: ${response.statusText}`);
      }
      
      const data = await response.json();
      setSummary(data);
    } catch (err) {
      console.error('Error fetching analytics:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  /**
   * Fetch scan logs
   */
  const fetchScans = useCallback(async () => {
    if (!organizationId) return;
    
    setScansLoading(true);
    
    try {
      const params = new URLSearchParams({
        organization_id: organizationId,
        page: (scansPage + 1).toString(),
        page_size: scansRowsPerPage.toString(),
      });
      
      if (accessTypeFilter) params.append('access_type', accessTypeFilter);
      if (outcomeFilter) params.append('outcome', outcomeFilter);
      if (walletTypeFilter) params.append('wallet_type', walletTypeFilter);
      
      const response = await fetch(
        `${API_URL}/api/issuance/analytics/scans?${params.toString()}`,
        {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      
      if (!response.ok) {
        throw new Error(`Failed to fetch scan logs: ${response.statusText}`);
      }
      
      const data = await response.json();
      setScans(data.scans || []);
      setScansTotal(data.total || 0);
    } catch (err) {
      console.error('Error fetching scan logs:', err);
    } finally {
      setScansLoading(false);
    }
  }, [organizationId, scansPage, scansRowsPerPage, accessTypeFilter, outcomeFilter, walletTypeFilter]);

  /**
   * Handle scan logs page change
   */
  const handleScansPageChange = useCallback((event, newPage) => {
    setScansPage(newPage);
  }, []);

  /**
   * Handle scan logs rows per page change
   */
  const handleScansRowsPerPageChange = useCallback((event) => {
    setScansRowsPerPage(parseInt(event.target.value, 10));
    setScansPage(0);
  }, []);

  /**
   * Refresh all data
   */
  const handleRefresh = useCallback(() => {
    fetchSummary();
    fetchScans();
  }, [fetchSummary, fetchScans]);

  // Fetch data on mount and when filters change
  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  if (loading && !summary) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', py: 8 }}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h6">Analytics & Insights</Typography>
          <Typography variant="body2" color="text.secondary">
            QR code scan statistics and wallet analytics (Last 30 days)
          </Typography>
        </Box>
        <IconButton onClick={handleRefresh} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {/* Summary Metrics */}
      {summary && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title="Total Offers"
              value={summary.total_offers}
              icon={QrCodeScannerIcon}
              color="primary"
              subtitle={`${summary.active_offers} active`}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title="Total Scans"
              value={summary.total_scans}
              icon={TrendingUpIcon}
              color="info"
              subtitle={`${summary.avg_scans_per_offer.toFixed(1)} per offer`}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title="Success Rate"
              value={`${summary.success_rate}%`}
              icon={CheckCircleIcon}
              color="success"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title="Unique Wallets"
              value={summary.unique_wallets}
              icon={DevicesIcon}
              color="warning"
            />
          </Grid>
        </Grid>
      )}

      {/* Wallet Distribution & Recent Activity */}
      {summary && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {/* Top Wallet Types */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DevicesIcon />
                  Top Wallet Types
                </Typography>
                <Divider sx={{ my: 2 }} />
                {summary.top_wallet_types.length > 0 ? (
                  <Stack spacing={2}>
                    {summary.top_wallet_types.map((item, index) => (
                      <Box key={index}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                          <Typography variant="body2">{formatWalletType(item.wallet_type)}</Typography>
                          <Typography variant="body2" fontWeight="medium">{item.count}</Typography>
                        </Box>
                        <Box sx={{ width: '100%', bgcolor: 'grey.200', borderRadius: 1, height: 8 }}>
                          <Box
                            sx={{
                              width: `${(item.count / summary.total_scans) * 100}%`,
                              bgcolor: 'primary.main',
                              borderRadius: 1,
                              height: '100%',
                            }}
                          />
                        </Box>
                      </Box>
                    ))}
                  </Stack>
                ) : (
                  <Typography color="text.secondary">No wallet data available</Typography>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Activity */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TimelineIcon />
                  Recent Activity
                </Typography>
                <Divider sx={{ my: 2 }} />
                {summary.recent_activity.length > 0 ? (
                  <Stack spacing={1.5}>
                    {summary.recent_activity.map((activity, index) => (
                      <Box key={index} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Chip
                            label={activity.outcome}
                            size="small"
                            color={OUTCOME_COLORS[activity.outcome] || 'default'}
                          />
                          <Typography variant="body2" color="text.secondary">
                            {formatWalletType(activity.wallet_type || 'Unknown')}
                          </Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">
                          {formatDate(activity.accessed_at)}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                ) : (
                  <Typography color="text.secondary">No recent activity</Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Detailed Scan Logs */}
      <Paper sx={{ mb: 3 }}>
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="h6" gutterBottom>
            Detailed Scan Logs
          </Typography>
          
          {/* Filters */}
          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Access Type</InputLabel>
              <Select
                value={accessTypeFilter}
                label="Access Type"
                onChange={(e) => {
                  setAccessTypeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="qr_view">QR View</MenuItem>
                <MenuItem value="offer_retrieval">Offer Retrieval</MenuItem>
                <MenuItem value="token_exchange">Token Exchange</MenuItem>
                <MenuItem value="credential_request">Credential Request</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Outcome</InputLabel>
              <Select
                value={outcomeFilter}
                label="Outcome"
                onChange={(e) => {
                  setOutcomeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="success">Success</MenuItem>
                <MenuItem value="expired">Expired</MenuItem>
                <MenuItem value="error">Error</MenuItem>
                <MenuItem value="unauthorized">Unauthorized</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Wallet Type</InputLabel>
              <Select
                value={walletTypeFilter}
                label="Wallet Type"
                onChange={(e) => {
                  setWalletTypeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="microsoft_authenticator">Microsoft Authenticator</MenuItem>
                <MenuItem value="spruce_wallet">Spruce Wallet</MenuItem>
                <MenuItem value="waltid_wallet">Walt.ID Wallet</MenuItem>
                <MenuItem value="trinsic_wallet">Trinsic Wallet</MenuItem>
                <MenuItem value="android_wallet">Android Wallet</MenuItem>
                <MenuItem value="ios_wallet">iOS Wallet</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </Box>

        {/* Scan Logs Table */}
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Access Type</TableCell>
                <TableCell>Wallet Type</TableCell>
                <TableCell>Outcome</TableCell>
                <TableCell>Transaction ID</TableCell>
                <TableCell>IP Address</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scansLoading ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                    <CircularProgress size={40} />
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">No scan logs found</Typography>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow key={scan.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontSize="0.875rem">
                        {formatDate(scan.accessed_at)}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Chip label={scan.access_type} size="small" variant="outlined" />
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2">
                        {formatWalletType(scan.wallet_type)}
                        {scan.wallet_version && (
                          <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
                            v{scan.wallet_version}
                          </Typography>
                        )}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Chip
                        label={scan.outcome}
                        size="small"
                        color={OUTCOME_COLORS[scan.outcome] || 'default'}
                      />
                    </TableCell>
                    
                    <TableCell>
                      <Tooltip title={scan.transaction_id || 'N/A'}>
                        <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                          {scan.transaction_id ? `${scan.transaction_id.slice(0, 12)}...` : 'N/A'}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2" fontSize="0.75rem">
                        {scan.ip_address || 'N/A'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          
          {/* Pagination */}
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={scansTotal}
            rowsPerPage={scansRowsPerPage}
            page={scansPage}
            onPageChange={handleScansPageChange}
            onRowsPerPageChange={handleScansRowsPerPageChange}
          />
        </TableContainer>
      </Paper>
    </Box>
  );
}
