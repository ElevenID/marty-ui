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
import { useTranslation } from 'react-i18next';
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
import { fetchAnalyticsSummary, fetchAnalyticsScans } from '../../application/vendor';

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
function formatDate(dateString, t) {
  if (!dateString) return t('offerAnalytics.notAvailable');
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
function formatWalletType(walletType, t) {
  if (!walletType) return t('offerAnalytics.unknown');
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
  const { t } = useTranslation('vendor');
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
      const data = await fetchAnalyticsSummary({ organizationId });
      setSummary(data);
    } catch (err) {
      console.error('Error fetching analytics:', err);
      setError(t('offerAnalytics.loadFailed'));
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
      const data = await fetchAnalyticsScans({
        organizationId,
        page: scansPage + 1,
        pageSize: scansRowsPerPage,
        accessTypeFilter,
        outcomeFilter,
        walletTypeFilter,
      });
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
          <Typography variant="h6">{t('offerAnalytics.title')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('offerAnalytics.description')}
          </Typography>
        </Box>
        <IconButton onClick={handleRefresh} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          <AlertTitle>{t('offerAnalytics.error')}</AlertTitle>
          {error}
        </Alert>
      )}

      {/* Summary Metrics */}
      {summary && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title={t('offerAnalytics.metrics.totalOffers')}
              value={summary.total_offers}
              icon={QrCodeScannerIcon}
              color="primary"
              subtitle={t('offerAnalytics.metrics.totalOffersSubtitle', { count: summary.active_offers })}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title={t('offerAnalytics.metrics.totalScans')}
              value={summary.total_scans}
              icon={TrendingUpIcon}
              color="info"
              subtitle={t('offerAnalytics.metrics.totalScansSubtitle', { avg: summary.avg_scans_per_offer.toFixed(1) })}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title={t('offerAnalytics.metrics.successRate')}
              value={`${summary.success_rate}%`}
              icon={CheckCircleIcon}
              color="success"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <MetricCard
              title={t('offerAnalytics.metrics.uniqueWallets')}
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
                  {t('offerAnalytics.walletDistribution.title')}
                </Typography>
                <Divider sx={{ my: 2 }} />
                {summary.top_wallet_types.length > 0 ? (
                  <Stack spacing={2}>
                    {summary.top_wallet_types.map((item, index) => (
                      <Box key={index}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                          <Typography variant="body2">{formatWalletType(item.wallet_type, t)}</Typography>
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
                  <Typography color="text.secondary">{t('offerAnalytics.walletDistribution.noData')}</Typography>
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
                  {t('offerAnalytics.recentActivity.title')}
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
                            {formatWalletType(activity.wallet_type || 'Unknown', t)}
                          </Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">
                          {formatDate(activity.accessed_at, t)}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                ) : (
                  <Typography color="text.secondary">{t('offerAnalytics.recentActivity.noActivity')}</Typography>
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
            {t('offerAnalytics.detailedLogs.title')}
          </Typography>
          
          {/* Filters */}
          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>{t('offerAnalytics.filters.accessType')}</InputLabel>
              <Select
                value={accessTypeFilter}
                label={t('offerAnalytics.filters.accessType')}
                onChange={(e) => {
                  setAccessTypeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">{t('offerAnalytics.filters.all')}</MenuItem>
                <MenuItem value="qr_view">{t('offerAnalytics.accessTypes.qrView')}</MenuItem>
                <MenuItem value="offer_retrieval">{t('offerAnalytics.accessTypes.offerRetrieval')}</MenuItem>
                <MenuItem value="token_exchange">{t('offerAnalytics.accessTypes.tokenExchange')}</MenuItem>
                <MenuItem value="credential_request">{t('offerAnalytics.accessTypes.credentialRequest')}</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>{t('offerAnalytics.filters.outcome')}</InputLabel>
              <Select
                value={outcomeFilter}
                label={t('offerAnalytics.filters.outcome')}
                onChange={(e) => {
                  setOutcomeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">{t('offerAnalytics.filters.all')}</MenuItem>
                <MenuItem value="success">{t('offerAnalytics.outcomes.success')}</MenuItem>
                <MenuItem value="expired">{t('offerAnalytics.outcomes.expired')}</MenuItem>
                <MenuItem value="error">{t('offerAnalytics.outcomes.error')}</MenuItem>
                <MenuItem value="unauthorized">{t('offerAnalytics.outcomes.unauthorized')}</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>{t('offerAnalytics.filters.walletType')}</InputLabel>
              <Select
                value={walletTypeFilter}
                label={t('offerAnalytics.filters.walletType')}
                onChange={(e) => {
                  setWalletTypeFilter(e.target.value);
                  setScansPage(0);
                }}
              >
                <MenuItem value="">{t('offerAnalytics.filters.all')}</MenuItem>
                <MenuItem value="microsoft_authenticator">{t('offerAnalytics.walletTypes.microsoftAuthenticator')}</MenuItem>
                <MenuItem value="spruce_wallet">{t('offerAnalytics.walletTypes.spruce')}</MenuItem>
                <MenuItem value="waltid_wallet">{t('offerAnalytics.walletTypes.waltId')}</MenuItem>
                <MenuItem value="trinsic_wallet">{t('offerAnalytics.walletTypes.trinsic')}</MenuItem>
                <MenuItem value="android_wallet">{t('offerAnalytics.walletTypes.androidWallet')}</MenuItem>
                <MenuItem value="ios_wallet">{t('offerAnalytics.walletTypes.iosWallet')}</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </Box>

        {/* Scan Logs Table */}
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('offerAnalytics.table.time')}</TableCell>
                <TableCell>{t('offerAnalytics.table.accessType')}</TableCell>
                <TableCell>{t('offerAnalytics.table.walletType')}</TableCell>
                <TableCell>{t('offerAnalytics.table.outcome')}</TableCell>
                <TableCell>{t('offerAnalytics.table.transactionId')}</TableCell>
                <TableCell>{t('offerAnalytics.table.ipAddress')}</TableCell>
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
                    <Typography color="text.secondary">{t('offerAnalytics.table.noLogs')}</Typography>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow key={scan.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontSize="0.875rem">
                        {formatDate(scan.accessed_at, t)}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Chip label={scan.access_type} size="small" variant="outlined" />
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2">
                        {formatWalletType(scan.wallet_type, t)}
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
