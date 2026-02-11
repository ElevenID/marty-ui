/**
 * Vendor Offer List Component
 * 
 * Displays all credential offers for an organization with:
 * - QR code display
 * - Status tracking (active, scanned, expired, issued)
 * - Real-time updates via Server-Sent Events
 * - Actions: Regenerate, Copy link, View details
 * - Filtering by status and active state
 * - Pagination
 */

import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Typography,
  Chip,
  IconButton,
  Button,
  Menu,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Alert,
  AlertTitle,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Stack,
  Card,
  CardContent,
  Divider,
  CircularProgress,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import QrCodeIcon from '@mui/icons-material/QrCode';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import FilterListIcon from '@mui/icons-material/FilterList';

import QRCodeDisplay from '../issuance/QRCodeDisplay';
import { useAuth } from '../../hooks/useAuth';

const API_URL = import.meta.env.VITE_API_URL || '';

// Status configurations
const STATUS_COLORS = {
  pending: 'warning',
  ready: 'info',
  issued: 'success',
  deferred: 'info',
  expired: 'default',
  error: 'error',
  accepted: 'primary',
};

const STATUS_LABELS = {
  pending: 'Pending',
  ready: 'Ready',
  issued: 'Issued',
  deferred: 'Deferred',
  expired: 'Expired',
  error: 'Error',
  accepted: 'Accepted',
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
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

/**
 * Calculate time remaining until expiry
 */
function getTimeRemaining(expiresAt) {
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return 'Expired';
  
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  return `${minutes}m`;
}

/**
 * Offer Row Actions Menu
 */
function OfferActionsMenu({ offer, onRegenerate, onViewQR, onCopyLink }) {
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleRegenerate = () => {
    handleClose();
    onRegenerate(offer);
  };

  const handleViewQR = () => {
    handleClose();
    onViewQR(offer);
  };

  const handleCopyLink = () => {
    handleClose();
    onCopyLink(offer);
  };

  const canRegenerate = offer.is_expired || !offer.is_active;

  return (
    <>
      <IconButton
        size="small"
        onClick={handleClick}
        aria-label="offer actions"
      >
        <MoreVertIcon />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        <MenuItem onClick={handleViewQR}>
          <QrCodeIcon fontSize="small" sx={{ mr: 1 }} />
          View QR Code
        </MenuItem>
        <MenuItem onClick={handleCopyLink}>
          <ContentCopyIcon fontSize="small" sx={{ mr: 1 }} />
          Copy Link
        </MenuItem>
        {canRegenerate && (
          <MenuItem onClick={handleRegenerate}>
            <RefreshIcon fontSize="small" sx={{ mr: 1 }} />
            Regenerate
          </MenuItem>
        )}
      </Menu>
    </>
  );
}

OfferActionsMenu.propTypes = {
  offer: PropTypes.object.isRequired,
  onRegenerate: PropTypes.func.isRequired,
  onViewQR: PropTypes.func.isRequired,
  onCopyLink: PropTypes.func.isRequired,
};

/**
 * QR Code Dialog
 */
function QRCodeDialog({ open, offer, onClose }) {
  if (!offer) return null;

  const timeRemaining = !offer.is_expired ? getTimeRemaining(offer.expires_at) : null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        Credential Offer QR Code
        {offer.attempt_number > 1 && (
          <Chip
            label={`Attempt ${offer.attempt_number}`}
            size="small"
            sx={{ ml: 1 }}
            color="info"
          />
        )}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          {/* QR Code Display */}
          <Box sx={{ display: 'flex', justifyContent: 'center', my: 2 }}>
            <QRCodeDisplay
              value={offer.deep_link_uri || offer.credential_offer_uri}
              size={256}
              expiresAt={offer.expires_at}
              deepLinkUri={offer.deep_link_uri}
              qrCodeData={offer.qr_code_data}
            />
          </Box>

          {/* Offer Details */}
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Offer Details
              </Typography>
              <Divider sx={{ my: 1 }} />
              <Stack spacing={1}>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2" color="text.secondary">Status:</Typography>
                  <Chip
                    label={STATUS_LABELS[offer.status] || offer.status}
                    size="small"
                    color={STATUS_COLORS[offer.status] || 'default'}
                  />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2" color="text.secondary">Transaction ID:</Typography>
                  <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                    {offer.transaction_id.slice(0, 12)}...
                  </Typography>
                </Box>
                {timeRemaining && (
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2" color="text.secondary">Time Remaining:</Typography>
                    <Typography variant="body2" fontWeight="medium">
                      {timeRemaining}
                    </Typography>
                  </Box>
                )}
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2" color="text.secondary">Access Count:</Typography>
                  <Typography variant="body2">{offer.access_count}</Typography>
                </Box>
                {offer.accessed_at && (
                  <Box display="flex" justifyContent="space-between">
                    <Typography variant="body2" color="text.secondary">Last Accessed:</Typography>
                    <Typography variant="body2" fontSize="0.75rem">
                      {formatDate(offer.accessed_at)}
                    </Typography>
                  </Box>
                )}
              </Stack>
            </CardContent>
          </Card>

          {/* Deep Link Options */}
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Sharing Options
              </Typography>
              <Divider sx={{ my: 1 }} />
              <Stack spacing={1}>
                <Button
                  fullWidth
                  variant="outlined"
                  size="small"
                  startIcon={<ContentCopyIcon />}
                  onClick={() => {
                    navigator.clipboard.writeText(offer.deep_link_uri || offer.credential_offer_uri);
                  }}
                >
                  Copy Deep Link
                </Button>
                {offer.offer_endpoint && (
                  <Button
                    fullWidth
                    variant="outlined"
                    size="small"
                    startIcon={<OpenInNewIcon />}
                    onClick={() => {
                      navigator.clipboard.writeText(offer.offer_endpoint);
                    }}
                  >
                    Copy HTTP URL
                  </Button>
                )}
              </Stack>
            </CardContent>
          </Card>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

QRCodeDialog.propTypes = {
  open: PropTypes.bool.isRequired,
  offer: PropTypes.object,
  onClose: PropTypes.func.isRequired,
};

/**
 * Main Vendor Offer List Component
 */
export default function VendorOfferList() {
  const { organizationId } = useAuth();
  const [offers, setOffers] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  
  // Dialog state
  const [qrDialogOpen, setQrDialogOpen] = useState(false);
  const [selectedOffer, setSelectedOffer] = useState(null);
  
  // Regeneration state
  const [regenerating, setRegenerating] = useState(null);

  /**
   * Fetch offers from API
   */
  const fetchOffers = useCallback(async () => {
    if (!organizationId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams({
        organization_id: organizationId,
        page: (page + 1).toString(),
        page_size: rowsPerPage.toString(),
      });
      
      if (statusFilter) params.append('status', statusFilter);
      if (activeFilter !== '') params.append('is_active', activeFilter);
      
      const response = await fetch(
        `${API_URL}/api/issuance/offers?${params.toString()}`,
        {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      
      if (!response.ok) {
        throw new Error(`Failed to fetch offers: ${response.statusText}`);
      }
      
      const data = await response.json();
      setOffers(data.offers || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Error fetching offers:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId, page, rowsPerPage, statusFilter, activeFilter]);

  /**
   * Regenerate an expired offer
   */
  const handleRegenerate = useCallback(async (offer) => {
    setRegenerating(offer.offer_id);
    setError(null);
    
    try {
      const response = await fetch(
        `${API_URL}/api/issuance/offers/${offer.offer_id}/regenerate`,
        {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ force: false }),
        }
      );
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Failed to regenerate offer: ${response.statusText}`);
      }
      
      // Refresh the list
      await fetchOffers();
    } catch (err) {
      console.error('Error regenerating offer:', err);
      setError(err.message);
    } finally {
      setRegenerating(null);
    }
  }, [fetchOffers]);

  /**
   * View QR code dialog
   */
  const handleViewQR = useCallback((offer) => {
    setSelectedOffer(offer);
    setQrDialogOpen(true);
  }, []);

  /**
   * Copy offer link to clipboard
   */
  const handleCopyLink = useCallback((offer) => {
    const link = offer.deep_link_uri || offer.credential_offer_uri;
    navigator.clipboard.writeText(link);
  }, []);

  /**
   * Handle page change
   */
  const handleChangePage = useCallback((event, newPage) => {
    setPage(newPage);
  }, []);

  /**
   * Handle rows per page change
   */
  const handleChangeRowsPerPage = useCallback((event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  }, []);

  /**
   * Handle status filter change
   */
  const handleStatusFilterChange = useCallback((event) => {
    setStatusFilter(event.target.value);
    setPage(0);
  }, []);

  /**
   * Handle active filter change
   */
  const handleActiveFilterChange = useCallback((event) => {
    setActiveFilter(event.target.value);
    setPage(0);
  }, []);

  /**
   * Close QR dialog
   */
  const handleCloseQRDialog = useCallback(() => {
    setQrDialogOpen(false);
    setSelectedOffer(null);
  }, []);

  // Fetch offers on mount and when filters change
  useEffect(() => {
    fetchOffers();
  }, [fetchOffers]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      fetchOffers();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [fetchOffers]);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h6">Credential Offers</Typography>
          <Typography variant="body2" color="text.secondary">
            View and manage all credential offers with QR codes
          </Typography>
        </Box>
        <IconButton onClick={fetchOffers} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <FilterListIcon color="action" />
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={statusFilter}
              label="Status"
              onChange={handleStatusFilterChange}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="pending">Pending</MenuItem>
              <MenuItem value="ready">Ready</MenuItem>
              <MenuItem value="issued">Issued</MenuItem>
              <MenuItem value="deferred">Deferred</MenuItem>
              <MenuItem value="expired">Expired</MenuItem>
              <MenuItem value="error">Error</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Active</InputLabel>
            <Select
              value={activeFilter}
              label="Active"
              onChange={handleActiveFilterChange}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="true">Active</MenuItem>
              <MenuItem value="false">Inactive</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {/* Offers Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Created</TableCell>
              <TableCell>Transaction ID</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Active</TableCell>
              <TableCell>Time Remaining</TableCell>
              <TableCell>Access Count</TableCell>
              <TableCell>Attempt</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                  <CircularProgress size={40} />
                </TableCell>
              </TableRow>
            ) : offers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                  <Typography color="text.secondary">
                    No credential offers found
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              offers.map((offer) => (
                <TableRow key={offer.offer_id} hover>
                  {/* Created At */}
                  <TableCell>
                    <Typography variant="body2" fontSize="0.875rem">
                      {formatDate(offer.created_at)}
                    </Typography>
                  </TableCell>
                  
                  {/* Transaction ID */}
                  <TableCell>
                    <Tooltip title={offer.transaction_id}>
                      <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                        {offer.transaction_id.slice(0, 12)}...
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  
                  {/* Status */}
                  <TableCell>
                    <Chip
                      label={STATUS_LABELS[offer.status] || offer.status}
                      size="small"
                      color={STATUS_COLORS[offer.status] || 'default'}
                    />
                  </TableCell>
                  
                  {/* Active */}
                  <TableCell>
                    <Chip
                      label={offer.is_active ? 'Active' : 'Inactive'}
                      size="small"
                      color={offer.is_active ? 'success' : 'default'}
                      variant={offer.is_active ? 'filled' : 'outlined'}
                    />
                  </TableCell>
                  
                  {/* Time Remaining */}
                  <TableCell>
                    <Typography variant="body2" fontSize="0.875rem">
                      {getTimeRemaining(offer.expires_at)}
                    </Typography>
                  </TableCell>
                  
                  {/* Access Count */}
                  <TableCell>
                    <Typography variant="body2">
                      {offer.access_count}
                      {offer.accessed_at && (
                        <Tooltip title={`Last: ${formatDate(offer.accessed_at)}`}>
                          <span style={{ marginLeft: 4, cursor: 'help' }}>ⓘ</span>
                        </Tooltip>
                      )}
                    </Typography>
                  </TableCell>
                  
                  {/* Attempt Number */}
                  <TableCell>
                    {offer.attempt_number > 1 ? (
                      <Chip
                        label={offer.attempt_number}
                        size="small"
                        color="info"
                        variant="outlined"
                      />
                    ) : (
                      <Typography variant="body2" color="text.secondary">1</Typography>
                    )}
                  </TableCell>
                  
                  {/* Actions */}
                  <TableCell align="right">
                    {regenerating === offer.offer_id ? (
                      <CircularProgress size={24} />
                    ) : (
                      <OfferActionsMenu
                        offer={offer}
                        onRegenerate={handleRegenerate}
                        onViewQR={handleViewQR}
                        onCopyLink={handleCopyLink}
                      />
                    )}
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
          count={total}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </TableContainer>

      {/* QR Code Dialog */}
      <QRCodeDialog
        open={qrDialogOpen}
        offer={selectedOffer}
        onClose={handleCloseQRDialog}
      />
    </Box>
  );
}
