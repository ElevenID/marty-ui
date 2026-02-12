/**
 * Webhook Delivery Logs Component
 * 
 * Displays delivery attempt history for a specific webhook endpoint.
 * Shows success/failure status, response codes, retry count, and timestamps.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Collapse,
  Alert,
  CircularProgress,
  Pagination,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import { getWebhookDeliveryAttempts, getErrorMessage } from '../../services/webhooksApi';

/**
 * Webhook Delivery Logs Component
 * @param {Object} props - Component props
 * @param {string} props.webhookId - The webhook ID to show delivery logs for
 */
export default function WebhookDeliveryLogs({ webhookId }) {
  const { t } = useTranslation('vendor');
  const [deliveries, setDeliveries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [detailsDialog, setDetailsDialog] = useState(null);
  
  const itemsPerPage = 20;

  useEffect(() => {
    if (webhookId) {
      loadDeliveries();
    }
  }, [webhookId, page, loadDeliveries]);

  const loadDeliveries = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const offset = (page - 1) * itemsPerPage;
      const result = await getWebhookDeliveryAttempts(webhookId, {
        limit: itemsPerPage,
        offset,
      });
      
      setDeliveries(result);
      // Calculate total pages (backend should ideally return total count)
      setTotalPages(Math.ceil(result.length / itemsPerPage) || 1);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [webhookId, page, itemsPerPage]);

  const handleRowToggle = (deliveryId) => {
    setExpandedRow(expandedRow === deliveryId ? null : deliveryId);
  };

  const handleOpenDetails = (delivery) => {
    setDetailsDialog(delivery);
  };

  const handleCloseDetails = () => {
    setDetailsDialog(null);
  };

  const getStatusChip = (delivery) => {
    if (delivery.success) {
      return (
        <Chip
          icon={<CheckCircleIcon />}
          label={t('webhookDeliveryLogs.status.success', { code: delivery.response_status_code })}
          color="success"
          size="small"
        />
      );
    } else {
      return (
        <Chip
          icon={<ErrorIcon />}
          label={t('webhookDeliveryLogs.status.failed', { code: delivery.response_status_code || t('webhookDeliveryLogs.status.notAvailable') })}
          color="error"
          size="small"
        />
      );
    }
  };

  if (!webhookId) {
    return (
      <Alert severity="info">
        {t('webhookDeliveryLogs.selectWebhook')}
      </Alert>
    );
  }

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid="webhook-delivery-logs">
      <Typography variant="h6" gutterBottom>
        {t('webhookDeliveryLogs.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        {t('webhookDeliveryLogs.description')}
      </Typography>

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {deliveries.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center', bgcolor: 'grey.50' }}>
          <InfoIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            {t('webhookDeliveryLogs.empty.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('webhookDeliveryLogs.empty.description')}
          </Typography>
        </Paper>
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width={50} />
                  <TableCell>{t('webhookDeliveryLogs.table.timestamp')}</TableCell>
                  <TableCell>{t('webhookDeliveryLogs.table.eventType')}</TableCell>
                  <TableCell>{t('webhookDeliveryLogs.table.status')}</TableCell>
                  <TableCell>{t('webhookDeliveryLogs.table.responseTime')}</TableCell>
                  <TableCell>{t('webhookDeliveryLogs.table.retryCount')}</TableCell>
                  <TableCell align="right">{t('webhookDeliveryLogs.table.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {deliveries.map((delivery) => (
                  <React.Fragment key={delivery.id}>
                    <TableRow hover>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleRowToggle(delivery.id)}
                        >
                          {expandedRow === delivery.id ? (
                            <ExpandLessIcon />
                          ) : (
                            <ExpandMoreIcon />
                          )}
                        </IconButton>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(delivery.created_at).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={delivery.event_type || 'unknown'}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>{getStatusChip(delivery)}</TableCell>
                      <TableCell>
                        {delivery.response_time_ms ? `${delivery.response_time_ms}ms` : '-'}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={delivery.retry_count || 0}
                          size="small"
                          color={delivery.retry_count > 0 ? 'warning' : 'default'}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title={t('webhookDeliveryLogs.viewDetails')}>
                          <IconButton
                            size="small"
                            onClick={() => handleOpenDetails(delivery)}
                          >
                            <InfoIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                        <Collapse in={expandedRow === delivery.id} timeout="auto" unmountOnExit>
                          <Box sx={{ py: 2, px: 3, bgcolor: 'grey.50' }}>
                            <Typography variant="subtitle2" gutterBottom>
                              {t('webhookDeliveryLogs.errorMessage')}
                            </Typography>
                            <Typography
                              variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                bgcolor: 'background.paper',
                                p: 1,
                                borderRadius: 1,
                              }}
                            >
                              {delivery.error_message || t('webhookDeliveryLogs.noError')}
                            </Typography>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {totalPages > 1 && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={(_, value) => setPage(value)}
                color="primary"
              />
            </Box>
          )}
        </>
      )}

      {/* Delivery Details Dialog */}
      <Dialog
        open={!!detailsDialog}
        onClose={handleCloseDetails}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>{t('webhookDeliveryLogs.detailsDialog.title')}</DialogTitle>
        <DialogContent>
          {detailsDialog && (
            <Box sx={{ pt: 2 }}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.eventId')}
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {detailsDialog.event_id || t('webhookDeliveryLogs.status.notAvailable')}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.eventType')}
                </Typography>
                <Typography variant="body2">
                  {detailsDialog.event_type || 'unknown'}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.timestamp')}
                </Typography>
                <Typography variant="body2">
                  {new Date(detailsDialog.created_at).toLocaleString()}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.status')}
                </Typography>
                <Box sx={{ mt: 0.5 }}>
                  {getStatusChip(detailsDialog)}
                </Box>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.responseTime')}
                </Typography>
                <Typography variant="body2">
                  {detailsDialog.response_time_ms
                    ? `${detailsDialog.response_time_ms}ms`
                    : t('webhookDeliveryLogs.status.notAvailable')}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('webhookDeliveryLogs.detailsDialog.retryCount')}
                </Typography>
                <Typography variant="body2">
                  {detailsDialog.retry_count || 0}
                </Typography>
              </Box>

              {detailsDialog.error_message && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    {t('webhookDeliveryLogs.detailsDialog.errorMessage')}
                  </Typography>
                  <Paper
                    sx={{
                      p: 2,
                      bgcolor: 'grey.50',
                      fontFamily: 'monospace',
                      fontSize: '0.875rem',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {detailsDialog.error_message}
                  </Paper>
                </Box>
              )}

              {detailsDialog.response_body && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    {t('webhookDeliveryLogs.detailsDialog.responseBody')}
                  </Typography>
                  <Paper
                    sx={{
                      p: 2,
                      bgcolor: 'grey.50',
                      fontFamily: 'monospace',
                      fontSize: '0.875rem',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      maxHeight: 300,
                      overflow: 'auto',
                    }}
                  >
                    {detailsDialog.response_body}
                  </Paper>
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDetails}>{t('webhookDeliveryLogs.detailsDialog.closeButton')}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
