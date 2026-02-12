/**
 * Audit Logs Page
 * 
 * Displays comprehensive event history for credentials, verifications, 
 * applications, trust operations, and security events.
 * 
 * Features:
 * - Real-time event log with filtering
 * - Category filters (credential, verification, application, trust, security)
 * - Time range filtering
 * - Search by event ID, user, or resource
 * - Export to CSV/JSON
 * - Event detail drill-down
 */

import { useState, useEffect, useCallback } from 'react';import { useTranslation } from 'react-i18next';import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Stack,
  Tooltip,
  CircularProgress,
} from '@mui/material';
import {
  History as HistoryIcon,
  Search as SearchIcon,
  FileDownload as ExportIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';

// API base URL
const API_URL = import.meta.env.VITE_API_URL || '';


/**
 * Get icon for event severity
 */
function getSeverityIcon(severity) {
  switch (severity) {
    case 'error':
    case 'critical':
      return <ErrorIcon fontSize="small" color="error" />;
    case 'warning':
      return <WarningIcon fontSize="small" color="warning" />;
    case 'info':
    default:
      return <InfoIcon fontSize="small" color="info" />;
  }
}

/**
 * Get color for event type
 */
function getEventTypeColor(eventType) {
  if (eventType.startsWith('credential.')) return 'primary';
  if (eventType.startsWith('verification.')) return 'secondary';
  if (eventType.startsWith('application.')) return 'info';
  if (eventType.startsWith('trust.')) return 'warning';
  if (eventType.startsWith('audit.')) return 'success';
  if (eventType.startsWith('security.')) return 'error';
  return 'default';
}

/**
 * Format timestamp to readable format
 */
function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Event Detail Dialog Component
 */
function EventDetailDialog({ event, open, onClose }) {
  if (!event) return null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {getSeverityIcon(event.severity)}
          Event Details
        </Box>
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Event ID
            </Typography>
            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
              {event.id}
            </Typography>
          </Box>

          <Box>
            <Typography variant="caption" color="text.secondary">
              Event Type
            </Typography>
            <Box sx={{ mt: 0.5 }}>
              <Chip
                label={event.event_type}
                color={getEventTypeColor(event.event_type)}
                size="small"
              />
            </Box>
          </Box>

          <Box>
            <Typography variant="caption" color="text.secondary">
              Timestamp
            </Typography>
            <Typography variant="body2">{formatTimestamp(event.timestamp)}</Typography>
          </Box>

          {event.user && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                User
              </Typography>
              <Typography variant="body2">{event.user}</Typography>
            </Box>
          )}

          {event.resource_id && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Resource ID
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                {event.resource_id}
              </Typography>
            </Box>
          )}

          <Box>
            <Typography variant="caption" color="text.secondary">
              Description
            </Typography>
            <Typography variant="body2">{event.description}</Typography>
          </Box>

          {event.metadata && Object.keys(event.metadata).length > 0 && (
            <Box>
              <Typography variant="caption" color="text.secondary">
                Metadata
              </Typography>
              <Paper
                variant="outlined"
                sx={{ p: 1, mt: 0.5, bgcolor: 'grey.50', fontFamily: 'monospace', fontSize: 12 }}
              >
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              </Paper>
            </Box>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Main Audit Logs Component
 */
export default function AuditLogs() {
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState('24h');

  // Dialog state
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);

  // Event categories (dynamic to access t)
  const EVENT_CATEGORIES = [
    { id: 'all', label: t('auditLogs.categories.all'), color: 'default' },
    { id: 'credential', label: t('auditLogs.categories.credential'), color: 'primary' },
    { id: 'verification', label: t('auditLogs.categories.verification'), color: 'secondary' },
    { id: 'application', label: t('auditLogs.categories.application'), color: 'info' },
    { id: 'trust', label: t('auditLogs.categories.trust'), color: 'warning' },
    { id: 'security', label: t('auditLogs.categories.security'), color: 'error' },
    { id: 'audit', label: t('auditLogs.categories.audit'), color: 'success' },
  ];

  // Severity levels (dynamic to access t)
  const getSeverityLabel = (level) => {
    if (level === 'all') return t('auditLogs.severity.all');
    return t(`auditLogs.severity.${level}`);
  };

  /**
   * Load audit events from API
   */
  const loadEvents = useCallback(async () => {
    if (!organizationId) return;

    setLoading(true);
    setError(null);

    try {
      // Build query parameters
      const params = new URLSearchParams({
        organization_id: organizationId,
        page: page + 1,
        per_page: rowsPerPage,
        time_range: timeRange,
      });

      if (categoryFilter !== 'all') {
        params.append('category', categoryFilter);
      }

      if (severityFilter !== 'all') {
        params.append('severity', severityFilter);
      }

      if (searchQuery) {
        params.append('search', searchQuery);
      }

      const response = await fetch(`${API_URL}/v1/organizations/audit/events?${params}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to load audit events: ${response.statusText}`);
      }

      const data = await response.json();
      setEvents(data.events || []);
      setTotalCount(data.total || 0);
    } catch (err) {
      console.error('Error loading audit events:', err);
      setError(err.message);
      // Use mock data for development
      setEvents(generateMockEvents());
      setTotalCount(100);
    } finally {
      setLoading(false);
    }
  }, [organizationId, page, rowsPerPage, categoryFilter, severityFilter, searchQuery, timeRange]);

  // Load events on mount and when filters change
  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  /**
   * Handle page change
   */
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  /**
   * Handle rows per page change
   */
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  /**
   * Handle view event details
   */
  const handleViewEvent = (event) => {
    setSelectedEvent(event);
    setDetailDialogOpen(true);
  };

  /**
   * Handle export events
   */
  const handleExport = async (format) => {
    try {
      const params = new URLSearchParams({
        organization_id: organizationId,
        format: format,
        time_range: timeRange,
      });

      if (categoryFilter !== 'all') {
        params.append('category', categoryFilter);
      }

      if (severityFilter !== 'all') {
        params.append('severity', severityFilter);
      }

      const response = await fetch(`${API_URL}/v1/organizations/audit/events/export?${params}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to export: ${response.statusText}`);
      }

      // Download file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-logs-${Date.now()}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Error exporting events:', err);
      setError(err.message);
    }
  };

  return (
    <Box data-testid="audit-logs-page">
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <HistoryIcon fontSize="large" />
          {t('auditLogs.title')}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          {t('auditLogs.description')}
        </Typography>
      </Box>

      {/* Filters and Controls */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Stack spacing={2}>
          {/* Search and Time Range */}
          <Stack direction="row" spacing={2}>
            <TextField
              fullWidth
              placeholder={t('auditLogs.filters.search')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
            <FormControl sx={{ minWidth: 150 }}>
              <InputLabel>{t('auditLogs.filters.timeRange')}</InputLabel>
              <Select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} label={t('auditLogs.filters.timeRange')}>
                <MenuItem value="1h">{t('auditLogs.filters.timeRangeOptions.lastHour')}</MenuItem>
                <MenuItem value="24h">{t('auditLogs.filters.timeRangeOptions.last24Hours')}</MenuItem>
                <MenuItem value="7d">{t('auditLogs.filters.timeRangeOptions.last7Days')}</MenuItem>
                <MenuItem value="30d">{t('auditLogs.filters.timeRangeOptions.last30Days')}</MenuItem>
                <MenuItem value="all">{t('auditLogs.filters.timeRangeOptions.allTime')}</MenuItem>
              </Select>
            </FormControl>
          </Stack>

          {/* Category and Severity Filters */}
          <Stack direction="row" spacing={2} alignItems="center">
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', flex: 1 }}>
              {EVENT_CATEGORIES.map((category) => (
                <Chip
                  key={category.id}
                  label={category.label}
                  color={categoryFilter === category.id ? category.color : 'default'}
                  onClick={() => setCategoryFilter(category.id)}
                  variant={categoryFilter === category.id ? 'filled' : 'outlined'}
                />
              ))}
            </Box>

            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>{t('auditLogs.filters.severity')}</InputLabel>
              <Select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                label={t('auditLogs.filters.severity')}
              >
                {['all', 'info', 'warning', 'error', 'critical'].map((level) => (
                  <MenuItem key={level} value={level}>
                    {getSeverityLabel(level)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Tooltip title={t('auditLogs.refreshButton')}>
              <IconButton onClick={loadEvents} disabled={loading}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>

            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('csv')}
            >
              {t('auditLogs.exportButton')}
            </Button>
          </Stack>
        </Stack>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {t('auditLogs.loadFailed', { error })}
        </Alert>
      )}

      {/* Events Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell width="30">{t('auditLogs.table.severity')}</TableCell>
                <TableCell>{t('auditLogs.table.timestamp')}</TableCell>
                <TableCell>{t('auditLogs.table.eventType')}</TableCell>
                <TableCell>{t('auditLogs.table.user')}</TableCell>
                <TableCell>{t('auditLogs.table.resource')}</TableCell>
                <TableCell>{t('auditLogs.table.description')}</TableCell>
                <TableCell width="80" align="center">
                  {t('auditLogs.table.actions')}
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                    <CircularProgress />
                  </TableCell>
                </TableRow>
              ) : events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                    <Typography variant="body2" color="text.secondary">
                      {t('auditLogs.empty')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                events.map((event) => (
                  <TableRow key={event.id} hover>
                    <TableCell>{getSeverityIcon(event.severity)}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ whiteSpace: 'nowrap' }}>
                        {formatTimestamp(event.timestamp)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={event.event_type}
                        size="small"
                        color={getEventTypeColor(event.event_type)}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{event.user || '-'}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: 11 }}
                        noWrap
                      >
                        {event.resource_id ? event.resource_id.substring(0, 16) + '...' : '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" noWrap>
                        {event.description}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Tooltip title={t('auditLogs.viewDetailsTooltip')}>
                        <IconButton size="small" onClick={() => handleViewEvent(event)}>
                          <ViewIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={handleChangePage}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </Paper>

      {/* Event Detail Dialog */}
      <EventDetailDialog
        event={selectedEvent}
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
      />
    </Box>
  );
}

/**
 * Generate mock events for development
 */
function generateMockEvents() {
  const eventTypes = [
    { type: 'credential.issued', description: 'Credential issued to applicant', severity: 'info' },
    { type: 'credential.revoked', description: 'Credential revoked', severity: 'warning' },
    { type: 'verification.completed', description: 'Verification session completed', severity: 'info' },
    { type: 'application.submitted', description: 'New application submitted', severity: 'info' },
    { type: 'application.approved', description: 'Application approved', severity: 'info' },
    { type: 'trust.certificate_updated', description: 'Trust certificate updated', severity: 'warning' },
    { type: 'audit.configuration_changed', description: 'Configuration modified', severity: 'info' },
    { type: 'security.login_failed', description: 'Failed login attempt', severity: 'error' },
  ];

  return Array.from({ length: 25 }, (_, i) => {
    const eventType = eventTypes[i % eventTypes.length];
    return {
      id: `evt_${Date.now()}_${i}`,
      event_type: eventType.type,
      severity: eventType.severity,
      description: eventType.description,
      timestamp: new Date(Date.now() - i * 3600000).toISOString(),
      user: `user${(i % 5) + 1}@example.com`,
      resource_id: `res_${Math.random().toString(36).substring(2, 15)}`,
      metadata: {
        ip_address: `192.168.1.${(i % 255) + 1}`,
        user_agent: 'Mozilla/5.0',
      },
    };
  });
}
