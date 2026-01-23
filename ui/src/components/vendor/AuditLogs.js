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

import React, { useState, useEffect, useCallback } from 'react';
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
  ToggleButtonGroup,
  ToggleButton,
  CircularProgress,
} from '@mui/material';
import {
  History as HistoryIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  FileDownload as ExportIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';

// API base URL
const API_URL = process.env.REACT_APP_API_URL || '';

// Event categories
const EVENT_CATEGORIES = [
  { id: 'all', label: 'All Events', color: 'default' },
  { id: 'credential', label: 'Credentials', color: 'primary' },
  { id: 'verification', label: 'Verifications', color: 'secondary' },
  { id: 'application', label: 'Applications', color: 'info' },
  { id: 'trust', label: 'Trust Operations', color: 'warning' },
  { id: 'security', label: 'Security', color: 'error' },
  { id: 'audit', label: 'Audit', color: 'success' },
];

// Event severity levels
const SEVERITY_LEVELS = ['all', 'info', 'warning', 'error', 'critical'];

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

      const response = await fetch(`${API_URL}/api/v1/audit/events?${params}`, {
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

      const response = await fetch(`${API_URL}/api/v1/audit/events/export?${params}`, {
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
          Audit Logs
        </Typography>
        <Typography variant="body1" color="text.secondary">
          View and analyze all system events, credential operations, and security activities.
        </Typography>
      </Box>

      {/* Filters and Controls */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Stack spacing={2}>
          {/* Search and Time Range */}
          <Stack direction="row" spacing={2}>
            <TextField
              fullWidth
              placeholder="Search by event ID, user, or resource..."
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
              <InputLabel>Time Range</InputLabel>
              <Select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} label="Time Range">
                <MenuItem value="1h">Last Hour</MenuItem>
                <MenuItem value="24h">Last 24 Hours</MenuItem>
                <MenuItem value="7d">Last 7 Days</MenuItem>
                <MenuItem value="30d">Last 30 Days</MenuItem>
                <MenuItem value="all">All Time</MenuItem>
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
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                label="Severity"
              >
                {SEVERITY_LEVELS.map((level) => (
                  <MenuItem key={level} value={level}>
                    {level.charAt(0).toUpperCase() + level.slice(1)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Tooltip title="Refresh">
              <IconButton onClick={loadEvents} disabled={loading}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>

            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('csv')}
            >
              Export
            </Button>
          </Stack>
        </Stack>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error} (Showing mock data for development)
        </Alert>
      )}

      {/* Events Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell width="30">Severity</TableCell>
                <TableCell>Timestamp</TableCell>
                <TableCell>Event Type</TableCell>
                <TableCell>User</TableCell>
                <TableCell>Resource</TableCell>
                <TableCell>Description</TableCell>
                <TableCell width="80" align="center">
                  Actions
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
                      No events found for the selected filters.
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
                      <Tooltip title="View Details">
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
