/**
 * Audit Page
 * 
 * Audit logs and activity monitoring.
 */

import { useState, useEffect } from 'react';
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
  TextField,
  InputAdornment,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Collapse,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import FilterListIcon from '@mui/icons-material/FilterList';
import DownloadIcon from '@mui/icons-material/Download';
import RefreshIcon from '@mui/icons-material/Refresh';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import BookmarkIcon from '@mui/icons-material/Bookmark';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import HistoryIcon from '@mui/icons-material/History';
import auditApi from '../../../services/auditApi';
import { useNotifications } from '../../../hooks/useNotifications';

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Audit', path: '/console/audit' },
];

const EVENT_CATEGORIES = [
  { value: 'all', label: 'All Events' },
  { value: 'authentication', label: 'Authentication' },
  { value: 'credential', label: 'Credentials' },
  { value: 'flow', label: 'Flows' },
  { value: 'policy', label: 'Policies' },
  { value: 'template', label: 'Templates' },
  { value: 'team', label: 'Team' },
  { value: 'settings', label: 'Settings' },
];

const SEVERITY_LEVELS = [
  { value: 'all', label: 'All Levels' },
  { value: 'info', label: 'Info' },
  { value: 'warning', label: 'Warning' },
  { value: 'error', label: 'Error' },
];

function AuditPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [expandedRow, setExpandedRow] = useState(null);
  const [savedViews, setSavedViews] = useState([]);
  const [exporting, setExporting] = useState(false);
  
  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [actor, setActor] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [startDate, setStartDate] = useState(null);
  const [endDate, setEndDate] = useState(null);

  const { showNotification } = useNotifications();

  useEffect(() => {
    loadEvents();
  }, [page, rowsPerPage, category, severity, startDate, endDate]);

  useEffect(() => {
    loadSavedViews();
  }, []);

  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const filters = {
        limit: rowsPerPage,
        offset: page * rowsPerPage,
      };
      
      if (category !== 'all') filters.resource_type = category;
      if (severity !== 'all') filters.severity = severity;
      if (actor) filters.actor = actor;
      if (resourceType) filters.resource_type = resourceType;
      if (ipAddress) filters.ip_address = ipAddress;
      if (startDate) filters.start_date = startDate.toISOString();
      if (endDate) filters.end_date = endDate.toISOString();

      const data = await auditApi.listAuditEvents(filters);
      setEvents(Array.isArray(data) ? data : data.events || []);
      setTotalCount(data.total || data.length || 0);
    } catch (err) {
      console.error('Failed to load audit events:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const loadSavedViews = async () => {
    try {
      const views = await auditApi.listFilterViews();
      setSavedViews(Array.isArray(views) ? views : []);
    } catch (err) {
      console.error('Failed to load saved views:', err);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const filters = {
        resource_type: category !== 'all' ? category : undefined,
        severity: severity !== 'all' ? severity : undefined,
        actor,
        ip_address: ipAddress,
        start_date: startDate?.toISOString(),
        end_date: endDate?.toISOString(),
      };
      
      const result = await auditApi.exportAuditEvents(filters, 'csv');
      
      // If backend returns download URL, open it
      if (result.download_url) {
        window.open(result.download_url, '_blank');
        showNotification?.('Export started. Download will begin shortly.', 'success');
      } else {
        showNotification?.('Export job created. You\'ll receive a notification when ready.', 'info');
      }
    } catch (err) {
      console.error('Failed to export audit logs:', err);
      showNotification?.('Failed to export audit logs', 'error');
    } finally {
      setExporting(false);
    }
  };

  const handleSaveView = async () => {
    const viewName = prompt('Enter a name for this filter view:');
    if (!viewName) return;

    try {
      await auditApi.saveFilterView({
        name: viewName,
        filters: {
          category,
          severity,
          actor,
          resourceType,
          ipAddress,
          startDate: startDate?.toISOString(),
          endDate: endDate?.toISOString(),
        },
      });
      showNotification?.('Filter view saved', 'success');
      loadSavedViews();
    } catch (err) {
      console.error('Failed to save view:', err);
      showNotification?.('Failed to save filter view', 'error');
    }
  };

  const applyView = (view) => {
    const filters = view.filters;
    setCategory(filters.category || 'all');
    setSeverity(filters.severity || 'all');
    setActor(filters.actor || '');
    setResourceType(filters.resourceType || '');
    setIpAddress(filters.ipAddress || '');
    setStartDate(filters.startDate ? new Date(filters.startDate) : null);
    setEndDate(filters.endDate ? new Date(filters.endDate) : null);
    showNotification?.(`Applied view: ${view.name}`, 'info');
  };

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'error':
        return 'error';
      case 'warning':
        return 'warning';
      case 'success':
        return 'success';
      default:
        return 'info';
    }
  };

  const getSeverityIcon = (sev) => {
    switch (sev) {
      case 'error':
        return <ErrorIcon fontSize="small" />;
      case 'warning':
        return <WarningIcon fontSize="small" />;
      case 'success':
        return <CheckCircleIcon fontSize="small" />;
      default:
        return <InfoIcon fontSize="small" />;
    }
  };

  const getResourceLink = (event) => {
    const { category, details, resource } = event;
    
    // Generate deep links based on event category and details
    switch (category) {
      case 'credential':
        return details?.credentialId ? `/console/operate/issuance/${details.credentialId}` : null;
      case 'flow':
        return details?.instanceId ? `/console/operate/flow-instances/${details.instanceId}` 
             : details?.flowId ? `/console/flows/definitions/${details.flowId}` 
             : null;
      case 'policy':
        return details?.policyId ? `/console/policies/presentation/${details.policyId}` : null;
      case 'template':
        return details?.templateId ? `/console/templates/credentials/${details.templateId}` : null;
      case 'authentication':
        return null; // No deep link for auth events
      case 'team':
        return '/console/org/team';
      default:
        return null;
    }
  };

  const getCategoryColor = (cat) => {
    switch (cat) {
      case 'authentication':
        return 'primary';
      case 'credential':
        return 'success';
      case 'flow':
        return 'secondary';
      case 'policy':
        return 'warning';
      case 'team':
        return 'info';
      default:
        return 'default';
    }
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  return (
    <ResourcePage
      title="Audit Log"
      description="Monitor and review all system activity and security events."
      breadcrumbs={BREADCRUMBS}
      actions={
        <Box sx={{ display: 'flex', gap: 1 }}>
          {savedViews.length > 0 && (
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Saved Views</InputLabel>
              <Select
                label="Saved Views"
                onChange={(e) => {
                  const view = savedViews.find(v => v.id === e.target.value);
                  if (view) applyView(view);
                }}
                displayEmpty
              >
                <MenuItem value="">Select view...</MenuItem>
                {savedViews.map((view) => (
                  <MenuItem key={view.id} value={view.id}>
                    {view.name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <Button
            variant="outlined"
            size="small"
            startIcon={<BookmarkIcon />}
            onClick={handleSaveView}
          >
            Save View
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<FilterListIcon />}
            onClick={() => setShowFilters(!showFilters)}
          >
            Filters
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<DownloadIcon />}
            onClick={handleExport}
            disabled={exporting}
          >
            {exporting ? 'Exporting...' : 'Export'}
          </Button>
          <IconButton size="small" onClick={loadEvents}>
            <RefreshIcon />
          </IconButton>
        </Box>
      }
    >
      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <TextField
          fullWidth
          placeholder="Search by action, actor, or resource..."
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

        {/* Advanced Filters */}
        <Collapse in={showFilters}>
          <Box sx={{ mt: 2, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <FormControl sx={{ minWidth: 150 }}>
              <InputLabel>Category</InputLabel>
              <Select
                value={category}
                label="Category"
                onChange={(e) => setCategory(e.target.value)}
              >
                {EVENT_CATEGORIES.map((cat) => (
                  <MenuItem key={cat.value} value={cat.value}>
                    {cat.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={severity}
                label="Severity"
                onChange={(e) => setSeverity(e.target.value)}
              >
                {SEVERITY_LEVELS.map((sev) => (
                  <MenuItem key={sev.value} value={sev.value}>
                    {sev.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              label="Actor (email)"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              size="small"
              sx={{ minWidth: 200 }}
            />

            <TextField
              label="IP Address"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              size="small"
              sx={{ minWidth: 150 }}
            />

            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <DatePicker
                label="Start Date"
                value={startDate}
                onChange={setStartDate}
                slotProps={{ textField: { size: 'small' } }}
              />
              <DatePicker
                label="End Date"
                value={endDate}
                onChange={setEndDate}
                slotProps={{ textField: { size: 'small' } }}
              />
            </LocalizationProvider>
          </Box>
        </Collapse>
      </Paper>

      {/* Events Table */}
      {loading ? (
        <TableSkeleton rows={rowsPerPage} columns={5} showActions={false} />
      ) : error ? (
        <ErrorState error={error} onRetry={loadEvents} variant="inline" />
      ) : events.length === 0 ? (
        <EmptyState
          icon={HistoryIcon}
          title="No audit events yet"
          description="Audit logs track security-relevant events in your organization. Events will appear as users interact with your system."
          whyItMatters="Audit logs help you monitor security, troubleshoot issues, and maintain compliance."
        />
      ) : (
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width={40} />
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell>Actor</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell>Severity</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      <Typography color="text.secondary" sx={{ py: 4 }}>
                        No audit events found matching your criteria.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((event) => (
                    <>
                      <TableRow 
                        key={event.id} 
                        hover
                        onClick={() => setExpandedRow(expandedRow === event.id ? null : event.id)}
                        sx={{ cursor: 'pointer' }}
                      >
                        <TableCell>
                          <IconButton size="small">
                            {expandedRow === event.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {new Date(event.timestamp).toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                            <Chip 
                              label={event.category} 
                              size="small" 
                              color={getCategoryColor(event.category)}
                              variant="outlined"
                            />
                            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                              {event.action}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>{event.actor}</TableCell>
                        <TableCell>
                          {
                            (() => {
                              const resourceLink = getResourceLink(event);
                              return resourceLink ? (
                                <Button
                                  component={Link}
                                  to={resourceLink}
                                  size="small"
                                  endIcon={<OpenInNewIcon fontSize="small" />}
                                  sx={{ 
                                    maxWidth: 200, 
                                    overflow: 'hidden', 
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                    textTransform: 'none',
                                    justifyContent: 'flex-start',
                                  }}
                                >
                                  {event.resource}
                                </Button>
                              ) : (
                                <Typography 
                                  variant="body2" 
                                  sx={{ 
                                    maxWidth: 200, 
                                    overflow: 'hidden', 
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {event.resource}
                                </Typography>
                              );
                            })()
                          }
                        </TableCell>
                        <TableCell>
                          <Chip 
                            icon={getSeverityIcon(event.severity)}
                            label={event.severity.charAt(0).toUpperCase() + event.severity.slice(1)} 
                            size="small" 
                            color={getSeverityColor(event.severity)}
                            variant="filled"
                          />
                        </TableCell>
                      </TableRow>
                      <TableRow key={`${event.id}-details`}>
                        <TableCell colSpan={6} sx={{ py: 0 }}>
                          <Collapse in={expandedRow === event.id}>
                            <Box sx={{ p: 2, bgcolor: 'action.hover' }}>
                              <Typography variant="subtitle2" gutterBottom>
                                Event Details
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 2 }}>
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
                                    IP Address
                                  </Typography>
                                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                    {event.ipAddress || 'N/A'}
                                  </Typography>
                                </Box>
                                <Box sx={{ gridColumn: '1 / -1' }}>
                                  <Typography variant="caption" color="text.secondary">
                                    Additional Data
                                  </Typography>
                                  <Typography 
                                    variant="body2" 
                                    component="pre"
                                    sx={{ 
                                      fontFamily: 'monospace', 
                                      fontSize: 12,
                                      bgcolor: 'background.paper',
                                      p: 1,
                                      borderRadius: 1,
                                      overflow: 'auto',
                                    }}
                                  >
                                    {JSON.stringify(event.details, null, 2)}
                                  </Typography>
                                </Box>
                              </Box>
                            </Box>
                          </Collapse>
                        </TableCell>
                      </TableRow>
                    </>
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
      )}
    </ResourcePage>
  );
}

export default AuditPage;
