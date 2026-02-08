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
  Alert,
  LinearProgress,
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
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';

import { ResourcePage } from '../../common';
import { Link } from 'react-router-dom';

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
  
  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [startDate, setStartDate] = useState(null);
  const [endDate, setEndDate] = useState(null);

  useEffect(() => {
    loadEvents();
  }, [page, rowsPerPage, category, severity, startDate, endDate]);

  const loadEvents = async () => {
    setLoading(true);
    try {
      // TODO: Fetch from API with filters
      await new Promise((resolve) => setTimeout(resolve, 500));
      setEvents([
        {
          id: 'evt-1',
          timestamp: '2026-02-07T09:45:23Z',
          category: 'credential',
          action: 'credential.issued',
          actor: 'john@example.com',
          resource: 'Driver License - DL-2026-00456',
          severity: 'info',
          ipAddress: '192.168.1.105',
          details: { templateId: 'tmpl-dl-1', flowId: 'flow-123' },
        },
        {
          id: 'evt-2',
          timestamp: '2026-02-07T09:30:15Z',
          category: 'authentication',
          action: 'login.success',
          actor: 'jane@example.com',
          resource: 'Console',
          severity: 'info',
          ipAddress: '10.0.0.50',
          details: { mfaUsed: true },
        },
        {
          id: 'evt-3',
          timestamp: '2026-02-07T09:15:10Z',
          category: 'policy',
          action: 'policy.updated',
          actor: 'john@example.com',
          resource: 'Age Verification Policy',
          severity: 'info',
          ipAddress: '192.168.1.105',
          details: { changes: ['minAge: 18 -> 21'] },
        },
        {
          id: 'evt-4',
          timestamp: '2026-02-07T08:55:00Z',
          category: 'authentication',
          action: 'login.failed',
          actor: 'unknown@attacker.com',
          resource: 'Console',
          severity: 'warning',
          ipAddress: '203.0.113.42',
          details: { reason: 'Invalid credentials', attempts: 3 },
        },
        {
          id: 'evt-5',
          timestamp: '2026-02-07T08:30:00Z',
          category: 'flow',
          action: 'flow.failed',
          actor: 'system',
          resource: 'Age Verification Flow',
          severity: 'error',
          ipAddress: null,
          details: { error: 'Timeout waiting for wallet response', instanceId: 'fi-789' },
        },
        {
          id: 'evt-6',
          timestamp: '2026-02-07T08:00:00Z',
          category: 'team',
          action: 'user.invited',
          actor: 'john@example.com',
          resource: 'bob@example.com',
          severity: 'info',
          ipAddress: '192.168.1.105',
          details: { role: 'developer' },
        },
        {
          id: 'evt-7',
          timestamp: '2026-02-06T17:45:00Z',
          category: 'credential',
          action: 'credential.revoked',
          actor: 'jane@example.com',
          resource: 'Employee Badge - EB-2025-00123',
          severity: 'warning',
          ipAddress: '10.0.0.50',
          details: { reason: 'Employee termination' },
        },
      ]);
      setTotalCount(150);
    } catch (err) {
      setError('Failed to load audit events');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    // TODO: Export audit logs as CSV
    console.log('Exporting audit logs...');
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
          <Button
            variant="outlined"
            startIcon={<FilterListIcon />}
            onClick={() => setShowFilters(!showFilters)}
          >
            Filters
          </Button>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleExport}
          >
            Export
          </Button>
          <IconButton onClick={loadEvents}>
            <RefreshIcon />
          </IconButton>
        </Box>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Search */}
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
        <LinearProgress />
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
