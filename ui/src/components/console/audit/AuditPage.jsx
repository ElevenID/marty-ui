/**
 * Audit Page
 * 
 * Audit logs and activity monitoring.
 */

import { Fragment, useState, useEffect } from 'react';
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
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import HistoryIcon from '@mui/icons-material/History';
import auditApi from '../../../services/auditApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';

function AuditPage() {
  const { t } = useTranslation('console');
  
  const getBreadcrumbs = () => [
    { label: t('audit.breadcrumbs.console'), path: '/console' },
    { label: t('audit.breadcrumbs.audit'), path: '/console/audit' },
  ];

  const getEventCategories = () => [
    { value: 'all', label: t('audit.categories.all') },
    { value: 'authentication', label: t('audit.categories.authentication') },
    { value: 'credential', label: t('audit.categories.credential') },
    { value: 'flow', label: t('audit.categories.flow') },
    { value: 'policy', label: t('audit.categories.policy') },
    { value: 'template', label: t('audit.categories.template') },
    { value: 'team', label: t('audit.categories.team') },
    { value: 'settings', label: t('audit.categories.settings') },
  ];

  const getSeverityLevels = () => [
    { value: 'all', label: t('audit.severity.all') },
    { value: 'info', label: t('audit.severity.info') },
    { value: 'warning', label: t('audit.severity.warning') },
    { value: 'error', label: t('audit.severity.error') },
  ];

  const EVENT_CATEGORIES = getEventCategories();
  const SEVERITY_LEVELS = getSeverityLevels();
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrgId = activeOrgId || organizationId;

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
  }, [effectiveOrgId, page, rowsPerPage, category, severity, actor, resourceType, ipAddress, searchQuery, startDate, endDate]);

  useEffect(() => {
    loadSavedViews();
  }, [effectiveOrgId]);

  const requireOrgId = () => {
    if (!effectiveOrgId) {
      throw new Error('Organization context unavailable');
    }

    return effectiveOrgId;
  };

  const loadEvents = async () => {
    if (!effectiveOrgId) {
      setEvents([]);
      setTotalCount(0);
      setLoading(false);
      setError(null);
      return;
    }

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
      if (searchQuery) filters.search = searchQuery;
      if (startDate) filters.start_date = startDate.toISOString();
      if (endDate) filters.end_date = endDate.toISOString();

      const data = await auditApi.listAuditEvents(requireOrgId(), filters);
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
    if (!effectiveOrgId) {
      setSavedViews([]);
      return;
    }

    try {
      const views = await auditApi.listFilterViews(requireOrgId());
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
        search: searchQuery || undefined,
        ip_address: ipAddress,
        start_date: startDate?.toISOString(),
        end_date: endDate?.toISOString(),
      };
      
      const result = await auditApi.exportAuditEvents(requireOrgId(), filters, 'csv');
      
      // If backend returns download URL, open it
      if (result.download_url) {
        window.open(result.download_url, '_blank');
        showNotification?.(t('audit.exportSuccess'), 'success');
      } else {
        showNotification?.(t('audit.messages.exportJobCreated'), 'info');
      }
    } catch (err) {
      console.error('Failed to export audit logs:', err);
      showNotification?.(t('audit.messages.exportFailed'), 'error');
    } finally {
      setExporting(false);
    }
  };

  const handleSaveView = async () => {
    const viewName = prompt(t('audit.messages.enterFilterViewName'));
    if (!viewName) return;

    try {
      await auditApi.saveFilterView(requireOrgId(), {
        name: viewName,
        filters: {
          category,
          severity,
          actor,
          searchQuery,
          resourceType,
          ipAddress,
          startDate: startDate?.toISOString(),
          endDate: endDate?.toISOString(),
        },
      });
      showNotification?.(t('audit.messages.filterViewSaved'), 'success');
      loadSavedViews();
    } catch (err) {
      console.error('Failed to save view:', err);
      showNotification?.(t('audit.messages.saveFilterViewFailed'), 'error');
    }
  };

  const applyView = (view) => {
    const filters = view.filters;
    setCategory(filters.category || 'all');
    setSeverity(filters.severity || 'all');
    setActor(filters.actor || '');
    setSearchQuery(filters.searchQuery || filters.search || '');
    setResourceType(filters.resourceType || '');
    setIpAddress(filters.ipAddress || '');
    setStartDate(filters.startDate ? new Date(filters.startDate) : null);
    setEndDate(filters.endDate ? new Date(filters.endDate) : null);
    showNotification?.(t('audit.messages.appliedView', { name: view.name }), 'info');
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
      title={t('audit.title')}
      description={t('audit.description')}
      breadcrumbs={getBreadcrumbs()}
      actions={
        <Box sx={{ display: 'flex', gap: 1 }}>
          {savedViews.length > 0 && (
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>{t('audit.filters.savedViews')}</InputLabel>
              <Select
                defaultValue=""
                label={t('audit.filters.savedViews')}
                onChange={(e) => {
                  const view = savedViews.find(v => v.id === e.target.value);
                  if (view) applyView(view);
                }}
                displayEmpty
              >
                <MenuItem value="">{t('audit.filters.selectView')}</MenuItem>
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
            {t('audit.actions.saveView')}
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<FilterListIcon />}
            onClick={() => setShowFilters(!showFilters)}
          >
            {showFilters ? t('audit.hideFilters') : t('audit.showFilters')}
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<DownloadIcon />}
            onClick={handleExport}
            disabled={exporting}
          >
            {exporting ? t('audit.exporting') : t('audit.export')}
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
          placeholder={t('audit.searchPlaceholder')}
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
              <InputLabel>{t('audit.filters.category')}</InputLabel>
              <Select
                value={category}
                label={t('audit.filters.category')}
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
              <InputLabel>{t('audit.filters.severity')}</InputLabel>
              <Select
                value={severity}
                label={t('audit.filters.severity')}
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
              label={t('audit.filters.actor')}
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              size="small"
              sx={{ minWidth: 200 }}
            />

            <TextField
              label={t('audit.filters.ipAddress')}
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              size="small"
              sx={{ minWidth: 150 }}
            />

            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <DatePicker
                label={t('audit.filters.startDate')}
                value={startDate}
                onChange={setStartDate}
                slotProps={{ textField: { size: 'small' } }}
              />
              <DatePicker
                label={t('audit.filters.endDate')}
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
          title={t('audit.empty.title')}
          description={t('audit.empty.description')}
          whyItMatters={t('audit.empty.whyItMatters')}
        />
      ) : (
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width={40} />
                  <TableCell>{t('audit.tableHeaders.timestamp')}</TableCell>
                  <TableCell>{t('audit.tableHeaders.event')}</TableCell>
                  <TableCell>{t('audit.tableHeaders.actor')}</TableCell>
                  <TableCell>{t('audit.tableHeaders.resource')}</TableCell>
                  <TableCell>{t('audit.tableHeaders.status')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      <Typography color="text.secondary" sx={{ py: 4 }}>
                        {t('audit.empty.noMatching')}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((event) => (
                    <Fragment key={event.id}>
                      <TableRow 
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
                      <TableRow>
                        <TableCell colSpan={6} sx={{ py: 0 }}>
                          <Collapse in={expandedRow === event.id}>
                            <Box sx={{ p: 2, bgcolor: 'action.hover' }}>
                              <Typography variant="subtitle2" gutterBottom>
                                {t('audit.details.title')}
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 2 }}>
                                <Box>
                                  <Typography variant="caption" color="text.secondary">
                                    {t('audit.details.eventId')}
                                  </Typography>
                                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                    {event.id}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="caption" color="text.secondary">
                                    {t('audit.details.ipAddress')}
                                  </Typography>
                                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                    {event.ipAddress || t('audit.details.notAvailable')}
                                  </Typography>
                                </Box>
                                <Box sx={{ gridColumn: '1 / -1' }}>
                                  <Typography variant="caption" color="text.secondary">
                                    {t('audit.details.additionalData')}
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
                    </Fragment>
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
