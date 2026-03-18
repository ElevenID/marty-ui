import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Alert,
  Snackbar,
  CircularProgress,
  Tabs,
  Tab,
  Divider,
  Tooltip,
} from '@mui/material';
import {
  Add as AddIcon,
  Visibility as ViewIcon,
  Block as SuspendIcon,
  Delete as DeleteIcon,
  History as AuditIcon,
  Refresh as RefreshIcon,
  FlightTakeoff as PassportIcon,
  Badge as IdIcon,
  DriveEta as LicenseIcon,
  Description as VisaIcon,
} from '@mui/icons-material';
import {
  TRAVEL_DOCUMENTS_DEFAULT_STATS,
  canSubmitTravelDocumentIssue,
  createTravelDocumentIssueForm,
  formatTravelDocumentDate,
  formatTravelDocumentDateTime,
  issueTravelDocument,
  loadApprovedTravelDocumentApplicants,
  loadTravelDocumentAudit,
  loadTravelDocumentsDashboard,
  prefillTravelDocumentIssueForm,
  updateTravelDocumentStatus as updateTravelDocumentStatusAction,
  deleteTravelDocument as deleteTravelDocumentAction,
} from '../application/documents';
import { useBranding } from '../hooks/useBranding';

// Document types from the backend
const DOCUMENT_TYPES = [
  { value: 'eMRTD', label: 'eMRTD (ePassport)', description: 'Electronic Machine Readable Travel Document per ICAO Doc 9303', icon: PassportIcon },
  { value: 'DTC', label: 'Digital Travel Credential', description: 'Digital Travel Credential per ICAO DTC Specification', icon: PassportIcon },
  { value: 'mDL', label: 'Mobile Driving License', description: 'Mobile Driving License per ISO/IEC 18013-5', icon: LicenseIcon },
  { value: 'National ID', label: 'National ID', description: 'National Identity Document', icon: IdIcon },
  { value: 'Visa', label: 'Visa', description: 'Travel Visa Document', icon: VisaIcon },
  { value: 'Residence Permit', label: 'Residence Permit', description: 'Residence Permit Document', icon: IdIcon },
];

const STATUS_COLORS = {
  active: 'success',
  suspended: 'warning',
  revoked: 'error',
  expired: 'default',
  draft: 'info',
};

export default function TravelDocuments() {
  const [tabValue, setTabValue] = useState(0);
  const [documents, setDocuments] = useState([]);
  const [stats, setStats] = useState(TRAVEL_DOCUMENTS_DEFAULT_STATS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [total, setTotal] = useState(0);
  
  // Filter state
  const [filterType, setFilterType] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  
  // Dialog states
  const [issueDialogOpen, setIssueDialogOpen] = useState(false);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [statusDialogOpen, setStatusDialogOpen] = useState(false);
  const [auditDialogOpen, setAuditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  
  // Selected document
  const [selectedDocument, setSelectedDocument] = useState(null);
  const [auditEntries, setAuditEntries] = useState([]);
  
  // Approved applicants for issuance
  const [approvedApplicants, setApprovedApplicants] = useState([]);
  const [loadingApplicants, setLoadingApplicants] = useState(false);
  const branding = useBranding();
  const [selectedApplicant, setSelectedApplicant] = useState(null);
  const [issueMode, setIssueMode] = useState('applicant'); // 'applicant' or 'manual'
  
  // Form state for issuing
  const [issueForm, setIssueForm] = useState(() => createTravelDocumentIssueForm({
    issuingAuthority: branding.issuingAuthority,
  }));
  
  // Status change form
  const [statusForm, setStatusForm] = useState({
    status: '',
    reason: '',
  });
  
  // Delete form
  const [deleteReason, setDeleteReason] = useState('');

  const resetIssueForm = useCallback((documentType = 'eMRTD') => {
    setIssueForm({
      ...createTravelDocumentIssueForm({ issuingAuthority: branding.issuingAuthority }),
      document_type: documentType,
    });
  }, [branding.issuingAuthority]);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    try {
      const result = await loadTravelDocumentsDashboard({
        filters: {
          document_type: filterType || undefined,
          status: filterStatus || undefined,
          limit: rowsPerPage,
          offset: page * rowsPerPage,
        },
      });

      setDocuments(result.documents);
      setTotal(result.total);
      setStats(result.stats);

      if (result.statsError) {
        console.error('Failed to load stats:', result.statsError);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage, filterType, filterStatus]);

  // Load documents on mount and when filters change
  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  // Load approved applicants when issue dialog opens
  const loadApprovedApplicants = useCallback(async (documentType = null) => {
    setLoadingApplicants(true);
    try {
      const applicants = await loadApprovedTravelDocumentApplicants({ documentType });
      setApprovedApplicants(applicants);
    } catch (err) {
      console.error('Failed to load approved applicants:', err);
      setApprovedApplicants([]);
    } finally {
      setLoadingApplicants(false);
    }
  }, []);

  // Handle opening issue dialog
  const handleOpenIssueDialog = useCallback((documentType = null) => {
    setIssueDialogOpen(true);
    setSelectedApplicant(null);
    setIssueMode('applicant');
    resetIssueForm(documentType || 'eMRTD');
    loadApprovedApplicants(documentType);
  }, [loadApprovedApplicants, resetIssueForm]);

  // Handle applicant selection
  const handleApplicantSelect = (applicant) => {
    setSelectedApplicant(applicant);
    // Pre-fill form from applicant data
    if (applicant) {
      setIssueForm((prev) => prefillTravelDocumentIssueForm(prev, applicant));
    }
  };

  const handleIssueDocument = async () => {
    setLoading(true);
    try {
      const result = await issueTravelDocument({
        issueMode,
        selectedApplicant,
        issueForm,
      });

      setSuccess(result.successMessage);
      setIssueDialogOpen(false);
      resetIssueForm();
      setSelectedApplicant(null);
      loadDashboard();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async () => {
    if (!selectedDocument || !statusForm.status || !statusForm.reason) return;
    
    setLoading(true);
    try {
      const result = await updateTravelDocumentStatusAction({
        documentId: selectedDocument.id,
        status: statusForm.status,
        reason: statusForm.reason,
      });

      setSuccess(result.successMessage);
      setStatusDialogOpen(false);
      setStatusForm({ status: '', reason: '' });
      loadDashboard();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!selectedDocument || !deleteReason) return;
    
    setLoading(true);
    try {
      const result = await deleteTravelDocumentAction({
        documentId: selectedDocument.id,
        reason: deleteReason,
      });

      setSuccess(result.successMessage);
      setDeleteDialogOpen(false);
      setDeleteReason('');
      loadDashboard();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleViewAudit = async (document) => {
    setSelectedDocument(document);
    try {
      const result = await loadTravelDocumentAudit({ documentId: document.id });
      setAuditEntries(result.entries);
      setAuditDialogOpen(true);
    } catch (err) {
      setError(err.message);
    }
  };

  const getDocumentTypeIcon = (type) => {
    const docType = DOCUMENT_TYPES.find(dt => dt.value === type);
    if (docType) {
      const IconComponent = docType.icon;
      return <IconComponent />;
    }
    return <PassportIcon />;
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Travel Documents
        </Typography>
        <Box>
          <IconButton onClick={loadDashboard} disabled={loading}>
            <RefreshIcon />
          </IconButton>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleOpenIssueDialog}
            data-testid="issue-document-button"
          >
            Issue Document
          </Button>
        </Box>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Total Documents</Typography>
              <Typography variant="h4">{stats?.total_documents || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Active</Typography>
              <Typography variant="h4" color="success.main">
                {stats?.by_status?.active || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Issued Today</Typography>
              <Typography variant="h4">{stats?.issued_today || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Expiring Soon</Typography>
              <Typography variant="h4" color="warning.main">
                {stats?.expiring_soon || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)} sx={{ mb: 2 }}>
        <Tab label="All Documents" />
        <Tab label="Document Types" />
      </Tabs>

      {/* Tab Panel: All Documents */}
      {tabValue === 0 && (
        <Paper sx={{ p: 2 }}>
          {/* Filters */}
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Document Type</InputLabel>
              <Select
                value={filterType}
                label="Document Type"
                onChange={(e) => setFilterType(e.target.value)}
              >
                <MenuItem value="">All</MenuItem>
                {DOCUMENT_TYPES.map(dt => (
                  <MenuItem key={dt.value} value={dt.value}>{dt.label}</MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={filterStatus}
                label="Status"
                onChange={(e) => setFilterStatus(e.target.value)}
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="suspended">Suspended</MenuItem>
                <MenuItem value="revoked">Revoked</MenuItem>
                <MenuItem value="expired">Expired</MenuItem>
              </Select>
            </FormControl>
          </Box>

          {/* Documents Table */}
          <TableContainer data-testid="documents-table">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Document #</TableCell>
                  <TableCell>Holder</TableCell>
                  <TableCell>Nationality</TableCell>
                  <TableCell>Issued</TableCell>
                  <TableCell>Expires</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : documents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      No documents found. Issue your first document to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  documents.map((doc) => (
                    <TableRow key={doc.id} data-testid={`document-row-${doc.id}`}>
                      <TableCell>
                        <Tooltip title={doc.document_type}>
                          {getDocumentTypeIcon(doc.document_type)}
                        </Tooltip>
                      </TableCell>
                      <TableCell>{doc.document_number}</TableCell>
                      <TableCell>{doc.holder_name}</TableCell>
                      <TableCell>{doc.nationality}</TableCell>
                      <TableCell>{formatTravelDocumentDate(doc.issued_at)}</TableCell>
                      <TableCell>{formatTravelDocumentDate(doc.expires_at)}</TableCell>
                      <TableCell>
                        <Chip
                          label={doc.status}
                          color={STATUS_COLORS[doc.status] || 'default'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => {
                              setSelectedDocument(doc);
                              setViewDialogOpen(true);
                            }}
                          >
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="View Audit Log">
                          <IconButton
                            size="small"
                            onClick={() => handleViewAudit(doc)}
                          >
                            <AuditIcon />
                          </IconButton>
                        </Tooltip>
                        {doc.status === 'active' && (
                          <Tooltip title="Suspend">
                            <IconButton
                              size="small"
                              onClick={() => {
                                setSelectedDocument(doc);
                                setStatusForm({ status: 'suspended', reason: '' });
                                setStatusDialogOpen(true);
                              }}
                            >
                              <SuspendIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => {
                              setSelectedDocument(doc);
                              setDeleteDialogOpen(true);
                            }}
                          >
                            <DeleteIcon />
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
            count={total}
            page={page}
            onPageChange={(e, newPage) => setPage(newPage)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
          />
        </Paper>
      )}

      {/* Tab Panel: Document Types */}
      {tabValue === 1 && (
        <Grid container spacing={2}>
          {DOCUMENT_TYPES.map((docType) => {
            const IconComponent = docType.icon;
            const count = stats?.by_type?.[docType.value] || 0;
            return (
              <Grid item xs={12} sm={6} md={4} key={docType.value}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                      <IconComponent sx={{ fontSize: 40, color: 'primary.main' }} />
                      <Box>
                        <Typography variant="h6">{docType.label}</Typography>
                        <Typography variant="h4">{count}</Typography>
                      </Box>
                    </Box>
                    <Typography variant="body2" color="textSecondary">
                      {docType.description}
                    </Typography>
                  </CardContent>
                  <CardActions>
                    <Button
                      size="small"
                      onClick={() => {
                        handleOpenIssueDialog(docType.value);
                      }}
                    >
                      Issue New
                    </Button>
                    <Button
                      size="small"
                      onClick={() => {
                        setFilterType(docType.value);
                        setTabValue(0);
                      }}
                    >
                      View All
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Issue Document Dialog */}
      <Dialog
        open={issueDialogOpen}
        onClose={() => setIssueDialogOpen(false)}
        maxWidth="md"
        fullWidth
        data-testid="issue-document-dialog"
      >
        <DialogTitle>Issue Travel Document</DialogTitle>
        <DialogContent>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
            <Tabs value={issueMode === 'applicant' ? 0 : 1} onChange={(e, v) => setIssueMode(v === 0 ? 'applicant' : 'manual')}>
              <Tab label="From Approved Applicant" data-testid="issue-tab-applicant" />
              <Tab label="Manual Entry (Demo)" data-testid="issue-tab-manual" />
            </Tabs>
          </Box>
          
          {issueMode === 'applicant' ? (
            /* Applicant Selection Mode */
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Select an approved applicant to issue their travel document. Only applicants who have completed all vetting requirements are shown.
                </Alert>
              </Grid>
              
              {loadingApplicants ? (
                <Grid item xs={12} sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                  <CircularProgress />
                </Grid>
              ) : approvedApplicants.length === 0 ? (
                <Grid item xs={12}>
                  <Alert severity="warning">
                    No approved applicants available. Applicants must complete KYC verification and biometric enrollment before document issuance.
                  </Alert>
                </Grid>
              ) : (
                <>
                  <Grid item xs={12}>
                    <FormControl fullWidth data-testid="approved-applicant-select">
                      <InputLabel>Select Approved Applicant</InputLabel>
                      <Select
                        value={selectedApplicant?.application_id || ''}
                        label="Select Approved Applicant"
                        onChange={(e) => {
                          const applicant = approvedApplicants.find(
                            a => a.application_id === e.target.value
                          );
                          handleApplicantSelect(applicant);
                        }}
                      >
                        {approvedApplicants.map(app => (
                          <MenuItem key={app.application_id} value={app.application_id}>
                            {app.applicant_name} - {app.credential_display_name || app.document_type} ({new Date(app.approved_at).toLocaleDateString()})
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  
                  {selectedApplicant && (
                    <>
                      <Grid item xs={12}>
                        <Divider sx={{ my: 1 }} />
                        <Typography variant="subtitle1" sx={{ mb: 1 }}>Applicant Details</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Name</Typography>
                        <Typography>{selectedApplicant.applicant_name}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Document Type</Typography>
                        <Typography>{selectedApplicant.credential_display_name || selectedApplicant.document_type}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Date of Birth</Typography>
                        <Typography>{selectedApplicant.applicant_dob || 'N/A'}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Nationality</Typography>
                        <Typography>{selectedApplicant.applicant_nationality || 'N/A'}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Vetting Level</Typography>
                        <Chip label={selectedApplicant.ial_level || 'IAL2'} color="success" size="small" />
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Approved</Typography>
                        <Typography>{new Date(selectedApplicant.approved_at).toLocaleString()}</Typography>
                      </Grid>
                      
                      <Grid item xs={12}>
                        <Divider sx={{ my: 1 }} />
                        <Typography variant="subtitle1" sx={{ mb: 1 }}>Document Options</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <TextField
                          fullWidth
                          label="Document Number (Optional)"
                          value={issueForm.document_number}
                          onChange={(e) => setIssueForm({ ...issueForm, document_number: e.target.value })}
                          placeholder="Auto-generated if empty"
                          helperText="Leave blank for auto-generation"
                          data-testid="issue-document-number"
                        />
                      </Grid>
                      <Grid item xs={6}>
                        <TextField
                          fullWidth
                          label="Validity (Years)"
                          type="number"
                          value={issueForm.validity_years}
                          onChange={(e) => setIssueForm({ ...issueForm, validity_years: parseInt(e.target.value) })}
                          inputProps={{ min: 1, max: 20 }}
                          data-testid="issue-validity-years"
                        />
                      </Grid>
                      <Grid item xs={12}>
                        <TextField
                          fullWidth
                          label="Issuing Authority"
                          value={issueForm.issuing_authority}
                          onChange={(e) => setIssueForm({ ...issueForm, issuing_authority: e.target.value })}
                          data-testid="issue-issuing-authority"
                        />
                      </Grid>
                    </>
                  )}
                </>
              )}
            </Grid>
          ) : (
            /* Manual Entry Mode (for demo/testing) */
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Alert severity="warning" sx={{ mb: 2 }}>
                  Manual entry bypasses applicant vetting. Use only for testing or demonstration purposes.
                </Alert>
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Document Type</InputLabel>
                  <Select
                    value={issueForm.document_type}
                    label="Document Type"
                    onChange={(e) => setIssueForm({ ...issueForm, document_type: e.target.value })}
                  >
                    {DOCUMENT_TYPES.map(dt => (
                      <MenuItem key={dt.value} value={dt.value}>{dt.label}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Document Number"
                  value={issueForm.document_number}
                  onChange={(e) => setIssueForm({ ...issueForm, document_number: e.target.value })}
                  placeholder="e.g., P1234567"
                  required
                  data-testid="manual-document-number"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Full Name"
                  value={issueForm.holder_name}
                  onChange={(e) => setIssueForm({ ...issueForm, holder_name: e.target.value })}
                  required
                  data-testid="manual-holder-name"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Given Name"
                  value={issueForm.holder_given_name}
                  onChange={(e) => setIssueForm({ ...issueForm, holder_given_name: e.target.value })}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Family Name"
                  value={issueForm.holder_family_name}
                  onChange={(e) => setIssueForm({ ...issueForm, holder_family_name: e.target.value })}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Date of Birth"
                  type="date"
                  value={issueForm.holder_dob}
                  onChange={(e) => setIssueForm({ ...issueForm, holder_dob: e.target.value })}
                  InputLabelProps={{ shrink: true }}
                  required
                  data-testid="manual-holder-dob"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Nationality (ISO 3166-1 alpha-3)"
                  value={issueForm.nationality}
                  onChange={(e) => setIssueForm({ ...issueForm, nationality: e.target.value.toUpperCase() })}
                  inputProps={{ maxLength: 3 }}
                  required
                  data-testid="manual-nationality"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Issuing Country (ISO 3166-1 alpha-3)"
                  value={issueForm.issuing_country}
                  onChange={(e) => setIssueForm({ ...issueForm, issuing_country: e.target.value.toUpperCase() })}
                  inputProps={{ maxLength: 3 }}
                  required
                  data-testid="manual-issuing-country"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Issuing Authority"
                  value={issueForm.issuing_authority}
                  onChange={(e) => setIssueForm({ ...issueForm, issuing_authority: e.target.value })}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Validity (Years)"
                  type="number"
                  value={issueForm.validity_years}
                  onChange={(e) => setIssueForm({ ...issueForm, validity_years: parseInt(e.target.value) })}
                  inputProps={{ min: 1, max: 20 }}
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIssueDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleIssueDocument}
            disabled={!canSubmitTravelDocumentIssue({
              loading,
              issueMode,
              selectedApplicant,
              issueForm,
            })}
            data-testid="confirm-issue-document"
          >
            {loading ? <CircularProgress size={24} /> : 'Issue Document'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* View Document Dialog */}
      <Dialog open={viewDialogOpen} onClose={() => setViewDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Document Details</DialogTitle>
        <DialogContent>
          {selectedDocument && (
            <Box sx={{ mt: 1 }}>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Document Type</Typography>
                  <Typography>{selectedDocument.document_type}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Document Number</Typography>
                  <Typography>{selectedDocument.document_number}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Divider sx={{ my: 1 }} />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Holder Name</Typography>
                  <Typography>{selectedDocument.holder_name}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Date of Birth</Typography>
                  <Typography>{formatTravelDocumentDate(selectedDocument.holder_dob)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Nationality</Typography>
                  <Typography>{selectedDocument.nationality}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Status</Typography>
                  <Chip
                    label={selectedDocument.status}
                    color={STATUS_COLORS[selectedDocument.status] || 'default'}
                    size="small"
                  />
                </Grid>
                <Grid item xs={12}>
                  <Divider sx={{ my: 1 }} />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Issued</Typography>
                  <Typography>{formatTravelDocumentDateTime(selectedDocument.issued_at)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Expires</Typography>
                  <Typography>{formatTravelDocumentDateTime(selectedDocument.expires_at)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Issuing Country</Typography>
                  <Typography>{selectedDocument.issuing_country}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="textSecondary">Issuing Authority</Typography>
                  <Typography>{selectedDocument.issuing_authority || 'N/A'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="textSecondary">Document ID</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{selectedDocument.id}</Typography>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleViewAudit(selectedDocument)}>View Audit Log</Button>
          <Button onClick={() => setViewDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Status Change Dialog */}
      <Dialog open={statusDialogOpen} onClose={() => setStatusDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Update Document Status</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 1 }}>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Changing status for document: {selectedDocument?.document_number}
            </Typography>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>New Status</InputLabel>
              <Select
                value={statusForm.status}
                label="New Status"
                onChange={(e) => setStatusForm({ ...statusForm, status: e.target.value })}
              >
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="suspended">Suspended</MenuItem>
                <MenuItem value="revoked">Revoked</MenuItem>
              </Select>
            </FormControl>
            <TextField
              fullWidth
              label="Reason for Status Change"
              multiline
              rows={3}
              value={statusForm.reason}
              onChange={(e) => setStatusForm({ ...statusForm, reason: e.target.value })}
              required
              helperText="Required for audit trail"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setStatusDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleStatusChange}
            disabled={loading || !statusForm.status || !statusForm.reason}
          >
            {loading ? <CircularProgress size={24} /> : 'Update Status'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Audit Log Dialog */}
      <Dialog open={auditDialogOpen} onClose={() => setAuditDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Audit Log - {selectedDocument?.document_number}
        </DialogTitle>
        <DialogContent>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Event</TableCell>
                  <TableCell>Actor</TableCell>
                  <TableCell>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {auditEntries.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} align="center">No audit entries found</TableCell>
                  </TableRow>
                ) : (
                  auditEntries.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell>{formatTravelDocumentDateTime(entry.timestamp)}</TableCell>
                      <TableCell>
                        <Chip label={entry.event_type} size="small" />
                      </TableCell>
                      <TableCell>{entry.actor_id} ({entry.actor_type})</TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {JSON.stringify(entry.details)}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAuditDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Document</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Are you sure you want to delete document {selectedDocument?.document_number}?
            This action cannot be undone.
          </Typography>
          <TextField
            fullWidth
            label="Reason for Deletion"
            multiline
            rows={2}
            value={deleteReason}
            onChange={(e) => setDeleteReason(e.target.value)}
            required
            helperText="Required for audit trail"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleDelete}
            disabled={loading || !deleteReason}
          >
            {loading ? <CircularProgress size={24} /> : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbars */}
      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert severity="error" onClose={() => setError(null)}>{error}</Alert>
      </Snackbar>
      <Snackbar
        open={!!success}
        autoHideDuration={4000}
        onClose={() => setSuccess(null)}
        data-testid="documents-success-snackbar"
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>{success}</Alert>
      </Snackbar>
    </Box>
  );
}
