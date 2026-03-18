import { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Grid,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Divider
} from '@mui/material';
import {
  ListAlt as ListIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  CheckCircle as ValidIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Upload as UploadIcon,
  Visibility as ViewIcon,
  Flag as FlagIcon
} from '@mui/icons-material';
import {
  formatMasterListDate,
  getMasterListCertificateStatus,
  getMasterListCountryStats,
  getMasterListSummary,
  loadMasterLists,
} from '../application/admin';

const MasterListViewer = () => {
  const [masterLists, setMasterLists] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedCert, setSelectedCert] = useState(null);
  const [certDialogOpen, setCertDialogOpen] = useState(false);
  const [tabValue, setTabValue] = useState(0);

  const fetchMasterLists = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await loadMasterLists();
      setMasterLists(result.masterLists);
      if (result.error) {
        setError(result.error);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMasterLists();
  }, []);

  const handleViewCert = (cert) => {
    setSelectedCert(cert);
    setCertDialogOpen(true);
  };
  const summary = getMasterListSummary(masterLists);

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            <ListIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
            Master List Viewer
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Browse ICAO PKD Master Lists and Certificates
          </Typography>
        </Box>
        <Box>
          <Button
            variant="outlined"
            startIcon={<UploadIcon />}
            sx={{ mr: 1 }}
          >
            Import ML
          </Button>
          <IconButton onClick={fetchMasterLists} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {error && (
        <Alert severity="info" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <FlagIcon color="primary" sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4">{summary.countryCount}</Typography>
                  <Typography color="text.secondary">Countries</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <SecurityIcon color="secondary" sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4">{summary.totalCertificates}</Typography>
                  <Typography color="text.secondary">Total Certificates</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <ValidIcon color="success" sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4">{summary.totalValid}</Typography>
                  <Typography color="text.secondary">Valid Certificates</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <WarningIcon color="warning" sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4">{summary.needsAttention}</Typography>
                  <Typography color="text.secondary">Needs Attention</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="By Country" />
          <Tab label="All Certificates" />
        </Tabs>
      </Paper>

      {loading ? (
        <Box display="flex" justifyContent="center" p={4}>
          <CircularProgress />
        </Box>
      ) : tabValue === 0 ? (
        /* Country-based view */
        <Box>
          {masterLists.map((ml) => {
            const stats = getMasterListCountryStats(ml);
            return (
              <Accordion key={ml.country} defaultExpanded={masterLists.length <= 3}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', mr: 2 }}>
                    <Typography variant="h6" sx={{ minWidth: 80 }}>{ml.country}</Typography>
                    <Chip 
                      label={`v${ml.version}`} 
                      size="small" 
                      sx={{ mr: 1 }} 
                    />
                    <Chip 
                      label={`Seq: ${ml.sequenceNumber}`} 
                      size="small" 
                      variant="outlined"
                      sx={{ mr: 2 }} 
                    />
                    <Box sx={{ flexGrow: 1 }} />
                    <Tooltip title="Valid">
                      <Chip icon={<ValidIcon />} label={stats.valid} color="success" size="small" sx={{ mr: 0.5 }} />
                    </Tooltip>
                    {stats.expiring > 0 && (
                      <Tooltip title="Expiring Soon">
                        <Chip icon={<WarningIcon />} label={stats.expiring} color="warning" size="small" sx={{ mr: 0.5 }} />
                      </Tooltip>
                    )}
                    {stats.expired > 0 && (
                      <Tooltip title="Expired">
                        <Chip icon={<ErrorIcon />} label={stats.expired} color="error" size="small" />
                      </Tooltip>
                    )}
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ mb: 2, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Issue Date</Typography>
                        <Typography>{formatMasterListDate(ml.issueDate)}</Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Next Update</Typography>
                        <Typography>{formatMasterListDate(ml.nextUpdate)}</Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Signer</Typography>
                        <Typography>{ml.signer}</Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Test Mode</Typography>
                        <Chip 
                          label={ml.metadata?.testingOnly ? 'Yes' : 'No'} 
                          size="small" 
                          color={ml.metadata?.testingOnly ? 'warning' : 'default'}
                        />
                      </Grid>
                    </Grid>
                  </Box>
                  
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Certificate ID</TableCell>
                          <TableCell>Subject</TableCell>
                          <TableCell>Valid From</TableCell>
                          <TableCell>Valid To</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell align="right">Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {ml.certificates.map((cert) => {
                          const status = getMasterListCertificateStatus(cert);
                          return (
                            <TableRow key={cert.certificateId}>
                              <TableCell>
                                <Typography variant="body2" fontFamily="monospace">
                                  {cert.certificateId}
                                </Typography>
                              </TableCell>
                              <TableCell>{cert.subject}</TableCell>
                              <TableCell>{formatMasterListDate(cert.validFrom)}</TableCell>
                              <TableCell>{formatMasterListDate(cert.validTo)}</TableCell>
                              <TableCell>
                                <Chip 
                                  label={status.label} 
                                  color={status.color} 
                                  size="small" 
                                />
                              </TableCell>
                              <TableCell align="right">
                                <IconButton size="small" onClick={() => handleViewCert(cert)}>
                                  <ViewIcon />
                                </IconButton>
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            );
          })}
        </Box>
      ) : (
        /* All certificates view */
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Country</TableCell>
                  <TableCell>Certificate ID</TableCell>
                  <TableCell>Subject</TableCell>
                  <TableCell>Thumbprint</TableCell>
                  <TableCell>Valid From</TableCell>
                  <TableCell>Valid To</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {masterLists.flatMap((ml) =>
                  ml.certificates.map((cert) => {
                    const status = getMasterListCertificateStatus(cert);
                    return (
                      <TableRow key={`${ml.country}-${cert.certificateId}`}>
                        <TableCell>
                          <Chip label={ml.country} size="small" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {cert.certificateId}
                          </Typography>
                        </TableCell>
                        <TableCell>{cert.subject}</TableCell>
                        <TableCell>
                          <Tooltip title={cert.thumbprint}>
                            <Typography variant="body2" fontFamily="monospace" sx={{ maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {cert.thumbprint.substring(0, 12)}...
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>{formatMasterListDate(cert.validFrom)}</TableCell>
                        <TableCell>{formatMasterListDate(cert.validTo)}</TableCell>
                        <TableCell>
                          <Chip label={status.label} color={status.color} size="small" />
                        </TableCell>
                        <TableCell align="right">
                          <IconButton size="small" onClick={() => handleViewCert(cert)}>
                            <ViewIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Certificate Details Dialog */}
      <Dialog open={certDialogOpen} onClose={() => setCertDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center">
            <SecurityIcon sx={{ mr: 1 }} />
            Certificate Details
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedCert && (
            <Box>
              <Divider sx={{ my: 2 }} />
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Certificate ID</Typography>
                  <Typography fontFamily="monospace">{selectedCert.certificateId}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Subject</Typography>
                  <Typography>{selectedCert.subject}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Thumbprint (SHA-1)</Typography>
                  <Typography fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
                    {selectedCert.thumbprint}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Valid From</Typography>
                  <Typography>{formatMasterListDate(selectedCert.validFrom)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Valid To</Typography>
                  <Typography>{formatMasterListDate(selectedCert.validTo)}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Status</Typography>
                  <Box sx={{ mt: 0.5 }}>
                    <Chip 
                      label={getMasterListCertificateStatus(selectedCert).label} 
                      color={getMasterListCertificateStatus(selectedCert).color} 
                    />
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCertDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default MasterListViewer;
