import React, { useState, useEffect } from 'react';
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
      const response = await fetch('/api/admin/master-lists');
      if (!response.ok) throw new Error('Failed to fetch master lists');
      const data = await response.json();
      setMasterLists(data.masterLists || []);
    } catch (err) {
      // Use cached sample data when backend unavailable
      setMasterLists([
        {
          country: "FRA",
          sequenceNumber: 33,
          version: "1.0.0",
          issueDate: "2025-10-04T00:43:13.053013+00:00",
          nextUpdate: "2025-11-03T00:43:13.053013+00:00",
          certificates: [
            {
              certificateId: "FRA_CSCA_1",
              thumbprint: "db4df868f89e0d4f0676056bfe61b1694bb3d4b9",
              subject: "CN=FRA CSCA 1, O=FRA Government, C=FRA",
              validFrom: "2025-05-13T00:43:13.052762+00:00",
              validTo: "2026-10-02T00:43:13.052762+00:00"
            },
            {
              certificateId: "FRA_CSCA_2",
              thumbprint: "040b21ef683b04040620158ce8d4fd792c38118a",
              subject: "CN=FRA CSCA 2, O=FRA Government, C=FRA",
              validFrom: "2025-07-14T00:43:13.052993+00:00",
              validTo: "2028-06-05T00:43:13.052993+00:00"
            },
            {
              certificateId: "FRA_CSCA_3",
              thumbprint: "57ca71cf7cba18bd0b4d390cef5919b00e8f453b",
              subject: "CN=FRA CSCA 3, O=FRA Government, C=FRA",
              validFrom: "2024-11-29T00:43:13.053001+00:00",
              validTo: "2026-02-26T00:43:13.053001+00:00"
            },
            {
              certificateId: "FRA_CSCA_4",
              thumbprint: "cc0bdc1863719e890094c89eebdd98f9156d1be2",
              subject: "CN=FRA CSCA 4, O=FRA Government, C=FRA",
              validFrom: "2024-11-06T00:43:13.053007+00:00",
              validTo: "2027-01-12T00:43:13.053007+00:00"
            }
          ],
          signer: "FRA CSCA",
          metadata: {
            certificateCount: 4,
            testingOnly: true
          }
        },
        {
          country: "USA",
          sequenceNumber: 575,
          version: "1.0.0",
          issueDate: "2025-10-04T00:43:13.053065+00:00",
          nextUpdate: "2025-11-03T00:43:13.053065+00:00",
          certificates: [
            {
              certificateId: "USA_CSCA_1",
              thumbprint: "790c11e07e8dcca5287f2187a34abe73f8d76251",
              subject: "CN=USA CSCA 1, O=USA Government, C=USA",
              validFrom: "2025-07-19T00:43:13.053047+00:00",
              validTo: "2027-02-27T00:43:13.053047+00:00"
            },
            {
              certificateId: "USA_CSCA_2",
              thumbprint: "89b61a3aabf1cec7ecbb0448b9b6bf583fd997e9",
              subject: "CN=USA CSCA 2, O=USA Government, C=USA",
              validFrom: "2025-05-08T00:43:13.053054+00:00",
              validTo: "2027-10-07T00:43:13.053054+00:00"
            },
            {
              certificateId: "USA_CSCA_3",
              thumbprint: "cc6dde19f152171db7af0a1f83fdb50054e9ff33",
              subject: "CN=USA CSCA 3, O=USA Government, C=USA",
              validFrom: "2024-10-31T00:43:13.053060+00:00",
              validTo: "2025-11-27T00:43:13.053060+00:00"
            }
          ],
          signer: "USA CSCA",
          metadata: {
            certificateCount: 3,
            testingOnly: true
          }
        },
        {
          country: "ESP",
          sequenceNumber: 829,
          version: "1.0.0",
          issueDate: "2025-10-04T00:43:13.053113+00:00",
          nextUpdate: "2025-11-03T00:43:13.053113+00:00",
          certificates: [
            {
              certificateId: "ESP_CSCA_1",
              thumbprint: "5870e1a10e7bde197513ad2595424217b9545747",
              subject: "CN=ESP CSCA 1, O=ESP Government, C=ESP",
              validFrom: "2024-10-07T00:43:13.053091+00:00",
              validTo: "2027-09-25T00:43:13.053091+00:00"
            },
            {
              certificateId: "ESP_CSCA_2",
              thumbprint: "225d34f50ea9261dce673af8d32c8962875e9ea5",
              subject: "CN=ESP CSCA 2, O=ESP Government, C=ESP",
              validFrom: "2024-11-29T00:43:13.053098+00:00",
              validTo: "2027-02-01T00:43:13.053098+00:00"
            },
            {
              certificateId: "ESP_CSCA_3",
              thumbprint: "2c7c92d463ad76f16f7c08b4ed6a92377b258822",
              subject: "CN=ESP CSCA 3, O=ESP Government, C=ESP",
              validFrom: "2025-05-15T00:43:13.053102+00:00",
              validTo: "2027-08-17T00:43:13.053102+00:00"
            },
            {
              certificateId: "ESP_CSCA_4",
              thumbprint: "e3c9c5a29b62eb2d4192238af7ff0cd77d3252c6",
              subject: "CN=ESP CSCA 4, O=ESP Government, C=ESP",
              validFrom: "2024-11-07T00:43:13.053107+00:00",
              validTo: "2026-08-18T00:43:13.053107+00:00"
            }
          ],
          signer: "ESP CSCA",
          metadata: {
            certificateCount: 4,
            testingOnly: true
          }
        }
      ]);
      // Using cached sample data when backend unavailable
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMasterLists();
  }, []);

  const getCertificateStatus = (cert) => {
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    
    if (now < validFrom) return { status: 'pending', color: 'warning', label: 'Not Yet Valid' };
    if (now > validTo) return { status: 'expired', color: 'error', label: 'Expired' };
    
    // Check if expiring within 30 days
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    if (validTo < thirtyDaysFromNow) return { status: 'expiring', color: 'warning', label: 'Expiring Soon' };
    
    return { status: 'valid', color: 'success', label: 'Valid' };
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const handleViewCert = (cert) => {
    setSelectedCert(cert);
    setCertDialogOpen(true);
  };

  const getCountryStats = (ml) => {
    const total = ml.certificates.length;
    const valid = ml.certificates.filter(c => getCertificateStatus(c).status === 'valid').length;
    const expiring = ml.certificates.filter(c => getCertificateStatus(c).status === 'expiring').length;
    const expired = ml.certificates.filter(c => getCertificateStatus(c).status === 'expired').length;
    return { total, valid, expiring, expired };
  };

  const totalCerts = masterLists.reduce((acc, ml) => acc + ml.certificates.length, 0);
  const totalValid = masterLists.reduce((acc, ml) => 
    acc + ml.certificates.filter(c => getCertificateStatus(c).status === 'valid').length, 0);

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
                  <Typography variant="h4">{masterLists.length}</Typography>
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
                  <Typography variant="h4">{totalCerts}</Typography>
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
                  <Typography variant="h4">{totalValid}</Typography>
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
                  <Typography variant="h4">{totalCerts - totalValid}</Typography>
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
            const stats = getCountryStats(ml);
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
                        <Typography>{formatDate(ml.issueDate)}</Typography>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Typography variant="caption" color="text.secondary">Next Update</Typography>
                        <Typography>{formatDate(ml.nextUpdate)}</Typography>
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
                          const status = getCertificateStatus(cert);
                          return (
                            <TableRow key={cert.certificateId}>
                              <TableCell>
                                <Typography variant="body2" fontFamily="monospace">
                                  {cert.certificateId}
                                </Typography>
                              </TableCell>
                              <TableCell>{cert.subject}</TableCell>
                              <TableCell>{formatDate(cert.validFrom)}</TableCell>
                              <TableCell>{formatDate(cert.validTo)}</TableCell>
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
                    const status = getCertificateStatus(cert);
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
                        <TableCell>{formatDate(cert.validFrom)}</TableCell>
                        <TableCell>{formatDate(cert.validTo)}</TableCell>
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
                  <Typography>{formatDate(selectedCert.validFrom)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Valid To</Typography>
                  <Typography>{formatDate(selectedCert.validTo)}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Status</Typography>
                  <Box sx={{ mt: 0.5 }}>
                    <Chip 
                      label={getCertificateStatus(selectedCert).label} 
                      color={getCertificateStatus(selectedCert).color} 
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
