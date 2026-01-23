import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Box,
  Alert,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  AccountBalanceWallet as WalletIcon,
  Add as AddIcon,
  Visibility as ViewIcon,
  Send as SendIcon,
  QrCode as QrCodeIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  CardMembership as CardIcon,
  Security as SecurityIcon
} from '@mui/icons-material';

const WalletDemo = () => {
  const [credentials, setCredentials] = useState([]);
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  const [presentationRequest, setPresentationRequest] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCredentials();
  }, []);

  const loadCredentials = async () => {
    try {
      const response = await fetch('/api/wallet/credentials');
      const data = await response.json();

      // API returns { credentials: [...], count: N }
      const creds = data.credentials || [];
      if (creds.length > 0) {
        // Map API response to component format
        setCredentials(creds.map(c => ({
          id: c.id,
          type: c.types ? c.types.join(', ') : 'VerifiableCredential',
          issuer: c.issuer,
          issued_date: c.issuance_date ? c.issuance_date.split('T')[0] : 'Unknown',
          expiry_date: c.expiration_date ? c.expiration_date.split('T')[0] : 'No expiry',
          status: 'active',
          subject_data: c.claims || {}
        })));
      } else {
        // Show mock credentials for demo
        setCredentials([
          {
            id: 'demo_mdl_001',
            type: 'DriverLicenseCredential',
            issuer: 'Demo DMV',
            issued_date: '2024-01-15',
            expiry_date: '2030-01-15',
            status: 'active',
            subject_data: {
              given_name: 'Jane',
              family_name: 'Doe',
              birth_date: '1990-01-01',
              document_number: 'DL123456789'
            }
          }
        ]);
      }
    } catch (error) {
      console.error('Failed to load credentials:', error);

      // Mock credentials for demo
      setCredentials([
        {
          id: 'mdl_001',
          type: 'DriverLicenseCredential',
          issuer: 'Demo DMV',
          issued_date: '2024-01-15',
          expiry_date: '2030-01-15',
          status: 'active',
          subject_data: {
            given_name: 'Jane',
            family_name: 'Doe',
            birth_date: '1990-01-01',
            document_number: 'DL123456789',
            age_over_18: true,
            age_over_21: true
          }
        }
      ]);
    }
  };

  const viewCredential = (credential) => {
    setSelectedCredential(credential);
    setDialogOpen(true);
  };

  const shareCredential = (credential) => {
    setSelectedCredential(credential);
    setShareDialogOpen(true);
  };

  const deleteCredential = async (credentialId) => {
    if (window.confirm('Are you sure you want to delete this credential?')) {
      try {
        const response = await fetch(`/api/wallet/credentials/${credentialId}`, {
          method: 'DELETE'
        });

        if (response.ok) {
          setCredentials(prev => prev.filter(cred => cred.id !== credentialId));
        }
      } catch (error) {
        console.error('Failed to delete credential:', error);
        // For demo, remove from local state
        setCredentials(prev => prev.filter(cred => cred.id !== credentialId));
      }
    }
  };

  const createPresentation = async () => {
    if (!selectedCredential) {
      alert('Please select a credential');
      return;
    }

    setLoading(true);

    try {
      // Parse verifier from presentation request or use default
      let audience = 'demo_verifier';
      let nonce = null;
      
      if (presentationRequest.trim()) {
        try {
          const parsed = JSON.parse(presentationRequest);
          audience = parsed.audience || parsed.verifier || 'demo_verifier';
          nonce = parsed.nonce || null;
        } catch (e) {
          // Use default if parsing fails
        }
      }

      const response = await fetch('/api/wallet/present', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          credential_ids: [selectedCredential.id],
          audience: audience,
          nonce: nonce
        })
      });

      const result = await response.json();

      if (result.success) {
        alert('Presentation created successfully!');
        setShareDialogOpen(false);
        setPresentationRequest('');
      } else {
        alert('Failed to create presentation: ' + result.error);
      }
    } catch (error) {
      console.error('Failed to create presentation:', error);
      alert('Failed to create presentation');
    } finally {
      setLoading(false);
    }
  };

  const addNewCredential = async () => {
    // Simulate adding a new credential
    const newCredential = {
      id: `mdl_${Date.now()}`,
      type: 'mDL',
      issuer: 'Demo Issuer',
      issued_date: new Date().toISOString().split('T')[0],
      expiry_date: '2030-12-31',
      status: 'active',
      subject_data: {
        given_name: 'New',
        family_name: 'User',
        birth_date: '1995-05-05',
        document_number: 'DL' + Math.random().toString().substr(2, 9),
        age_over_18: true,
        age_over_21: true
      }
    };

    setCredentials(prev => [...prev, newCredential]);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active':
        return 'success';
      case 'expired':
        return 'error';
      case 'revoked':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Container maxWidth="lg">
      <Paper sx={{ p: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          <WalletIcon sx={{ fontSize: 48, mr: 2, verticalAlign: 'middle' }} />
          Digital Wallet
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph align="center">
          Manage your mobile driving license (mDL) credentials securely. Store, view, and share
          your digital credentials.
        </Typography>

        <Box sx={{ mb: 3, textAlign: 'center' }}>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={addNewCredential}
            sx={{ mr: 2 }}
          >
            Add Sample Credential
          </Button>

          <Button
            variant="outlined"
            onClick={loadCredentials}
          >
            Refresh Wallet
          </Button>
        </Box>

        {credentials.length === 0 ? (
          <Alert severity="info">
            No credentials found in your wallet. Add a sample credential to get started.
          </Alert>
        ) : (
          <Grid container spacing={3}>
            {credentials.map((credential) => (
              <Grid item xs={12} md={6} lg={4} key={credential.id}>
                <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <CardIcon sx={{ mr: 1, color: 'primary.main' }} />
                      <Typography variant="h6">
                        {credential.type}
                      </Typography>
                      <Box sx={{ flexGrow: 1 }} />
                      <Chip
                        label={credential.status}
                        color={getStatusColor(credential.status)}
                        size="small"
                      />
                    </Box>

                    <Typography color="text.secondary" gutterBottom>
                      Issued by: {credential.issuer}
                    </Typography>

                    <Typography variant="body2">
                      <strong>Holder:</strong> {credential.subject_data.given_name} {credential.subject_data.family_name}
                    </Typography>

                    <Typography variant="body2">
                      <strong>Document:</strong> {credential.subject_data.document_number}
                    </Typography>

                    <Typography variant="body2">
                      <strong>Expires:</strong> {credential.expiry_date}
                    </Typography>
                  </CardContent>

                  <CardActions>
                    <Button
                      size="small"
                      startIcon={<ViewIcon />}
                      onClick={() => viewCredential(credential)}
                    >
                      View
                    </Button>
                    <Button
                      size="small"
                      startIcon={<SendIcon />}
                      onClick={() => shareCredential(credential)}
                    >
                      Share
                    </Button>
                    <Button
                      size="small"
                      startIcon={<DeleteIcon />}
                      color="error"
                      onClick={() => deleteCredential(credential.id)}
                    >
                      Delete
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {/* View Credential Dialog */}
        <Dialog
          open={dialogOpen}
          onClose={() => setDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Credential Details
          </DialogTitle>
          <DialogContent>
            {selectedCredential && (
              <Box>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">Type</Typography>
                    <Typography variant="body1">{selectedCredential.type}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">Status</Typography>
                    <Chip
                      label={selectedCredential.status}
                      color={getStatusColor(selectedCredential.status)}
                      size="small"
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">Issuer</Typography>
                    <Typography variant="body1">{selectedCredential.issuer}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">ID</Typography>
                    <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {selectedCredential.id}
                    </Typography>
                  </Grid>
                </Grid>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="h6">Subject Data</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <pre style={{ fontSize: '0.875rem', overflow: 'auto' }}>
                      {JSON.stringify(selectedCredential.subject_data, null, 2)}
                    </pre>
                  </AccordionDetails>
                </Accordion>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Share Credential Dialog */}
        <Dialog
          open={shareDialogOpen}
          onClose={() => setShareDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <QrCodeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Create Presentation
          </DialogTitle>
          <DialogContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Enter a presentation request to create a verifiable presentation from this credential.
            </Typography>

            <TextField
              fullWidth
              multiline
              rows={6}
              label="Presentation Request (JSON)"
              value={presentationRequest}
              onChange={(e) => setPresentationRequest(e.target.value)}
              placeholder='{"requested_attributes": ["given_name", "age_over_21"], "purpose": "age_verification"}'
              sx={{ mb: 2 }}
            />

            <Alert severity="info">
              This will create a verifiable presentation containing only the requested attributes
              from your credential, protecting your privacy through selective disclosure.
            </Alert>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShareDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={createPresentation}
              variant="contained"
              disabled={loading || !presentationRequest.trim()}
            >
              {loading ? 'Creating...' : 'Create Presentation'}
            </Button>
          </DialogActions>
        </Dialog>
      </Paper>
    </Container>
  );
};

export default WalletDemo;
