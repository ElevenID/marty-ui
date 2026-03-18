import { useState, useEffect } from 'react';
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
import {
  createSampleWalletCredential,
  createWalletDemoPresentation,
  deleteWalletDemoCredential,
  getWalletCredentialStatusColor,
  loadWalletDemoCredentials,
} from '../application/wallet';

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
    const result = await loadWalletDemoCredentials();
    setCredentials(result.credentials);
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
      const result = await deleteWalletDemoCredential({
        credentialId,
        credentials,
      });
      setCredentials(result.credentials);
    }
  };

  const createPresentation = async () => {
    if (!selectedCredential) {
      alert('Please select a credential');
      return;
    }

    setLoading(true);

    try {
      const result = await createWalletDemoPresentation({
        selectedCredential,
        presentationRequest,
      });

      if (result.success) {
        alert(result.message);
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
    setCredentials(prev => [...prev, createSampleWalletCredential()]);
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
                        color={getWalletCredentialStatusColor(credential.status)}
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
                      color={getWalletCredentialStatusColor(selectedCredential.status)}
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
