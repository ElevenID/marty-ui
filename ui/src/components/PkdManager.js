import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Alert,
  CircularProgress
} from '@mui/material';
import {
  VpnKey as KeyIcon,
  Sync as SyncIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon
} from '@mui/icons-material';

const PkdManager = () => {
  const [syncStatus, setSyncStatus] = useState(null); // 'success', 'error', null
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleSync = async () => {
    setLoading(true);
    setSyncStatus(null);
    setMessage('');
    
    try {
      const response = await fetch('/api/admin/pkd/sync?force_refresh=true', {
        method: 'POST'
      });
      
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.detail || 'Sync failed');
      
      setSyncStatus('success');
      setMessage(data.message || 'PKD synchronization completed successfully.');
    } catch (err) {
      setSyncStatus('error');
      setMessage(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <KeyIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          PKD Management
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Public Key Directory Service Management
        </Typography>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Synchronize PKD
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Typography variant="body2" color="text.secondary" paragraph>
              Trigger a synchronization of the Public Key Directory from configured sources.
            </Typography>
            
            <Box sx={{ textAlign: 'center', mb: 2, py: 4 }}>
              <SyncIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2, animation: loading ? 'spin 2s linear infinite' : 'none' }} />
              <style>
                {`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}
              </style>
            </Box>

            <Button 
              fullWidth 
              variant="contained" 
              color="primary"
              onClick={handleSync}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SyncIcon />}
            >
              {loading ? 'Synchronizing...' : 'Start Synchronization'}
            </Button>

            {syncStatus === 'success' && (
              <Alert severity="success" sx={{ mt: 2 }}>
                {message}
              </Alert>
            )}
            
            {syncStatus === 'error' && (
              <Alert severity="error" sx={{ mt: 2 }}>
                Error: {message}
              </Alert>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Directory Status
              </Typography>
              <List>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="LDAP Service" 
                    secondary="Running - Port 389" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="HTTP Service" 
                    secondary="Running - Port 8080" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText 
                    primary="Replication" 
                    secondary="Active" 
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>

          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Statistics
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="h4">142</Typography>
                  <Typography variant="body2" color="text.secondary">Active CSCA Certs</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h4">1,205</Typography>
                  <Typography variant="body2" color="text.secondary">Document Signer Certs</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h4">58</Typography>
                  <Typography variant="body2" color="text.secondary">CRLs Published</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h4">24/7</Typography>
                  <Typography variant="body2" color="text.secondary">Availability</Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default PkdManager;
