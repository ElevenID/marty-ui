import { useState } from 'react';
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
  CheckCircle as CheckCircleIcon
} from '@mui/icons-material';
import {
  PKD_DEFAULT_DIRECTORY_STATUS,
  PKD_DEFAULT_STATISTICS,
  synchronizePkd,
} from '../application/admin';

const PkdManager = () => {
  const [syncStatus, setSyncStatus] = useState(null); // 'success', 'error', null
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleSync = async () => {
    setLoading(true);
    setSyncStatus(null);
    setMessage('');
    
    try {
      const result = await synchronizePkd();

      setSyncStatus(result.syncStatus);
      setMessage(result.message);
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
                {PKD_DEFAULT_DIRECTORY_STATUS.map((item) => (
                  <ListItem key={item.key}>
                    <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                    <ListItemText
                      primary={item.primary}
                      secondary={item.secondary}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Statistics
              </Typography>
              <Grid container spacing={2}>
                {PKD_DEFAULT_STATISTICS.map((item) => (
                  <Grid item xs={6} key={item.key}>
                    <Typography variant="h4">{item.value}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.label}</Typography>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default PkdManager;
