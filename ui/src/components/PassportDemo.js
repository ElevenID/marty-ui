import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Divider,
  Alert,
  CircularProgress
} from '@mui/material';
import {
  Flight as PassportIcon,
  Search as SearchIcon,
  Add as AddIcon,
  CheckCircle as CheckCircleIcon
} from '@mui/icons-material';

const PassportDemo = () => {
  const [passportNumber, setPassportNumber] = useState('');
  const [inspectNumber, setInspectNumber] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [inspectResult, setInspectResult] = useState(null);
  const [error, setError] = useState(null);

  const handleIssue = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/passport/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passport_number: passportNumber })
      });
      const data = await response.json();
      
      setResult(data);
    } catch (err) {
      setError('Failed to issue passport');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleInspect = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInspectResult(null);

    try {
      const response = await fetch('/api/passport/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passport_number: inspectNumber })
      });
      const data = await response.json();

      setInspectResult(data);
    } catch (err) {
      setError('Failed to inspect passport');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <PassportIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          Passport Operations
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Issue and Inspect Electronic Passports
        </Typography>
      </Box>

      <Grid container spacing={4}>
        {/* Issue Passport Section */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Process Passport
            </Typography>
            <Divider sx={{ mb: 2 }} />
            
            <form onSubmit={handleIssue}>
              <TextField
                fullWidth
                label="Passport Number"
                placeholder="Enter or leave blank to auto-generate"
                value={passportNumber}
                onChange={(e) => setPassportNumber(e.target.value)}
                margin="normal"
                variant="outlined"
              />
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                startIcon={<AddIcon />}
                disabled={loading}
                sx={{ mt: 2 }}
              >
                {loading ? <CircularProgress size={24} /> : 'Issue Passport'}
              </Button>
            </form>

            {result && (
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="subtitle2">Passport Issued Successfully</Typography>
                <Typography variant="body2">Number: {result.passport_number}</Typography>
                <Typography variant="body2">Status: {result.status}</Typography>
              </Alert>
            )}
          </Paper>
        </Grid>

        {/* Inspect Passport Section */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Inspect Passport
            </Typography>
            <Divider sx={{ mb: 2 }} />

            <form onSubmit={handleInspect}>
              <TextField
                fullWidth
                required
                label="Passport Number"
                placeholder="Enter passport number to inspect"
                value={inspectNumber}
                onChange={(e) => setInspectNumber(e.target.value)}
                margin="normal"
                variant="outlined"
              />
              <Button
                type="submit"
                variant="contained"
                color="secondary"
                fullWidth
                startIcon={<SearchIcon />}
                disabled={loading}
                sx={{ mt: 2 }}
              >
                {loading ? <CircularProgress size={24} /> : 'Inspect Passport'}
              </Button>
            </form>

            {inspectResult && (
              <Card variant="outlined" sx={{ mt: 2 }}>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={1}>
                    <CheckCircleIcon color="success" sx={{ mr: 1 }} />
                    <Typography variant="h6">Valid Passport</Typography>
                  </Box>
                  <Divider sx={{ my: 1 }} />
                  <Grid container spacing={1}>
                    <Grid item xs={4}><Typography variant="body2" color="text.secondary">Number:</Typography></Grid>
                    <Grid item xs={8}><Typography variant="body2">{inspectResult.details.passport_number}</Typography></Grid>
                    
                    <Grid item xs={4}><Typography variant="body2" color="text.secondary">Holder:</Typography></Grid>
                    <Grid item xs={8}><Typography variant="body2">{inspectResult.details.holder}</Typography></Grid>
                    
                    <Grid item xs={4}><Typography variant="body2" color="text.secondary">Nationality:</Typography></Grid>
                    <Grid item xs={8}><Typography variant="body2">{inspectResult.details.nationality}</Typography></Grid>
                  </Grid>
                </CardContent>
              </Card>
            )}
          </Paper>
        </Grid>
      </Grid>

      {error && (
        <Alert severity="error" sx={{ mt: 3 }}>
          {error}
        </Alert>
      )}
    </Container>
  );
};

export default PassportDemo;
