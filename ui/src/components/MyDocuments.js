/**
 * My Documents Component
 *
 * Applicant view showing their issued travel documents.
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  CircularProgress,
  Alert,
  Button,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import VerifiedIcon from '@mui/icons-material/Verified';
import WarningIcon from '@mui/icons-material/Warning';
import { useAuth } from '../hooks/useAuth';

function MyDocuments() {
  const { user } = useAuth();
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDocuments = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/applicants/me/documents', {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch documents');
      }

      const data = await response.json();
      setDocuments(data.documents || []);
    } catch (err) {
      console.error('Error fetching documents:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const getIssueDate = (doc) => doc.issue_date || doc.issued_at;
  const getExpiryDate = (doc) => doc.expiry_date || doc.expires_at;

  const isExpiringSoon = (expiryDate) => {
    if (!expiryDate) return false;
    const expiry = new Date(expiryDate);
    const sixMonthsFromNow = new Date();
    sixMonthsFromNow.setMonth(sixMonthsFromNow.getMonth() + 6);
    return expiry <= sixMonthsFromNow;
  };

  const isExpired = (expiryDate) => {
    if (!expiryDate) return false;
    return new Date(expiryDate) < new Date();
  };

  const getStatusChip = (doc) => {
    const expiryDate = getExpiryDate(doc);
    if (isExpired(expiryDate)) {
      return <Chip icon={<WarningIcon />} label="Expired" color="error" size="small" />;
    }
    if (isExpiringSoon(expiryDate)) {
      return <Chip icon={<WarningIcon />} label="Expiring Soon" color="warning" size="small" />;
    }
    return <Chip icon={<VerifiedIcon />} label="Valid" color="success" size="small" />;
  };

  return (
    <Box data-testid="my-documents-page">
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" data-testid="documents-title">
          My Travel Documents
        </Typography>

        <Button 
          variant="outlined" 
          startIcon={<RefreshIcon />} 
          onClick={fetchDocuments}
          data-testid="refresh-documents-btn"
        >
          Refresh
        </Button>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} data-testid="documents-error">
          {error}
        </Alert>
      )}

      {/* Loading State */}
      {loading && (
        <Box display="flex" justifyContent="center" py={4} data-testid="documents-loading">
          <CircularProgress />
        </Box>
      )}

      {/* Documents Grid */}
      {!loading && !error && (
        <>
          {documents.length === 0 ? (
            <Card data-testid="no-documents-card">
              <CardContent sx={{ textAlign: 'center', py: 6 }}>
                <FlightTakeoffIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="textSecondary" gutterBottom data-testid="no-documents-title">
                  No Travel Documents Yet
                </Typography>
                <Typography variant="body2" color="textSecondary" data-testid="no-documents-message">
                  Once your application is approved, your travel documents will appear here.
                </Typography>
              </CardContent>
            </Card>
          ) : (
            <Grid container spacing={3} data-testid="documents-grid">
              {documents.map((doc) => (
                <Grid item xs={12} md={6} key={doc.id}>
                  <Card
                    data-testid={`document-card-${doc.id}`}
                    data-document-type={doc.metadata?.credential_display_name || doc.document_type || 'Credential'}
                    data-document-status={isExpired(getExpiryDate(doc)) ? 'expired' : isExpiringSoon(getExpiryDate(doc)) ? 'expiring' : 'valid'}
                    sx={{
                      height: '100%',
                      border: isExpired(getExpiryDate(doc)) ? '2px solid' : 'none',
                      borderColor: 'error.main',
                    }}
                  >
                    <CardContent>
                      <Box
                        sx={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'flex-start',
                          mb: 2,
                        }}
                      >
                        <Typography variant="h6" data-testid="document-type">
                          {doc.metadata?.credential_display_name || doc.document_type || 'Credential'}
                        </Typography>
                        {getStatusChip(doc)}
                      </Box>

                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">
                            Document Number
                          </Typography>
                          <Typography variant="body2" fontFamily="monospace" data-testid="document-number">
                            {doc.document_number || 'N/A'}
                          </Typography>
                        </Grid>

                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">
                            Nationality
                          </Typography>
                          <Typography variant="body2" data-testid="document-nationality">{doc.nationality || user?.nationality || 'N/A'}</Typography>
                        </Grid>

                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">
                            Issue Date
                          </Typography>
                          <Typography variant="body2" data-testid="document-issue-date">{formatDate(getIssueDate(doc))}</Typography>
                        </Grid>

                        <Grid item xs={6}>
                          <Typography variant="caption" color="textSecondary">
                            Expiry Date
                          </Typography>
                          <Typography
                            variant="body2"
                            color={isExpired(getExpiryDate(doc)) ? 'error' : 'inherit'}
                            data-testid="document-expiry-date"
                          >
                            {formatDate(getExpiryDate(doc))}
                          </Typography>
                        </Grid>
                      </Grid>

                      <Box sx={{ mt: 2, pt: 2, borderTop: 1, borderColor: 'divider' }}>
                        <Button size="small" variant="outlined" data-testid="view-details-btn">
                          View Details
                        </Button>
                        {isExpiringSoon(getExpiryDate(doc)) && !isExpired(getExpiryDate(doc)) && (
                          <Button size="small" variant="contained" sx={{ ml: 1 }} data-testid="renew-btn">
                            Renew
                          </Button>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          )}
        </>
      )}
    </Box>
  );
}

export default MyDocuments;
