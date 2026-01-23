/**
 * Invite Accept Page
 *
 * Page for applicants to accept an organization invitation.
 * Handles the invitation token from email link and adds user to org.
 */

import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Paper,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Fade,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import BusinessIcon from '@mui/icons-material/Business';
import EmailIcon from '@mui/icons-material/Email';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ErrorIcon from '@mui/icons-material/Error';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { useAuth } from '../hooks/useAuth';

const API_URL = process.env.REACT_APP_API_URL || '';

// Invitation states
const STATES = {
  LOADING: 'loading',
  VALID: 'valid',
  ACCEPTING: 'accepting',
  ACCEPTED: 'accepted',
  EXPIRED: 'expired',
  INVALID: 'invalid',
  ERROR: 'error',
  LOGIN_REQUIRED: 'login_required',
};

export default function InviteAcceptPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { isAuthenticated, login } = useAuth();
  
  const [state, setState] = useState(STATES.LOADING);
  const [invitation, setInvitation] = useState(null);
  const [error, setError] = useState(null);

  const token = searchParams.get('token');

  useEffect(() => {
    if (!token) {
      setState(STATES.INVALID);
      setError('No invitation token provided');
      return;
    }

    validateInvitation();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const validateInvitation = async () => {
    setState(STATES.LOADING);
    try {
      const response = await fetch(`${API_URL}/api/invitations/validate?token=${token}`, {
        credentials: 'include',
      });

      if (!response.ok) {
        if (response.status === 404) {
          setState(STATES.INVALID);
          setError('Invitation not found or has been cancelled');
          return;
        }
        if (response.status === 410) {
          setState(STATES.EXPIRED);
          setError('This invitation has expired');
          return;
        }
        throw new Error('Failed to validate invitation');
      }

      const data = await response.json();
      setInvitation(data);
      
      // Check if user needs to login
      if (!isAuthenticated) {
        setState(STATES.LOGIN_REQUIRED);
      } else {
        setState(STATES.VALID);
      }
    } catch (err) {
      console.error('Error validating invitation:', err);
      setState(STATES.ERROR);
      setError(err.message);
    }
  };

  const handleAcceptInvitation = async () => {
    setState(STATES.ACCEPTING);
    try {
      const response = await fetch(`${API_URL}/api/invitations/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to accept invitation');
      }

      const data = await response.json();
      setInvitation(prev => ({ ...prev, ...data }));
      setState(STATES.ACCEPTED);

      // Redirect to dashboard after a short delay
      setTimeout(() => {
        navigate('/my-applications');
      }, 3000);
    } catch (err) {
      console.error('Error accepting invitation:', err);
      setState(STATES.ERROR);
      setError(err.message);
    }
  };

  const handleLogin = () => {
    // Store the current URL to return after login
    sessionStorage.setItem('returnUrl', window.location.href);
    login();
  };

  const renderContent = () => {
    switch (state) {
      case STATES.LOADING:
        return (
          <Box sx={{ textAlign: 'center', py: 6 }} data-testid="invite-loading">
            <CircularProgress size={48} sx={{ mb: 2 }} />
            <Typography variant="h6">Validating invitation...</Typography>
          </Box>
        );

      case STATES.LOGIN_REQUIRED:
        return (
          <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-login-required">
            <BusinessIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              You're Invited!
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              You've been invited to join <strong>{invitation?.organization_name}</strong>
            </Typography>
            
            <Alert severity="info" sx={{ mb: 3, textAlign: 'left' }}>
              Please sign in or create an account to accept this invitation.
            </Alert>

            <Button
              variant="contained"
              size="large"
              startIcon={<PersonAddIcon />}
              onClick={handleLogin}
              data-testid="login-to-accept-btn"
            >
              Sign In to Accept Invitation
            </Button>
          </Box>
        );

      case STATES.VALID:
        return (
          <Box data-testid="invite-valid">
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <BusinessIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
              <Typography variant="h4" gutterBottom>
                Join {invitation?.organization_name}
              </Typography>
              <Typography variant="body1" color="text.secondary">
                You've been invited to join as an applicant
              </Typography>
            </Box>

            <Card variant="outlined" sx={{ mb: 3 }} data-testid="invitation-details">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Invitation Details
                </Typography>
                <Divider sx={{ mb: 2 }} />
                
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <BusinessIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Organization"
                      secondary={invitation?.organization_name}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <EmailIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Invited Email"
                      secondary={invitation?.email}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <AccessTimeIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Expires"
                      secondary={invitation?.expires_at ? new Date(invitation.expires_at).toLocaleString() : 'N/A'}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>

            {/* Available Credentials */}
            {invitation?.available_credentials && invitation.available_credentials.length > 0 && (
              <Card variant="outlined" sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Available Credentials
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    After joining, you'll be able to apply for these credentials:
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {invitation.available_credentials.map((cred, idx) => (
                      <Chip
                        key={idx}
                        icon={<VerifiedUserIcon />}
                        label={cred}
                        color="primary"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            )}

            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
              <Button
                variant="outlined"
                onClick={() => navigate('/')}
              >
                Decline
              </Button>
              <Button
                variant="contained"
                size="large"
                endIcon={<ArrowForwardIcon />}
                onClick={handleAcceptInvitation}
                data-testid="accept-invitation-btn"
              >
                Accept Invitation
              </Button>
            </Box>
          </Box>
        );

      case STATES.ACCEPTING:
        return (
          <Box sx={{ textAlign: 'center', py: 6 }} data-testid="invite-accepting">
            <CircularProgress size={48} sx={{ mb: 2 }} />
            <Typography variant="h6">Accepting invitation...</Typography>
          </Box>
        );

      case STATES.ACCEPTED:
        return (
          <Fade in>
            <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-accepted">
              <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
              <Typography variant="h4" gutterBottom>
                Welcome to {invitation?.organization_name}!
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                You've successfully joined the organization as an applicant.
              </Typography>
              
              <Alert severity="success" sx={{ mb: 3 }}>
                Redirecting to your applications page...
              </Alert>

              <Button
                variant="contained"
                endIcon={<ArrowForwardIcon />}
                onClick={() => navigate('/my-applications')}
                data-testid="go-to-applications-btn"
              >
                Go to My Applications
              </Button>
            </Box>
          </Fade>
        );

      case STATES.EXPIRED:
        return (
          <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-expired">
            <AccessTimeIcon sx={{ fontSize: 64, color: 'warning.main', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              Invitation Expired
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              This invitation has expired. Please contact the organization administrator for a new invitation.
            </Typography>
            <Button variant="outlined" onClick={() => navigate('/')}>
              Go Home
            </Button>
          </Box>
        );

      case STATES.INVALID:
      case STATES.ERROR:
        return (
          <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-error">
            <ErrorIcon sx={{ fontSize: 64, color: 'error.main', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              Invalid Invitation
            </Typography>
            <Alert severity="error" sx={{ mb: 3 }}>
              {error || 'This invitation is invalid or has already been used.'}
            </Alert>
            <Button variant="outlined" onClick={() => navigate('/')}>
              Go Home
            </Button>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #1976d2 0%, #42a5f5 100%)',
        py: 8,
      }}
      data-testid="invite-accept-page"
    >
      <Container maxWidth="sm">
        <Paper sx={{ p: 4, borderRadius: 2 }}>
          {renderContent()}
        </Paper>
      </Container>
    </Box>
  );
}
