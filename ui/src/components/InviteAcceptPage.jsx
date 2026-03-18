/**
 * Invite Accept Page
 *
 * Page for applicants to accept an organization invitation.
 * Handles the invitation token from email link and adds user to org.
 */

import { useCallback, useEffect, useState } from 'react';
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
import { acceptOrganizationInvitation, validateOrganizationInvitation } from '../services/organizationsApi';
import {
  getInviteAcceptLoginReturnUrl,
  INVITE_ACCEPT_STATES,
  loadInviteAcceptInvitation,
  submitInviteAcceptInvitation,
} from '../application/onboarding';

export default function InviteAcceptPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { isAuthenticated, login } = useAuth();
  
  const [state, setState] = useState(INVITE_ACCEPT_STATES.LOADING);
  const [invitation, setInvitation] = useState(null);
  const [error, setError] = useState(null);

  const token = searchParams.get('token');

  const validateInvitation = useCallback(async () => {
    setState(INVITE_ACCEPT_STATES.LOADING);
    const result = await loadInviteAcceptInvitation({
      token,
      isAuthenticated,
      validateOrganizationInvitation,
    });

    if (result.redirectTo) {
      navigate(result.redirectTo, { replace: true });
      return;
    }

    setInvitation(result.invitation);
    setState(result.state);
    setError(result.error);
  }, [token, isAuthenticated, navigate]);

  useEffect(() => {
    validateInvitation();
  }, [validateInvitation]);

  const handleAcceptInvitation = async () => {
    setState(INVITE_ACCEPT_STATES.ACCEPTING);
    const result = await submitInviteAcceptInvitation({
      token,
      invitation,
      acceptOrganizationInvitation,
    });

    setInvitation(result.invitation);
    setState(result.state);
    setError(result.error);

    if (result.redirectTo) {
      setTimeout(() => {
        navigate(result.redirectTo);
      }, 3000);
    }
  };

  const handleLogin = () => {
    sessionStorage.setItem('returnUrl', getInviteAcceptLoginReturnUrl(token));
    login();
  };

  const renderContent = () => {
    switch (state) {
      case INVITE_ACCEPT_STATES.LOADING:
        return (
          <Box sx={{ textAlign: 'center', py: 6 }} data-testid="invite-loading">
            <CircularProgress size={48} sx={{ mb: 2 }} />
            <Typography variant="h6">Validating invitation...</Typography>
          </Box>
        );

      case INVITE_ACCEPT_STATES.LOGIN_REQUIRED:
        return (
          <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-login-required">
            <BusinessIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
            <Typography variant="h5" gutterBottom>
              You&apos;re Invited!
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              You&apos;ve been invited to join <strong>{invitation?.organization_name}</strong>
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

      case INVITE_ACCEPT_STATES.VALID:
        return (
          <Box data-testid="invite-valid">
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <BusinessIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
              <Typography variant="h4" gutterBottom>
                Join {invitation?.organization_name}
              </Typography>
              <Typography variant="body1" color="text.secondary">
                You&apos;ve been invited to join as an applicant
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
                    After joining, you&apos;ll be able to apply for these credentials:
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

      case INVITE_ACCEPT_STATES.ACCEPTING:
        return (
          <Box sx={{ textAlign: 'center', py: 6 }} data-testid="invite-accepting">
            <CircularProgress size={48} sx={{ mb: 2 }} />
            <Typography variant="h6">Accepting invitation...</Typography>
          </Box>
        );

      case INVITE_ACCEPT_STATES.ACCEPTED:
        return (
          <Fade in>
            <Box sx={{ textAlign: 'center', py: 4 }} data-testid="invite-accepted">
              <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
              <Typography variant="h4" gutterBottom>
                Welcome to {invitation?.organization_name}!
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                You&apos;ve successfully joined the organization as an applicant.
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

      case INVITE_ACCEPT_STATES.EXPIRED:
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

      case INVITE_ACCEPT_STATES.INVALID:
      case INVITE_ACCEPT_STATES.ERROR:
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
