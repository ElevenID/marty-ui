/**
 * Completion Step Component
 * 
 * Final step showing success message and redirecting to dashboard
 */

import React from 'react';
import {
  Box,
  Typography,
  Paper,
  Button,
  Alert,
  CircularProgress,
  Tooltip,
  Fade,
  Chip,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SecurityIcon from '@mui/icons-material/Security';
import ScheduleIcon from '@mui/icons-material/Schedule';

const CompletionStep = ({
  userType,
  resultOrgName,
  resultInviteCode,
  membershipStatus,
  walletPaired,
  pairedDeviceId,
  existingOrganization = false,
  trustConfigured = false,
  trustSkipped = false,
}) => {
  const copyInviteCode = () => {
    navigator.clipboard.writeText(resultInviteCode);
  };

  return (
    <Fade in>
      <Box sx={{ textAlign: 'center', py: 6 }} data-testid="setup-complete">
        <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
        <Typography variant="h4" gutterBottom>
          You're All Set!
        </Typography>
        
        {userType === 'vendor' && resultInviteCode && (
          <Box sx={{ my: 4, maxWidth: 400, mx: 'auto' }}>
            <Alert severity="success" sx={{ mb: 2 }}>
              <Typography variant="body2">
                {existingOrganization
                  ? <>Organization <strong data-testid="org-name-display">{resultOrgName}</strong> is ready.</>
                  : <>Your organization <strong data-testid="org-name-display">{resultOrgName}</strong> has been created!</>}
              </Typography>
            </Alert>
            <Paper variant="outlined" sx={{ p: 3, bgcolor: 'grey.50' }}>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Your Invite Code:
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                <Typography variant="h4" fontFamily="monospace" fontWeight="bold" data-testid="invite-code-display">
                  {resultInviteCode}
                </Typography>
                <Tooltip title="Copy to clipboard">
                  <Button size="small" onClick={copyInviteCode} data-testid="copy-invite-code-btn">
                    <ContentCopyIcon />
                  </Button>
                </Tooltip>
              </Box>
              <Typography variant="caption" color="text.secondary">
                Share this code with users who need to join your organization
              </Typography>
            </Paper>
          </Box>
        )}

        {/* Trust configuration status for vendors */}
        {userType === 'vendor' && trustConfigured && (
          <Alert 
            severity="success" 
            icon={<SecurityIcon />}
            sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}
            data-testid="trust-configured-success"
          >
            <Typography variant="body2">
              Trust profile configured and activated!
              <Chip 
                label="Ready to verify & issue" 
                size="small" 
                color="success"
                sx={{ ml: 1 }}
              />
            </Typography>
          </Alert>
        )}

        {userType === 'vendor' && trustSkipped && (
          <Alert 
            severity="info" 
            icon={<ScheduleIcon />}
            sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}
            data-testid="trust-skipped-info"
          >
            <Typography variant="body2">
              Trust profile setup was skipped. You can configure it later from your organization settings.
            </Typography>
          </Alert>
        )}

        {userType === 'applicant' && membershipStatus === 'joined' && (
          <Alert severity="success" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}>
            You've joined <strong>{resultOrgName}</strong>!
          </Alert>
        )}

        {userType === 'applicant' && membershipStatus === 'pending_approval' && (
          <Alert severity="info" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}>
            Your request to join <strong>{resultOrgName}</strong> is pending approval.
          </Alert>
        )}

        {userType === 'applicant' && walletPaired && (
          <Alert severity="success" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }} data-testid="wallet-paired-success">
            <Typography variant="body2">
              Wallet paired successfully!
              {pairedDeviceId && (
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  Device ID: {pairedDeviceId}
                </Typography>
              )}
            </Typography>
          </Alert>
        )}

        {userType === 'applicant' && walletPaired === false && (
          <Alert severity="warning" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }} data-testid="wallet-skipped-warning">
            <Typography variant="body2">
              Wallet pairing was skipped. You can pair your wallet later from your profile settings.
            </Typography>
          </Alert>
        )}

        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Redirecting to your dashboard...
        </Typography>
        <CircularProgress size={24} />
      </Box>
    </Fade>
  );
};

export default CompletionStep;
