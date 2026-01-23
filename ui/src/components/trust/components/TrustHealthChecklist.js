/**
 * Trust Health Checklist Component
 * 
 * Displays a comprehensive health check for trust configuration:
 * - Verifier checks (RP access cert, signing, permissions)
 * - Issuer checks (access cert, signing key, signing cert)
 * - Trust checks (list configured, revocation enabled)
 * - Chain status (optional)
 * 
 * Used in onboarding final step and settings overview.
 */

import React from 'react';
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Divider,
  Alert,
  Button,
  CircularProgress,
  Chip,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BadgeIcon from '@mui/icons-material/Badge';
import PolicyIcon from '@mui/icons-material/Policy';
import TrustChainStatus from './TrustChainStatus';

/**
 * Get check icon based on status.
 */
const getCheckIcon = (passed, warning = false) => {
  if (passed && warning) {
    return <WarningIcon color="warning" />;
  }
  if (passed) {
    return <CheckCircleIcon color="success" />;
  }
  return <RadioButtonUncheckedIcon color="disabled" />;
};

/**
 * Check item component.
 */
const CheckItem = ({ label, passed, warning = false, helperText }) => (
  <ListItem disableGutters sx={{ py: 0.5 }}>
    <ListItemIcon sx={{ minWidth: 36 }}>
      {getCheckIcon(passed, warning)}
    </ListItemIcon>
    <ListItemText
      primary={label}
      secondary={helperText}
      primaryTypographyProps={{ variant: 'body2' }}
      secondaryTypographyProps={{ variant: 'caption' }}
    />
  </ListItem>
);

/**
 * Check section component.
 */
const CheckSection = ({ icon, title, children }) => (
  <Box sx={{ mb: 3 }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
      {icon}
      <Typography variant="subtitle2" fontWeight="bold">
        {title}
      </Typography>
    </Box>
    <List dense disablePadding>
      {children}
    </List>
  </Box>
);

/**
 * Trust Health Checklist Component.
 * 
 * @param {Object} props
 * @param {import('../ports/types').TrustHealthStatus} [props.healthStatus] - Health status data
 * @param {boolean} [props.loading] - Loading state
 * @param {function} [props.onActivate] - Activate callback (when all passed)
 * @param {function} [props.onReviewIssues] - Review issues callback (when not all passed)
 * @param {boolean} [props.showChainStatus] - Show chain status section
 * @param {boolean} [props.showActions] - Show action buttons
 * @param {boolean} [props.compact] - Compact mode
 */
const TrustHealthChecklist = ({
  healthStatus,
  loading = false,
  onActivate,
  onReviewIssues,
  showChainStatus = true,
  showActions = true,
  compact = false,
}) => {
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!healthStatus) {
    return (
      <Alert severity="info">
        No health status available. Complete trust profile setup first.
      </Alert>
    );
  }

  const { verifier, issuer, trust, chainStatus, allPassed, warnings, errors } = healthStatus;

  const verifierChecks = [
    { key: 'accessCertLoaded', label: 'Verifier access certificate loaded', passed: verifier?.accessCertLoaded },
    { key: 'signingConfigured', label: 'Verifier signing configured', passed: verifier?.signingConfigured },
    { key: 'permissionsConfirmed', label: 'Verifier permissions confirmed', passed: verifier?.permissionsConfirmed },
  ];

  const issuerChecks = [
    { key: 'accessCertLoaded', label: 'Issuer access certificate loaded', passed: issuer?.accessCertLoaded },
    { key: 'signingKeyReachable', label: 'Credential signing key reachable', passed: issuer?.signingKeyReachable },
    { key: 'signingCertAttached', label: 'Signing certificate attached', passed: issuer?.signingCertAttached },
  ];

  const trustChecks = [
    { key: 'listConfigured', label: 'Trusted list configured', passed: trust?.listConfigured },
    { key: 'revocationEnabled', label: 'Revocation checks enabled', passed: trust?.revocationEnabled },
  ];

  const content = (
    <>
      <CheckSection icon={<VerifiedUserIcon color="primary" />} title="Verifier (Gate/RP)">
        {verifierChecks.map((check) => (
          <CheckItem key={check.key} label={check.label} passed={check.passed} />
        ))}
      </CheckSection>

      <CheckSection icon={<BadgeIcon color="primary" />} title="Issuer">
        {issuerChecks.map((check) => (
          <CheckItem key={check.key} label={check.label} passed={check.passed} />
        ))}
      </CheckSection>

      <CheckSection icon={<PolicyIcon color="primary" />} title="Trust">
        {trustChecks.map((check) => (
          <CheckItem key={check.key} label={check.label} passed={check.passed} />
        ))}
      </CheckSection>

      {showChainStatus && chainStatus && (
        <>
          <Divider sx={{ my: 2 }} />
          <TrustChainStatus chainStatus={chainStatus} compact showTitle={false} />
        </>
      )}

      {/* Warnings */}
      {warnings && warnings.length > 0 && (
        <Box sx={{ mt: 2 }}>
          {warnings.map((warning, index) => (
            <Alert key={index} severity="warning" sx={{ mb: 1 }}>
              {warning}
            </Alert>
          ))}
        </Box>
      )}

      {/* Errors */}
      {errors && errors.length > 0 && (
        <Box sx={{ mt: 2 }}>
          {errors.map((err, index) => (
            <Alert key={index} severity="error" sx={{ mb: 1 }}>
              {err}
            </Alert>
          ))}
        </Box>
      )}

      {/* Result Summary */}
      <Box sx={{ mt: 3, textAlign: 'center' }}>
        {allPassed ? (
          <>
            <Chip
              icon={<CheckCircleIcon />}
              label="All checks passed"
              color="success"
              sx={{ mb: 2 }}
            />
            <Typography variant="body2" color="text.secondary">
              Your organization is ready to verify and issue.
            </Typography>
          </>
        ) : (
          <>
            <Chip
              icon={<WarningIcon />}
              label="Some checks need attention"
              color="warning"
              sx={{ mb: 2 }}
            />
            <Typography variant="body2" color="text.secondary">
              You can activate now, but these items may affect verification or issuance.
            </Typography>
          </>
        )}
      </Box>

      {/* Action Buttons */}
      {showActions && (
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 3 }}>
          {allPassed ? (
            onActivate && (
              <Button variant="contained" color="primary" onClick={onActivate}>
                Activate organization
              </Button>
            )
          ) : (
            <>
              {onReviewIssues && (
                <Button variant="outlined" onClick={onReviewIssues}>
                  Review issues
                </Button>
              )}
              {onActivate && (
                <Button variant="contained" color="warning" onClick={onActivate}>
                  Activate anyway
                </Button>
              )}
            </>
          )}
        </Box>
      )}
    </>
  );

  if (compact) {
    return content;
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Health Check
      </Typography>
      <Divider sx={{ mb: 3 }} />
      {content}
    </Paper>
  );
};

export default TrustHealthChecklist;
