/**
 * Technical Identity Step Component
 * 
 * Consolidated step combining Verifier Identity, Issuer Identity, and Trust Sources.
 * Gathers all cryptographic setup in one place.
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Fade,
  Paper,
  Divider,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BadgeIcon from '@mui/icons-material/Badge';
import { CertificateUploader, KeyLocationSelector } from '../../trust/components';
import { useCertParser, useTrust } from '../../trust';

/**
 * Technical Identity Step Component.
 * 
 * @param {Object} props
 * @param {Object} props.verifierConfig - Verifier configuration
 * @param {function} props.onVerifierConfigChange - Verifier config change callback
 * @param {Object} props.issuerConfig - Issuer configuration
 * @param {function} props.onIssuerConfigChange - Issuer config change callback
 * @param {boolean} [props.disabled] - Disable inputs
 */
const TechnicalIdentityStep = ({
  verifierConfig,
  onVerifierConfigChange,
  issuerConfig,
  onIssuerConfigChange,
  disabled = false,
}) => {
  const certParser = useCertParser();
  const { testKeyConnection } = useTrust();

  const [expanded, setExpanded] = useState('verifier');

  const handleAccordionChange = (panel) => (event, isExpanded) => {
    setExpanded(isExpanded ? panel : false);
  };

  const handleVerifierCertChange = useCallback((certData) => {
    onVerifierConfigChange({
      ...verifierConfig,
      accessCert: certData,
    });
  }, [verifierConfig, onVerifierConfigChange]);

  const handleVerifierKeyChange = useCallback((keyConfig) => {
    onVerifierConfigChange({
      ...verifierConfig,
      keyLocation: keyConfig,
    });
  }, [verifierConfig, onVerifierConfigChange]);

  const handleIssuerKeyChange = useCallback((keyConfig) => {
    onIssuerConfigChange({
      ...issuerConfig,
      keyLocation: keyConfig,
    });
  }, [issuerConfig, onIssuerConfigChange]);

  const handleTestConnection = useCallback(async (keyConfig) => {
    return testKeyConnection(keyConfig);
  }, [testKeyConnection]);

  const verifierComplete = verifierConfig?.accessCert && verifierConfig?.keyLocation?.source;
  const issuerComplete = issuerConfig?.keyLocation?.source;

  return (
    <Fade in>
      <Box data-testid="technical-identity-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Set up your cryptographic identity
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 4 }}>
          Configure certificates and keys for secure verification and issuance
        </Typography>

        <Box sx={{ maxWidth: 800, mx: 'auto' }}>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              Your private keys never leave your infrastructure. We only need to know how to request signatures.
            </Typography>
          </Alert>

          {/* Verifier Identity */}
          <Accordion
            expanded={expanded === 'verifier'}
            onChange={handleAccordionChange('verifier')}
            sx={{ mb: 2 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                <VerifiedUserIcon color={verifierComplete ? 'success' : 'action'} />
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="subtitle1" fontWeight="bold">
                    1. Verifier Identity (for verification)
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Public certificate + private key location
                  </Typography>
                </Box>
                {verifierComplete && (
                  <Typography variant="caption" color="success.main" fontWeight="bold">
                    ✓ Complete
                  </Typography>
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  When verifying credentials, wallets need to know who you are. Upload your public certificate
                  and tell us where your private signing key lives.
                </Typography>

                {/* Verifier Certificate */}
                <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
                  <Typography variant="subtitle2" fontWeight="bold" sx={{ mb: 2 }}>
                    Verifier public certificate
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Upload your <strong>public certificate</strong> (not your private key)
                  </Typography>

                  <CertificateUploader
                    label="Upload public certificate file"
                    helperText="A chain may include intermediate certificates. We'll detect it."
                    value={verifierConfig?.accessCert}
                    onChange={handleVerifierCertChange}
                    certParser={certParser}
                    disabled={disabled}
                    showChainDetails
                  />
                </Paper>

                {/* Verifier Key Location */}
                <Paper variant="outlined" sx={{ p: 3 }}>
                  <Typography variant="subtitle2" fontWeight="bold" sx={{ mb: 1 }}>
                    Where is your private signing key?
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Your private key never leaves your infrastructure
                  </Typography>

                  <KeyLocationSelector
                    value={verifierConfig?.keyLocation}
                    onChange={handleVerifierKeyChange}
                    onTestConnection={handleTestConnection}
                    disabled={disabled}
                    label=""
                  />
                </Paper>
              </Box>
            </AccordionDetails>
          </Accordion>

          {/* Issuer Identity */}
          <Accordion
            expanded={expanded === 'issuer'}
            onChange={handleAccordionChange('issuer')}
            sx={{ mb: 2 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                <BadgeIcon color={issuerComplete ? 'success' : 'action'} />
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="subtitle1" fontWeight="bold">
                    2. Issuer Identity (for issuance)
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Signing key location for credential issuance
                  </Typography>
                </Box>
                {issuerComplete && (
                  <Typography variant="caption" color="success.main" fontWeight="bold">
                    ✓ Complete
                  </Typography>
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  When issuing credentials, you'll sign them with your private key to prove authenticity.
                  Tell us where your issuer signing key lives.
                </Typography>

                <Paper variant="outlined" sx={{ p: 3 }}>
                  <Typography variant="subtitle2" fontWeight="bold" sx={{ mb: 1 }}>
                    Where is your issuer signing key?
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    This key will sign all credentials you issue
                  </Typography>

                  <KeyLocationSelector
                    value={issuerConfig?.keyLocation}
                    onChange={handleIssuerKeyChange}
                    onTestConnection={handleTestConnection}
                    disabled={disabled}
                    label=""
                    showAlgorithm
                  />
                </Paper>
              </Box>
            </AccordionDetails>
          </Accordion>

          {/* Summary */}
          <Paper sx={{ p: 3, bgcolor: 'grey.50', mt: 3 }}>
            <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
              Setup Summary
            </Typography>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="body2">Verifier Certificate:</Typography>
                <Typography variant="body2" color={verifierConfig?.accessCert ? 'success.main' : 'text.secondary'}>
                  {verifierConfig?.accessCert ? '✓ Uploaded' : 'Not uploaded'}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="body2">Verifier Key:</Typography>
                <Typography variant="body2" color={verifierConfig?.keyLocation?.source ? 'success.main' : 'text.secondary'}>
                  {verifierConfig?.keyLocation?.source || 'Not configured'}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="body2">Issuer Key:</Typography>
                <Typography variant="body2" color={issuerConfig?.keyLocation?.source ? 'success.main' : 'text.secondary'}>
                  {issuerConfig?.keyLocation?.source || 'Not configured'}
                </Typography>
              </Box>
            </Box>
          </Paper>
        </Box>
      </Box>
    </Fade>
  );
};

export default TechnicalIdentityStep;
