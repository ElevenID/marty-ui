/**
 * Verifier Identity Step Component
 * 
 * Step 2 of trust setup: Configure verifier/relying party identity.
 * - Upload RP access certificate
 * - Configure key location (KMS, Signing Agent, etc.)
 * - Optional: Upload registration certificate
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Fade,
  Paper,
  Switch,
  FormControlLabel,
  Alert,
} from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { CertificateUploader, KeyLocationSelector } from '../../trust/components';
import { useCertParser, useTrust } from '../../trust';

/**
 * Verifier Identity Step Component.
 * 
 * @param {Object} props
 * @param {Object} props.verifierConfig - Current verifier configuration
 * @param {function} props.onConfigChange - Callback when config changes
 * @param {boolean} [props.disabled] - Disable inputs
 */
const VerifierIdentityStep = ({
  verifierConfig,
  onConfigChange,
  disabled = false,
}) => {
  const certParser = useCertParser();
  const { testKeyConnection } = useTrust();

  const [showRegistration, setShowRegistration] = useState(
    Boolean(verifierConfig?.registrationCert)
  );

  const handleAccessCertChange = useCallback((certData) => {
    onConfigChange({
      ...verifierConfig,
      accessCert: certData,
    });
  }, [verifierConfig, onConfigChange]);

  const handleKeyLocationChange = useCallback((keyConfig) => {
    onConfigChange({
      ...verifierConfig,
      keyLocation: keyConfig,
    });
  }, [verifierConfig, onConfigChange]);

  const handleRegistrationCertChange = useCallback((certData) => {
    onConfigChange({
      ...verifierConfig,
      registrationCert: certData,
    });
  }, [verifierConfig, onConfigChange]);

  const handleTestConnection = useCallback(async (keyConfig) => {
    return testKeyConnection(keyConfig);
  }, [testKeyConnection]);

  return (
    <Fade in>
      <Box data-testid="verifier-identity-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Set up your verifier identity
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Wallets need to recognize your organization before they share any data.
        </Typography>

        <Box sx={{ maxWidth: 700, mx: 'auto' }}>
          {/* Section: Verifier Access Certificate */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <VerifiedUserIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Verifier public certificate
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Upload your <strong>public certificate</strong> (not your private key). This is presented to wallets to prove who you are.
            </Typography>

            <CertificateUploader
              label="Upload public certificate file"
              helperText="A chain may include intermediate certificates. We'll detect it."
              value={verifierConfig?.accessCert}
              onChange={handleAccessCertChange}
              certParser={certParser}
              disabled={disabled}
              showChainDetails
            />
          </Paper>

          {/* Section: Key Location */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 1 }}>
              Where is your private signing key?
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Your private key never leaves your infrastructure. We just need to know how to request signatures.
            </Typography>

            <KeyLocationSelector
              value={verifierConfig?.keyLocation}
              onChange={handleKeyLocationChange}
              onTestConnection={handleTestConnection}
              disabled={disabled}
              label=""
            />
          </Paper>

          {/* Section: Optional Registration Certificate */}
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold">
                Verifier permissions (Registration)
              </Typography>
              <FormControlLabel
                control={
                  <Switch
                    checked={showRegistration}
                    onChange={(e) => setShowRegistration(e.target.checked)}
                    disabled={disabled}
                  />
                }
                label="I have a registration certificate"
                labelPlacement="start"
              />
            </Box>

            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Some ecosystems require a separate proof of what you're allowed to request.
            </Typography>

            {showRegistration ? (
              <CertificateUploader
                label="Upload registration certificate"
                value={verifierConfig?.registrationCert}
                onChange={handleRegistrationCertChange}
                certParser={certParser}
                disabled={disabled}
                showChainDetails={false}
              />
            ) : (
              <Alert severity="info" sx={{ mt: 1 }}>
                No problem. We'll use registry/registrar checks if required by the wallet ecosystem.
              </Alert>
            )}
          </Paper>
        </Box>
      </Box>
    </Fade>
  );
};

export default VerifierIdentityStep;
