/**
 * Issuer Identity Step Component
 * 
 * Step 3 of trust setup: Configure issuer identity.
 * - Upload issuer access certificate
 * - Configure credential signing key location
 */

import React, { useCallback } from 'react';
import {
  Box,
  Typography,
  Fade,
  Paper,
  Alert,
} from '@mui/material';
import BadgeIcon from '@mui/icons-material/Badge';
import CreateIcon from '@mui/icons-material/Create';
import { CertificateUploader, KeyLocationSelector } from '../../trust/components';
import { useCertParser, useTrust } from '../../trust';

/**
 * Issuer Identity Step Component.
 * 
 * @param {Object} props
 * @param {Object} props.issuerConfig - Current issuer configuration
 * @param {function} props.onConfigChange - Callback when config changes
 * @param {boolean} [props.disabled] - Disable inputs
 */
const IssuerIdentityStep = ({
  issuerConfig,
  onConfigChange,
  disabled = false,
}) => {
  const certParser = useCertParser();
  const { testKeyConnection } = useTrust();

  const handleAccessCertChange = useCallback((certData) => {
    onConfigChange({
      ...issuerConfig,
      accessCert: certData,
    });
  }, [issuerConfig, onConfigChange]);

  const handleSigningCertChange = useCallback((certData) => {
    onConfigChange({
      ...issuerConfig,
      signingCert: certData,
    });
  }, [issuerConfig, onConfigChange]);

  const handleKeyLocationChange = useCallback((keyConfig) => {
    onConfigChange({
      ...issuerConfig,
      keyLocation: keyConfig,
    });
  }, [issuerConfig, onConfigChange]);

  const handleTestConnection = useCallback(async (keyConfig) => {
    return testKeyConnection(keyConfig);
  }, [testKeyConnection]);

  return (
    <Fade in>
      <Box data-testid="issuer-identity-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Set up your issuer identity
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          This is how wallets and verifiers trust credentials you issue.
        </Typography>

        <Box sx={{ maxWidth: 700, mx: 'auto' }}>
          {/* Section: Issuer Access Certificate */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <BadgeIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Issuer certificate (Access Certificate)
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Used to authenticate your issuer service during wallet interactions.
            </Typography>

            <CertificateUploader
              label="Upload issuer access certificate"
              value={issuerConfig?.accessCert}
              onChange={handleAccessCertChange}
              certParser={certParser}
              disabled={disabled}
              showChainDetails
            />
          </Paper>

          {/* Section: Credential Signing Key */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <CreateIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Credential signing key
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              This key signs the credentials themselves. It should be protected like a "company seal."
            </Typography>

            <KeyLocationSelector
              value={issuerConfig?.keyLocation}
              onChange={handleKeyLocationChange}
              onTestConnection={handleTestConnection}
              disabled={disabled}
              label=""
              showAlgorithm
            />
          </Paper>

          {/* Section: Signing Certificate (matches the key) */}
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}>
              Signing certificate (public)
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Upload the public certificate that matches the signing key. This is distributed to verifiers.
            </Typography>

            <CertificateUploader
              label="Upload signing certificate"
              value={issuerConfig?.signingCert}
              onChange={handleSigningCertChange}
              certParser={certParser}
              disabled={disabled}
              showChainDetails
            />

            {issuerConfig?.keyLocation?.source === 'marty_generated' && !issuerConfig?.signingCert && (
              <Alert severity="info" sx={{ mt: 2 }}>
                When using platform-managed keys, we'll generate a certificate automatically.
              </Alert>
            )}
          </Paper>
        </Box>
      </Box>
    </Fade>
  );
};

export default IssuerIdentityStep;
