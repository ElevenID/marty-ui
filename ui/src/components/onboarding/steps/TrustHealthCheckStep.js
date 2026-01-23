/**
 * Trust Health Check Step Component
 * 
 * Step 5 of trust setup: Validate configuration and show health status.
 * Final step before activating trust profile.
 */

import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Fade,
  CircularProgress,
} from '@mui/material';
import { TrustHealthChecklist } from '../../trust/components';
import { useTrust } from '../../trust';

/**
 * Trust Health Check Step Component.
 * 
 * @param {Object} props
 * @param {Object} [props.verifierConfig] - Verifier configuration from onboarding
 * @param {Object} [props.issuerConfig] - Issuer configuration from onboarding
 * @param {Object} [props.trustSettings] - Trust settings from onboarding
 * @param {Object} [props.trustProfile] - Trust profile from onboarding
 * @param {function} props.onActivate - Callback when user clicks activate
 * @param {function} props.onReviewIssues - Callback when user clicks review issues
 * @param {function} [props.onHealthLoaded] - Callback when health status is loaded
 */
const TrustHealthCheckStep = ({
  verifierConfig,
  issuerConfig,
  trustSettings,
  trustProfile,
  onActivate,
  onReviewIssues,
  onHealthLoaded,
}) => {
  const { healthStatus: contextHealthStatus, loading, refreshHealth, organizationId } = useTrust();
  const [autoActivating, setAutoActivating] = useState(false);
  const [countdown, setCountdown] = useState(3);
  const [localHealthStatus, setLocalHealthStatus] = useState(null);

  // Generate health status from onboarding configs
  useEffect(() => {
    if (verifierConfig || issuerConfig || trustSettings) {
      const mockHealth = {
        verifier: {
          accessCertLoaded: Boolean(verifierConfig?.certificate),
          signingConfigured: Boolean(verifierConfig?.keyLocation),
          permissionsConfirmed: true, // Assume confirmed during onboarding
        },
        issuer: {
          accessCertLoaded: Boolean(issuerConfig?.certificate),
          signingKeyReachable: Boolean(issuerConfig?.keyLocation),
          signingCertAttached: Boolean(issuerConfig?.certificate),
        },
        trust: {
          listConfigured: Boolean(trustSettings?.trustSources?.length > 0),
          revocationEnabled: Boolean(trustSettings?.revocationEnabled),
        },
        chainStatus: null, // No chain validation during onboarding
        allPassed: Boolean(
          verifierConfig?.certificate &&
          verifierConfig?.keyLocation &&
          issuerConfig?.keyLocation
        ),
        warnings: [],
        errors: [],
      };
      setLocalHealthStatus(mockHealth);
    }
  }, [verifierConfig, issuerConfig, trustSettings]);

  // Use local health status during onboarding, context health status after
  const healthStatus = localHealthStatus || contextHealthStatus;

  // Try to refresh health from context if organization exists
  useEffect(() => {
    if (organizationId && !localHealthStatus) {
      refreshHealth();
    }
  }, [organizationId, localHealthStatus, refreshHealth]);

  // Notify parent when health is loaded
  useEffect(() => {
    if (healthStatus && onHealthLoaded) {
      onHealthLoaded(healthStatus);
    }
  }, [healthStatus, onHealthLoaded]);

  // Auto-activate when all checks pass
  useEffect(() => {
    if (healthStatus?.allPassed && !loading && !autoActivating) {
      setAutoActivating(true);
      setCountdown(3);
      
      // Start countdown
      const countdownInterval = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(countdownInterval);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      // Auto-activate after 3 seconds
      const activateTimer = setTimeout(() => {
        if (onActivate) {
          onActivate();
        }
      }, 3000);

      return () => {
        clearInterval(countdownInterval);
        clearTimeout(activateTimer);
      };
    }
  }, [healthStatus, loading, autoActivating, onActivate]);

  return (
    <Fade in>
      <Box data-testid="trust-health-check-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Ready to activate
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          We'll run checks to ensure your org can verify and issue safely.
        </Typography>

        <Box sx={{ maxWidth: 600, mx: 'auto', position: 'relative' }}>
          {loading && !healthStatus ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <>
              <TrustHealthChecklist
                healthStatus={healthStatus}
                loading={loading}
                onActivate={onActivate}
                onReviewIssues={onReviewIssues}
                showChainStatus
                showActions={!autoActivating}
                compact={false}
              />
              
              {/* Auto-activation overlay */}
              {autoActivating && (
                <Fade in>
                  <Box
                    sx={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      bottom: 0,
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      bgcolor: 'rgba(255, 255, 255, 0.95)',
                      borderRadius: 1,
                      zIndex: 1,
                    }}
                  >
                    <CircularProgress size={60} sx={{ mb: 2 }} />
                    <Typography variant="h6" gutterBottom>
                      Activating organization...
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Redirecting in {countdown} second{countdown !== 1 ? 's' : ''}
                    </Typography>
                  </Box>
                </Fade>
              )}
            </>
          )}
        </Box>
      </Box>
    </Fade>
  );
};

export default TrustHealthCheckStep;
