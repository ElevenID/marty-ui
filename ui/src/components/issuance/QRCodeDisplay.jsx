/**
 * QR Code Display Component
 * 
 * Displays OID4VCI credential offer QR codes with:
 * - Auto-refresh timer for expiry
 * - Deep link fallback button
 * - Copy link action
 * - Scan status indicator (SSE-driven)
 * - Wallet instructions tooltip
 */

import { useState, useEffect, useRef } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Stack,
  Tooltip,
  Typography,
  Alert,
  LinearProgress,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  ContentCopy as ContentCopyIcon,
  Refresh as RefreshIcon,
  QrCode2 as QrCode2Icon,
  Info as InfoIcon,
  PhoneAndroid as PhoneAndroidIcon,
} from '@mui/icons-material';

/**
 * Format time remaining as human-readable string
 */
const formatTimeRemaining = (expiresAt) => {
  if (!expiresAt) return 'Unknown';
  
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return 'Expired';
  
  const minutes = Math.floor(diff / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);
  
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
};

/**
 * Calculate progress percentage (0-100)
 */
const calculateProgress = (expiresAt, createdAt) => {
  if (!expiresAt || !createdAt) return 100;
  
  const now = new Date();
  const expiry = new Date(expiresAt);
  const created = new Date(createdAt);
  
  const total = expiry - created;
  const remaining = expiry - now;
  
  if (remaining <= 0) return 0;
  if (remaining >= total) return 100;
  
  return (remaining / total) * 100;
};

const QRCodeDisplay = ({
  offerUri,
  qrPayload = null,  // Base64 data URI or null
  expiresAt,
  createdAt = null,
  status = 'active',  // active, scanned, expired
  onScanned = null,
  onRefresh = null,
  showDeepLink = true,
  showCopyLink = true,
  size = 256,
  title = 'Scan with Wallet',
  instructions = 'Open your digital wallet app and scan this QR code to receive your credential.',
  // Branding/styling props (from deployment profile)
  branding = null,  // BrandingConfiguration object
  fgColor = '#000000',
  bgColor = '#ffffff',
  borderColor = null,
  borderWidth = 2,
  logoUrl = null,
  customInstructions = null,
}) => {
  const [timeRemaining, setTimeRemaining] = useState('');
  const [progress, setProgress] = useState(100);
  const [copied, setCopied] = useState(false);
  const timerRef = useRef(null);
  
  // Apply branding overrides if provided
  const effectiveSize = branding?.qr_size || size;
  const effectiveFgColor = branding?.qr_foreground_color || fgColor;
  const effectiveBgColor = branding?.qr_background_color || bgColor;
  const effectiveBorderColor = branding?.qr_border_color || borderColor;
  const effectiveBorderWidth = branding?.qr_border_width ?? borderWidth;
  const effectiveLogoUrl = branding?.qr_logo_url || logoUrl;
  const effectiveInstructions = branding?.qr_custom_instruction_text || customInstructions || instructions;
  const showInstructions = branding?.qr_show_instructions ?? true;

  // Update timer every second
  useEffect(() => {
    const updateTimer = () => {
      setTimeRemaining(formatTimeRemaining(expiresAt));
      setProgress(calculateProgress(expiresAt, createdAt));
    };

    updateTimer();
    timerRef.current = setInterval(updateTimer, 1000);

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [expiresAt, createdAt]);

  // Notify parent when scanned (SSE would update status)
  useEffect(() => {
    if (status === 'scanned' && onScanned) {
      onScanned();
    }
  }, [status, onScanned]);

  // Handle copy link
  const handleCopyLink = async () => {
    try {
      // Always copy the deep link format for mobile sharing
      let linkToCopy = offerUri;
      if (!offerUri.startsWith('openid-credential-offer://')) {
        linkToCopy = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
      }
      await navigator.clipboard.writeText(linkToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Handle deep link (mobile)
  const handleOpenLink = () => {
    // If already in deep link format, use directly
    // Otherwise, convert http:// URL to openid-credential-offer:// URL
    let deepLinkUrl = offerUri;
    if (!offerUri.startsWith('openid-credential-offer://')) {
      deepLinkUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
    }
    window.location.href = deepLinkUrl;
  };

  // Determine status color and icon
  const getStatusDisplay = () => {
    switch (status) {
      case 'scanned':
        return {
          color: 'success',
          icon: <CheckCircleIcon />,
          label: 'Scanned',
          message: 'Wallet has received the credential offer',
        };
      case 'expired':
        return {
          color: 'error',
          icon: <RefreshIcon />,
          label: 'Expired',
          message: 'This QR code has expired',
        };
      default:
        return {
          color: 'primary',
          icon: <QrCode2Icon />,
          label: 'Active',
          message: 'Waiting for wallet to scan',
        };
    }
  };

  const statusDisplay = getStatusDisplay();
  const isExpired = status === 'expired' || progress === 0;

  return (
    <Card elevation={2}>
      <CardContent>
        <Stack spacing={2}>
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <QrCode2Icon />
              {title}
            </Typography>
            <Chip
              icon={statusDisplay.icon}
              label={statusDisplay.label}
              color={statusDisplay.color}
              size="small"
            />
          </Box>

          {/* Instructions */}
          {showInstructions && effectiveInstructions && (
            <Alert severity="info" icon={<InfoIcon />} sx={{ fontSize: '0.875rem' }}>
              {effectiveInstructions}
            </Alert>
          )}

          {/* QR Code */}
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              p: 3,
              bgcolor: effectiveBgColor,
              borderRadius: 2,
              border: effectiveBorderWidth > 0 ? `${effectiveBorderWidth}px solid` : 'none',
              borderColor: effectiveBorderColor || (isExpired ? 'error.light' : status === 'scanned' ? 'success.light' : 'primary.light'),
              position: 'relative',
              opacity: isExpired ? 0.4 : 1,
            }}
          >
            {qrPayload ? (
              // Use pre-generated QR image
              <Box sx={{ position: 'relative' }}>
                <img
                  src={qrPayload}
                  alt="Credential Offer QR Code"
                  style={{ width: effectiveSize, height: effectiveSize }}
                />
                {effectiveLogoUrl && (
                  <Box
                    sx={{
                      position: 'absolute',
                      top: '50%',
                      left: '50%',
                      transform: 'translate(-50%, -50%)',
                      width: `${20}%`,
                      height: `${20}%`,
                      bgcolor: 'white',
                      borderRadius: 1,
                      p: 0.5,
                      boxShadow: 2,
                    }}
                  >
                    <img
                      src={effectiveLogoUrl}
                      alt="Organization Logo"
                      style={{
                        width: '100%',
                        height: '100%',
                        objectFit: 'contain',
                      }}
                    />
                  </Box>
                )}
              </Box>
            ) : (
              // Generate QR code from URI
              <Box sx={{ position: 'relative' }}>
                <QRCodeSVG
                  value={offerUri}
                  size={effectiveSize}
                  level={branding?.qr_error_correction || "H"}
                  includeMargin={true}
                  bgColor={effectiveBgColor}
                  fgColor={effectiveFgColor}
                />
                {effectiveLogoUrl && (
                  <Box
                    sx={{
                      position: 'absolute',
                      top: '50%',
                      left: '50%',
                      transform: 'translate(-50%, -50%)',
                      width: `${branding?.qr_logo_size_percent || 20}%`,
                      height: `${branding?.qr_logo_size_percent || 20}%`,
                      bgcolor: 'white',
                      borderRadius: 1,
                      p: 0.5,
                      boxShadow: 2,
                    }}
                  >
                    <img
                      src={effectiveLogoUrl}
                      alt="Organization Logo"
                      style={{
                        width: '100%',
                        height: '100%',
                        objectFit: 'contain',
                      }}
                    />
                  </Box>
                )}
              </Box>
            )}

            {/* Overlay for scanned state */}
            {status === 'scanned' && (
              <Box
                sx={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  bgcolor: 'rgba(76, 175, 80, 0.9)',
                  borderRadius: 2,
                }}
              >
                <CheckCircleIcon sx={{ fontSize: 80, color: 'white' }} />
              </Box>
            )}

            {/* Overlay for expired state */}
            {isExpired && (
              <Box
                sx={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexDirection: 'column',
                  gap: 1,
                }}
              >
                <Typography variant="h5" color="error" fontWeight="bold">
                  EXPIRED
                </Typography>
                {onRefresh && (
                  <Button
                    variant="contained"
                    startIcon={<RefreshIcon />}
                    onClick={onRefresh}
                    size="small"
                  >
                    Generate New
                  </Button>
                )}
              </Box>
            )}
          </Box>

          {/* Timer Progress Bar */}
          {!isExpired && (
            <Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  Time Remaining
                </Typography>
                <Typography variant="caption" fontWeight="medium">
                  {timeRemaining}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={progress}
                color={progress < 20 ? 'error' : progress < 50 ? 'warning' : 'primary'}
                sx={{ height: 8, borderRadius: 1 }}
              />
            </Box>
          )}

          {/* Actions */}
          <Stack direction="row" spacing={1} justifyContent="center">
            {showCopyLink && (
              <Tooltip title={copied ? 'Copied!' : 'Copy Link'}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<ContentCopyIcon />}
                  onClick={handleCopyLink}
                  disabled={isExpired}
                  color={copied ? 'success' : 'primary'}
                >
                  {copied ? 'Copied' : 'Copy Link'}
                </Button>
              </Tooltip>
            )}

            {showDeepLink && (
              <Tooltip title="Open in mobile wallet app">
                <Button
                  variant="contained"
                  size="small"
                  startIcon={<PhoneAndroidIcon />}
                  onClick={handleOpenLink}
                  disabled={isExpired}
                >
                  Open in Wallet
                </Button>
              </Tooltip>
            )}
          </Stack>

          {/* Status Message */}
          {statusDisplay.message && (
            <Typography
              variant="body2"
              color="text.secondary"
              align="center"
              sx={{ fontStyle: 'italic' }}
            >
              {statusDisplay.message}
            </Typography>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
};

export default QRCodeDisplay;
