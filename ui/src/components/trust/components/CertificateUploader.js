/**
 * Certificate Uploader Component
 * 
 * Drag-and-drop certificate upload with:
 * - Client-side parsing via node-forge (lazy loaded)
 * - Support for PEM, DER, CER, CRT, P7B formats
 * - Parsed certificate details display
 * - Advanced view showing full chain
 * - Validity status indicators
 */

import React, { useState, useCallback, useRef } from 'react';
import {
  Box,
  Typography,
  Paper,
  Button,
  Alert,
  Chip,
  Collapse,
  CircularProgress,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Divider,
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import DescriptionIcon from '@mui/icons-material/Description';
import { SUPPORTED_CERT_EXTENSIONS } from '../ports/ICertParser';

/**
 * Format date for display.
 */
const formatDate = (date) => {
  if (!date) return 'Unknown';
  const d = new Date(date);
  return d.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

/**
 * Get validity status display.
 */
const getValidityStatus = (certData) => {
  if (!certData) return { label: 'Unknown', color: 'default', icon: null };
  
  if (!certData.isValid) {
    return { label: 'Invalid', color: 'error', icon: <ErrorIcon fontSize="small" /> };
  }
  
  if (certData.isExpiringSoon) {
    return { label: 'Expiring Soon', color: 'warning', icon: <WarningIcon fontSize="small" /> };
  }
  
  return { label: 'Valid', color: 'success', icon: <CheckCircleIcon fontSize="small" /> };
};

/**
 * Parsed certificate info display.
 */
const CertificateInfo = ({ certData, onRemove, showAdvanced, onToggleAdvanced }) => {
  const { label, color, icon } = getValidityStatus(certData);

  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <DescriptionIcon color="primary" />
          <Box>
            <Typography variant="subtitle2" fontWeight="bold">
              {certData.subject || 'Certificate'}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Issued by: {certData.issuer || 'Unknown'}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip icon={icon} label={label} color={color} size="small" />
          {onRemove && (
            <IconButton size="small" onClick={onRemove} aria-label="Remove certificate">
              <DeleteIcon fontSize="small" />
            </IconButton>
          )}
        </Box>
      </Box>

      <Box sx={{ mt: 2, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        <Box>
          <Typography variant="caption" color="text.secondary">Valid From</Typography>
          <Typography variant="body2">{formatDate(certData.validFrom)}</Typography>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">Valid Until</Typography>
          <Typography variant="body2">{formatDate(certData.validUntil)}</Typography>
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">Algorithm</Typography>
          <Typography variant="body2">{certData.algorithm || 'Unknown'}</Typography>
        </Box>
      </Box>

      {onToggleAdvanced && (
        <Button
          size="small"
          onClick={onToggleAdvanced}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          sx={{ mt: 1 }}
        >
          {showAdvanced ? 'Hide chain details' : 'Show chain details'}
        </Button>
      )}

      <Collapse in={showAdvanced}>
        <Divider sx={{ my: 2 }} />
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            Serial Number
          </Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
            {certData.serialNumber || 'Unknown'}
          </Typography>
        </Box>
        <Box sx={{ mt: 1 }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            SHA-256 Fingerprint
          </Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
            {certData.fingerprint || 'Unknown'}
          </Typography>
        </Box>
        {certData.chain && certData.chain.length > 0 && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
              Certificate Chain ({certData.chain.length} intermediate)
            </Typography>
            <List dense disablePadding>
              {certData.chain.map((chainCert, index) => (
                <ListItem key={index} disableGutters>
                  <ListItemText
                    primary={chainCert.subject}
                    secondary={`Expires: ${formatDate(chainCert.validUntil)}`}
                    primaryTypographyProps={{ variant: 'body2' }}
                    secondaryTypographyProps={{ variant: 'caption' }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        )}
      </Collapse>
    </Paper>
  );
};

/**
 * Certificate Uploader Component.
 * 
 * @param {Object} props
 * @param {string} props.label - Upload label text
 * @param {string} [props.helperText] - Helper text below label
 * @param {import('../ports/types').CertificateData} [props.value] - Current certificate data
 * @param {function} props.onChange - Callback when certificate is uploaded/removed
 * @param {Object} props.certParser - ICertParser implementation
 * @param {boolean} [props.disabled] - Disable upload
 * @param {string} [props.error] - Error message
 * @param {boolean} [props.required] - Required field
 * @param {boolean} [props.showChainDetails] - Enable chain details view
 */
const CertificateUploader = ({
  label = 'Upload certificate file',
  helperText,
  value,
  onChange,
  certParser,
  disabled = false,
  error,
  required = false,
  showChainDetails = true,
}) => {
  const [loading, setLoading] = useState(false);
  const [parseError, setParseError] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const fileInputRef = useRef(null);

  const acceptedExtensions = SUPPORTED_CERT_EXTENSIONS.join(',');

  const handleFile = useCallback(async (file) => {
    if (!file || !certParser) return;

    setLoading(true);
    setParseError(null);

    try {
      // Read and convert file to PEM
      const pemData = await certParser.readCertificateFile(file);
      
      // Parse the certificate(s)
      const certs = await certParser.parseChain(pemData);
      
      if (certs.length === 0) {
        throw new Error('No valid certificates found in file');
      }

      // First cert is the main one, rest are chain
      const mainCert = {
        ...certs[0],
        chain: certs.slice(1),
        pemData,
      };

      onChange(mainCert);
    } catch (err) {
      setParseError(err.message);
      onChange(null);
    } finally {
      setLoading(false);
    }
  }, [certParser, onChange]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    
    if (disabled) return;

    const file = e.dataTransfer?.files?.[0];
    if (file) {
      handleFile(file);
    }
  }, [disabled, handleFile]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    if (!disabled) {
      setDragOver(true);
    }
  }, [disabled]);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleInputChange = useCallback((e) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFile(file);
    }
    // Reset input so same file can be selected again
    e.target.value = '';
  }, [handleFile]);

  const handleRemove = useCallback(() => {
    onChange(null);
    setParseError(null);
  }, [onChange]);

  const handleClick = () => {
    if (!disabled) {
      fileInputRef.current?.click();
    }
  };

  const displayError = error || parseError;

  return (
    <Box>
      <Typography variant="body2" fontWeight="medium" sx={{ mb: 0.5 }}>
        {label}
        {required && <Typography component="span" color="error.main"> *</Typography>}
      </Typography>
      
      {helperText && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
          {helperText}
        </Typography>
      )}

      {!value && (
        <Paper
          variant="outlined"
          sx={{
            p: 3,
            textAlign: 'center',
            cursor: disabled ? 'not-allowed' : 'pointer',
            bgcolor: dragOver ? 'action.hover' : 'background.paper',
            borderStyle: 'dashed',
            borderColor: displayError ? 'error.main' : dragOver ? 'primary.main' : 'divider',
            opacity: disabled ? 0.6 : 1,
            transition: 'all 0.2s ease',
            '&:hover': disabled ? {} : {
              borderColor: 'primary.main',
              bgcolor: 'action.hover',
            },
          }}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={handleClick}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={acceptedExtensions}
            onChange={handleInputChange}
            style={{ display: 'none' }}
            disabled={disabled}
          />

          {loading ? (
            <CircularProgress size={32} />
          ) : (
            <>
              <CloudUploadIcon sx={{ fontSize: 40, color: 'text.secondary', mb: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Drag and drop a certificate file, or click to browse
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Accepts: {SUPPORTED_CERT_EXTENSIONS.join(', ')}
              </Typography>
            </>
          )}
        </Paper>
      )}

      {value && (
        <CertificateInfo
          certData={value}
          onRemove={disabled ? null : handleRemove}
          showAdvanced={showAdvanced}
          onToggleAdvanced={showChainDetails ? () => setShowAdvanced(!showAdvanced) : null}
        />
      )}

      {displayError && (
        <Alert severity="error" sx={{ mt: 1 }}>
          {displayError}
        </Alert>
      )}
    </Box>
  );
};

export default CertificateUploader;
