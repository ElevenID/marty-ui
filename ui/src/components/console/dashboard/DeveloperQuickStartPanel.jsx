/**
 * Developer Quick Start Panel
 * 
 * Shows org-scoped integration information for developers:
 * - Organization ID (with copy button)
 * - Base API URL
 * - Example API request
 * - Links to API keys and docs
 */

import { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  Button,
  TextField,
  IconButton,
  Tooltip,
  Skeleton,
  Alert,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CodeIcon from '@mui/icons-material/Code';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import { useAuth } from '../../../hooks/useAuth';
import { getOrganizationIntegrationInfo } from '../../../services/dashboardApi';

/**
 * Developer Quick Start Panel Component
 */
export function DeveloperQuickStartPanel() {
  const { organizationId } = useAuth();
  const [integrationInfo, setIntegrationInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(null);

  useEffect(() => {
    async function fetchIntegrationInfo() {
      if (!organizationId) return;

      try {
        const info = await getOrganizationIntegrationInfo(organizationId);
        setIntegrationInfo(info);
      } catch (error) {
        console.error('Failed to load integration info:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchIntegrationInfo();
  }, [organizationId]);

  const handleCopy = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  // Generate example curl request
  const exampleRequest = integrationInfo?.exampleRequest || 
    `curl -X GET "${integrationInfo?.baseUrl}/v1/organizations/${organizationId}" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json"`;

  if (loading) {
    return (
      <Paper sx={{ p: 3 }}>
        <Skeleton variant="text" width={200} height={32} />
        <Skeleton variant="rectangular" height={150} sx={{ mt: 2 }} />
      </Paper>
    );
  }

  if (!integrationInfo) {
    return (
      <Paper sx={{ p: 3 }}>
        <Alert severity="info">
          Integration information unavailable
        </Alert>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <CodeIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          Developer Quick Start
        </Typography>
      </Box>

      <Typography variant="body2" color="text.secondary" paragraph>
        Org-scoped integration details for API development
      </Typography>

      {/* Organization ID */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
          Organization ID
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TextField
            value={integrationInfo.orgId}
            fullWidth
            size="small"
            InputProps={{
              readOnly: true,
              sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
            }}
          />
          <Tooltip title={copied === 'orgId' ? 'Copied!' : 'Copy to clipboard'}>
            <IconButton 
              size="small" 
              onClick={() => handleCopy(integrationInfo.orgId, 'orgId')}
              color={copied === 'orgId' ? 'success' : 'default'}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Base API URL */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
          Base API URL
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TextField
            value={integrationInfo.baseUrl}
            fullWidth
            size="small"
            InputProps={{
              readOnly: true,
              sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
            }}
          />
          <Tooltip title={copied === 'baseUrl' ? 'Copied!' : 'Copy to clipboard'}>
            <IconButton 
              size="small" 
              onClick={() => handleCopy(integrationInfo.baseUrl, 'baseUrl')}
              color={copied === 'baseUrl' ? 'success' : 'default'}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Example Request */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
          Example API Request (curl)
        </Typography>
        <Box 
          sx={{ 
            position: 'relative',
            bgcolor: 'grey.900', 
            color: 'grey.100',
            p: 2, 
            borderRadius: 1,
            fontFamily: 'monospace',
            fontSize: '0.75rem',
            overflow: 'auto',
          }}
        >
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {exampleRequest}
          </pre>
          <Tooltip title={copied === 'example' ? 'Copied!' : 'Copy to clipboard'}>
            <IconButton
              size="small"
              onClick={() => handleCopy(exampleRequest, 'example')}
              sx={{ 
                position: 'absolute', 
                top: 8, 
                right: 8,
                color: 'grey.100',
                '&:hover': { bgcolor: 'grey.800' },
              }}
              color={copied === 'example' ? 'success' : 'default'}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Action Buttons */}
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
        <Button
          variant="outlined"
          component={RouterLink}
          to="/console/deploy/api-keys"
          startIcon={<VpnKeyIcon />}
          size="small"
        >
          Manage API Keys
        </Button>
        <Button
          variant="outlined"
          component={RouterLink}
          to="/docs"
          endIcon={<OpenInNewIcon />}
          size="small"
        >
          API Documentation
        </Button>
      </Box>
    </Paper>
  );
}

export default DeveloperQuickStartPanel;
