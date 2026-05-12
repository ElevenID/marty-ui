/**
 * Developer Quick Start Panel
 * 
 * Shows org-scoped integration information for developers:
 * - Organization Reference (with copy button)
 * - Base API URL
 * - Example API request
 * - Links to API keys and docs
 */

import { useMemo, useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import {
  Paper,
  Typography,
  Box,
  Button,
  Collapse,
  TextField,
  IconButton,
  Tooltip,
  Skeleton,
  Alert,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link as RouterLink } from 'react-router-dom';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CodeIcon from '@mui/icons-material/Code';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import { useAuth } from '../../../hooks/useAuth';
import { getOrganizationIntegrationInfo } from '../../../services/dashboardApi';
import { formatOfficialReference } from '../../../utils/officialReferences';

/**
 * Developer Quick Start Panel Component
 */
export function DeveloperQuickStartPanel() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { data: integrationInfo, loading } = useAsyncData(
    async () => {
      if (!organizationId) return null;
      return await getOrganizationIntegrationInfo(organizationId);
    },
    [organizationId]
  );

  const [copied, setCopied] = useState(null);
  const [showTechnicalId, setShowTechnicalId] = useState(false);

  const handleCopy = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const organizationReference = formatOfficialReference(integrationInfo?.orgId || organizationId, 'organization');

  // Generate example curl request
  const exampleRequest = integrationInfo?.exampleRequest || 
    `curl -X GET "${integrationInfo?.baseUrl}/v1/organizations/${organizationId}" \
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json"`;
  const sanitizedExampleRequest = useMemo(() => {
    const identifiers = [integrationInfo?.orgId, organizationId].filter(Boolean);
    return identifiers.reduce(
      (output, identifier) => output.replaceAll(identifier, '<organization-id>'),
      exampleRequest,
    );
  }, [exampleRequest, integrationInfo?.orgId, organizationId]);

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
          {t('dashboard.developerQuickStart.unavailable')}
        </Alert>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <CodeIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('dashboard.developerQuickStart.title')}
        </Typography>
      </Box>

      <Typography variant="body2" color="text.secondary" paragraph>
        {t('dashboard.developerQuickStart.description')}
      </Typography>

      {/* Organization Reference */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
          Organization Reference
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TextField
            value={organizationReference}
            fullWidth
            size="small"
            InputProps={{
              readOnly: true,
              sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
            }}
          />
          <Tooltip title={copied === 'orgRef' ? t('dashboard.developerQuickStart.copied') : t('dashboard.developerQuickStart.copyToClipboard')}>
            <IconButton 
              size="small" 
              onClick={() => handleCopy(organizationReference, 'orgRef')}
              color={copied === 'orgRef' ? 'success' : 'default'}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
        <Button
          size="small"
          sx={{ mt: 1, px: 0 }}
          onClick={() => setShowTechnicalId((previous) => !previous)}
        >
          {showTechnicalId ? 'Hide technical organization ID' : 'Show technical organization ID'}
        </Button>

        <Collapse in={showTechnicalId}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
            <TextField
              value={integrationInfo.orgId}
              fullWidth
              size="small"
              InputProps={{
                readOnly: true,
                sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
              }}
            />
            <Tooltip title={copied === 'orgId' ? t('dashboard.developerQuickStart.copied') : t('dashboard.developerQuickStart.copyToClipboard')}>
              <IconButton 
                size="small" 
                onClick={() => handleCopy(integrationInfo.orgId, 'orgId')}
                color={copied === 'orgId' ? 'success' : 'default'}
              >
                <ContentCopyIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Collapse>
      </Box>

      {/* Base API URL */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
          {t('dashboard.developerQuickStart.baseApiUrl')}
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
          <Tooltip title={copied === 'baseUrl' ? t('dashboard.developerQuickStart.copied') : t('dashboard.developerQuickStart.copyToClipboard')}>
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
          {t('dashboard.developerQuickStart.exampleRequest')}
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
            {sanitizedExampleRequest}
          </pre>
          <Tooltip title={copied === 'example' ? t('dashboard.developerQuickStart.copied') : t('dashboard.developerQuickStart.copyToClipboard')}>
            <IconButton
              size="small"
              onClick={() => handleCopy(sanitizedExampleRequest, 'example')}
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
          to="/console/org/deploy/api-keys"
          startIcon={<VpnKeyIcon />}
          size="small"
        >
          {t('dashboard.developerQuickStart.manageApiKeys')}
        </Button>
        <Button
          variant="outlined"
          component={RouterLink}
          to="/docs"
          endIcon={<OpenInNewIcon />}
          size="small"
        >
          {t('dashboard.developerQuickStart.apiDocumentation')}
        </Button>
      </Box>
    </Paper>
  );
}

export default DeveloperQuickStartPanel;
