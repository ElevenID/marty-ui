/**
 * Trust Sources Step - Trust Profile Wizard
 *
 * Define trusted issuers (DIDs, X.509 certificates, certificate authorities, etc.)
 * This step is optional and can be skipped.
 */

import { useRef, useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Checkbox,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Chip,
  Alert,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  FormControlLabel,
  InputLabel,
  Select,
  MenuItem,
  Paper,
  CircularProgress,
  Stack,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import InfoIcon from '@mui/icons-material/Info';
import CloudDownloadIcon from '@mui/icons-material/CloudDownload';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import LinkIcon from '@mui/icons-material/Link';
import { useTranslation } from 'react-i18next';

const DEFAULT_REGISTRIES = [
  {
    id: 'ICAO_PKD',
    name: 'ICAO Public Key Directory',
    description: 'ePassports and travel documents',
    frameworks: ['ICAO'],
    credential_types: ['MDOC'],
  },
  {
    id: 'EU_TRUST_LIST',
    name: 'EU List of Trusted Lists (LoTL)',
    description: 'EU credential issuers',
    frameworks: ['EUDI'],
    credential_types: ['SD_JWT_VC', 'VC_JWT'],
  },
  {
    id: 'AAMVA',
    name: 'AAMVA Mobile Driver License',
    description: 'Mobile driver licenses and travel documents',
    frameworks: ['AAMVA'],
    credential_types: ['MDOC', 'SD_JWT_VC'],
  },
];

const splitCsvLine = (line) => line.split(',').map((value) => value.trim());

const toArray = (value) => {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter(Boolean);
  }

  return String(value)
    .split(/[|;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
};

const normalizeCertSource = (entry, importSource = 'manual') => {
  const pem = String(entry.certificate_pem || '').trim();
  if (!pem) return null;
  return {
    certificate_pem: pem,
    source_type: 'ROOT_CA',
    name: entry.name || '',
    description: entry.description || '',
    added_at: entry.added_at || new Date().toISOString(),
    metadata: {
      country: entry.metadata?.country || entry.country || '',
      credential_types: toArray(entry.metadata?.credential_types || entry.credential_types),
      source: entry.metadata?.source || entry.source || importSource,
    },
  };
};

const normalizeIssuer = (issuer, importSource = 'manual') => {
  // Delegate PEM content to cert normalizer
  const rawDid = String(issuer.did || issuer.issuer_did || '').trim();
  if (rawDid.startsWith('-----BEGIN') || issuer.certificate_pem) {
    return normalizeCertSource({ ...issuer, certificate_pem: issuer.certificate_pem || rawDid }, importSource);
  }

  const did = rawDid;
  if (!did) {
    return null;
  }

  return {
    did,
    source_type: 'PINNED_ISSUER',
    name: issuer.name || '',
    description: issuer.description || '',
    added_at: issuer.added_at || new Date().toISOString(),
    metadata: {
      country: issuer.metadata?.country || issuer.country || '',
      credential_types: toArray(issuer.metadata?.credential_types || issuer.credential_types),
      source: issuer.metadata?.source || issuer.source || importSource,
      url: issuer.metadata?.url || issuer.url || '',
    },
  };
};

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

const parseImportContent = (content, importSource = 'file') => {
  const trimmed = String(content || '').trim();
  if (!trimmed) {
    return [];
  }

  // PEM file — extract all certificate blocks before any other parsing
  if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
    const pemBlocks = trimmed.match(PEM_CERT_RE) || [];
    return pemBlocks
      .map((pem) => normalizeCertSource({ certificate_pem: pem }, importSource))
      .filter(Boolean);
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed);
    const list = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed.issuers)
        ? parsed.issuers
        : [];

    return list
      .map((item) => (typeof item === 'string' ? { did: item } : item))
      .map((issuer) => normalizeIssuer(issuer, importSource))
      .filter(Boolean);
  }

  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) {
    return [];
  }

  const firstLine = lines[0].toLowerCase();
  const hasCsvHeader = firstLine.includes('did') && firstLine.includes(',');

  if (hasCsvHeader) {
    const headers = splitCsvLine(lines[0]).map((value) => value.toLowerCase());
    return lines
      .slice(1)
      .map((line) => {
        const values = splitCsvLine(line);
        const row = {};
        headers.forEach((header, index) => {
          row[header] = values[index] || '';
        });

        return normalizeIssuer(
          {
            did: row.did || row.issuer_did,
            certificate_pem: row.certificate_pem || row.cert_pem,
            name: row.name,
            description: row.description,
            country: row.country,
            credential_types: row.credential_types,
            source: row.source,
            url: row.url,
          },
          importSource,
        );
      })
      .filter(Boolean);
  }

  return lines
    .map((line) => normalizeIssuer({ did: line }, importSource))
    .filter(Boolean);
};

const getRegistrySyncSummary = (registryImport) => {
  if (registryImport.sync_enabled === false) {
    return 'Manual sync only';
  }

  const intervalHours = Number(registryImport.sync_interval_hours || 24);
  return `Auto-sync enabled (${intervalHours}h)`;
};

const TrustSourcesStep = ({ data, onChange }) => {
  const { t } = useTranslation(['console', 'common']);
  const [newIssuerDid, setNewIssuerDid] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [openRegistryDialog, setOpenRegistryDialog] = useState(false);
  const [selectedRegistry, setSelectedRegistry] = useState('');
  const [availableRegistries, setAvailableRegistries] = useState([]);
  const [loadingRegistries, setLoadingRegistries] = useState(false);
  const [registryImports, setRegistryImports] = useState(data.registry_imports || []);
  const [newIssuerName, setNewIssuerName] = useState('');
  const [newIssuerCountry, setNewIssuerCountry] = useState('');
  const [newIssuerCredentialTypes, setNewIssuerCredentialTypes] = useState('');
  const [importUrl, setImportUrl] = useState('');
  const [importFeedback, setImportFeedback] = useState({ type: '', message: '' });
  const [loadingUrlImport, setLoadingUrlImport] = useState(false);
  const [entryType, setEntryType] = useState('did'); // 'did' | 'x509'
  const [newCertPem, setNewCertPem] = useState('');
  const fileInputRef = useRef(null);

  const trustedIssuers = data.trusted_issuers || [];
  const allowAllIssuers = data.allow_all_issuers === true;
  const hasConfiguredPinnedIssuers = trustedIssuers.length > 0;

  const getEntryKey = (entry) => {
    if (entry.certificate_pem) {
      return `cert:${String(entry.certificate_pem).replace(/\s/g, '').slice(0, 64)}`;
    }
    return `did:${String(entry.did || entry.issuer_did || '').trim()}`;
  };

  const updateTrustedIssuers = (nextTrustedIssuers) => {
    onChange({ trusted_issuers: nextTrustedIssuers, allow_all_issuers: false });
  };

  const mergeIssuers = (incomingIssuers) => {
    const existing = [...trustedIssuers];
    const existingKeys = new Set(existing.map(getEntryKey));
    let added = 0;

    incomingIssuers.forEach((issuer) => {
      const normalized = normalizeIssuer(issuer, issuer?.metadata?.source || 'import');
      if (!normalized || existingKeys.has(getEntryKey(normalized))) {
        return;
      }
      existing.push(normalized);
      existingKeys.add(getEntryKey(normalized));
      added += 1;
    });

    if (added > 0) {
      updateTrustedIssuers(existing);
    }

    return added;
  };

  // Fetch available registries when dialog opens
  const handleOpenRegistryDialog = async () => {
    setLoadingRegistries(true);
    try {
      const framework = data.profile_type || 'CUSTOM';
      const filtered = framework === 'CUSTOM'
        ? DEFAULT_REGISTRIES
        : DEFAULT_REGISTRIES.filter((registry) => registry.frameworks.includes(framework));
      setAvailableRegistries(filtered);
      setOpenRegistryDialog(true);
    } finally {
      setLoadingRegistries(false);
    }
  };

  const handleAddRegistry = async () => {
    if (!selectedRegistry) return;

    // Check for duplicates
    if (registryImports.some((imp) => imp.registry_type === selectedRegistry)) {
      return;
    }

    const newImport = {
      registry_type: selectedRegistry,
      sync_enabled: true,
      sync_interval_hours: 24,
      credential_format_filter: [],
      added_at: new Date().toISOString(),
      metadata: availableRegistries.find((registry) => registry.id === selectedRegistry) || {},
    };

    setRegistryImports([...registryImports, newImport]);
    onChange({ registry_imports: [...registryImports, newImport] });
    setSelectedRegistry('');
    setOpenRegistryDialog(false);
  };

  const handleRemoveRegistry = (index) => {
    const newImports = registryImports.filter((_, i) => i !== index);
    setRegistryImports(newImports);
    onChange({ registry_imports: newImports });
  };

  const handleAddIssuer = () => {
    if (entryType === 'x509') {
      if (!newCertPem.trim()) return;
      const entry = normalizeCertSource(
        {
          certificate_pem: newCertPem.trim(),
          name: newIssuerName.trim(),
          country: newIssuerCountry.trim(),
          credential_types: newIssuerCredentialTypes,
        },
        'manual',
      );
      if (!entry) return;
      const trusted = [...trustedIssuers];
      const key = getEntryKey(entry);
      if (trusted.some((i) => getEntryKey(i) === key)) return;
      trusted.push(entry);
      updateTrustedIssuers(trusted);
      setNewCertPem('');
      setNewIssuerName('');
      setNewIssuerCountry('');
      setNewIssuerCredentialTypes('');
      return;
    }

    if (!newIssuerDid.trim()) return;
    const trusted = [...trustedIssuers];

    // Check for duplicates
    if (trusted.some((issuer) => getEntryKey(issuer) === `did:${newIssuerDid.trim()}`)) {
      return;
    }

    trusted.push(
      normalizeIssuer(
        {
          did: newIssuerDid.trim(),
          name: newIssuerName.trim(),
          country: newIssuerCountry.trim(),
          credential_types: newIssuerCredentialTypes,
          source: 'manual',
        },
        'manual',
      ),
    );

    updateTrustedIssuers(trusted);
    setNewIssuerDid('');
    setNewIssuerName('');
    setNewIssuerCountry('');
    setNewIssuerCredentialTypes('');
  };

  const handleImportFileClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileImport = async (event) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    try {
      const text = await file.text();
      const parsedIssuers = parseImportContent(text, file.name || 'file');
      const added = mergeIssuers(parsedIssuers);
      setImportFeedback({
        type: added > 0 ? 'success' : 'warning',
        message: added > 0
          ? t('wizards.trustProfile.trustSourcesStep.import.feedbackAdded', { defaultValue: `Imported ${added} issuer(s).`, count: added })
          : t('wizards.trustProfile.trustSourcesStep.import.feedbackNone', { defaultValue: 'No new issuers were imported.' }),
      });
    } catch {
      setImportFeedback({
        type: 'error',
        message: t('wizards.trustProfile.trustSourcesStep.import.feedbackError', { defaultValue: 'Could not parse file. Use CSV, JSON, PEM, or line-separated DID text.' }),
      });
    }

    event.target.value = '';
  };

  const handleUrlImport = async () => {
    if (!importUrl.trim()) {
      return;
    }

    setLoadingUrlImport(true);
    setImportFeedback({ type: '', message: '' });

    try {
      const response = await fetch(importUrl.trim());
      if (!response.ok) {
        throw new Error('Request failed');
      }

      const content = await response.text();
      const parsedIssuers = parseImportContent(content, importUrl.trim());
      const added = mergeIssuers(parsedIssuers);
      setImportFeedback({
        type: added > 0 ? 'success' : 'warning',
        message: added > 0
          ? t('wizards.trustProfile.trustSourcesStep.import.feedbackAdded', { defaultValue: `Imported ${added} issuer(s).`, count: added })
          : t('wizards.trustProfile.trustSourcesStep.import.feedbackNone', { defaultValue: 'No new issuers were imported.' }),
      });
    } catch {
      setImportFeedback({
        type: 'error',
        message: t('wizards.trustProfile.trustSourcesStep.import.feedbackUrlError', { defaultValue: 'URL import failed. Check CORS, URL reachability, and format.' }),
      });
    } finally {
      setLoadingUrlImport(false);
    }
  };

  const handleRemoveIssuer = (index) => {
    const trusted = [...trustedIssuers];
    trusted.splice(index, 1);
    onChange({ trusted_issuers: trusted });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && entryType === 'did') {
      e.preventDefault();
      handleAddIssuer();
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <Typography variant="h6">
          {t('wizards.trustProfile.trustSourcesStep.title')}
        </Typography>
        <Chip
          label={t('wizards.trustProfile.trustSourcesStep.optionalChip')}
          size="small"
          color="default"
          variant="outlined"
        />
      </Box>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.trustSourcesStep.description')}
      </Typography>
      <Alert severity="info" sx={{ mb: 3 }} icon={<InfoIcon />}>
        <Typography variant="body2" gutterBottom>
          {t('wizards.trustProfile.trustSourcesStep.infoAlert.body')}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          <strong>{t('wizards.trustProfile.trustSourcesStep.infoAlert.skippingTitle')}</strong>{' '}
          {t('wizards.trustProfile.trustSourcesStep.infoAlert.skippingDescription')}
        </Typography>
      </Alert>
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <FormControlLabel
          control={(
            <Checkbox
              checked={allowAllIssuers}
              onChange={(event) => onChange({ allow_all_issuers: event.target.checked })}
              disabled={hasConfiguredPinnedIssuers}
              slotProps={{ input: { 'data-testid': 'wizard.trustProfile.allowAllIssuers' } }}
            />
          )}
          label={t('wizards.trustProfile.trustSourcesStep.allowAllIssuers.label', {
            defaultValue: 'Allow any issuer',
          })}
        />
        <Typography variant="body2" color="text.secondary">
          {hasConfiguredPinnedIssuers
            ? t('wizards.trustProfile.trustSourcesStep.allowAllIssuers.disabledDescription', {
                defaultValue: 'Explicit trust sources are configured. Remove them if you want this profile to fall back to a global issuer policy.',
              })
            : allowAllIssuers
              ? t('wizards.trustProfile.trustSourcesStep.allowAllIssuers.enabledDescription', {
                  defaultValue: 'This empty trust profile will accept credentials from any issuer that passes the configured cryptographic validation.',
                })
              : t('wizards.trustProfile.trustSourcesStep.allowAllIssuers.defaultDescription', {
                  defaultValue: 'Disabled by default. If you leave this off and do not add trust sources, the profile will trust no issuers.',
                })}
        </Typography>
      </Paper>
      {/* Tabs for Manual vs Registry Imports */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label={t('wizards.trustProfile.trustSourcesStep.tabs.manual')} data-testid="wizard.trustProfile.tab.manual" />
          <Tab label={t('wizards.trustProfile.trustSourcesStep.tabs.registries')} data-testid="wizard.trustProfile.tab.registries" />
        </Tabs>
      </Box>
      {/* Manual Issuers Tab */}
      {tabValue === 0 && (
        <Box>
          <Alert severity="info" sx={{ mb: 3 }}>
            {t('wizards.trustProfile.trustSourcesStep.issuerBoundary', {
              defaultValue: 'Add the issuer DID you intend to trust. Signing profiles and custody keys are resolved internally and are never selected through a trust profile.',
            })}
          </Alert>

          {/* Source Type Select */}
          <FormControl size="small" sx={{ mb: 2, minWidth: 220 }}>
            <InputLabel>
              {t('wizards.trustProfile.trustSourcesStep.entryType.label', { defaultValue: 'Source Type' })}
            </InputLabel>
            <Select
              value={entryType}
              onChange={(e) => setEntryType(e.target.value)}
              data-testid="wizard.trustProfile.entryType"
              label={t('wizards.trustProfile.trustSourcesStep.entryType.label', { defaultValue: 'Source Type' })}
            >
              <MenuItem value="did">
                {t('wizards.trustProfile.trustSourcesStep.entryType.did', { defaultValue: 'DID Issuer' })}
              </MenuItem>
              <MenuItem value="x509">
                {t('wizards.trustProfile.trustSourcesStep.entryType.x509', { defaultValue: 'X.509 Certificate' })}
              </MenuItem>
            </Select>
          </FormControl>

          {/* Examples — conditional per type */}
          <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1, border: 1, borderColor: 'grey.200' }}>
            <Typography variant="caption" color="text.secondary" gutterBottom display="block">
              {t('wizards.trustProfile.trustSourcesStep.examplesTitle')}
            </Typography>
            {entryType === 'x509' ? (
              <Box sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}>
                <Box>{'• -----BEGIN CERTIFICATE-----'}</Box>
                <Box sx={{ pl: 2 }}>{'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'}</Box>
                <Box>{'• -----END CERTIFICATE-----'}</Box>
                <Box sx={{ mt: 0.5, fontFamily: 'inherit' }}>
                  {t('wizards.trustProfile.trustSourcesStep.x509.fileHint', { defaultValue: 'Upload a .pem, .crt, or .cer file, or paste certificate PEM below.' })}
                </Box>
              </Box>
            ) : (
              <Box sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}>
                <Box>{'• did:web:issuer.example.com'}</Box>
                <Box>{'• did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'}</Box>
                <Box>{'• did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5A'}</Box>
              </Box>
            )}
          </Box>

          {/* Entry form — X.509 or DID */}
          {entryType === 'x509' ? (
            <>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }}>
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.certPem.label', { defaultValue: 'Certificate PEM' })}
                  placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                  value={newCertPem}
                  onChange={(e) => setNewCertPem(e.target.value)}
                  multiline
                  rows={5}
                  helperText={t('wizards.trustProfile.trustSourcesStep.certPem.helper', { defaultValue: 'Paste a PEM-encoded X.509 certificate (root CA or issuing CA).' })}
                  slotProps={{ htmlInput: { 'data-testid': 'wizard.trustProfile.certPem', style: { fontFamily: 'monospace', fontSize: '0.8rem' } } }}
                  fullWidth
                />
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerName.label', { defaultValue: 'Name' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerName.placeholder', { defaultValue: 'Issuer display name' })}
                  value={newIssuerName}
                  onChange={(e) => setNewIssuerName(e.target.value)}
                  fullWidth
                />
              </Stack>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 3 }}>
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerCountry.label', { defaultValue: 'Country' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerCountry.placeholder', { defaultValue: 'ISO country code or name' })}
                  value={newIssuerCountry}
                  onChange={(e) => setNewIssuerCountry(e.target.value)}
                  fullWidth
                />
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.label', { defaultValue: 'Credential Types' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.placeholder', { defaultValue: 'e.g. MDOC|SD_JWT_VC' })}
                  value={newIssuerCredentialTypes}
                  onChange={(e) => setNewIssuerCredentialTypes(e.target.value)}
                  helperText={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.helper', { defaultValue: 'Use | or ; between multiple values.' })}
                  fullWidth
                />
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleAddIssuer}
                  disabled={!newCertPem.trim()}
                  sx={{ minWidth: 120 }}
                  data-testid="wizard.trustProfile.addIssuer"
                >
                  {t('wizards.trustProfile.trustSourcesStep.addButton')}
                </Button>
              </Stack>
            </>
          ) : (
            <>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }}>
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerDid.label')}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerDid.placeholder')}
                  value={newIssuerDid}
                  onChange={(e) => setNewIssuerDid(e.target.value)}
                  onKeyPress={handleKeyPress}
                  helperText={t('wizards.trustProfile.trustSourcesStep.issuerDid.helper')}
                  slotProps={{ htmlInput: { 'data-testid': 'wizard.trustProfile.issuerDid' } }}
                  fullWidth
                />
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerName.label', { defaultValue: 'Name' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerName.placeholder', { defaultValue: 'Issuer display name' })}
                  value={newIssuerName}
                  onChange={(e) => setNewIssuerName(e.target.value)}
                  fullWidth
                />
              </Stack>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 3 }}>
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerCountry.label', { defaultValue: 'Country' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerCountry.placeholder', { defaultValue: 'ISO country code or name' })}
                  value={newIssuerCountry}
                  onChange={(e) => setNewIssuerCountry(e.target.value)}
                  fullWidth
                />
                <TextField
                  label={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.label', { defaultValue: 'Credential Types' })}
                  placeholder={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.placeholder', { defaultValue: 'e.g. MDOC|SD_JWT_VC' })}
                  value={newIssuerCredentialTypes}
                  onChange={(e) => setNewIssuerCredentialTypes(e.target.value)}
                  helperText={t('wizards.trustProfile.trustSourcesStep.issuerCredentialTypes.helper', { defaultValue: 'Use | or ; between multiple values.' })}
                  fullWidth
                />
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleAddIssuer}
                  disabled={!newIssuerDid.trim()}
                  sx={{ minWidth: 120 }}
                  data-testid="wizard.trustProfile.addIssuer"
                >
                  {t('wizards.trustProfile.trustSourcesStep.addButton')}
                </Button>
              </Stack>
            </>
          )}

          {/* Bulk Import */}
          <Paper sx={{ p: 2, mb: 3, bgcolor: 'grey.50' }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {t('wizards.trustProfile.trustSourcesStep.import.title', { defaultValue: 'Bulk Import' })}
            </Typography>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} sx={{ mb: 1.5 }}>
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.json,.txt,.pem,.crt,.cer,.der"
                onChange={handleFileImport}
                data-testid="wizard.trustProfile.importFile"
                style={{ display: 'none' }}
              />
              <Button variant="outlined" startIcon={<UploadFileIcon />} onClick={handleImportFileClick}>
                {t('wizards.trustProfile.trustSourcesStep.import.fileButton', { defaultValue: 'Upload CSV / JSON / PEM' })}
              </Button>
              <TextField
                value={importUrl}
                onChange={(event) => setImportUrl(event.target.value)}
                placeholder={t('wizards.trustProfile.trustSourcesStep.import.urlPlaceholder', { defaultValue: 'https://example.com/trusted-issuers.csv' })}
                size="small"
                fullWidth
              />
              <Button
                variant="outlined"
                startIcon={<LinkIcon />}
                onClick={handleUrlImport}
                disabled={!importUrl.trim() || loadingUrlImport}
              >
                {t('wizards.trustProfile.trustSourcesStep.import.urlButton', { defaultValue: 'Import URL' })}
              </Button>
            </Stack>
            <Typography variant="caption" color="text.secondary">
              {t('wizards.trustProfile.trustSourcesStep.import.helper', { defaultValue: 'Accepted: CSV (did or certificate_pem column), JSON, PEM/CRT/CER files, or line-separated DIDs.' })}
            </Typography>
            {importFeedback.message ? (
              <Alert severity={importFeedback.type || 'info'} sx={{ mt: 1.5 }}>
                {importFeedback.message}
              </Alert>
            ) : null}
          </Paper>

          {trustedIssuers.length > 0 ? (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                {t('wizards.trustProfile.trustSourcesStep.trustedIssuersTitle', {
                  count: trustedIssuers.length,
                })}
              </Typography>
              <List>
                {trustedIssuers.map((issuer, index) => (
                  <ListItem
                    key={index}
                    secondaryAction={
                      <IconButton
                        edge="end"
                        onClick={() => handleRemoveIssuer(index)}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    }
                    sx={{ bgcolor: 'background.paper', mb: 1, borderRadius: 1 }}
                  >
                    <ListItemText
                      primary={
                        <Stack spacing={0.5}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                            {issuer.certificate_pem ? (
                              <Chip label="X.509" size="small" color="warning" />
                            ) : null}
                            {issuer.name ? <Chip label={issuer.name} size="small" color="primary" variant="outlined" /> : null}
                            {issuer.metadata?.country ? <Chip label={issuer.metadata.country} size="small" /> : null}
                            {(issuer.metadata?.credential_types || []).map((type) => (
                              <Chip key={`${getEntryKey(issuer)}-${type}`} label={type} size="small" color="info" variant="outlined" />
                            ))}
                            {issuer.metadata?.source ? (
                              <Chip label={`${t('wizards.trustProfile.trustSourcesStep.sourceChip', { defaultValue: 'Source' })}: ${issuer.metadata.source}`} size="small" variant="outlined" />
                            ) : null}
                          </Box>
                          {issuer.certificate_pem ? (
                            <Typography
                              variant="body2"
                              sx={{ fontFamily: 'monospace', wordBreak: 'break-all', fontSize: '0.75rem', color: 'text.secondary' }}
                            >
                              {`-----BEGIN CERTIFICATE----- ${String(issuer.certificate_pem).replace(/\s/g, '').slice(27, 59)}\u2026`}
                            </Typography>
                          ) : (
                            <Typography
                              variant="body2"
                              sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                            >
                              {issuer.did}
                            </Typography>
                          )}
                          {issuer.description ? <Typography variant="caption" color="text.secondary">{issuer.description}</Typography> : null}
                        </Stack>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          ) : (
            <Box
              sx={{
                p: 4,
                textAlign: 'center',
                border: '2px dashed',
                borderColor: 'divider',
                borderRadius: 1,
              }}
            >
              <Typography color="text.secondary">
                {t('wizards.trustProfile.trustSourcesStep.emptyState')}
              </Typography>
            </Box>
          )}
        </Box>
      )}
      {/* Registry Imports Tab */}
      {tabValue === 1 && (
        <Box>
          <Alert severity="success" sx={{ mb: 3 }} icon={<CloudDownloadIcon />}>
            <Typography variant="body2">
              {t('wizards.trustProfile.trustSourcesStep.registryAlert.title')}
            </Typography>
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
              {t('wizards.trustProfile.trustSourcesStep.registryAlert.description')}
            </Typography>
          </Alert>

          {/* Import from Registry Button */}
          <Button
            variant="contained"
            startIcon={<CloudDownloadIcon />}
            onClick={handleOpenRegistryDialog}
            disabled={loadingRegistries}
            sx={{ mb: 3 }}
            data-testid="wizard.trustProfile.addRegistry"
          >
            {loadingRegistries ? (
              <CircularProgress size={20} sx={{ mr: 1 }} />
            ) : null}
            {t('wizards.trustProfile.trustSourcesStep.importButton')}
          </Button>

          {/* Registry Imports List */}
          {registryImports && registryImports.length > 0 ? (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                {t('wizards.trustProfile.trustSourcesStep.registryImportsTitle', {
                  count: registryImports.length,
                })}
              </Typography>
              <List>
                {registryImports.map((imp, index) => (
                  <Paper key={index} sx={{ p: 2, mb: 1 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                            {imp.metadata?.name || imp.registry_type.replace(/_/g, ' ')}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" data-testid={`wizard.trustProfile.registryImport.sync.${index}`}>
                          {getRegistrySyncSummary(imp)}
                        </Typography>
                          <Box sx={{ mt: 0.5, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(imp.metadata?.frameworks || []).map((framework) => (
                              <Chip key={`${imp.registry_type}-${framework}`} label={framework} size="small" variant="outlined" />
                            ))}
                            {(imp.metadata?.credential_types || []).map((format) => (
                              <Chip key={`${imp.registry_type}-${format}`} label={format} size="small" color="info" variant="outlined" />
                            ))}
                          </Box>
                      </Box>
                      <IconButton
                        onClick={() => handleRemoveRegistry(index)}
                        color="error"
                        size="small"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  </Paper>
                ))}
              </List>
            </Box>
          ) : (
            <Box
              sx={{
                p: 4,
                textAlign: 'center',
                border: '2px dashed',
                borderColor: 'divider',
                borderRadius: 1,
              }}
            >
              <CloudDownloadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
              <Typography color="text.secondary">
                {t('wizards.trustProfile.trustSourcesStep.noRegistriesState')}
              </Typography>
            </Box>
          )}
        </Box>
      )}
      {/* Registry Import Dialog */}
      <Dialog open={openRegistryDialog} onClose={() => setOpenRegistryDialog(false)} maxWidth="sm" fullWidth data-testid="wizard.trustProfile.registryDialog">
        <DialogTitle>{t('wizards.trustProfile.trustSourcesStep.registryDialog.title')}</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <FormControl fullWidth>
            <InputLabel>{t('wizards.trustProfile.trustSourcesStep.registryDialog.label')}</InputLabel>
            <Select
              value={selectedRegistry}
              onChange={(e) => setSelectedRegistry(e.target.value)}
              data-testid="wizard.trustProfile.registrySelect"
              label={t('wizards.trustProfile.trustSourcesStep.registryDialog.label')}
            >
              {availableRegistries.map((reg) => (
                <MenuItem key={reg.id} value={reg.id}>
                  <Box>
                    <Typography variant="body2">{reg.name}</Typography>
                    <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary' }}>
                      {reg.description}
                    </Typography>
                    <Box sx={{ mt: 0.5, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {reg.frameworks.map((framework) => (
                        <Chip key={`${reg.id}-${framework}`} label={framework} size="small" variant="outlined" />
                      ))}
                      {reg.credential_types.map((format) => (
                        <Chip key={`${reg.id}-${format}`} label={format} size="small" color="info" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="caption">
              {t('wizards.trustProfile.trustSourcesStep.registryDialog.info')}
            </Typography>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRegistryDialog(false)}>
            {t('cancel', { ns: 'common', defaultValue: 'Cancel' })}
          </Button>
          <Button
            onClick={handleAddRegistry}
            variant="contained"
            disabled={!selectedRegistry}
            data-testid="wizard.trustProfile.registryDialog.add"
          >
            {t('add', { ns: 'common', defaultValue: 'Add' })}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default TrustSourcesStep;
