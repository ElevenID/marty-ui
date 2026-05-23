/**
 * Application Template Manager
 * 
 * Manages application templates that encapsulate:
 * - Trust Profile (which trust framework applies)
 * - Credential Templates (what can be issued)
 * - Required documents and evidence
 * - Approval workflow settings
 * - Validity and expiration policies
 * 
 * Application templates define what applicants can apply for.
 * Applications are instances of templates submitted by applicants.
 */

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  CircularProgress,
  Stack,
  Grid,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Divider,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Radio,
  RadioGroup,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ContentCopy as DuplicateIcon,
  CheckCircle as ActiveIcon,
  Cancel as InactiveIcon,
  Badge as BadgeIcon,
  Security as TrustIcon,
  School as SchoolIcon,
  Flight as FlightIcon,
  DirectionsCar as DriverLicenseIcon,
  EmojiEvents as OpenBadgeIcon,
  VerifiedUser as VerifiedIcon,
  ExpandMore as ExpandMoreIcon,
  CloudUpload as UploadIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';
import { useNotifications } from '../../hooks/useNotifications';
import { useDialog } from '../../hooks/useDialog';
import { ConfirmDeleteDialog } from '../common';
import complianceProfilesApi from '../../services/complianceProfilesApi';
import {
  fetchIssuanceTemplates,
  fetchTrustProfiles,
  saveIssuanceTemplate,
  deleteIssuanceTemplate,
} from '../../application/vendor';

// Credential types by trust framework
const CREDENTIAL_TYPES_BY_FRAMEWORK = {
  eudi: [
    { id: 'national_id', label: 'National ID', icon: <VerifiedIcon /> },
    { id: 'drivers_license', label: "Driver's License", icon: <DriverLicenseIcon /> },
  ],
  icao: [
    { id: 'passport', label: 'Passport', icon: <FlightIcon /> },
    { id: 'travel_visa', label: 'Travel Visa', icon: <FlightIcon /> },
    { id: 'dtc', label: 'Digital Travel Credential', icon: <FlightIcon /> },
  ],
  aamva: [
    { id: 'drivers_license', label: "Driver's License", icon: <DriverLicenseIcon /> },
    { id: 'national_id', label: 'National ID', icon: <VerifiedIcon /> },
  ],
  open_badges: [
    { id: 'open_badge', label: 'Open Badge', icon: <OpenBadgeIcon /> },
  ],
  custom: [
    { id: 'access_badge', label: 'Access Badge', icon: <BadgeIcon /> },
    { id: 'employee_id', label: 'Employee ID', icon: <BadgeIcon /> },
    { id: 'student_id', label: 'Student ID', icon: <SchoolIcon /> },
  ],
};

// Required document types
const DOCUMENT_TYPES = [
  'government_id',
  'passport',
  'birth_certificate',
  'proof_of_address',
  'photo',
  'biometric_data',
  'education_transcript',
  'employment_verification',
  'other',
];

const EVIDENCE_TYPE_OPTIONS = [
  { value: 'DOCUMENT_SCAN', label: 'Document scan' },
  { value: 'BIOMETRIC', label: 'Biometric' },
  { value: 'SELFIE', label: 'Selfie' },
  { value: 'THIRD_PARTY_VERIFICATION', label: 'Third-party verification' },
  { value: 'EXTERNAL_FACT', label: 'External fact' },
  { value: 'EXTERNAL_API', label: 'External API check' },
  { value: 'document', label: 'Document (legacy)' },
  { value: 'biometric', label: 'Biometric (legacy)' },
  { value: 'electronic', label: 'Electronic record (legacy)' },
  { value: 'vouch', label: 'Vouch/reference (legacy)' },
];

const EXTERNAL_API_METHODS = ['GET', 'POST', 'PUT', 'PATCH'];

const jsonFormat = (value, fallback = {}) => JSON.stringify(value ?? fallback, null, 2);

export function createEvidenceRequirement(type = 'EXTERNAL_API', ordinal = 1) {
  const normalizedType = type || 'EXTERNAL_API';
  const evidenceId = `${normalizedType.toLowerCase().replace(/_/g, '-')}-${ordinal}`;
  const common = {
    evidence_id: evidenceId,
    evidence_type: normalizedType,
    description: '',
    required: true,
  };

  if (normalizedType === 'EXTERNAL_API') {
    return {
      ...common,
      provider: '',
      fact_type: '',
      scope: {},
      pass_rule: {},
      verification_method: 'EXTERNAL_API_RESPONSE',
      auto_issue_on_permit: false,
      api: {
        method: 'POST',
        url: '',
        timeout_seconds: 10,
        headers: {
          'content-type': 'application/json',
        },
        secret_headers: {},
        params: {},
        body: {},
      },
      expected_response: {
        status_codes: [200],
        json: {
          all: [
            { path: '$.status', op: 'eq', value: 'verified' },
          ],
        },
      },
      response_mapping: {
        provider_event_id_path: '$.id',
        verification_status_path: '$.status',
        verification_verified_values: ['verified'],
        scope: {},
        assertion: {},
      },
    };
  }

  if (normalizedType === 'EXTERNAL_FACT') {
    return {
      ...common,
      provider: '',
      fact_type: '',
      scope: {},
      pass_rule: {},
      verification_method: '',
      auto_issue_on_permit: false,
    };
  }

  return {
    ...common,
    accepted_formats: normalizedType === 'DOCUMENT_SCAN' ? ['jpg', 'png', 'pdf'] : [],
    max_file_size_bytes: normalizedType === 'DOCUMENT_SCAN' ? 10485760 : undefined,
    provider_config: {},
    auto_validate: false,
  };
}

export function applyEvidenceTypeDefaults(evidence, type, ordinal = 1) {
  const defaults = createEvidenceRequirement(type, ordinal);
  const preserved = {
    evidence_id: evidence.evidence_id || defaults.evidence_id,
    description: evidence.description || defaults.description,
    required: evidence.required ?? defaults.required,
  };

  if (type === 'EXTERNAL_API') {
    return {
      ...defaults,
      ...evidence,
      ...preserved,
      evidence_type: type,
      scope: evidence.scope || defaults.scope,
      pass_rule: evidence.pass_rule || defaults.pass_rule,
      api: { ...defaults.api, ...(evidence.api || {}) },
      expected_response: evidence.expected_response || defaults.expected_response,
      response_mapping: {
        ...defaults.response_mapping,
        ...(evidence.response_mapping || {}),
      },
    };
  }

  if (type === 'EXTERNAL_FACT') {
    return {
      ...defaults,
      ...evidence,
      ...preserved,
      evidence_type: type,
      scope: evidence.scope || defaults.scope,
      pass_rule: evidence.pass_rule || defaults.pass_rule,
    };
  }

  return {
    ...defaults,
    ...preserved,
    evidence_type: type,
  };
}

/**
 * Get credential type label
 */
function getCredentialTypeLabel(typeId, framework) {
  const types = CREDENTIAL_TYPES_BY_FRAMEWORK[framework] || [];
  const found = types.find((t) => t.id === typeId);
  return found ? found.label : typeId;
}

/**
 * Application Template Form Dialog
 */
export function TemplateFormDialog({ open, onClose, onSave, template, trustProfiles }) {
  const { t } = useTranslation('vendor');
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    trust_profile_id: '',
    compliance_profile_id: '',
    credential_types: [],
    required_documents: [],
    evidence_requirements: [],
    claim_verification_rules: {},
    issuer_config: {
      hosting_mode: 'marty_hosted',
      issuer_did: '',
      auto_generate_did: true,
      issuer_certificate_chain_pem: '',
    },
    environment: 'production',
    retention_policy: {
      retention_days: 90,
      auto_delete: true,
    },
    requires_approval: true,
    auto_issue_on_approval: true,
    validity_days: 365,
    max_applications_per_user: 1,
    is_active: true,
  });

  const [availableCredentialTypes, setAvailableCredentialTypes] = useState([]);
  const [complianceProfiles, setComplianceProfiles] = useState([]);
  const [certificateFile, setCertificateFile] = useState(null);
  const [validationStatus, setValidationStatus] = useState(null);
  const [jsonDrafts, setJsonDrafts] = useState({});
  const [jsonErrors, setJsonErrors] = useState({});

  // Initialize form when template changes
  useEffect(() => {
    setJsonDrafts({});
    setJsonErrors({});
    if (template) {
      setFormData({
        name: template.name || '',
        description: template.description || '',
        trust_profile_id: template.trust_profile_id || '',
        compliance_profile_id: template.compliance_profile_id || '',
        credential_types: template.credential_types || [],
        required_documents: template.required_documents || [],
        evidence_requirements: template.evidence_requirements || [],
        claim_verification_rules: template.claim_verification_rules || {},
        issuer_config: template.issuer_config || {
          hosting_mode: 'marty_hosted',
          issuer_did: '',
          auto_generate_did: true,
          issuer_certificate_chain_pem: '',
        },
        environment: template.environment || 'production',
        retention_policy: template.retention_policy || {
          retention_days: 90,
          auto_delete: true,
        },
        requires_approval: template.requires_approval !== false,
        auto_issue_on_approval: template.auto_issue_on_approval !== false,
        validity_days: template.validity_days || 365,
        max_applications_per_user: template.max_applications_per_user || 1,
        is_active: template.is_active !== false,
      });
    } else {
      setFormData({
        name: '',
        description: '',
        trust_profile_id: '',
        compliance_profile_id: '',
        credential_types: [],
        required_documents: [],
        evidence_requirements: [],
        claim_verification_rules: {},
        issuer_config: {
          hosting_mode: 'marty_hosted',
          issuer_did: '',
          auto_generate_did: true,
          issuer_certificate_chain_pem: '',
        },
        environment: 'production',
        retention_policy: {
          retention_days: 90,
          auto_delete: true,
        },
        requires_approval: true,
        auto_issue_on_approval: true,
        validity_days: 365,
        max_applications_per_user: 1,
        is_active: true,
      });
    }
  }, [template, open]);

  // Load compliance profiles
  useEffect(() => {
    const loadComplianceProfiles = async () => {
      try {
        const profiles = await complianceProfilesApi.listComplianceProfiles();
        setComplianceProfiles(profiles);
      } catch (err) {
        console.error('Failed to load compliance profiles:', err);
      }
    };
    if (open) {
      loadComplianceProfiles();
    }
  }, [open]);

  // Update available credential types when trust profile changes
  useEffect(() => {
    if (formData.trust_profile_id) {
      const profile = trustProfiles.find((p) => p.id === formData.trust_profile_id);
      if (profile && profile.framework) {
        setAvailableCredentialTypes(CREDENTIAL_TYPES_BY_FRAMEWORK[profile.framework] || []);
        // Clear selected credential types if they're not compatible
        const validTypes = (CREDENTIAL_TYPES_BY_FRAMEWORK[profile.framework] || []).map((t) => t.id);
        setFormData((prev) => ({
          ...prev,
          credential_types: prev.credential_types.filter((t) => validTypes.includes(t)),
        }));
      }
    } else {
      setAvailableCredentialTypes([]);
    }
  }, [formData.trust_profile_id, trustProfiles]);

  const handleChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleToggleCredentialType = (typeId) => {
    setFormData((prev) => ({
      ...prev,
      credential_types: prev.credential_types.includes(typeId)
        ? prev.credential_types.filter((t) => t !== typeId)
        : [...prev.credential_types, typeId],
    }));
  };

  const handleToggleDocument = (docType) => {
    setFormData((prev) => ({
      ...prev,
      required_documents: prev.required_documents.includes(docType)
        ? prev.required_documents.filter((d) => d !== docType)
        : [...prev.required_documents, docType],
    }));
  };

  const handleSubmit = () => {
    onSave({ ...template, ...formData });
  };

  const handleValidateArtifacts = async () => {
    try {
      setValidationStatus({ loading: true });
      await complianceProfilesApi.validateIssuerArtifacts(
        formData.compliance_profile_id,
        formData.issuer_config
      );
      setValidationStatus({ success: true, message: 'Issuer artifacts validated successfully' });
    } catch (err) {
      setValidationStatus({ success: false, message: err.message });
    }
  };

  const handleCertificateUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        handleChange('issuer_config', {
          ...formData.issuer_config,
          issuer_certificate_chain_pem: e.target.result,
        });
      };
      reader.readAsText(file);
      setCertificateFile(file);
    }
  };

  const handleAddEvidence = () => {
    const newEvidence = createEvidenceRequirement('EXTERNAL_API', formData.evidence_requirements.length + 1);
    handleChange('evidence_requirements', [...formData.evidence_requirements, newEvidence]);
  };

  const handleRemoveEvidence = (index) => {
    handleChange(
      'evidence_requirements',
      formData.evidence_requirements.filter((_, i) => i !== index)
    );
  };

  const handleUpdateEvidence = (index, field, value) => {
    const updated = [...formData.evidence_requirements];
    updated[index] = { ...updated[index], [field]: value };
    handleChange('evidence_requirements', updated);
  };

  const handleChangeEvidenceType = (index, value) => {
    const updated = [...formData.evidence_requirements];
    updated[index] = applyEvidenceTypeDefaults(updated[index] || {}, value, index + 1);
    handleChange('evidence_requirements', updated);
  };

  const handleUpdateEvidenceApi = (index, field, value) => {
    const updated = [...formData.evidence_requirements];
    const current = updated[index] || {};
    updated[index] = {
      ...current,
      api: {
        ...(current.api || {}),
        [field]: value,
      },
    };
    handleChange('evidence_requirements', updated);
  };

  const handleUpdateEvidenceJson = (index, field, rawValue, updater) => {
    const key = `${index}:${field}`;
    setJsonDrafts((prev) => ({ ...prev, [key]: rawValue }));
    try {
      const parsed = rawValue.trim() ? JSON.parse(rawValue) : {};
      updater(parsed);
      setJsonErrors((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    } catch (err) {
      setJsonErrors((prev) => ({ ...prev, [key]: 'Invalid JSON' }));
    }
  };

  const jsonFieldValue = (index, field, value, fallback = {}) => {
    const key = `${index}:${field}`;
    return jsonDrafts[key] ?? jsonFormat(value, fallback);
  };

  const jsonFieldError = (index, field) => jsonErrors[`${index}:${field}`] || '';

  const hasExternalEvidenceErrors = formData.evidence_requirements.some((evidence) => (
    evidence.evidence_type === 'EXTERNAL_API' &&
    (!evidence.evidence_id || !evidence.provider || !evidence.fact_type || !evidence.api?.url)
  ));

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{template ? t('applicationTemplateManager.dialog.editTitle') : t('applicationTemplateManager.dialog.createTitle')}</DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          {/* Basic Information */}
          <TextField
            fullWidth
            label={t('applicationTemplateManager.form.templateName')}
            value={formData.name}
            onChange={(e) => handleChange('name', e.target.value)}
            required
            helperText={t('applicationTemplateManager.form.templateNameHelper')}
          />

          <TextField
            fullWidth
            multiline
            rows={2}
            label={t('applicationTemplateManager.form.description')}
            value={formData.description}
            onChange={(e) => handleChange('description', e.target.value)}
          />

          <Divider />

          {/* Compliance Profile Selection */}
          <FormControl fullWidth>
            <InputLabel>{t('applicationTemplateManager.form.complianceProfile')}</InputLabel>
            <Select
              value={formData.compliance_profile_id}
              onChange={(e) => handleChange('compliance_profile_id', e.target.value)}
              label={t('applicationTemplateManager.form.complianceProfile')}
            >
              {complianceProfiles.map((profile) => (
                <MenuItem key={profile.id} value={profile.id}>
                  {profile.name} ({profile.code})
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Trust Profile Selection */}
          <FormControl fullWidth required>
            <InputLabel>{t('applicationTemplateManager.form.trustProfile')}</InputLabel>
            <Select
              value={formData.trust_profile_id}
              onChange={(e) => handleChange('trust_profile_id', e.target.value)}
              label={t('applicationTemplateManager.form.trustProfile')}
            >
              {trustProfiles.map((profile) => (
                <MenuItem key={profile.id} value={profile.id}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TrustIcon fontSize="small" />
                    {profile.name} ({profile.framework})
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Credential Types */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              {t('applicationTemplateManager.form.credentialTypes')} *
            </Typography>
            <Typography variant="caption" color="text.secondary" gutterBottom display="block">
              Select which credentials can be issued through this template
            </Typography>
            {availableCredentialTypes.length === 0 ? (
              <Alert severity="info" sx={{ mt: 1 }}>
                Select a trust profile first to see available credential types
              </Alert>
            ) : (
              <FormGroup>
                {availableCredentialTypes.map((type) => (
                  <FormControlLabel
                    key={type.id}
                    control={
                      <Checkbox
                        checked={formData.credential_types.includes(type.id)}
                        onChange={() => handleToggleCredentialType(type.id)}
                      />
                    }
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {type.icon}
                        {type.label}
                      </Box>
                    }
                  />
                ))}
              </FormGroup>
            )}
          </Box>

          <Divider />

          {/* Evidence Requirements */}
          <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
              <Typography variant="subtitle2">Evidence Requirements</Typography>
              <Button size="small" startIcon={<AddIcon />} onClick={handleAddEvidence}>
                Add Evidence
              </Button>
            </Box>
            <Typography variant="caption" color="text.secondary" display="block" mb={2}>
              Configure structured evidence that applicants must provide
            </Typography>
            {formData.evidence_requirements.map((evidence, index) => (
              <Accordion key={index}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Evidence {index + 1}: {evidence.evidence_type}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Stack spacing={2}>
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6}>
                        <TextField
                          fullWidth
                          label="Evidence ID"
                          value={evidence.evidence_id || ''}
                          onChange={(e) => handleUpdateEvidence(index, 'evidence_id', e.target.value)}
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <FormControl fullWidth>
                          <InputLabel>Evidence Type</InputLabel>
                          <Select
                            value={evidence.evidence_type}
                            onChange={(e) => handleChangeEvidenceType(index, e.target.value)}
                            label="Evidence Type"
                          >
                            {EVIDENCE_TYPE_OPTIONS.map((option) => (
                              <MenuItem key={option.value} value={option.value}>
                                {option.label}
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                      </Grid>
                    </Grid>

                    <TextField
                      fullWidth
                      label="Description"
                      value={evidence.description || ''}
                      onChange={(e) => handleUpdateEvidence(index, 'description', e.target.value)}
                    />

                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={evidence.required !== false}
                          onChange={(e) => handleUpdateEvidence(index, 'required', e.target.checked)}
                        />
                      }
                      label="Required"
                    />

                    {(evidence.evidence_type === 'EXTERNAL_API' || evidence.evidence_type === 'EXTERNAL_FACT') && (
                      <>
                        <Grid container spacing={2}>
                          <Grid item xs={12} sm={4}>
                            <TextField
                              fullWidth
                              label="Provider"
                              value={evidence.provider || ''}
                              onChange={(e) => handleUpdateEvidence(index, 'provider', e.target.value)}
                              placeholder="passport_verifier"
                            />
                          </Grid>
                          <Grid item xs={12} sm={4}>
                            <TextField
                              fullWidth
                              label="Fact Type"
                              value={evidence.fact_type || ''}
                              onChange={(e) => handleUpdateEvidence(index, 'fact_type', e.target.value)}
                              placeholder="passport.document_verified"
                            />
                          </Grid>
                          <Grid item xs={12} sm={4}>
                            <TextField
                              fullWidth
                              label="Verification Method"
                              value={evidence.verification_method || ''}
                              onChange={(e) => handleUpdateEvidence(index, 'verification_method', e.target.value)}
                              placeholder="EXTERNAL_API_RESPONSE"
                            />
                          </Grid>
                        </Grid>

                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Scope JSON"
                              value={jsonFieldValue(index, 'scope', evidence.scope)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'scope',
                                e.target.value,
                                (parsed) => handleUpdateEvidence(index, 'scope', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'scope'))}
                              helperText={jsonFieldError(index, 'scope') || 'Required fact scope values.'}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Pass Rule JSON"
                              value={jsonFieldValue(index, 'pass_rule', evidence.pass_rule)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'pass_rule',
                                e.target.value,
                                (parsed) => handleUpdateEvidence(index, 'pass_rule', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'pass_rule'))}
                              helperText={jsonFieldError(index, 'pass_rule') || 'Rules over assertion.*, scope.*, verification.*, or source.* paths.'}
                            />
                          </Grid>
                        </Grid>

                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={Boolean(evidence.auto_issue_on_permit || evidence.auto_approve_on_evidence)}
                              onChange={(e) => handleUpdateEvidence(index, 'auto_issue_on_permit', e.target.checked)}
                            />
                          }
                          label="Auto-issue when policy permits"
                        />
                      </>
                    )}

                    {evidence.evidence_type === 'EXTERNAL_API' && (
                      <>
                        {(!evidence.provider || !evidence.fact_type || !evidence.api?.url) && (
                          <Alert severity="warning">
                            External API evidence requires a provider, fact type, and API URL.
                          </Alert>
                        )}

                        <Grid container spacing={2}>
                          <Grid item xs={12} sm={3}>
                            <FormControl fullWidth>
                              <InputLabel>Method</InputLabel>
                              <Select
                                value={evidence.api?.method || 'POST'}
                                onChange={(e) => handleUpdateEvidenceApi(index, 'method', e.target.value)}
                                label="Method"
                              >
                                {EXTERNAL_API_METHODS.map((method) => (
                                  <MenuItem key={method} value={method}>
                                    {method}
                                  </MenuItem>
                                ))}
                              </Select>
                            </FormControl>
                          </Grid>
                          <Grid item xs={12} sm={7}>
                            <TextField
                              fullWidth
                              label="API URL"
                              value={evidence.api?.url || ''}
                              onChange={(e) => handleUpdateEvidenceApi(index, 'url', e.target.value)}
                              placeholder="https://verify.example.test/passports"
                            />
                          </Grid>
                          <Grid item xs={12} sm={2}>
                            <TextField
                              fullWidth
                              type="number"
                              label="Timeout"
                              value={evidence.api?.timeout_seconds || 10}
                              onChange={(e) => handleUpdateEvidenceApi(index, 'timeout_seconds', Number(e.target.value))}
                              inputProps={{ min: 1, max: 20 }}
                            />
                          </Grid>
                        </Grid>

                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Headers JSON"
                              value={jsonFieldValue(index, 'api.headers', evidence.api?.headers)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'api.headers',
                                e.target.value,
                                (parsed) => handleUpdateEvidenceApi(index, 'headers', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'api.headers'))}
                              helperText={jsonFieldError(index, 'api.headers') || 'Non-secret headers only.'}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Secret Headers JSON"
                              value={jsonFieldValue(index, 'api.secret_headers', evidence.api?.secret_headers)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'api.secret_headers',
                                e.target.value,
                                (parsed) => handleUpdateEvidenceApi(index, 'secret_headers', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'api.secret_headers'))}
                              helperText={jsonFieldError(index, 'api.secret_headers') || 'Map header names to deployment secret names.'}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Query Params JSON"
                              value={jsonFieldValue(index, 'api.params', evidence.api?.params)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'api.params',
                                e.target.value,
                                (parsed) => handleUpdateEvidenceApi(index, 'params', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'api.params'))}
                              helperText={jsonFieldError(index, 'api.params') || 'Optional query parameters.'}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={4}
                              label="Body JSON"
                              value={jsonFieldValue(index, 'api.body', evidence.api?.body)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'api.body',
                                e.target.value,
                                (parsed) => handleUpdateEvidenceApi(index, 'body', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'api.body'))}
                              helperText={jsonFieldError(index, 'api.body') || 'Supports {{application.form_data.field_id}} templates.'}
                            />
                          </Grid>
                        </Grid>

                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={6}
                              label="Expected Response JSON"
                              value={jsonFieldValue(index, 'expected_response', evidence.expected_response)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'expected_response',
                                e.target.value,
                                (parsed) => handleUpdateEvidence(index, 'expected_response', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'expected_response'))}
                              helperText={jsonFieldError(index, 'expected_response') || 'Status codes and response path predicates.'}
                            />
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <TextField
                              fullWidth
                              multiline
                              rows={6}
                              label="Response Mapping JSON"
                              value={jsonFieldValue(index, 'response_mapping', evidence.response_mapping)}
                              onChange={(e) => handleUpdateEvidenceJson(
                                index,
                                'response_mapping',
                                e.target.value,
                                (parsed) => handleUpdateEvidence(index, 'response_mapping', parsed)
                              )}
                              error={Boolean(jsonFieldError(index, 'response_mapping'))}
                              helperText={jsonFieldError(index, 'response_mapping') || 'Maps response fields to EvidenceFact fields.'}
                            />
                          </Grid>
                        </Grid>
                      </>
                    )}

                    {!['EXTERNAL_API', 'EXTERNAL_FACT'].includes(evidence.evidence_type) && (
                      <>
                        {evidence.evidence_type === 'DOCUMENT_SCAN' && (
                          <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                              <TextField
                                fullWidth
                                label="Accepted Formats"
                                value={(evidence.accepted_formats || []).join(', ')}
                                onChange={(e) => handleUpdateEvidence(
                                  index,
                                  'accepted_formats',
                                  e.target.value.split(',').map((item) => item.trim()).filter(Boolean)
                                )}
                              />
                            </Grid>
                            <Grid item xs={12} md={6}>
                              <TextField
                                fullWidth
                                type="number"
                                label="Max File Size"
                                value={evidence.max_file_size_bytes || ''}
                                onChange={(e) => handleUpdateEvidence(index, 'max_file_size_bytes', Number(e.target.value))}
                              />
                            </Grid>
                          </Grid>
                        )}
                        <TextField
                          fullWidth
                          label="Provider Configuration JSON"
                          multiline
                          rows={3}
                          value={jsonFieldValue(index, 'provider_config', evidence.provider_config)}
                          onChange={(e) => handleUpdateEvidenceJson(
                            index,
                            'provider_config',
                            e.target.value,
                            (parsed) => handleUpdateEvidence(index, 'provider_config', parsed)
                          )}
                          error={Boolean(jsonFieldError(index, 'provider_config'))}
                          helperText={jsonFieldError(index, 'provider_config') || 'Optional provider-specific configuration.'}
                        />
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={evidence.auto_validate || false}
                              onChange={(e) => handleUpdateEvidence(index, 'auto_validate', e.target.checked)}
                            />
                          }
                          label="Auto-validate when possible"
                        />
                      </>
                    )}

                    <Button
                      size="small"
                      color="error"
                      onClick={() => handleRemoveEvidence(index)}
                    >
                      Remove Evidence
                    </Button>
                  </Stack>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>

          <Divider />

          {/* Issuer Configuration */}
          <Box>
            <Typography variant="subtitle2" mb={2}>Issuer Configuration</Typography>
            
            <FormControl fullWidth sx={{ mb: 2 }}>
              <Typography variant="caption" color="text.secondary" mb={1}>DID Hosting Mode</Typography>
              <RadioGroup
                value={formData.issuer_config.hosting_mode}
                onChange={(e) => handleChange('issuer_config', {
                  ...formData.issuer_config,
                  hosting_mode: e.target.value,
                })}
              >
                <FormControlLabel
                  value="marty_hosted"
                  control={<Radio />}
                  label="Marty-Hosted (did:web with Marty domain)"
                />
                <FormControlLabel
                  value="self_hosted"
                  control={<Radio />}
                  label="Self-Hosted (did:web with your domain)"
                />
              </RadioGroup>
            </FormControl>

            {formData.environment === 'development' && (
              <Alert severity="info" sx={{ mb: 2 }}>
                Development mode: did:key will be auto-generated for testing
              </Alert>
            )}

            {formData.issuer_config.hosting_mode === 'self_hosted' && (
              <TextField
                fullWidth
                label="Issuer DID"
                value={formData.issuer_config.issuer_did}
                onChange={(e) => handleChange('issuer_config', {
                  ...formData.issuer_config,
                  issuer_did: e.target.value,
                })}
                placeholder="did:web:example.com"
                sx={{ mb: 2 }}
              />
            )}

            {formData.issuer_config.hosting_mode === 'marty_hosted' && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={formData.issuer_config.auto_generate_did || false}
                    onChange={(e) => handleChange('issuer_config', {
                      ...formData.issuer_config,
                      auto_generate_did: e.target.checked,
                    })}
                  />
                }
                label="Auto-generate DID on deployment"
              />
            )}

            {/* mDoc Certificate Upload */}
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>X.509 Certificate Chain (for mDoc)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="warning" icon={<WarningIcon />} sx={{ mb: 2 }}>
                  Required for mDoc credentials. Must be validated against Compliance Profile rules.
                </Alert>
                <input
                  accept=".pem,.crt,.cer"
                  style={{ display: 'none' }}
                  id="certificate-upload"
                  type="file"
                  onChange={handleCertificateUpload}
                />
                <label htmlFor="certificate-upload">
                  <Button variant="outlined" component="span" startIcon={<UploadIcon />}>
                    Upload Certificate Chain
                  </Button>
                </label>
                {certificateFile && (
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    Loaded: {certificateFile.name}
                  </Typography>
                )}
              </AccordionDetails>
            </Accordion>

            {formData.compliance_profile_id && (
              <Box sx={{ mt: 2 }}>
                <Button
                  variant="outlined"
                  onClick={handleValidateArtifacts}
                  disabled={validationStatus?.loading}
                >
                  {validationStatus?.loading ? 'Validating...' : 'Validate Issuer Artifacts'}
                </Button>
                {validationStatus && !validationStatus.loading && (
                  <Alert
                    severity={validationStatus.success ? 'success' : 'error'}
                    sx={{ mt: 2 }}
                    onClose={() => setValidationStatus(null)}
                  >
                    {validationStatus.message}
                  </Alert>
                )}
              </Box>
            )}
          </Box>

          <Divider />

          {/* Environment and Retention */}
          <Grid container spacing={2}>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Environment</InputLabel>
                <Select
                  value={formData.environment}
                  onChange={(e) => handleChange('environment', e.target.value)}
                  label="Environment"
                >
                  <MenuItem value="development">Development</MenuItem>
                  <MenuItem value="staging">Staging</MenuItem>
                  <MenuItem value="production">Production</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                type="number"
                label="Retention Days"
                value={formData.retention_policy.retention_days}
                onChange={(e) => handleChange('retention_policy', {
                  ...formData.retention_policy,
                  retention_days: parseInt(e.target.value, 10),
                })}
                inputProps={{ min: 1 }}
                helperText="Application data retained after completion"
              />
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ mt: 1 }}>
            Applications will be automatically deleted after {formData.retention_policy.retention_days} days.
            Credentials are never stored (privacy-preserving).
          </Alert>

          <Divider />

          {/* Required Documents */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              {t('applicationTemplateManager.form.requiredDocuments')}
            </Typography>
            <Typography variant="caption" color="text.secondary" gutterBottom display="block">
              Select which documents applicants must submit
            </Typography>
            <Grid container spacing={1} sx={{ mt: 1 }}>
              {DOCUMENT_TYPES.map((docType) => (
                <Grid item xs={6} key={docType}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={formData.required_documents.includes(docType)}
                        onChange={() => handleToggleDocument(docType)}
                      />
                    }
                    label={docType.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                  />
                </Grid>
              ))}
            </Grid>
          </Box>

          <Divider />

          {/* Workflow Settings */}
          <Typography variant="subtitle2">Workflow Settings</Typography>

          <FormControlLabel
            control={
              <Checkbox
                checked={formData.requires_approval}
                onChange={(e) => handleChange('requires_approval', e.target.checked)}
              />
            }
            label={t('applicationTemplateManager.form.requiresApproval')}
          />

          <FormControlLabel
            control={
              <Checkbox
                checked={formData.auto_issue_on_approval}
                onChange={(e) => handleChange('auto_issue_on_approval', e.target.checked)}
                disabled={!formData.requires_approval}
              />
            }
            label="Automatically issue credential upon approval"
          />

          <Grid container spacing={2}>
            <Grid item xs={6}>
              <TextField
                fullWidth
                type="number"
                label={t('applicationTemplateManager.form.validityDays')}
                value={formData.validity_days}
                onChange={(e) => handleChange('validity_days', parseInt(e.target.value, 10))}
                inputProps={{ min: 1 }}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                type="number"
                label={t('applicationTemplateManager.form.maxApplications')}
                value={formData.max_applications_per_user}
                onChange={(e) => handleChange('max_applications_per_user', parseInt(e.target.value, 10))}
                inputProps={{ min: 1 }}
              />
            </Grid>
          </Grid>

          <FormControlLabel
            control={
              <Checkbox
                checked={formData.is_active}
                onChange={(e) => handleChange('is_active', e.target.checked)}
              />
            }
            label="Template is active (visible to applicants)"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={
            !formData.name ||
            !formData.trust_profile_id ||
            formData.credential_types.length === 0
            || hasExternalEvidenceErrors
            || Object.keys(jsonErrors).length > 0
          }
        >
          {template ? 'Save Changes' : 'Create Template'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Main Application Template Manager Component
 */
export default function ApplicationTemplateManager() {
  const { organizationId } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const [templates, setTemplates] = useState([]);
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Dialog state
  const [formDialogOpen, setFormDialogOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);
  const deleteDialog = useDialog();

  /**
   * Load templates from API
   */
  const loadTemplates = useCallback(async () => {
    if (!organizationId) return;

    setLoading(true);
    try {
      const data = await fetchIssuanceTemplates({ organizationId });
      setTemplates(data.templates || []);
    } catch (err) {
      console.error('Error loading templates:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  /**
   * Load trust profiles
   */
  const loadTrustProfiles = useCallback(async () => {
    if (!organizationId) return;

    try {
      const data = await fetchTrustProfiles({ organizationId });
      setTrustProfiles(data.profiles || []);
    } catch (err) {
      console.error('Error loading trust profiles:', err);
      setTrustProfiles([]);
    }
  }, [organizationId]);

  // Load data on mount
  useEffect(() => {
    loadTemplates();
    loadTrustProfiles();
  }, [loadTemplates, loadTrustProfiles]);

  /**
   * Handle create new template
   */
  const handleCreate = () => {
    setEditingTemplate(null);
    setFormDialogOpen(true);
  };

  /**
   * Handle edit template
   */
  const handleEdit = (template) => {
    setEditingTemplate(template);
    setFormDialogOpen(true);
  };

  /**
   * Handle save template
   */
  const handleSave = async (templateData) => {
    try {
      await saveIssuanceTemplate({ templateData, organizationId });

      showSuccess(templateData.id ? t('applicationTemplateManager.snackbar.updateSuccess') : t('applicationTemplateManager.snackbar.createSuccess'));

      setFormDialogOpen(false);
      loadTemplates();
    } catch (err) {
      console.error('Error saving template:', err);
      showError(err.message);
    }
  };

  /**
   * Handle delete template
   */
  const handleDelete = async () => {
    try {
      await deleteIssuanceTemplate({ templateId: deleteDialog.data.id });

      showSuccess(t('applicationTemplateManager.snackbar.deleteSuccess'));
      loadTemplates();
    } catch (err) {
      showError(err.message);
      throw err;
    }
  };

  /**
   * Handle duplicate template
   */
  const handleDuplicate = (template) => {
    const duplicated = {
      ...template,
      id: undefined,
      name: `${template.name} (Copy)`,
    };
    setEditingTemplate(duplicated);
    setFormDialogOpen(true);
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            {t('applicationTemplateManager.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('applicationTemplateManager.description')}
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
          {t('applicationTemplateManager.createButton')}
        </Button>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error} (Showing mock data for development)
        </Alert>
      )}

      {/* Templates Table */}
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
          <CircularProgress />
        </Box>
      ) : templates.length === 0 ? (
        <Paper sx={{ p: 8, textAlign: 'center' }}>
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No Application Templates
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Create your first application template to define what credentials applicants can request.
          </Typography>
          <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
            Create Template
          </Button>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Trust Profile</TableCell>
                <TableCell>Credential Types</TableCell>
                <TableCell>Required Docs</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {templates.map((template) => {
                const profile = trustProfiles.find((p) => p.id === template.trust_profile_id);
                return (
                  <TableRow key={template.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {template.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {template.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {profile ? (
                        <Chip
                          icon={<TrustIcon />}
                          label={profile.name}
                          size="small"
                          variant="outlined"
                        />
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {template.credential_types.map((typeId) => (
                          <Chip
                            key={typeId}
                            label={getCredentialTypeLabel(typeId, profile?.framework)}
                            size="small"
                          />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{template.required_documents.length} docs</Typography>
                    </TableCell>
                    <TableCell>
                      {template.is_active ? (
                        <Chip icon={<ActiveIcon />} label="Active" color="success" size="small" />
                      ) : (
                        <Chip icon={<InactiveIcon />} label="Inactive" color="default" size="small" />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => handleEdit(template)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Duplicate">
                        <IconButton size="small" onClick={() => handleDuplicate(template)}>
                          <DuplicateIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          onClick={() => deleteDialog.open(template)}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Template Form Dialog */}
      <TemplateFormDialog
        open={formDialogOpen}
        onClose={() => setFormDialogOpen(false)}
        onSave={handleSave}
        template={editingTemplate}
        trustProfiles={trustProfiles}
      />

      <ConfirmDeleteDialog
        open={deleteDialog.isOpen}
        onClose={deleteDialog.close}
        onConfirm={handleDelete}
        title="Delete Template"
        itemName={deleteDialog.data?.name}
      />

    </Box>
  );
}

/**
 * Generate mock templates for development
 */
function generateMockTemplates() {
  return [
    {
      id: 'tpl_1',
      name: 'Travel Visa Application',
      description: 'Standard travel visa for international travel',
      trust_profile_id: 'tp_icao',
      credential_types: ['travel_visa'],
      required_documents: ['passport', 'photo', 'proof_of_address'],
      requires_approval: true,
      auto_issue_on_approval: true,
      validity_days: 90,
      max_applications_per_user: 1,
      is_active: true,
    },
    {
      id: 'tpl_2',
      name: 'Employee Badge Request',
      description: 'Internal employee access badge',
      trust_profile_id: 'tp_custom',
      credential_types: ['access_badge'],
      required_documents: ['government_id', 'photo', 'employment_verification'],
      requires_approval: true,
      auto_issue_on_approval: false,
      validity_days: 365,
      max_applications_per_user: 1,
      is_active: true,
    },
  ];
}

/**
 * Generate mock trust profiles for development
 */
function generateMockTrustProfiles() {
  return [
    { id: 'tp_icao', name: 'ICAO Travel Trust', framework: 'icao' },
    { id: 'tp_aamva', name: 'AAMVA Driver License', framework: 'aamva' },
    { id: 'tp_custom', name: 'Company PKI', framework: 'custom' },
    { id: 'tp_open_badges', name: 'Educational Credentials', framework: 'open_badges' },
  ];
}
