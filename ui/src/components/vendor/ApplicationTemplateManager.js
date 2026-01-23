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

import React, { useState, useEffect, useCallback } from 'react';
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
  Snackbar,
  CircularProgress,
  Stack,
  Card,
  CardContent,
  Grid,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Divider,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  ContentCopy as DuplicateIcon,
  CheckCircle as ActiveIcon,
  Cancel as InactiveIcon,
  Description as DocumentIcon,
  Badge as BadgeIcon,
  Security as TrustIcon,
  School as SchoolIcon,
  Flight as FlightIcon,
  DirectionsCar as DriverLicenseIcon,
  EmojiEvents as OpenBadgeIcon,
  VerifiedUser as VerifiedIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';

// API base URL
const API_URL = process.env.REACT_APP_API_URL || '';

// Trust frameworks
const TRUST_FRAMEWORKS = [
  { id: 'eudi', label: 'EUDI (EU Digital Identity)', color: '#0d47a1' },
  { id: 'icao', label: 'ICAO PKD (Travel)', color: '#1976d2' },
  { id: 'aamva', label: 'AAMVA (North America)', color: '#2e7d32' },
  { id: 'open_badges', label: 'Open Badges 3.0', color: '#FF6B35' },
  { id: 'custom', label: 'Custom X.509', color: '#424242' },
];

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
function TemplateFormDialog({ open, onClose, onSave, template, trustProfiles }) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    trust_profile_id: '',
    credential_types: [],
    required_documents: [],
    requires_approval: true,
    auto_issue_on_approval: true,
    validity_days: 365,
    max_applications_per_user: 1,
    is_active: true,
  });

  const [availableCredentialTypes, setAvailableCredentialTypes] = useState([]);

  // Initialize form when template changes
  useEffect(() => {
    if (template) {
      setFormData({
        name: template.name || '',
        description: template.description || '',
        trust_profile_id: template.trust_profile_id || '',
        credential_types: template.credential_types || [],
        required_documents: template.required_documents || [],
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
        credential_types: [],
        required_documents: [],
        requires_approval: true,
        auto_issue_on_approval: true,
        validity_days: 365,
        max_applications_per_user: 1,
        is_active: true,
      });
    }
  }, [template, open]);

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

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{template ? 'Edit Application Template' : 'Create Application Template'}</DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          {/* Basic Information */}
          <TextField
            fullWidth
            label="Template Name"
            value={formData.name}
            onChange={(e) => handleChange('name', e.target.value)}
            required
            helperText="E.g., 'Travel Visa Application', 'Employee Badge Request'"
          />

          <TextField
            fullWidth
            multiline
            rows={2}
            label="Description"
            value={formData.description}
            onChange={(e) => handleChange('description', e.target.value)}
            helperText="Describe what this application is for"
          />

          <Divider />

          {/* Trust Profile Selection */}
          <FormControl fullWidth required>
            <InputLabel>Trust Profile</InputLabel>
            <Select
              value={formData.trust_profile_id}
              onChange={(e) => handleChange('trust_profile_id', e.target.value)}
              label="Trust Profile"
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
              Credential Types *
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

          {/* Required Documents */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Required Documents
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
            label="Requires manual approval before issuance"
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
                label="Validity Period (days)"
                value={formData.validity_days}
                onChange={(e) => handleChange('validity_days', parseInt(e.target.value, 10))}
                inputProps={{ min: 1 }}
              />
            </Grid>
            <Grid item xs={6}>
              <TextField
                fullWidth
                type="number"
                label="Max Applications Per User"
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
  const [templates, setTemplates] = useState([]);
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Dialog state
  const [formDialogOpen, setFormDialogOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [templateToDelete, setTemplateToDelete] = useState(null);

  /**
   * Load templates from API
   */
  const loadTemplates = useCallback(async () => {
    if (!organizationId) return;

    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/v1/application-templates?organization_id=${organizationId}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to load templates: ${response.statusText}`);
      }

      const data = await response.json();
      setTemplates(data.templates || []);
    } catch (err) {
      console.error('Error loading templates:', err);
      setError(err.message);
      // Use mock data for development
      setTemplates(generateMockTemplates());
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
      const response = await fetch(`${API_URL}/api/v1/trust-profiles?organization_id=${organizationId}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to load trust profiles: ${response.statusText}`);
      }

      const data = await response.json();
      setTrustProfiles(data.profiles || []);
    } catch (err) {
      console.error('Error loading trust profiles:', err);
      // Use mock data
      setTrustProfiles(generateMockTrustProfiles());
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
      const method = templateData.id ? 'PUT' : 'POST';
      const url = templateData.id
        ? `${API_URL}/api/v1/application-templates/${templateData.id}`
        : `${API_URL}/api/v1/application-templates`;

      const response = await fetch(url, {
        method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...templateData, organization_id: organizationId }),
      });

      if (!response.ok) {
        throw new Error(`Failed to save template: ${response.statusText}`);
      }

      setSnackbar({
        open: true,
        message: templateData.id ? 'Template updated successfully' : 'Template created successfully',
        severity: 'success',
      });

      setFormDialogOpen(false);
      loadTemplates();
    } catch (err) {
      console.error('Error saving template:', err);
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  /**
   * Handle delete template
   */
  const handleDelete = async () => {
    if (!templateToDelete) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/application-templates/${templateToDelete.id}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to delete template: ${response.statusText}`);
      }

      setSnackbar({
        open: true,
        message: 'Template deleted successfully',
        severity: 'success',
      });

      setDeleteDialogOpen(false);
      setTemplateToDelete(null);
      loadTemplates();
    } catch (err) {
      console.error('Error deleting template:', err);
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
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
            Application Templates
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Templates define what applicants can apply for and encapsulate trust profiles, credential types, and
            required documents.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
          Create Template
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
                          onClick={() => {
                            setTemplateToDelete(template);
                            setDeleteDialogOpen(true);
                          }}
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

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Template</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete <strong>{templateToDelete?.name}</strong>? This action cannot be
            undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
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
