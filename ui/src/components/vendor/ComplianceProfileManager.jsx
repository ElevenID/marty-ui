/**
 * Compliance Profile Manager Component
 * 
 * Manages compliance profiles that abstract credential format complexity
 * behind compliance-focused configurations (ICAO_DTC, AAMVA_MDL, EUDI_PID, ENTERPRISE_VC).
 * Includes issuer consistency validation rules per compliance standard.
 */

import { useState, useEffect } from 'react';
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
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

import { useAuth } from '../../hooks/useAuth';
import complianceProfilesApi from '../../services/complianceProfilesApi';

const ComplianceProfileManager = () => {
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  const COMPLIANCE_CODES = [
    { value: 'ICAO_DTC', label: t('complianceProfiles.codes.icao'), description: t('complianceProfiles.codes.icaoDesc') },
    { value: 'AAMVA_MDL', label: t('complianceProfiles.codes.aamva'), description: t('complianceProfiles.codes.aamvaDesc') },
    { value: 'EUDI_PID', label: t('complianceProfiles.codes.eudi'), description: t('complianceProfiles.codes.eudiDesc') },
    { value: 'ENTERPRISE_VC', label: t('complianceProfiles.codes.enterprise'), description: t('complianceProfiles.codes.enterpriseDesc') },
  ];

  const CREDENTIAL_FORMATS = [
    { value: 'mdoc', label: t('complianceProfiles.formats.mdoc') },
    { value: 'sd_jwt_vc', label: t('complianceProfiles.formats.sdJwtVc') },
    { value: 'jwt_vc', label: t('complianceProfiles.formats.jwtVc') },
    { value: 'ldp_vc', label: t('complianceProfiles.formats.ldpVc') },
  ];
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [currentProfile, setCurrentProfile] = useState({
    name: '',
    code: '',
    description: '',
    credential_format_mapping: {},
    issuer_artifact_requirements: {},
    default_claim_verification_rules: {},
    trust_profile_constraints: {},
    is_system_profile: false,
  });

  // Load profiles
  useEffect(() => {
    loadProfiles();
  }, [organizationId]);

  const loadProfiles = async () => {
    if (!organizationId) {
      setProfiles([]);
      setError(t('complianceProfiles.loadFailed'));
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const allProfiles = await complianceProfilesApi.listComplianceProfiles({ organization_id: organizationId });
      setProfiles(allProfiles);
      setError(null);
    } catch (err) {
      console.error('Failed to load compliance profiles:', err);
      setError(t('complianceProfiles.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setCurrentProfile({
      name: '',
      code: 'ENTERPRISE_VC',
      description: '',
      credential_format_mapping: {
        primary_format: 'jwt_vc',
        supported_formats: ['jwt_vc', 'sd_jwt_vc'],
      },
      issuer_artifact_requirements: {
        jwt_vc: {
          requires_issuer_did: true,
          requires_signing_key: true,
          requires_certificate_chain: false,
        },
      },
      default_claim_verification_rules: {},
      trust_profile_constraints: {
        enforce_issuer_consistency: true,
        allowed_did_methods: ['did:web', 'did:key'],
      },
      is_system_profile: false,
    });
    setEditMode(false);
    setDialogOpen(true);
  };

  const handleEdit = (profile) => {
    setCurrentProfile(profile);
    setEditMode(true);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    try {
      if (editMode) {
        await complianceProfilesApi.updateComplianceProfile(currentProfile.id, currentProfile);
      } else {
        await complianceProfilesApi.createComplianceProfile(currentProfile);
      }
      setDialogOpen(false);
      loadProfiles();
    } catch (err) {
      console.error('Failed to save compliance profile:', err);
      setError(t('complianceProfiles.saveFailed', { error: err.message }));
    }
  };

  const handleDelete = async (profileId) => {
    if (!window.confirm(t('complianceProfiles.deleteConfirm'))) {
      return;
    }
    try {
      await complianceProfilesApi.deleteComplianceProfile(profileId);
      loadProfiles();
    } catch (err) {
      console.error('Failed to delete compliance profile:', err);
      setError(t('complianceProfiles.deleteFailed', { error: err.message }));
    }
  };

  const getIssuerConsistencyRules = (code) => {
    const rules = {
      ICAO_DTC: t('complianceProfiles.consistencyRules.icao'),
      AAMVA_MDL: t('complianceProfiles.consistencyRules.aamva'),
      EUDI_PID: t('complianceProfiles.consistencyRules.eudi'),
      ENTERPRISE_VC: t('complianceProfiles.consistencyRules.enterprise'),
    };
    return rules[code] || t('complianceProfiles.consistencyRules.none');
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4">{t('complianceProfiles.title')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('complianceProfiles.description')}
          </Typography>
        </Box>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={handleCreate}
        >
          {t('complianceProfiles.createButton')}
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* System Presets */}
      <Paper sx={{ mb: 3, p: 2 }}>
        <Box display="flex" alignItems="center" mb={2}>
          <SecurityIcon sx={{ mr: 1 }} />
          <Typography variant="h6">{t('complianceProfiles.systemPresets.title')}</Typography>
          <Chip label={t('complianceProfiles.systemPresets.immutable')} size="small" sx={{ ml: 2 }} />
        </Box>
        <Typography variant="body2" color="text.secondary" mb={2}>
          {t('complianceProfiles.systemPresets.description')}
        </Typography>
        <Box display="flex" flexWrap="wrap" gap={2}>
          {COMPLIANCE_CODES.map((preset) => (
            <Paper
              key={preset.value}
              variant="outlined"
              sx={{
                p: 2,
                flex: '1 1 calc(50% - 16px)',
                minWidth: '300px',
                cursor: 'pointer',
                '&:hover': { borderColor: 'primary.main' },
              }}
            >
              <Box display="flex" alignItems="center" mb={1}>
                <VerifiedUserIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="subtitle1">{preset.label}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" mb={1}>
                {preset.description}
              </Typography>
              <Divider sx={{ my: 1 }} />
              <Typography variant="caption" color="text.secondary">
                <strong>{t('complianceProfiles.systemPresets.issuerConsistency')}:</strong> {getIssuerConsistencyRules(preset.value)}
              </Typography>
            </Paper>
          ))}
        </Box>
      </Paper>

      {/* Custom Profiles */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" mb={2}>{t('complianceProfiles.customProfiles.title')}</Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('complianceProfiles.table.name')}</TableCell>
                  <TableCell>{t('complianceProfiles.table.code')}</TableCell>
                  <TableCell>{t('complianceProfiles.table.primaryFormat')}</TableCell>
                  <TableCell>{t('complianceProfiles.table.issuerConsistency')}</TableCell>
                  <TableCell align="right">{t('complianceProfiles.table.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {profiles.filter(p => !p.is_system_profile).map((profile) => (
                  <TableRow key={profile.id}>
                    <TableCell>{profile.name}</TableCell>
                    <TableCell>
                      <Chip label={profile.code} size="small" />
                    </TableCell>
                    <TableCell>
                      {profile.credential_format_mapping?.primary_format || t('complianceProfiles.table.notAvailable')}
                    </TableCell>
                    <TableCell>
                      {profile.trust_profile_constraints?.enforce_issuer_consistency ? (
                        <Chip label={t('complianceProfiles.table.enforced')} color="success" size="small" />
                      ) : (
                        <Chip label={t('complianceProfiles.table.optional')} size="small" />
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('complianceProfiles.table.edit')}>
                        <IconButton size="small" onClick={() => handleEdit(profile)}>
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('complianceProfiles.table.delete')}>
                        <IconButton size="small" onClick={() => handleDelete(profile.id)}>
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {profiles.filter(p => !p.is_system_profile).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center">
                      <Typography color="text.secondary">
                        {t('complianceProfiles.customProfiles.empty')}
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      </Paper>

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {editMode ? t('complianceProfiles.dialog.editTitle') : t('complianceProfiles.dialog.createTitle')}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label={t('complianceProfiles.dialog.nameLabel')}
              value={currentProfile.name}
              onChange={(e) => setCurrentProfile({ ...currentProfile, name: e.target.value })}
              sx={{ mb: 2 }}
              required
            />

            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>{t('complianceProfiles.dialog.codeLabel')}</InputLabel>
              <Select
                value={currentProfile.code}
                onChange={(e) => setCurrentProfile({ ...currentProfile, code: e.target.value })}
                label={t('complianceProfiles.dialog.codeLabel')}
              >
                {COMPLIANCE_CODES.map((code) => (
                  <MenuItem key={code.value} value={code.value}>
                    {code.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              fullWidth
              label={t('complianceProfiles.dialog.descriptionLabel')}
              value={currentProfile.description}
              onChange={(e) => setCurrentProfile({ ...currentProfile, description: e.target.value })}
              multiline
              rows={2}
              sx={{ mb: 2 }}
            />

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>{t('complianceProfiles.dialog.formatMapping')}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>{t('complianceProfiles.dialog.primaryFormat')}</InputLabel>
                  <Select
                    value={currentProfile.credential_format_mapping?.primary_format || ''}
                    onChange={(e) => setCurrentProfile({
                      ...currentProfile,
                      credential_format_mapping: {
                        ...currentProfile.credential_format_mapping,
                        primary_format: e.target.value,
                      },
                    })}
                    label={t('complianceProfiles.dialog.primaryFormat')}
                  >
                    {CREDENTIAL_FORMATS.map((fmt) => (
                      <MenuItem key={fmt.value} value={fmt.value}>
                        {fmt.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <Typography variant="subtitle2" mb={1}>{t('complianceProfiles.dialog.supportedFormats')}</Typography>
                <FormGroup>
                  {CREDENTIAL_FORMATS.map((fmt) => (
                    <FormControlLabel
                      key={fmt.value}
                      control={
                        <Checkbox
                          checked={currentProfile.credential_format_mapping?.supported_formats?.includes(fmt.value) || false}
                          onChange={(e) => {
                            const formats = currentProfile.credential_format_mapping?.supported_formats || [];
                            const newFormats = e.target.checked
                              ? [...formats, fmt.value]
                              : formats.filter(f => f !== fmt.value);
                            setCurrentProfile({
                              ...currentProfile,
                              credential_format_mapping: {
                                ...currentProfile.credential_format_mapping,
                                supported_formats: newFormats,
                              },
                            });
                          }}
                        />
                      }
                      label={fmt.label}
                    />
                  ))}
                </FormGroup>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>{t('complianceProfiles.dialog.consistencyRules')}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="info" sx={{ mb: 2 }}>
                  {getIssuerConsistencyRules(currentProfile.code)}
                </Alert>
                
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={currentProfile.trust_profile_constraints?.enforce_issuer_consistency || false}
                      onChange={(e) => setCurrentProfile({
                        ...currentProfile,
                        trust_profile_constraints: {
                          ...currentProfile.trust_profile_constraints,
                          enforce_issuer_consistency: e.target.checked,
                        },
                      })}
                    />
                  }
                  label={t('complianceProfiles.dialog.enforceConsistency')}
                />

                <Typography variant="subtitle2" mt={2} mb={1}>{t('complianceProfiles.dialog.allowedDidMethods')}</Typography>
                <FormGroup>
                  {['did:web', 'did:key', 'did:jwk'].map((method) => (
                    <FormControlLabel
                      key={method}
                      control={
                        <Checkbox
                          checked={currentProfile.trust_profile_constraints?.allowed_did_methods?.includes(method) || false}
                          onChange={(e) => {
                            const methods = currentProfile.trust_profile_constraints?.allowed_did_methods || [];
                            const newMethods = e.target.checked
                              ? [...methods, method]
                              : methods.filter(m => m !== method);
                            setCurrentProfile({
                              ...currentProfile,
                              trust_profile_constraints: {
                                ...currentProfile.trust_profile_constraints,
                                allowed_did_methods: newMethods,
                              },
                            });
                          }}
                        />
                      }
                      label={method}
                    />
                  ))}
                </FormGroup>
              </AccordionDetails>
            </Accordion>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>{t('complianceProfiles.dialog.cancelButton')}</Button>
          <Button onClick={handleSave} variant="contained" color="primary">
            {editMode ? t('complianceProfiles.dialog.updateButton') : t('complianceProfiles.dialog.createButton')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ComplianceProfileManager;
