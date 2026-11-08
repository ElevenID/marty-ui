/** Organization profile and admission settings for the selected organization. */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert, Avatar, Box, Button, Card, CardContent, FormControl,
  FormControlLabel, FormHelperText, Grid, InputLabel, LinearProgress,
  MenuItem, Paper, Select, Switch, TextField, Typography,
} from '@mui/material';
import BusinessIcon from '@mui/icons-material/Business';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Save';

import { ResourcePage } from '../../common';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { loadOrgSettings, saveOrgSettings } from '../../../application/orgSettings';
import { isValidOrganizationName } from '../../../application/orgSettings/orgSettingsFlow';
import OrgDefaultsSection from './OrgDefaultsSection';

const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: t('org.tabs.apiKeys', 'API Keys'), path: '/console/org/api-keys' },
  { label: t('org.tabs.webhooks'), path: '/console/org/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: t('org.breadcrumbs.organization'), path: '/console/org/settings' },
];

function OrganizationSettingsForm({ organizationId, organizationName }) {
  const { t } = useTranslation('console');
  const { can } = usePermissions();
  const canEdit = can('organization', 'edit');
  const [org, setOrg] = useState(null);
  const [savedOrg, setSavedOrg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [retry, setRetry] = useState(0);
  const generation = useRef(0);
  const savePending = useRef(false);

  useEffect(() => {
    const request = ++generation.current;
    const current = () => generation.current === request;
    setLoading(true);
    setOrg(null);
    setSavedOrg(null);
    setError(null);
    setSuccess(false);
    setEditMode(false);
    setSaving(false);
    savePending.current = false;

    if (!organizationId) {
      setLoading(false);
    } else {
      loadOrgSettings({ organizationId }).then(({ org: loaded, error: loadError }) => {
        if (!current()) return;
        setOrg(loaded);
        setSavedOrg(loaded);
        setError(loadError);
        setLoading(false);
      });
    }
    return () => { generation.current += 1; };
  }, [organizationId, retry]);

  const handleSave = async (event) => {
    event.preventDefault();
    if (!organizationId || !savedOrg || loading || !canEdit || !editMode || !formValid || savePending.current) return;
    const request = generation.current;
    savePending.current = true;
    setSaving(true);
    setError(null);
    setSuccess(false);
    const { org: updated, error: saveError } = await saveOrgSettings({ organizationId, org, originalOrg: savedOrg });
    if (generation.current !== request) return;
    savePending.current = false;
    setSaving(false);
    if (saveError) {
      setError(saveError);
    } else {
      setOrg(updated);
      setSavedOrg(updated);
      setSuccess(true);
      setEditMode(false);
    }
  };

  const handleChange = (field, value) => {
    setSuccess(false);
    setOrg((previous) => ({ ...previous, [field]: value }));
  };

  const editable = editMode && canEdit && !saving;
  const invalidAdmission = org?.joinMechanism === 'open' && org?.visibility !== 'PUBLIC';
  const nameChanged = org && savedOrg && org.name.trim() !== savedOrg.name.trim();
  const invalidName = nameChanged && !isValidOrganizationName(org.name.trim());
  const formValid = Boolean(org?.name.trim() && org?.displayName.trim() && !invalidAdmission && !invalidName);
  const formId = 'organization-settings-profile';
  const textField = (field, label, options = {}) => (
    <TextField
      fullWidth
      label={label}
      value={org[field]}
      onChange={(event) => handleChange(field, event.target.value)}
      disabled={!editable}
      {...options}
    />
  );

  return (
    <ResourcePage
      title={t('org.title')}
      description={t('org.settings.description')}
      tabs={getOrgTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={org && !loading && canEdit ? (
        editMode ? (
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              disabled={saving}
              onClick={() => { setOrg(savedOrg); setEditMode(false); setError(null); }}
            >
              {t('actions.cancel', { ns: 'common' })}
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              type="submit"
              form={formId}
              disabled={saving || !formValid}
            >
              {saving ? t('org.settings.saving') : t('org.settings.saveChanges')}
            </Button>
          </Box>
        ) : (
          <Button
            variant="outlined"
            startIcon={<EditIcon />}
            onClick={() => { setEditMode(true); setSuccess(false); }}
          >
            {t('org.settings.editMode')}
          </Button>
        )
      ) : null}
    >
      {loading && <LinearProgress aria-label={t('org.settings.loading', 'Loading organization details')} />}
      {!organizationId && (
        <Alert severity="info">{t('org.settings.organizationRequired', 'Select an organization to view its settings.')}</Alert>
      )}
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={!org && organizationId ? (
            <Button color="inherit" onClick={() => setRetry((value) => value + 1)}>
              {t('actions.retry', { ns: 'common', defaultValue: 'Retry' })}
            </Button>
          ) : undefined}
        >
          {!org && organizationId ? `${t('org.settings.errorLoading')}: ${error}` : error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess(false)}>
          {t('org.settings.successMessage')}
        </Alert>
      )}

      {organizationId && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar sx={{ width: 64, height: 64, bgcolor: 'primary.main' }}>
                <BusinessIcon sx={{ fontSize: 32 }} />
              </Avatar>
              <Box>
                <Typography variant="h5">{savedOrg?.displayName || organizationName}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t('org.settings.organizationId')}: {organizationId}
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {org && !loading && (
        <>
          <Box component="form" id={formId} onSubmit={handleSave}>
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>{t('org.settings.profile.title')}</Typography>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  {textField('name', t('org.settings.profile.name'), {
                    required: true,
                    error: Boolean(invalidName),
                    helperText: editMode ? t('org.settings.profile.nameHelp', 'Use 2–64 lowercase letters, numbers, or hyphens. Start and end with a letter or number.') : undefined,
                    slotProps: { htmlInput: { minLength: 2, maxLength: 64 } },
                  })}
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  {textField('displayName', t('org.settings.profile.displayName'), { required: true, slotProps: { htmlInput: { maxLength: 128 } } })}
                </Grid>
                <Grid size={12}>
                  {textField('description', t('org.settings.profile.description'), { multiline: true, rows: 2, slotProps: { htmlInput: { maxLength: 1024 } } })}
                </Grid>
              </Grid>
            </Paper>

            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>{t('org.settings.profile.contactInfo')}</Typography>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  {textField('website', t('org.settings.profile.website'), { type: 'url' })}
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  {textField('contactEmail', t('org.settings.profile.contactEmail'), { type: 'email' })}
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  {textField('contactPhone', t('org.settings.profile.contactPhone', 'Contact Phone'), { type: 'tel', slotProps: { htmlInput: { maxLength: 50 } } })}
                </Grid>
              </Grid>
            </Paper>

            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>{t('org.settings.admission.title', 'Organization Membership')}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                {t('org.settings.admission.description', 'Choose who can find your organization and how new members join.')}
              </Typography>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth disabled={!editable}>
                    <InputLabel id="org-visibility-label">{t('org.settings.admission.visibility', 'Visibility')}</InputLabel>
                    <Select
                      labelId="org-visibility-label"
                      id="org-visibility"
                      label={t('org.settings.admission.visibility', 'Visibility')}
                      value={org.visibility}
                      onChange={(event) => handleChange('visibility', event.target.value)}
                    >
                      <MenuItem value="PRIVATE">{t('org.settings.admission.private', 'Private')}</MenuItem>
                      <MenuItem value="PUBLIC">{t('org.settings.admission.public', 'Public')}</MenuItem>
                    </Select>
                    <FormHelperText>{t('org.settings.admission.visibilityHelp', 'Public organizations appear in the organization directory.')}</FormHelperText>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth disabled={!editable}>
                    <InputLabel id="org-join-method-label">{t('org.settings.admission.joinMethod', 'Join Method')}</InputLabel>
                    <Select
                      labelId="org-join-method-label"
                      id="org-join-method"
                      label={t('org.settings.admission.joinMethod', 'Join Method')}
                      value={org.joinMechanism}
                      onChange={(event) => handleChange('joinMechanism', event.target.value)}
                    >
                      <MenuItem value="invite">{t('org.settings.admission.invite', 'Invitation')}</MenuItem>
                      <MenuItem value="code" disabled>{t('org.settings.admission.code', 'Join code (existing configuration only)')}</MenuItem>
                      <MenuItem value="open">{t('org.settings.admission.open', 'Open enrollment')}</MenuItem>
                      <MenuItem value="domain" disabled>{t('org.settings.admission.domain', 'Email domain (unavailable)')}</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={12}>
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={org.requiresApproval}
                        disabled={!editable}
                        onChange={(event) => handleChange('requiresApproval', event.target.checked)}
                      />
                    )}
                    label={t('org.settings.admission.requiresApproval', 'Require approval for join requests')}
                  />
                </Grid>
              </Grid>
              {invalidAdmission && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  {t('org.settings.admission.openRequiresPublic', 'Open enrollment requires public visibility. Choose public visibility or another join method.')}
                </Alert>
              )}
            </Paper>
          </Box>
          <OrgDefaultsSection />
          <Paper sx={{ p: 3, border: 1, borderColor: 'error.main' }}>
            <Typography variant="h6" color="error" gutterBottom>{t('org.settings.danger.title')}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{t('org.settings.danger.description')}</Typography>
            <Button variant="outlined" color="error" disabled>{t('org.settings.danger.deleteOrganization')}</Button>
          </Paper>
        </>
      )}
    </ResourcePage>
  );
}

export default function OrganizationSettingsPage() {
  const { activeOrgId, memberships = [] } = useConsole();
  const membership = memberships.find((item) => item.id === activeOrgId);
  // A new organization gets a fresh draft; pending work from the old form is discarded.
  return (
    <OrganizationSettingsForm
      key={activeOrgId || 'no-organization'}
      organizationId={activeOrgId}
      organizationName={membership?.display_name || membership?.name || ''}
    />
  );
}
