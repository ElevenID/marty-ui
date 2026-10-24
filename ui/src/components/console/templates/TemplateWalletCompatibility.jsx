import { useEffect, useState } from 'react';
import { Alert, Box, Button, Chip, LinearProgress, Paper, Stack, Typography } from '@mui/material';
import { getTemplateWalletCompatibility } from '../../../services/walletRegistryApi';

const stringArray = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');

function validateProfile(profile, organizationId, template) {
  if (!profile || typeof profile !== 'object'
    || (profile.organization_id != null && profile.organization_id !== organizationId)
    || !['name', 'description', 'credential_format', 'issuance_protocol', 'deep_link_pattern', 'merge_strategy'].every((key) => typeof profile[key] === 'string')
    || !['wallet_apps', 'specifications', 'supported_platforms', 'applied_override_ids'].every((key) => stringArray(profile[key]))
    || typeof profile.is_override !== 'boolean' || !Number.isInteger(profile.override_precedence)
    || (template.credential_payload_format && profile.credential_format !== template.credential_payload_format)
    || (template.issuance_protocol && profile.issuance_protocol !== template.issuance_protocol)
    || profile.derived_from?.credential_format !== profile.credential_format
    || profile.derived_from?.issuance_protocol !== profile.issuance_protocol
    || !Array.isArray(profile.template_wallet_configs)
    || !profile.template_wallet_configs.every((config) => typeof config?.wallet_id === 'string' && typeof config.deep_link_scheme === 'string'
      && (config.format_variant == null || typeof config.format_variant === 'string'))) {
    throw new Error('Wallet profile response is invalid or outside the selected organization.');
  }
  return profile;
}

function Values({ label, values }) {
  return <Box><Typography variant="subtitle2">{label}</Typography>
    {values.length ? <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">{values.map((value, index) => <Chip key={`${index}-${value}`} label={value} size="small" />)}</Stack>
      : <Typography variant="body2">None configured</Typography>}</Box>;
}

/** Mount only after checking the owning template and selected organization. */
export default function TemplateWalletCompatibility({ template, organizationId }) {
  const [state, setState] = useState({ loading: true, profile: null, error: '' });
  const [attempt, setAttempt] = useState(0);
  const physical = template.credential_payload_format === 'ICAO_EMRTD' || template.issuance_protocol === 'PHYSICAL_DOCUMENT';
  useEffect(() => {
    let current = true;
    if (physical) return () => { current = false; };
    setState({ loading: true, profile: null, error: '' });
    getTemplateWalletCompatibility(template.id).then((profile) => validateProfile(profile, organizationId, template))
      .then((profile) => { if (current) setState({ loading: false, profile, error: '' }); })
      .catch((error) => { if (current) setState({ loading: false, profile: null, error: error?.message || 'Wallet profile could not be loaded.' }); });
    return () => { current = false; };
  }, [template, organizationId, attempt, physical]);

  if (physical) return <Alert severity="info">Wallet profiles do not apply to physical documents.</Alert>;
  const { loading, profile, error } = state;
  return <Stack spacing={2}>
    <Alert severity="info">This profile is derived from the template's primary credential format, issuance protocol and compliance profile, with registry overrides. It is configuration, not verified wallet interoperability or delivery evidence. Other declared credential formats require separate qualification.</Alert>
    {loading && <LinearProgress aria-label="Loading wallet profile" />}
    {error && <Alert severity="error">{error}<Button onClick={() => setAttempt((value) => value + 1)}>Retry wallet profile</Button></Alert>}
    {profile && <Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={2}>
      <Stack direction="row" spacing={1} alignItems="center"><Typography variant="h6">{profile.name}</Typography><Chip label="Derived configuration" size="small" /></Stack>
      <Typography>{profile.description}</Typography>
      <Typography variant="body2"><strong>Derived from:</strong> {profile.derived_from.credential_format} / {profile.derived_from.issuance_protocol} / {profile.derived_from.compliance_profile_code || 'No compliance code'}</Typography>
      <Values label="Configured wallet applications" values={profile.wallet_apps} />
      <Values label="Specifications" values={profile.specifications} />
      <Values label="Configured platforms" values={profile.supported_platforms} />
      <Typography variant="body2"><strong>Registry overrides:</strong> {profile.is_override ? `${profile.merge_strategy}; primary precedence ${profile.override_precedence}` : 'None applied'}</Typography>
      <Values label="Applied override IDs" values={profile.applied_override_ids} />
      <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}><strong>Deep-link pattern:</strong> {profile.deep_link_pattern || 'Not configured'}</Typography>
      <Typography variant="subtitle2">Template wallet configuration</Typography>
      {profile.template_wallet_configs.length ? profile.template_wallet_configs.map((config, index) => <Typography key={`${index}-${config.wallet_id}`} variant="body2" sx={{ overflowWrap: 'anywhere' }}>
        {config.wallet_id} / {config.deep_link_scheme || 'Default scheme'} / {config.format_variant || 'Default variant'}
      </Typography>) : <Typography variant="body2">No template-specific wallet configuration</Typography>}
      <Button sx={{ alignSelf: 'flex-start' }} onClick={() => setAttempt((value) => value + 1)}>Refresh wallet profile</Button>
    </Stack></Paper>}
  </Stack>;
}
