/** Select active profiles and a DID compatible with the API-derived template context. */
import { useEffect, useState } from 'react';
import { Box, Typography, FormControl, InputLabel, Select, MenuItem, FormHelperText, Alert, CircularProgress, Button, Stack, TextField } from '@mui/material';
import { useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { listTrustProfiles } from '../../../../services/presentationPolicyApi';
import { listComplianceProfiles } from '../../../../services/complianceProfilesApi';
import issuerIdentitiesApi from '../../../../services/issuerIdentitiesApi';
import { useConsole } from '../../../../contexts/ConsoleContext';
import { templateIssuerRequest } from '../templateIssuerSelection';
import { loadScopedCatalog } from '../../../../services/loadScopedCatalog';

const active = (profile) => String(profile?.status || '').toLowerCase() === 'active';
const EMPTY = [];
const profilesFrom = (response) => {
  const profiles = response?.data || response;
  if (!Array.isArray(profiles)) throw new Error('Profile catalog returned invalid data.');
  return profiles;
};

const TrustComplianceStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const [catalog, setCatalog] = useState(null);
  const [options, setOptions] = useState(null);
  const [refreshCatalog, setRefreshCatalog] = useState(0);
  const [refreshOptions, setRefreshOptions] = useState(0);
  const requestKey = JSON.stringify(templateIssuerRequest(data, activeOrgId));

  useEffect(() => {
    let current = true;
    const controller = new AbortController();
    setCatalog(null);
    if (activeOrgId) {
      Promise.all([
        loadScopedCatalog(listTrustProfiles, activeOrgId, { signal: controller.signal }),
        loadScopedCatalog(listComplianceProfiles, activeOrgId, { signal: controller.signal }),
      ]).then(([trust, compliance]) => {
        if (!current) return;
        setCatalog({ organizationId: activeOrgId,
          trust: profilesFrom(trust).filter((profile) => active(profile)
            && (!profile.organization_id || profile.organization_id === activeOrgId)),
          compliance: profilesFrom(compliance).filter((profile) => active(profile) && profile.discoverable !== false
            && (profile.organization_id === activeOrgId || (profile.organization_id == null && profile.is_system === true))),
        });
      }).catch((error) => { if (current) setCatalog({ organizationId: activeOrgId, error }); });
    }
    return () => { current = false; controller.abort(); };
  }, [activeOrgId, refreshCatalog]);

  const trustProfiles = catalog?.organizationId === activeOrgId ? catalog.trust || EMPTY : EMPTY;
  const complianceProfiles = catalog?.organizationId === activeOrgId ? catalog.compliance || EMPTY : EMPTY;
  const catalogsReady = catalog?.organizationId === activeOrgId && !catalog.error;
  const trustValid = catalogsReady && trustProfiles.some((profile) => profile.id === data.trust_profile_id);
  const complianceValid = catalogsReady && complianceProfiles.some((profile) => profile.id === data.compliance_profile_id);

  useEffect(() => {
    if (!catalogsReady) return;
    const patch = {};
    if (!trustValid) patch.trust_profile_id = trustProfiles.length === 1 ? trustProfiles[0].id : null;
    if (!complianceValid) {
      patch.compliance_profile_id = complianceProfiles.length === 1 ? complianceProfiles[0].id : null;
      patch.issuer_did = null;
      patch.credential_payload_format = undefined;
      patch.supported_formats = undefined;
      patch.issuance_protocol = undefined;
      patch._issuer_selection = null;
    }
    if (Object.keys(patch).some((key) => patch[key] !== data[key])) onChange(patch);
  }, [catalogsReady, trustValid, complianceValid, catalog, data, onChange, trustProfiles, complianceProfiles]);

  useEffect(() => {
    let current = true;
    if (complianceValid && options?.canonicalKey === requestKey && options.generation === refreshOptions) return;
    setOptions(null);
    if (data._issuer_selection) onChange({ _issuer_selection: null });
    const request = JSON.parse(requestKey);
    if (request.organization_id && request.compliance_profile_id && complianceValid) {
      issuerIdentitiesApi.getTemplateIssuerOptions(request).then((result) => {
        if (current) setOptions({ key: requestKey, canonicalKey: JSON.stringify(templateIssuerRequest(result, activeOrgId)), generation: refreshOptions, data: result });
      }).catch((error) => { if (current) setOptions({ key: requestKey, error }); });
    }
    return () => { current = false; };
    // Selection metadata is output of this request, not a reason to reload it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey, refreshOptions, complianceValid, onChange]);

  const currentOptions = complianceValid && (options?.key === requestKey || options?.canonicalKey === requestKey) ? options.data : null;
  const identities = currentOptions?.identities || [];
  const selectedIdentity = identities.find((identity) => identity.issuer_did === data.issuer_did);

  useEffect(() => {
    if (!currentOptions) return;
    const patch = {
      credential_payload_format: currentOptions.credential_payload_format,
      supported_formats: currentOptions.supported_formats,
      issuance_protocol: currentOptions.issuance_protocol,
      ...(currentOptions.requirements.revocation_profile === false && data.revocation_profile_id ? { revocation_profile_id: null } : {}),
      _issuer_selection: selectedIdentity && trustValid ? {
        organization_id: activeOrgId, compliance_profile_id: currentOptions.compliance_profile_id,
        trust_profile_id: data.trust_profile_id, issuer_did: selectedIdentity.issuer_did,
        credential_payload_format: currentOptions.credential_payload_format,
        supported_formats: currentOptions.supported_formats, issuance_protocol: currentOptions.issuance_protocol,
        requirements: currentOptions.requirements,
      } : null,
      ...(!selectedIdentity && data.issuer_did ? { issuer_did: null } : {}),
    };
    if (Object.keys(patch).some((key) => JSON.stringify(patch[key]) !== JSON.stringify(data[key]))) onChange(patch);
  }, [currentOptions, selectedIdentity, trustValid, activeOrgId, data, onChange]);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>{t('wizards.credentialTemplate.trustComplianceStep.title')}</Typography>
      <Typography color="text.secondary" sx={{ mb: 2 }}>Choose active profiles, then select an issuer DID that supports this template.</Typography>
      {!activeOrgId && <Alert severity="warning">Select an organization before choosing profiles.</Alert>}
      {activeOrgId && !catalog && <CircularProgress aria-label="Loading profile catalogs" size={24} />}
      {catalog?.organizationId === activeOrgId && catalog.error && <Alert severity="error">Profiles could not be loaded. {catalog.error.message}</Alert>}
      <Button disabled={!activeOrgId} onClick={() => setRefreshCatalog((value) => value + 1)}>Refresh profiles</Button>
      {catalogsReady && trustProfiles.length === 0 && <Alert severity="warning">Trust profile required. Create or activate a Trust Profile before continuing.</Alert>}
      <FormControl fullWidth required sx={{ my: 2 }}>
        <InputLabel id="template-trust-label">Trust Profile</InputLabel>
        <Select labelId="template-trust-label" label="Trust Profile" value={trustValid ? data.trust_profile_id : ''}
          onChange={(event) => onChange({ trust_profile_id: event.target.value, _issuer_selection: null })}
          disabled={!catalogsReady} SelectDisplayProps={{ 'data-testid': 'template-trust-profile-select' }}>
          {trustProfiles.map((profile) => <MenuItem key={profile.id} value={profile.id}>{profile.name}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl fullWidth required sx={{ mb: 2 }}>
        <InputLabel id="template-compliance-label">Compliance Profile</InputLabel>
        <Select labelId="template-compliance-label" label="Compliance Profile" value={complianceValid ? data.compliance_profile_id : ''}
          data-testid="template-compliance-profile-select" disabled={!catalogsReady}
          onChange={(event) => onChange({ compliance_profile_id: event.target.value, issuer_did: null,
            credential_payload_format: undefined, supported_formats: undefined, issuance_protocol: undefined, _issuer_selection: null })}>
          {complianceProfiles.map((profile) => <MenuItem key={profile.id} value={profile.id}>{profile.name || profile.compliance_code || profile.id}</MenuItem>)}
        </Select>
        <FormHelperText>{complianceProfiles.length} active compliance profiles available.</FormHelperText>
      </FormControl>
      {!complianceValid && <Alert severity="info">Select an active Compliance Profile to discover compatible issuer DIDs.</Alert>}
      {complianceValid && !options && <CircularProgress aria-label="Checking issuer compatibility" size={24} />}
      {options?.key === requestKey && options.error && <Alert severity="error">Issuer compatibility could not be checked. {options.error.message}</Alert>}
      {currentOptions && <Typography sx={{ mb: 2 }}>Format: {currentOptions.credential_payload_format}. Issuance protocol: {currentOptions.issuance_protocol}.</Typography>}
      {currentOptions && identities.length === 0 && <Alert severity="warning">No compatible issuer DID is available for this template. Create a matching identity or repair its registry bindings.</Alert>}
      {currentOptions?.rejected_issuers?.some((issuer) => issuer.reason === 'ambiguous_identity') && <Alert severity="warning">An issuer DID has ambiguous registry bindings and cannot be selected.</Alert>}
      <FormControl fullWidth required sx={{ my: 2 }}>
        <InputLabel id="template-issuer-label">Issuer DID</InputLabel>
        <Select labelId="template-issuer-label" label="Issuer DID" value={selectedIdentity?.issuer_did || ''} disabled={!currentOptions}
          onChange={(event) => onChange({ issuer_did: event.target.value, _issuer_selection: null })}
          SelectDisplayProps={{ 'data-testid': 'template-issuer-profile-select' }}>
          {identities.map((identity) => <MenuItem key={identity.issuer_did} value={identity.issuer_did}>{identity.issuer_did}</MenuItem>)}
        </Select>
        <FormHelperText>{identities.length} compatible issuer DIDs available.</FormHelperText>
      </FormControl>
      <Button disabled={!complianceValid} onClick={() => setRefreshOptions((value) => value + 1)}>Refresh issuer compatibility</Button>
      {currentOptions?.requirements?.vct && <TextField fullWidth required label="Credential type URI (VCT)" value={data.vct || ''}
        onChange={(event) => onChange({ vct: event.target.value })} helperText="Required by the selected credential format." sx={{ mt: 2 }} />}
      {currentOptions?.requirements?.doctype && <TextField fullWidth required label="Document type (doctype)" value={data.doctype || ''}
        onChange={(event) => onChange({ doctype: event.target.value })} helperText="Required by the selected credential format." sx={{ mt: 2 }} />}
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button onClick={() => navigate('/console/org/trust/profiles/new')}>Create Trust Profile</Button>
        <Button onClick={() => navigate('/console/org/deploy/issuer-identity/new')}>Create issuer identity</Button>
      </Stack>
    </Box>
  );
};

export default TrustComplianceStep;
