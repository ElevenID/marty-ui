import { loadScopedCatalog } from '../../../services/loadScopedCatalog';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import {
  Alert, Box, Button, Checkbox, CircularProgress, Container, FormControl,
  FormControlLabel, IconButton, InputLabel, MenuItem, Paper, Select, Stack,
  TextField, Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DeleteIcon from '@mui/icons-material/Delete';
import SaveIcon from '@mui/icons-material/Save';

import { useConsole } from '../../../contexts/ConsoleContext';
import { useAuth } from '../../../hooks/useAuth';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { usePermissions } from '../../../hooks/usePermissions';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { listPolicySets } from '../../../services/policySetsApi';
import {
  createApplicationTemplate,
  getApplicationTemplate,
  updateApplicationTemplate,
} from '../../../services/applicationTemplatesApi';
import ApplicationEvidenceEditor from './ApplicationEvidenceEditor';
import DraftListField from './DraftListField';
import { formatFieldOptions, parseFieldOptions } from './applicationFieldOptions';

const EMPTY = {
  name: '', description: '', credential_template_id: '',
  evidence_requirements: [], required_checks: [], approval_strategy: 'MANUAL',
  approval_policy_set_id: null, application_validity_days: 30, notification_config: {},
  ui_config: {},
};

const SYSTEM_CLAIM_SOURCES = [
  'applicant.user_id', 'applicant.email', 'applicant.given_name', 'applicant.family_name',
  'application.id', 'application.reference_number', 'application.organization_id',
  'current.date', 'current.datetime', 'validity.expiry_date',
  'template.name', 'template.description', 'canvas.course_name', 'constant',
];

function normalizeFieldType(value) {
  const type = String(value || '').trim().toUpperCase();
  if (['DATE', 'DATETIME', 'INTEGER', 'NUMBER', 'BOOLEAN', 'EMAIL', 'URL', 'SELECT', 'FILE_UPLOAD'].includes(type)) return type;
  if (['ENUM', 'CHOICE'].includes(type)) return 'SELECT';
  return 'TEXT';
}

function claimField(claim) {
  const fieldId = claim.field_id || claim.name;
  return {
    field_id: fieldId,
    label: claim.display_name || claim.label || fieldId,
    field_type: normalizeFieldType(claim.field_type || claim.claim_type || claim.type),
    required: Boolean(claim.required),
    options: claim.options || claim.enum || undefined,
    validation_pattern: claim.validation_pattern || claim.pattern || undefined,
    minimum: claim.minimum,
    maximum: claim.maximum,
    claim_mapping: fieldId,
  };
}

function actionInView(action, isCurrentView) {
  const isCurrent = () => action.isCurrent() && isCurrentView();
  const requireCurrent = () => {
    if (!isCurrent()) {
      const error = new Error('The Application Template view or action changed.');
      error.name = 'AbortError';
      throw error;
    }
  };
  return {
    isCurrent,
    async run(operation, ...args) {
      requireCurrent();
      try {
        return await action.run(operation, ...args);
      } finally {
        requireCurrent();
      }
    },
  };
}

function ApplicationTemplateEditorContent({ organizationId, templateId, advanced, browserEntry }) {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const beginSave = useAsyncActionScope();
  const savingRef = useRef(false);
  const isCurrentBrowserEntry = useCallback(() => browserEntry.href === null || (
    typeof window !== 'undefined' && window.location.href === browserEntry.href
      && window.history.state?.key === browserEntry.key
      && (browserEntry.key || 'default') === browserEntry.routeKey
  ), [browserEntry]);
  const [data, setData] = useState(EMPTY);
  const [fieldRows, setFieldRows] = useState([]);
  const [claimRows, setClaimRows] = useState([]);
  const nextRowId = useRef(0);
  const formFields = fieldRows.map(({ field }) => field);
  const claimRules = claimRows.map(({ rule }) => rule);
  const [credentialTemplates, setCredentialTemplates] = useState([]);
  const [approvalPolicySets, setApprovalPolicySets] = useState([]);
  const [policySetsError, setPolicySetsError] = useState('');
  const [loading, setLoading] = useState(Boolean(templateId));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [resourceReady, setResourceReady] = useState(!templateId);

  useLayoutEffect(() => {
    if (typeof window === 'undefined') return undefined;
    // Back can restore the original URL before React replaces the departed editor.
    const invalidateSave = () => { beginSave(); };
    window.addEventListener('popstate', invalidateSave, true);
    return () => window.removeEventListener('popstate', invalidateSave, true);
  }, [beginSave]);

  useEffect(() => {
    let active = true;
    if (!organizationId) {
      setCredentialTemplates([]);
      setError('Select an organization before editing Application Templates.');
      setLoading(false);
      return () => { active = false; };
    }
    Promise.all([
      loadScopedCatalog(listCredentialTemplates, organizationId),
      templateId ? getApplicationTemplate(templateId, organizationId) : Promise.resolve(null),
    ]).then(([templates, existing]) => {
      if (!active) return;
      if (!Array.isArray(templates) || templates.some((item) => item.organization_id !== organizationId)) {
        throw new Error('Credential Templates are not available in the selected organization.');
      }
      setCredentialTemplates(templates.filter((item) => (
        String(item.status || '').toUpperCase() === 'ACTIVE'
        && Boolean(item.revocation_profile_id)
      )));
      if (existing) {
        if (existing.id !== templateId || existing.organization_id !== organizationId) {
          throw new Error('This Application Template is not available in the selected organization.');
        }
        const { form_fields, claim_collection_rules, ...details } = existing;
        setData({ ...EMPTY, ...details });
        setFieldRows((form_fields || []).map((field) => ({ rowId: nextRowId.current++, field })));
        setClaimRows((claim_collection_rules || []).map((rule) => ({ rowId: nextRowId.current++, rule })));
        setResourceReady(true);
        if (String(existing.status || '').toUpperCase() !== 'DRAFT') {
          setError('Only draft Application Templates can be edited.');
        }
      }
    }).catch((reason) => active && setError(reason.message || String(reason)))
      .finally(() => active && setLoading(false));

    listPolicySets(organizationId, 'ACTIVE').then((policySets) => {
      if (!active) return;
      setApprovalPolicySets((Array.isArray(policySets) ? policySets : []).filter((item) => (
        String(item.status || '').toUpperCase() === 'ACTIVE'
        && String(item.policy_type || '').toUpperCase() === 'APPROVAL_RULES'
      )));
      setPolicySetsError('');
    }).catch((reason) => {
      if (!active) return;
      setApprovalPolicySets([]);
      setPolicySetsError(reason.message || String(reason));
    });
    return () => { active = false; };
  }, [organizationId, templateId]);

  const selectedCredential = useMemo(
    () => credentialTemplates.find((item) => item.id === data.credential_template_id),
    [credentialTemplates, data.credential_template_id],
  );
  // Keep the editable draft unchanged; only save a validated native integer.
  const validityDays = ['string', 'number'].includes(typeof data.application_validity_days)
    ? Number(data.application_validity_days) : NaN;
  const validityDaysError = Number.isInteger(validityDays) && validityDays >= 1 && validityDays <= 3650
    ? '' : t('applicationTemplatesPage.validation.validityDays', {
      defaultValue: 'Enter a whole number from 1 to 3650 days.',
    });

  const selectCredential = (credentialTemplateId) => {
    const selected = credentialTemplates.find((item) => item.id === credentialTemplateId);
    const derivedFields = Array.isArray(selected?.claims) ? selected.claims.map(claimField).filter((field) => field.field_id) : [];
    setData((current) => ({
      ...current,
      credential_template_id: credentialTemplateId,
    }));
    if (fieldRows.length === 0) {
      setFieldRows(derivedFields.map((field) => ({ rowId: nextRowId.current++, field })));
    }
  };

  const updateField = (index, changes) => setFieldRows((current) => current.map((row, fieldIndex) => (
    fieldIndex === index ? { ...row, field: { ...row.field, ...changes } } : row
  )));

  const updateClaimRule = (index, changes) => setClaimRows((current) => current.map((row, ruleIndex) => (
    ruleIndex === index ? { ...row, rule: { ...row.rule, ...changes } } : row
  )));

  const updateEvidenceSource = (index, key, value) => {
    const sourceConfig = { ...claimRules[index].source_config };
    if (value) sourceConfig[key] = value;
    else delete sourceConfig[key];
    updateClaimRule(index, { source_config: sourceConfig });
  };

  const save = async () => {
    if (savingRef.current || !isCurrentBrowserEntry() || String(data.status || 'DRAFT').toUpperCase() !== 'DRAFT') return;
    const invalidEvidence = data.evidence_requirements.some((item) => (
      !item.evidence_id || !item.description || !item.evidence_type
      || (['EXTERNAL_FACT', 'EXTERNAL_API'].includes(item.evidence_type) && (!item.provider || !item.fact_type))
      || (item.evidence_type === 'EXTERNAL_API' && !item.api?.url)
    ));
    if (!resourceReady || !organizationId || !data.name.trim() || !data.credential_template_id || formFields.length === 0) {
      setError('Name, active Credential Template, and at least one form field are required.');
      return;
    }
    if (validityDaysError) {
      setError(validityDaysError);
      return;
    }
    if (invalidEvidence) {
      setError('Complete every required Evidence field before saving.');
      return;
    }
    if (data.approval_strategy === 'RULES_BASED' && !data.approval_policy_set_id) {
      setError('Select an active approval Policy Set for rules-based approval.');
      return;
    }
    const action = actionInView(beginSave(), isCurrentBrowserEntry);
    savingRef.current = true;
    setSaving(true);
    setError('');
    try {
      const payload = {
        name: data.name.trim(),
        description: data.description || null,
        credential_template_id: data.credential_template_id,
        form_fields: formFields,
        evidence_requirements: data.evidence_requirements,
        required_checks: data.required_checks,
        claim_collection_rules: claimRules,
        approval_strategy: data.approval_strategy,
        approval_policy_set_id: data.approval_strategy === 'RULES_BASED' ? data.approval_policy_set_id : null,
        application_validity_days: validityDays,
        notification_config: data.notification_config,
        ui_config: data.ui_config,
      };
      const saved = templateId
        ? await action.run(updateApplicationTemplate, templateId, payload)
        : await action.run(createApplicationTemplate, { ...payload, organization_id: organizationId }, { isCurrent: action.isCurrent });
      if (action.isCurrent()) navigate(`/console/org/templates/applications/${encodeURIComponent(saved.id || templateId)}`);
    } catch (reason) {
      if (action.isCurrent()) setError(reason.message || String(reason));
    } finally {
      if (action.isCurrent()) {
        savingRef.current = false;
        setSaving(false);
      }
    }
  };

  const blockPendingEdit = (event) => {
    if (!savingRef.current && isCurrentBrowserEntry()) return;
    event.preventDefault();
    event.stopPropagation();
  };

  const leaveEditor = () => {
    if (!isCurrentBrowserEntry()) return;
    // Invalidate completion immediately, even if the destination needs time to render.
    beginSave();
    navigate('/console/org/templates/applications');
  };

  if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;
  if (!resourceReady) return <Alert severity="error">{error || 'Application Template unavailable.'}</Alert>;

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 3 }}>
        <IconButton aria-label="Back" onClick={leaveEditor}><ArrowBackIcon /></IconButton>
        <Box>
          <Typography variant="h4">{templateId ? 'Edit Application Template' : 'Create Application Template'}</Typography>
          <Typography color="text.secondary">Draft applicant form and approval contract</Typography>
        </Box>
      </Stack>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Box>
        <Stack component="fieldset" disabled={saving || !isCurrentBrowserEntry()} aria-label="Application Template settings"
          onChangeCapture={blockPendingEdit} onClickCapture={blockPendingEdit} onKeyDownCapture={blockPendingEdit}
          onMouseDownCapture={blockPendingEdit} onBlurCapture={blockPendingEdit}
          spacing={2.5} sx={{ p: 0, m: 0, border: 0, minWidth: 0 }}>
          <TextField required label="Name" value={data.name} onChange={(event) => setData({ ...data, name: event.target.value })} />
          <TextField label="Description" multiline minRows={2} value={data.description || ''} onChange={(event) => setData({ ...data, description: event.target.value })} />
          <FormControl required>
            <InputLabel id="application-template-credential-label">Credential Template</InputLabel>
            <Select
              id="application-template-credential"
              labelId="application-template-credential-label"
              label="Credential Template"
              value={data.credential_template_id}
              onChange={(event) => selectCredential(event.target.value)}
            >
              {credentialTemplates.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
            </Select>
          </FormControl>

          <Box>
            <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="h6">Form fields</Typography>
              <Button startIcon={<AddIcon />} onClick={() => {
                const row = { rowId: nextRowId.current++, field: { field_id: '', label: '', field_type: 'TEXT', required: false } };
                setFieldRows((current) => [...current, row]);
              }}>Add field</Button>
            </Stack>
            <Stack spacing={1.5}>
              {fieldRows.map(({ rowId, field }, index) => (
                <Paper key={rowId} variant="outlined" sx={{ p: 2 }}>
                  <Stack spacing={1.5}>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'center' } }}>
                      <TextField required label="Field ID" value={field.field_id || ''} onChange={(event) => updateField(index, { field_id: event.target.value })} sx={{ flex: 1 }} />
                      <TextField required label="Label" value={field.label || ''} onChange={(event) => updateField(index, { label: event.target.value })} sx={{ flex: 1 }} />
                      <FormControl sx={{ minWidth: 145 }}><InputLabel id={`application-field-type-${index}-label`}>Type</InputLabel><Select id={`application-field-type-${index}`} labelId={`application-field-type-${index}-label`} label="Type" value={field.field_type || 'TEXT'} onChange={(event) => updateField(index, { field_type: event.target.value })}>
                        {['TEXT', 'DATE', 'DATETIME', 'INTEGER', 'NUMBER', 'BOOLEAN', 'SELECT', 'EMAIL', 'URL', 'FILE_UPLOAD'].map((type) => <MenuItem key={type} value={type}>{type}</MenuItem>)}
                      </Select></FormControl>
                      <FormControlLabel control={<Checkbox checked={Boolean(field.required)} onChange={(event) => updateField(index, { required: event.target.checked })} />} label="Required" />
                      <IconButton aria-label={`Delete ${field.label || field.field_id || 'field'}`} onClick={() => setFieldRows((current) => current.filter((row) => row.rowId !== rowId))}><DeleteIcon /></IconButton>
                    </Stack>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <TextField label="Claim mapping" value={field.claim_mapping || ''} onChange={(event) => updateField(index, { claim_mapping: event.target.value || null })} sx={{ flex: 1 }} />
                      <TextField label="Validation pattern" value={field.validation_pattern || ''} onChange={(event) => updateField(index, { validation_pattern: event.target.value || null })} sx={{ flex: 1 }} />
                      {field.field_type === 'SELECT' && <DraftListField label="Options" helperText="Comma-separated values or Label=VALUE" value={field.options} format={formatFieldOptions} parse={parseFieldOptions} onChange={(options) => updateField(index, { options })} sx={{ flex: 1 }} />}
                      {['INTEGER', 'NUMBER'].includes(field.field_type) && <TextField type="number" label="Minimum" value={field.minimum ?? ''} onChange={(event) => updateField(index, { minimum: event.target.value === '' ? null : Number(event.target.value) })} sx={{ width: { sm: 120 } }} />}
                      {['INTEGER', 'NUMBER'].includes(field.field_type) && <TextField type="number" label="Maximum" value={field.maximum ?? ''} onChange={(event) => updateField(index, { maximum: event.target.value === '' ? null : Number(event.target.value) })} sx={{ width: { sm: 120 } }} />}
                    </Stack>
                  </Stack>
                </Paper>
              ))}
            </Stack>
          </Box>

          <ApplicationEvidenceEditor
            requirements={data.evidence_requirements}
            onChange={(evidenceRequirements) => setData({ ...data, evidence_requirements: evidenceRequirements })}
          />

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <FormControl fullWidth><InputLabel id="application-approval-label">Approval</InputLabel><Select id="application-approval" labelId="application-approval-label" label="Approval" value={data.approval_strategy || 'MANUAL'} onChange={(event) => setData({ ...data, approval_strategy: event.target.value })}>
              <MenuItem value="MANUAL">Manual review</MenuItem><MenuItem value="AUTO">Automatic</MenuItem><MenuItem value="RULES_BASED">Rules based</MenuItem>
            </Select></FormControl>
            <TextField fullWidth type="number" label="Valid for days" value={data.application_validity_days ?? ''} onChange={(event) => setData({ ...data, application_validity_days: event.target.value })} error={Boolean(validityDaysError)} helperText={validityDaysError || undefined} slotProps={{
              htmlInput: { min: 1, max: 3650, step: 1 }
            }} />
          </Stack>

          {data.approval_strategy === 'RULES_BASED' && (
            <Stack spacing={1}>
              {policySetsError && <Alert severity="warning">Approval Policy Sets are unavailable: {policySetsError}</Alert>}
              <FormControl required>
                <InputLabel id="application-approval-policy-label">Approval Policy Set</InputLabel>
                <Select id="application-approval-policy" labelId="application-approval-policy-label" label="Approval Policy Set" value={data.approval_policy_set_id || ''} onChange={(event) => setData({ ...data, approval_policy_set_id: event.target.value })}>
                  {approvalPolicySets.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
                </Select>
              </FormControl>
              {approvalPolicySets.length === 0 && !policySetsError && (
                <Alert
                  severity="info"
                  action={<Button onClick={() => navigate('/console/org/policies/sets/new')}>Create</Button>}
                >
                  Create and activate an Approval Rules Policy Set before using rules-based approval.
                </Alert>
              )}
            </Stack>
          )}

          {advanced && (
            <>
              <DraftListField label="Required checks" helperText="Comma-separated check types" value={(data.required_checks || []).map((item) => item.check_type).filter(Boolean)} onChange={(values) => setData((current) => ({ ...current, required_checks: values.map((check_type, index) => ({ check_type, is_required: true, order: index + 1 })) }))} />
              <Box>
                <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="h6">Claim collection rules</Typography>
                  <Button
                    startIcon={<AddIcon />}
                    onClick={() => {
                      const row = { rowId: nextRowId.current++, rule: { claim_name: '', source: 'FORM_FIELD', source_config: {} } };
                      setClaimRows((current) => [...current, row]);
                    }}
                  >
                    Add rule
                  </Button>
                </Stack>
                <Stack spacing={1.5}>
                  {claimRows.map(({ rowId, rule }, index) => (
                    <Paper key={rowId} variant="outlined" sx={{ p: 2 }}>
                      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'center' } }}>
                        <TextField required label="Claim name" value={rule.claim_name || ''} onChange={(event) => updateClaimRule(index, { claim_name: event.target.value })} sx={{ flex: 1 }} />
                        <FormControl sx={{ minWidth: { sm: 190 } }}>
                          <InputLabel id={`application-claim-source-${index}-label`}>Source</InputLabel>
                          <Select id={`application-claim-source-${index}`} labelId={`application-claim-source-${index}-label`} label="Source" value={rule.source || 'FORM_FIELD'} onChange={(event) => updateClaimRule(index, { source: event.target.value, source_config: {} })}>
                            {['FORM_FIELD', 'EVIDENCE_EXTRACTION', 'EXTERNAL_API', 'SYSTEM'].map((source) => <MenuItem key={source} value={source}>{source}</MenuItem>)}
                          </Select>
                        </FormControl>
                        {rule.source === 'FORM_FIELD' && (
                          <FormControl sx={{ minWidth: { sm: 190 } }}>
                            <InputLabel id={`application-claim-form-field-${index}-label`}>Form field</InputLabel>
                            <Select id={`application-claim-form-field-${index}`} labelId={`application-claim-form-field-${index}-label`} label="Form field" value={rule.source_config?.field_id || ''} onChange={(event) => updateClaimRule(index, { source_config: { field_id: event.target.value } })}>
                              {fieldRows.map(({ rowId: fieldRowId, field }) => <MenuItem key={fieldRowId} value={field.field_id}>{field.label || field.field_id}</MenuItem>)}
                            </Select>
                          </FormControl>
                        )}
                        {rule.source === 'SYSTEM' && (
                          <FormControl sx={{ minWidth: { sm: 220 } }}>
                            <InputLabel id={`application-claim-system-${index}-label`}>System value</InputLabel>
                            <Select id={`application-claim-system-${index}`} labelId={`application-claim-system-${index}-label`} label="System value" value={rule.source_config?.system_field || ''} onChange={(event) => updateClaimRule(index, { source_config: { system_field: event.target.value } })}>
                              {SYSTEM_CLAIM_SOURCES.map((source) => <MenuItem key={source} value={source}>{source}</MenuItem>)}
                            </Select>
                          </FormControl>
                        )}
                        {rule.source === 'SYSTEM' && rule.source_config?.system_field === 'constant' && (
                          <TextField label="Constant value" value={rule.source_config?.value ?? ''} onChange={(event) => updateClaimRule(index, { source_config: { ...rule.source_config, value: event.target.value } })} sx={{ flex: 1 }} />
                        )}
                        <IconButton aria-label={`Delete ${rule.claim_name || 'claim rule'}`} onClick={() => setClaimRows((current) => current.filter((row) => row.rowId !== rowId))}><DeleteIcon /></IconButton>
                      </Stack>
                      {rule.source === 'EVIDENCE_EXTRACTION' && (
                        <Stack spacing={1} sx={{ mt: 1.5 }}>
                          <Typography variant="body2">Use a verified evidence fact. Specify a requirement ID, a fact type, or both; exactly one fact must match.</Typography>
                          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                            <TextField label="Evidence requirement ID" value={rule.source_config?.requirement_id || ''} onChange={(event) => updateEvidenceSource(index, 'requirement_id', event.target.value)} sx={{ flex: 1 }} />
                            <TextField label="Evidence fact type" placeholder="canvas.quiz_score" value={rule.source_config?.fact_type || ''} onChange={(event) => updateEvidenceSource(index, 'fact_type', event.target.value)} sx={{ flex: 1 }} />
                            <FormControl sx={{ minWidth: 180 }}>
                              <InputLabel id={`application-claim-evidence-format-${index}-label`}>Evidence format</InputLabel>
                              <Select id={`application-claim-evidence-format-${index}`} labelId={`application-claim-evidence-format-${index}-label`} label="Evidence format" value={rule.source_config?.format || ''} onChange={(event) => updateEvidenceSource(index, 'format', event.target.value)}>
                                <MenuItem value="">Original value</MenuItem>
                                <MenuItem value="date">Date (YYYY-MM-DD)</MenuItem>
                              </Select>
                            </FormControl>
                          </Stack>
                          <TextField required label="Evidence value path" placeholder="/assertion/score" helperText="JSON pointer under /assertion, /scope, /effective_at or /observed_at. Missing or ambiguous evidence leaves the claim unavailable." value={rule.source_config?.json_pointer || ''} onChange={(event) => updateEvidenceSource(index, 'json_pointer', event.target.value)} />
                        </Stack>
                      )}
                    </Paper>
                  ))}
                </Stack>
              </Box>
              <TextField label="Submission instructions" multiline minRows={2} value={data.ui_config?.submission_instructions || ''} onChange={(event) => setData({ ...data, ui_config: { ...(data.ui_config || {}), submission_instructions: event.target.value } })} />
              <Stack direction={{ xs: 'column', sm: 'row' }}>
                <FormControlLabel control={<Checkbox checked={data.notification_config?.send_confirmation !== false} onChange={(event) => setData({ ...data, notification_config: { ...(data.notification_config || {}), send_confirmation: event.target.checked } })} />} label="Send confirmation" />
                <FormControlLabel control={<Checkbox checked={data.notification_config?.send_status_updates !== false} onChange={(event) => setData({ ...data, notification_config: { ...(data.notification_config || {}), send_status_updates: event.target.checked } })} />} label="Send status updates" />
              </Stack>
            </>
          )}

        </Stack>
        <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end', mt: 2.5 }}>
          <Button onClick={leaveEditor}>Cancel</Button>
          <Button variant="contained" startIcon={saving ? <CircularProgress size={18} /> : <SaveIcon />} disabled={saving || !isCurrentBrowserEntry() || !selectedCredential || Boolean(validityDaysError) || String(data.status || 'DRAFT').toUpperCase() !== 'DRAFT'} onClick={save}>Save draft</Button>
        </Stack>
      </Box>
    </Container>
  );
}

export default function ApplicationTemplateEditorPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const location = useLocation();
  const [returnedEntry, setReturnedEntry] = useState(0);
  // Retain the committed entry through organization/auth changes while a newer
  // BrowserRouter destination has changed history but is still suspended.
  const browserEntry = useMemo(() => ({
    href: typeof window === 'undefined' ? null : window.location.href,
    key: typeof window === 'undefined' ? undefined : window.history.state?.key,
    routeKey: location.key,
    generation: returnedEntry,
  }), [location, returnedEntry]);
  useLayoutEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const entry = { href: window.location.href, key: window.history.state?.key };
    const handlePopState = () => {
      if (window.location.href === entry.href && window.history.state?.key === entry.key) {
        setReturnedEntry((value) => value + 1);
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [location.key, location.pathname, location.search, location.hash]);
  const { templateId } = useParams();
  const [searchParams] = useSearchParams();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before editing Application Templates.</Alert>;
  if (isLoading) return <CircularProgress />;
  const action = templateId ? 'edit' : 'create';
  if (!can('application-template', action)) return <Alert severity="error">You do not have permission to {action} Application Templates.</Alert>;
  const principalId = user?.user_id || user?.sub || user?.id || null;
  return <ApplicationTemplateEditorContent
    key={JSON.stringify([activeOrgId, templateId, principalId, isAuthenticated, location.key, location.pathname, location.search, location.hash, browserEntry.generation])}
    organizationId={activeOrgId} templateId={templateId} advanced={searchParams.get('mode') === 'advanced'} browserEntry={browserEntry}
  />;
}
