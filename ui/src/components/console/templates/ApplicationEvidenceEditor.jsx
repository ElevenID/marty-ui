import {
  Box, Button, Checkbox, FormControl, FormControlLabel, IconButton, InputLabel,
  MenuItem, Paper, Select, Stack, TextField, Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';

const EVIDENCE_TYPES = [
  'DOCUMENT_SCAN',
  'BIOMETRIC',
  'SELFIE',
  'THIRD_PARTY_VERIFICATION',
  'EXTERNAL_FACT',
  'EXTERNAL_API',
];

export function newEvidenceRequirement(ordinal = 1) {
  return {
    evidence_id: `evidence_${ordinal}`,
    evidence_type: 'DOCUMENT_SCAN',
    description: '',
    required: true,
    accepted_formats: [],
  };
}

function csv(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
}

function updateNested(requirement, key, field, value) {
  return { ...requirement, [key]: { ...(requirement[key] || {}), [field]: value } };
}

export default function ApplicationEvidenceEditor({ requirements = [], onChange }) {
  const update = (index, next) => onChange(requirements.map((item, itemIndex) => (
    itemIndex === index ? next : item
  )));
  const remove = (index) => onChange(requirements.filter((_, itemIndex) => itemIndex !== index));

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6">Evidence</Typography>
        <Button
          startIcon={<AddIcon />}
          onClick={() => onChange([...requirements, newEvidenceRequirement(requirements.length + 1)])}
        >
          Add evidence
        </Button>
      </Stack>

      <Stack spacing={1.5}>
        {requirements.map((requirement, index) => {
          const external = ['EXTERNAL_FACT', 'EXTERNAL_API'].includes(requirement.evidence_type);
          return (
            <Paper key={`${requirement.evidence_id}-${index}`} variant="outlined" sx={{ p: 2 }}>
              <Stack spacing={1.5}>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
                  <TextField
                    required
                    label="Evidence ID"
                    value={requirement.evidence_id || ''}
                    onChange={(event) => update(index, { ...requirement, evidence_id: event.target.value })}
                    sx={{ flex: 1 }}
                  />
                  <FormControl sx={{ minWidth: { sm: 210 } }}>
                    <InputLabel>Type</InputLabel>
                    <Select
                      label="Type"
                      value={requirement.evidence_type || 'DOCUMENT_SCAN'}
                      onChange={(event) => update(index, {
                        ...newEvidenceRequirement(index + 1),
                        evidence_id: requirement.evidence_id,
                        description: requirement.description,
                        required: requirement.required,
                        evidence_type: event.target.value,
                      })}
                    >
                      {EVIDENCE_TYPES.map((type) => <MenuItem key={type} value={type}>{type}</MenuItem>)}
                    </Select>
                  </FormControl>
                  <FormControlLabel
                    control={<Checkbox checked={requirement.required !== false} onChange={(event) => update(index, { ...requirement, required: event.target.checked })} />}
                    label="Required"
                  />
                  <IconButton aria-label={`Delete ${requirement.evidence_id || 'evidence'}`} onClick={() => remove(index)}>
                    <DeleteIcon />
                  </IconButton>
                </Stack>

                <TextField
                  required
                  label="Description"
                  value={requirement.description || ''}
                  onChange={(event) => update(index, { ...requirement, description: event.target.value })}
                />

                {requirement.evidence_type === 'DOCUMENT_SCAN' && (
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                    <TextField
                      label="Accepted formats"
                      value={(requirement.accepted_formats || []).join(', ')}
                      onChange={(event) => update(index, { ...requirement, accepted_formats: csv(event.target.value) })}
                      sx={{ flex: 1 }}
                    />
                    <TextField
                      type="number"
                      label="Maximum bytes"
                      value={requirement.max_file_size_bytes ?? ''}
                      onChange={(event) => update(index, {
                        ...requirement,
                        max_file_size_bytes: event.target.value === '' ? null : Number(event.target.value),
                      })}
                      sx={{ width: { sm: 180 } }}
                    />
                  </Stack>
                )}

                {external && (
                  <>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <TextField required label="Provider" value={requirement.provider || ''} onChange={(event) => update(index, { ...requirement, provider: event.target.value })} sx={{ flex: 1 }} />
                      <TextField required label="Fact type" value={requirement.fact_type || ''} onChange={(event) => update(index, { ...requirement, fact_type: event.target.value })} sx={{ flex: 1 }} />
                      <TextField label="Verification method" value={requirement.verification_method || ''} onChange={(event) => update(index, { ...requirement, verification_method: event.target.value || null })} sx={{ flex: 1 }} />
                    </Stack>
                    <FormControlLabel
                      control={<Checkbox checked={Boolean(requirement.auto_issue_on_permit)} onChange={(event) => update(index, { ...requirement, auto_issue_on_permit: event.target.checked })} />}
                      label="Issue automatically when policy permits"
                    />
                  </>
                )}

                {requirement.evidence_type === 'EXTERNAL_API' && (
                  <>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <FormControl sx={{ minWidth: { sm: 120 } }}>
                        <InputLabel>Method</InputLabel>
                        <Select
                          label="Method"
                          value={requirement.api?.method || 'POST'}
                          onChange={(event) => update(index, updateNested(requirement, 'api', 'method', event.target.value))}
                        >
                          {['GET', 'POST', 'PUT', 'PATCH'].map((method) => <MenuItem key={method} value={method}>{method}</MenuItem>)}
                        </Select>
                      </FormControl>
                      <TextField required label="Endpoint URL" value={requirement.api?.url || ''} onChange={(event) => update(index, updateNested(requirement, 'api', 'url', event.target.value))} sx={{ flex: 1 }} />
                      <TextField type="number" label="Timeout seconds" value={requirement.api?.timeout_seconds ?? 10} onChange={(event) => update(index, updateNested(requirement, 'api', 'timeout_seconds', Number(event.target.value)))} sx={{ width: { sm: 160 } }} />
                    </Stack>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <TextField
                        label="Accepted status codes"
                        value={(requirement.expected_response?.status_codes || [200]).join(', ')}
                        onChange={(event) => update(index, updateNested(requirement, 'expected_response', 'status_codes', csv(event.target.value).map(Number).filter(Number.isInteger)))}
                        sx={{ flex: 1 }}
                      />
                      <TextField
                        label="Verification status path"
                        value={requirement.response_mapping?.verification_status_path || ''}
                        onChange={(event) => update(index, updateNested(requirement, 'response_mapping', 'verification_status_path', event.target.value))}
                        sx={{ flex: 1 }}
                      />
                      <TextField
                        label="Verified values"
                        value={(requirement.response_mapping?.verification_verified_values || []).join(', ')}
                        onChange={(event) => update(index, updateNested(requirement, 'response_mapping', 'verification_verified_values', csv(event.target.value)))}
                        sx={{ flex: 1 }}
                      />
                    </Stack>
                  </>
                )}
              </Stack>
            </Paper>
          );
        })}
      </Stack>
    </Box>
  );
}
