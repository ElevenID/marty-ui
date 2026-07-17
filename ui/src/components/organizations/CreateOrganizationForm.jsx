import { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import HowToRegIcon from '@mui/icons-material/HowToReg';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';

const DEFAULT_VALUES = {
  name: '',
  displayName: '',
  orgType: 'enterprise',
  jurisdiction: 'US',
  description: '',
  contactEmail: '',
  isDiscoverable: false,
  membershipMode: 'invite_only',
};

function buildPayload(values) {
  const isDiscoverable = Boolean(values.isDiscoverable);

  return {
    name: values.name.trim(),
    display_name: values.displayName.trim(),
    org_type: values.orgType || undefined,
    jurisdiction: values.jurisdiction || undefined,
    description: values.description.trim() || undefined,
    contact_email: values.contactEmail.trim() || undefined,
    is_discoverable: isDiscoverable,
    visibility: isDiscoverable ? 'PUBLIC' : 'PRIVATE',
    membership_mode: values.membershipMode,
  };
}

function CreateOrganizationForm({
  initialValues = {},
  submitting = false,
  error = null,
  submitLabel = 'Create Organization',
  cancelLabel = 'Cancel',
  onSubmit,
  onCancel,
}) {
  const [values, setValues] = useState({ ...DEFAULT_VALUES, ...initialValues });

  const updateValue = (field) => (event) => {
    const nextValue = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    setValues((prev) => ({ ...prev, [field]: nextValue }));
  };

  const canSubmit = Boolean(values.name.trim() && values.displayName.trim()) && !submitting;

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!canSubmit) return;
    onSubmit?.(buildPayload(values));
  };

  return (
    <Box component="form" onSubmit={handleSubmit} data-testid="create-organization-form">
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
        Organization Details
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            required
            label="Organization Slug"
            value={values.name}
            onChange={updateValue('name')}
            helperText="Unique identifier, lowercase letters, numbers, and hyphens"
            slotProps={{ htmlInput: { 'aria-label': 'Organization Slug' } }}
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            required
            label="Display Name"
            value={values.displayName}
            onChange={updateValue('displayName')}
            helperText="How the organization appears to users"
            slotProps={{ htmlInput: { 'aria-label': 'Display Name' } }}
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <FormControl fullWidth>
            <InputLabel id="create-org-type-label">Organization Type</InputLabel>
            <Select
              labelId="create-org-type-label"
              value={values.orgType}
              label="Organization Type"
              onChange={updateValue('orgType')}
            >
              <MenuItem value="enterprise">Enterprise / Corporation</MenuItem>
              <MenuItem value="startup">Startup</MenuItem>
              <MenuItem value="individual">Individual</MenuItem>
              <MenuItem value="government">Government Agency</MenuItem>
              <MenuItem value="education">Educational Institution</MenuItem>
              <MenuItem value="healthcare">Healthcare Provider</MenuItem>
              <MenuItem value="financial">Financial Services</MenuItem>
              <MenuItem value="other">Other</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={6}>
          <FormControl fullWidth>
            <InputLabel id="create-org-jurisdiction-label">Jurisdiction</InputLabel>
            <Select
              labelId="create-org-jurisdiction-label"
              value={values.jurisdiction}
              label="Jurisdiction"
              onChange={updateValue('jurisdiction')}
            >
              <MenuItem value="US">United States</MenuItem>
              <MenuItem value="US-CA">United States - California</MenuItem>
              <MenuItem value="US-TX">United States - Texas</MenuItem>
              <MenuItem value="US-NY">United States - New York</MenuItem>
              <MenuItem value="US-FL">United States - Florida</MenuItem>
              <MenuItem value="CA">Canada</MenuItem>
              <MenuItem value="UK">United Kingdom</MenuItem>
              <MenuItem value="EU">European Union</MenuItem>
              <MenuItem value="OTHER">Other</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Description"
            value={values.description}
            onChange={updateValue('description')}
            multiline
            rows={2}
            helperText="Optional summary shown in organization discovery and management screens"
          />
        </Grid>
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Contact Email"
            type="email"
            value={values.contactEmail}
            onChange={updateValue('contactEmail')}
            helperText="Optional contact address for applicants and administrators"
          />
        </Grid>
      </Grid>

      <Divider sx={{ my: 3 }} />

      <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
        Discovery and Membership
      </Typography>

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'flex-start', sm: 'center' }} justifyContent="space-between">
          <Stack direction="row" spacing={1.5} alignItems="center">
            {values.isDiscoverable ? <VisibilityIcon color="primary" /> : <VisibilityOffIcon color="action" />}
            <Box>
              <Typography variant="body1">Discoverable</Typography>
              <Typography variant="body2" color="text.secondary">
                {values.isDiscoverable
                  ? 'This organization can appear in public organization search.'
                  : 'Users need an invitation or join code unless you publish it later.'}
              </Typography>
            </Box>
          </Stack>
          <FormControlLabel
            control={<Switch checked={values.isDiscoverable} onChange={updateValue('isDiscoverable')} />}
            label="Discoverable"
            labelPlacement="start"
          />
        </Stack>
      </Paper>

      <FormControl component="fieldset" sx={{ width: '100%' }}>
        <RadioGroup value={values.membershipMode} onChange={updateValue('membershipMode')}>
          <Paper
            variant="outlined"
            sx={{ p: 2, mb: 1, borderColor: values.membershipMode === 'invite_only' ? 'primary.main' : 'divider' }}
          >
            <FormControlLabel
              value="invite_only"
              control={<Radio />}
              label={
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <LockIcon fontSize="small" color="action" />
                    <Typography fontWeight={500}>Invite Only</Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    Users can join only through an invitation or join code.
                  </Typography>
                </Box>
              }
              sx={{ m: 0, width: '100%' }}
            />
          </Paper>
          <Paper
            variant="outlined"
            sx={{ p: 2, mb: 1, borderColor: values.membershipMode === 'approval' ? 'primary.main' : 'divider' }}
          >
            <FormControlLabel
              value="approval"
              control={<Radio />}
              label={
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <HowToRegIcon fontSize="small" color="warning" />
                    <Typography fontWeight={500}>Approval Required</Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    Users can request access and administrators approve requests.
                  </Typography>
                </Box>
              }
              sx={{ m: 0, width: '100%' }}
            />
          </Paper>
          <Paper
            variant="outlined"
            sx={{ p: 2, borderColor: values.membershipMode === 'open' ? 'primary.main' : 'divider' }}
          >
            <FormControlLabel
              value="open"
              control={<Radio />}
              label={
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <LockOpenIcon fontSize="small" color="success" />
                    <Typography fontWeight={500}>Open</Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    Authenticated users can join directly without approval.
                  </Typography>
                </Box>
              }
              sx={{ m: 0, width: '100%' }}
            />
          </Paper>
        </RadioGroup>
      </FormControl>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent="flex-end" sx={{ mt: 3 }}>
        {onCancel && (
          <Button variant="outlined" onClick={onCancel} disabled={submitting}>
            {cancelLabel}
          </Button>
        )}
        <Button type="submit" variant="contained" disabled={!canSubmit}>
          {submitting ? 'Creating...' : submitLabel}
        </Button>
      </Stack>
    </Box>
  );
}

export default CreateOrganizationForm;
