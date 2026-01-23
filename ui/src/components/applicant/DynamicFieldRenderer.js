/**
 * Dynamic Field Renderer
 *
 * Renders form fields dynamically based on credential configuration.
 * Supports all field types: text, number, date, select, file, address, etc.
 * Handles validation rules from field_validation_rules.
 */

import React from 'react';
import {
  Grid,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Checkbox,
  FormControlLabel,
  Button,
  Box,
  Typography,
  IconButton,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import UploadFileIcon from '@mui/icons-material/UploadFile';

// US States for address fields
const US_STATES = [
  { value: 'AL', label: 'Alabama' },
  { value: 'AK', label: 'Alaska' },
  { value: 'AZ', label: 'Arizona' },
  { value: 'AR', label: 'Arkansas' },
  { value: 'CA', label: 'California' },
  { value: 'CO', label: 'Colorado' },
  { value: 'CT', label: 'Connecticut' },
  { value: 'DE', label: 'Delaware' },
  { value: 'FL', label: 'Florida' },
  { value: 'GA', label: 'Georgia' },
  { value: 'HI', label: 'Hawaii' },
  { value: 'ID', label: 'Idaho' },
  { value: 'IL', label: 'Illinois' },
  { value: 'IN', label: 'Indiana' },
  { value: 'IA', label: 'Iowa' },
  { value: 'KS', label: 'Kansas' },
  { value: 'KY', label: 'Kentucky' },
  { value: 'LA', label: 'Louisiana' },
  { value: 'ME', label: 'Maine' },
  { value: 'MD', label: 'Maryland' },
  { value: 'MA', label: 'Massachusetts' },
  { value: 'MI', label: 'Michigan' },
  { value: 'MN', label: 'Minnesota' },
  { value: 'MS', label: 'Mississippi' },
  { value: 'MO', label: 'Missouri' },
  { value: 'MT', label: 'Montana' },
  { value: 'NE', label: 'Nebraska' },
  { value: 'NV', label: 'Nevada' },
  { value: 'NH', label: 'New Hampshire' },
  { value: 'NJ', label: 'New Jersey' },
  { value: 'NM', label: 'New Mexico' },
  { value: 'NY', label: 'New York' },
  { value: 'NC', label: 'North Carolina' },
  { value: 'ND', label: 'North Dakota' },
  { value: 'OH', label: 'Ohio' },
  { value: 'OK', label: 'Oklahoma' },
  { value: 'OR', label: 'Oregon' },
  { value: 'PA', label: 'Pennsylvania' },
  { value: 'RI', label: 'Rhode Island' },
  { value: 'SC', label: 'South Carolina' },
  { value: 'SD', label: 'South Dakota' },
  { value: 'TN', label: 'Tennessee' },
  { value: 'TX', label: 'Texas' },
  { value: 'UT', label: 'Utah' },
  { value: 'VT', label: 'Vermont' },
  { value: 'VA', label: 'Virginia' },
  { value: 'WA', label: 'Washington' },
  { value: 'WV', label: 'West Virginia' },
  { value: 'WI', label: 'Wisconsin' },
  { value: 'WY', label: 'Wyoming' },
];

/**
 * Format field name to human-readable label
 */
function formatFieldLabel(fieldName) {
  return fieldName
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (l) => l.toUpperCase());
}

/**
 * Render text input field
 */
function TextFieldRenderer({ field, value, onChange, error, required, validation }) {
  const inputProps = {};
  
  if (validation?.min_length) {
    inputProps.minLength = validation.min_length;
  }
  if (validation?.max_length) {
    inputProps.maxLength = validation.max_length;
  }
  if (validation?.pattern) {
    inputProps.pattern = validation.pattern;
  }

  return (
    <TextField
      fullWidth
      label={field.label || formatFieldLabel(field.name)}
      value={value || ''}
      onChange={(e) => onChange(field.name, e.target.value)}
      required={required}
      error={!!error}
      helperText={error || validation?.pattern_description}
      inputProps={inputProps}
    />
  );
}

/**
 * Render number input field
 */
function NumberFieldRenderer({ field, value, onChange, error, required, validation }) {
  return (
    <TextField
      fullWidth
      type="number"
      label={field.label || formatFieldLabel(field.name)}
      value={value || ''}
      onChange={(e) => onChange(field.name, parseFloat(e.target.value) || '')}
      required={required}
      error={!!error}
      helperText={error}
      inputProps={{
        min: validation?.min_value,
        max: validation?.max_value,
        step: field.step || 'any',
      }}
    />
  );
}

/**
 * Render date input field
 */
function DateFieldRenderer({ field, value, onChange, error, required }) {
  return (
    <TextField
      fullWidth
      type="date"
      label={field.label || formatFieldLabel(field.name)}
      value={value || ''}
      onChange={(e) => onChange(field.name, e.target.value)}
      required={required}
      error={!!error}
      helperText={error}
      InputLabelProps={{ shrink: true }}
    />
  );
}

/**
 * Render datetime input field
 */
function DateTimeFieldRenderer({ field, value, onChange, error, required }) {
  return (
    <TextField
      fullWidth
      type="datetime-local"
      label={field.label || formatFieldLabel(field.name)}
      value={value || ''}
      onChange={(e) => onChange(field.name, e.target.value)}
      required={required}
      error={!!error}
      helperText={error}
      InputLabelProps={{ shrink: true }}
    />
  );
}

/**
 * Render select/dropdown field
 */
function SelectFieldRenderer({ field, value, onChange, error, required, validation }) {
  const options = validation?.allowed_values || field.options || [];

  return (
    <FormControl fullWidth error={!!error} required={required}>
      <InputLabel>{field.label || formatFieldLabel(field.name)}</InputLabel>
      <Select
        value={value || ''}
        onChange={(e) => onChange(field.name, e.target.value)}
        label={field.label || formatFieldLabel(field.name)}
      >
        {options.map((option) => (
          <MenuItem key={option} value={option}>
            {typeof option === 'string' ? formatFieldLabel(option) : option}
          </MenuItem>
        ))}
      </Select>
      {error && (
        <Typography variant="caption" color="error" sx={{ mt: 0.5, ml: 1.75 }}>
          {error}
        </Typography>
      )}
    </FormControl>
  );
}

/**
 * Render boolean/checkbox field
 */
function BooleanFieldRenderer({ field, value, onChange, error, required }) {
  return (
    <FormControlLabel
      control={
        <Checkbox
          checked={!!value}
          onChange={(e) => onChange(field.name, e.target.checked)}
          required={required}
        />
      }
      label={field.label || formatFieldLabel(field.name)}
    />
  );
}

/**
 * Render file upload field
 */
function FileFieldRenderer({ field, value, onChange, error, required, fileInputRef }) {
  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      onChange(field.name, file);
    }
  };

  return (
    <Box>
      <input
        ref={fileInputRef}
        type="file"
        accept={field.accept || 'image/*'}
        onChange={handleFileSelect}
        style={{ display: 'none' }}
      />
      <Button
        variant="outlined"
        fullWidth
        startIcon={<UploadFileIcon />}
        onClick={() => fileInputRef?.current?.click()}
      >
        {value ? value.name : `Upload ${field.label || formatFieldLabel(field.name)}`}
      </Button>
      {value && (
        <IconButton
          size="small"
          onClick={() => onChange(field.name, null)}
          sx={{ ml: 1 }}
        >
          <DeleteIcon />
        </IconButton>
      )}
      {error && (
        <Typography variant="caption" color="error" sx={{ mt: 0.5, ml: 1.75 }}>
          {error}
        </Typography>
      )}
    </Box>
  );
}

/**
 * Render address field (composite)
 */
function AddressFieldRenderer({ field, value, onChange, error, required }) {
  const addressValue = value || {};
  
  const handleAddressChange = (subfield, subvalue) => {
    onChange(field.name, {
      ...addressValue,
      [subfield]: subvalue,
    });
  };

  return (
    <Box>
      <Typography variant="subtitle2" gutterBottom>
        {field.label || formatFieldLabel(field.name)}
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Street Address"
            value={addressValue.street || ''}
            onChange={(e) => handleAddressChange('street', e.target.value)}
            required={required}
          />
        </Grid>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="City"
            value={addressValue.city || ''}
            onChange={(e) => handleAddressChange('city', e.target.value)}
            required={required}
          />
        </Grid>
        <Grid item xs={12} sm={3}>
          <FormControl fullWidth required={required}>
            <InputLabel>State</InputLabel>
            <Select
              value={addressValue.state || ''}
              onChange={(e) => handleAddressChange('state', e.target.value)}
              label="State"
            >
              {US_STATES.map((state) => (
                <MenuItem key={state.value} value={state.value}>
                  {state.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} sm={3}>
          <TextField
            fullWidth
            label="ZIP Code"
            value={addressValue.zip || ''}
            onChange={(e) => handleAddressChange('zip', e.target.value)}
            required={required}
          />
        </Grid>
      </Grid>
      {error && (
        <Typography variant="caption" color="error" sx={{ mt: 0.5 }}>
          {error}
        </Typography>
      )}
    </Box>
  );
}

/**
 * Main dynamic field renderer
 */
export function DynamicFieldRenderer({
  field,
  value,
  onChange,
  error,
  required,
  validation,
  fileInputRef,
}) {
  const fieldType = field.type || 'text';

  const renderers = {
    text: TextFieldRenderer,
    number: NumberFieldRenderer,
    date: DateFieldRenderer,
    datetime: DateTimeFieldRenderer,
    select: SelectFieldRenderer,
    boolean: BooleanFieldRenderer,
    file: FileFieldRenderer,
    address: AddressFieldRenderer,
    email: (props) => <TextFieldRenderer {...props} type="email" />,
    phone: (props) => <TextFieldRenderer {...props} type="tel" />,
    url: (props) => <TextFieldRenderer {...props} type="url" />,
  };

  const Renderer = renderers[fieldType] || TextFieldRenderer;

  return (
    <Renderer
      field={field}
      value={value}
      onChange={onChange}
      error={error}
      required={required}
      validation={validation}
      fileInputRef={fileInputRef}
    />
  );
}

/**
 * Render a group of fields in a grid
 */
export function DynamicFieldGroup({
  fields,
  values,
  onChange,
  errors,
  requiredFields,
  validationRules,
  fileInputRefs,
}) {
  return (
    <Grid container spacing={3}>
      {fields.map((field) => {
        const fieldName = typeof field === 'string' ? field : field.name;
        const fieldDef = typeof field === 'string' 
          ? { name: fieldName, type: 'text' }
          : field;
        
        const isRequired = requiredFields?.includes(fieldName);
        const validation = validationRules?.[fieldName];
        const error = errors?.[fieldName];

        return (
          <Grid item xs={12} sm={6} key={fieldName}>
            <DynamicFieldRenderer
              field={fieldDef}
              value={values[fieldName]}
              onChange={onChange}
              error={error}
              required={isRequired}
              validation={validation}
              fileInputRef={fileInputRefs?.[fieldName]}
            />
          </Grid>
        );
      })}
    </Grid>
  );
}
