import { useState } from 'react';
import {
  Drawer,
  Box,
  Typography,
  TextField,
  Button,
  IconButton,
  Divider,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { Link } from 'react-router-dom';

/**
 * ResourceCreateDrawer - Generic drawer for quick resource creation
 * 
 * Provides a streamlined form for creating resources without leaving the current page.
 * Users can access advanced options via a link to the full wizard/editor.
 * 
 * @param {boolean} open - Whether the drawer is open
 * @param {function} onClose - Close callback
 * @param {function} onSubmit - Submit handler (async)
 * @param {string} title - Drawer title (e.g., "Create Trust Profile")
 * @param {string} resourceType - Resource type (e.g., "trust-profile")
 * @param {string} advancedPath - Path to full editor/wizard
 * @param {Array} fields - Array of field configurations
 * @param {Object} initialData - Initial form data
 */
function ResourceCreateDrawer({
  open,
  onClose,
  onSubmit,
  title,
  resourceType,
  advancedPath,
  fields = [],
  initialData = {},
}) {
  const [formData, setFormData] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = (fieldName, value) => {
    setFormData((prev) => ({ ...prev, [fieldName]: value }));
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    try {
      await onSubmit(formData);
      setFormData(initialData); // Reset form
      onClose();
    } catch (err) {
      console.error(`Failed to create ${resourceType}:`, err);
      setError(err.message || 'Failed to create resource');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    if (loading) return;
    setFormData(initialData);
    setError(null);
    onClose();
  };

  const renderField = (field) => {
    switch (field.type) {
      case 'text':
      case 'email':
        return (
          <TextField
            key={field.name}
            fullWidth
            label={field.label}
            type={field.type}
            value={formData[field.name] || ''}
            onChange={(e) => handleChange(field.name, e.target.value)}
            required={field.required}
            placeholder={field.placeholder}
            helperText={field.helperText}
            margin="normal"
            disabled={loading}
          />
        );

      case 'textarea':
        return (
          <TextField
            key={field.name}
            fullWidth
            label={field.label}
            value={formData[field.name] || ''}
            onChange={(e) => handleChange(field.name, e.target.value)}
            required={field.required}
            placeholder={field.placeholder}
            helperText={field.helperText}
            margin="normal"
            multiline
            rows={field.rows || 3}
            disabled={loading}
          />
        );

      case 'select':
        return (
          <FormControl key={field.name} fullWidth margin="normal" disabled={loading}>
            <InputLabel>{field.label}</InputLabel>
            <Select
              value={formData[field.name] || ''}
              label={field.label}
              onChange={(e) => handleChange(field.name, e.target.value)}
              required={field.required}
            >
              {field.options?.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        );

      default:
        return null;
    }
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={handleClose}
      PaperProps={{
        sx: { width: { xs: '100%', sm: 600 } },
      }}
    >
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box sx={{ p: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h6">{title}</Typography>
          <IconButton onClick={handleClose} disabled={loading}>
            <CloseIcon />
          </IconButton>
        </Box>
        <Divider />

        {/* Content */}
        <Box sx={{ flex: 1, p: 3, overflow: 'auto' }}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              This is a quick create form with essential fields.{' '}
              {advancedPath && (
                <>
                  For advanced configuration,{' '}
                  <Link to={advancedPath} target="_blank" style={{ color: 'inherit', fontWeight: 600 }}>
                    open the full editor
                    <OpenInNewIcon sx={{ fontSize: 14, verticalAlign: 'middle', ml: 0.5 }} />
                  </Link>
                </>
              )}
            </Typography>
          </Alert>

          {fields.map((field) => renderField(field))}
        </Box>

        {/* Footer */}
        <Divider />
        <Box sx={{ p: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
          <Button onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={loading}
            startIcon={loading && <CircularProgress size={16} />}
          >
            {loading ? 'Creating...' : 'Create'}
          </Button>
        </Box>
      </Box>
    </Drawer>
  );
}

export default ResourceCreateDrawer;
