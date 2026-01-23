/**
 * Template Catalog Component
 *
 * Browse and clone public and system credential templates.
 * Marketplace for discovering pre-built templates from standards (ISO, ICAO, W3C).
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  Divider,
  Paper,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import FlightIcon from '@mui/icons-material/Flight';
import BadgeIcon from '@mui/icons-material/Badge';
import SchoolIcon from '@mui/icons-material/School';
import WorkIcon from '@mui/icons-material/Work';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useAuth } from '../../hooks/useAuth';

const API_URL = process.env.REACT_APP_API_URL || '';

// Icons for credential types
const CREDENTIAL_ICONS = {
  drivers_license: <DirectionsCarIcon />,
  passport: <FlightIcon />,
  travel_visa: <FlightIcon />,
  permanent_resident_card: <BadgeIcon />,
  university_degree: <SchoolIcon />,
  employment_authorization: <WorkIcon />,
};

export default function TemplateCatalog() {
  const { organizationId } = useAuth();
  const navigate = useNavigate();
  const [templates, setTemplates] = useState([]);
  const [filteredTemplates, setFilteredTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false);
  const [cloning, setCloning] = useState(false);
  const [customName, setCustomName] = useState('');
  const [error, setError] = useState(null);

  const filterTemplates = useCallback(() => {
    let filtered = templates;

    if (search) {
      const searchLower = search.toLowerCase();
      filtered = filtered.filter(
        (t) =>
          t.display_name?.toLowerCase().includes(searchLower) ||
          t.description?.toLowerCase().includes(searchLower)
      );
    }

    if (category && category !== 'all') {
      filtered = filtered.filter((t) => t.credential_type === category);
    }

    setFilteredTemplates(filtered);
  }, [templates, search, category]);

  useEffect(() => {
    fetchTemplates();
  }, []);

  useEffect(() => {
    filterTemplates();
  }, [filterTemplates]);

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/credential-types/templates`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setTemplates(data.templates || []);
        setFilteredTemplates(data.templates || []);
      }
    } catch (err) {
      console.error('Failed to fetch templates:', err);
      setError('Failed to load templates');
    } finally {
      setLoading(false);
    }
  };

  const handleCloneTemplate = async () => {
    if (!selectedTemplate) return;

    setCloning(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types/clone/${selectedTemplate.id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            display_name: customName || undefined,
            customize_fields: true,
          }),
        }
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to clone template');
      }

      setCloneDialogOpen(false);
      setCustomName('');
      // Navigate to credential config manager
      navigate('/vendor/credentials');
    } catch (err) {
      setError(err.message);
    } finally {
      setCloning(false);
    }
  };

  const openCloneDialog = (template) => {
    setSelectedTemplate(template);
    setCustomName(`${template.display_name} (Custom)`);
    setCloneDialogOpen(true);
    setError(null);
  };

  if (loading) {
    return (
      <Container>
        <Box display="flex" justifyContent="center" py={8}>
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg">
      <Box sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Template Marketplace
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Browse and clone pre-built credential templates based on international standards
          </Typography>
        </Box>

        {/* Filters */}
        <Paper sx={{ p: 2, mb: 4 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                placeholder="Search templates..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  label="Category"
                >
                  <MenuItem value="all">All Templates</MenuItem>
                  <MenuItem value="drivers_license">Driver's License</MenuItem>
                  <MenuItem value="passport">Passport</MenuItem>
                  <MenuItem value="travel_visa">Travel Visa</MenuItem>
                  <MenuItem value="permanent_resident_card">Permanent Resident Card</MenuItem>
                  <MenuItem value="university_degree">University Degree</MenuItem>
                  <MenuItem value="employment_authorization">Employment Authorization</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </Paper>

        {/* Templates Grid */}
        <Grid container spacing={3}>
          {filteredTemplates.map((template) => (
            <Grid item xs={12} md={6} lg={4} key={template.id}>
              <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    {CREDENTIAL_ICONS[template.credential_type] || <BadgeIcon />}
                    <Typography variant="h6" noWrap>
                      {template.display_name}
                    </Typography>
                  </Box>

                  {template.is_system_template && (
                    <Chip
                      label="Official Template"
                      size="small"
                      color="primary"
                      sx={{ mb: 1 }}
                    />
                  )}

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 60 }}>
                    {template.description || 'No description available'}
                  </Typography>

                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
                    <Chip
                      label={`${(template.required_fields || []).length} required fields`}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      label={`${(template.optional_fields || []).length} optional fields`}
                      size="small"
                      variant="outlined"
                    />
                    {template.custom_fields && template.custom_fields.length > 0 && (
                      <Chip
                        label={`${template.custom_fields.length} custom fields`}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>

                  {template.estimated_processing_time && (
                    <Typography variant="caption" color="text.secondary">
                      Processing: {template.estimated_processing_time}
                    </Typography>
                  )}
                </CardContent>

                <CardActions>
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={<ContentCopyIcon />}
                    onClick={() => openCloneDialog(template)}
                  >
                    Clone Template
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>

        {filteredTemplates.length === 0 && (
          <Alert severity="info" sx={{ mt: 4 }}>
            No templates found matching your search criteria.
          </Alert>
        )}

        {/* Clone Dialog */}
        <Dialog open={cloneDialogOpen} onClose={() => setCloneDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>Clone Template</DialogTitle>
          <DialogContent>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <Alert severity="info" sx={{ mb: 3 }}>
              Cloning creates a customizable copy of this template for your organization.
              You can modify fields, validation rules, and publishing settings.
            </Alert>

            {selectedTemplate && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  {selectedTemplate.display_name}
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {selectedTemplate.description}
                </Typography>

                <Divider sx={{ my: 2 }} />

                <Typography variant="subtitle2" gutterBottom>
                  Template Details:
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary="Required Fields"
                      secondary={(selectedTemplate.required_fields || []).join(', ') || 'None'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Optional Fields"
                      secondary={(selectedTemplate.optional_fields || []).join(', ') || 'None'}
                    />
                  </ListItem>
                  {selectedTemplate.eligibility_criteria && (
                    <ListItem>
                      <ListItemText
                        primary="Eligibility"
                        secondary={selectedTemplate.eligibility_criteria}
                      />
                    </ListItem>
                  )}
                </List>
              </Box>
            )}

            <TextField
              fullWidth
              label="Custom Template Name"
              value={customName}
              onChange={(e) => setCustomName(e.target.value)}
              helperText="Give your cloned template a unique name"
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCloneDialogOpen(false)} disabled={cloning}>
              Cancel
            </Button>
            <Button
              variant="contained"
              onClick={handleCloneTemplate}
              disabled={cloning || !customName}
              startIcon={cloning ? <CircularProgress size={16} /> : <CheckCircleIcon />}
            >
              {cloning ? 'Cloning...' : 'Clone & Customize'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
}
