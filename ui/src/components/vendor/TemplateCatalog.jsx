/**
 * Template Catalog Component
 *
 * Browse and clone public and system credential templates.
 * Marketplace for discovering pre-built templates from standards (ISO, ICAO, W3C).
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
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

const API_URL = import.meta.env.VITE_API_URL || '';

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
  const { t } = useTranslation('vendor');
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
      setError(t('templateCatalog.loadFailed'));
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
        throw new Error(data.detail || t('templateCatalog.cloneFailed'));
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
            {t('templateCatalog.title')}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {t('templateCatalog.description')}
          </Typography>
        </Box>

        {/* Filters */}
        <Paper sx={{ p: 2, mb: 4 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                placeholder={t('templateCatalog.searchPlaceholder')}
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
                <InputLabel>{t('templateCatalog.categoryLabel')}</InputLabel>
                <Select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  label={t('templateCatalog.categoryLabel')}
                >
                  <MenuItem value="all">{t('templateCatalog.categories.all')}</MenuItem>
                  <MenuItem value="drivers_license">{t('templateCatalog.categories.driversLicense')}</MenuItem>
                  <MenuItem value="passport">{t('templateCatalog.categories.passport')}</MenuItem>
                  <MenuItem value="travel_visa">{t('templateCatalog.categories.travelVisa')}</MenuItem>
                  <MenuItem value="permanent_resident_card">{t('templateCatalog.categories.permanentResidentCard')}</MenuItem>
                  <MenuItem value="university_degree">{t('templateCatalog.categories.universityDegree')}</MenuItem>
                  <MenuItem value="employment_authorization">{t('templateCatalog.categories.employmentAuthorization')}</MenuItem>
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
                      label={t('templateCatalog.card.officialTemplate')}
                      size="small"
                      color="primary"
                      sx={{ mb: 1 }}
                    />
                  )}

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 60 }}>
                    {template.description || t('templateCatalog.card.noDescription')}
                  </Typography>

                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
                    <Chip
                      label={t('templateCatalog.card.requiredFields', { count: (template.required_fields || []).length })}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      label={t('templateCatalog.card.optionalFields', { count: (template.optional_fields || []).length })}
                      size="small"
                      variant="outlined"
                    />
                    {template.custom_fields && template.custom_fields.length > 0 && (
                      <Chip
                        label={t('templateCatalog.card.customFields', { count: template.custom_fields.length })}
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>

                  {template.estimated_processing_time && (
                    <Typography variant="caption" color="text.secondary">
                      {t('templateCatalog.card.processing', { time: template.estimated_processing_time })}
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
                    {t('templateCatalog.card.cloneButton')}
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>

        {filteredTemplates.length === 0 && (
          <Alert severity="info" sx={{ mt: 4 }}>
            {t('templateCatalog.noResults')}
          </Alert>
        )}

        {/* Clone Dialog */}
        <Dialog open={cloneDialogOpen} onClose={() => setCloneDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>{t('templateCatalog.cloneDialog.title')}</DialogTitle>
          <DialogContent>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <Alert severity="info" sx={{ mb: 3 }}>
              {t('templateCatalog.cloneDialog.infoMessage')}
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
                  {t('templateCatalog.cloneDialog.detailsTitle')}
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary={t('templateCatalog.cloneDialog.requiredFields')}
                      secondary={(selectedTemplate.required_fields || []).join(', ') || t('templateCatalog.cloneDialog.none')}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary={t('templateCatalog.cloneDialog.optionalFields')}
                      secondary={(selectedTemplate.optional_fields || []).join(', ') || t('templateCatalog.cloneDialog.none')}
                    />
                  </ListItem>
                  {selectedTemplate.eligibility_criteria && (
                    <ListItem>
                      <ListItemText
                        primary={t('templateCatalog.cloneDialog.eligibility')}
                        secondary={selectedTemplate.eligibility_criteria}
                      />
                    </ListItem>
                  )}
                </List>
              </Box>
            )}

            <TextField
              fullWidth
              label={t('templateCatalog.cloneDialog.nameLabel')}
              value={customName}
              onChange={(e) => setCustomName(e.target.value)}
              helperText={t('templateCatalog.cloneDialog.nameHelper')}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCloneDialogOpen(false)} disabled={cloning}>
              {t('templateCatalog.cloneDialog.cancelButton')}
            </Button>
            <Button
              variant="contained"
              onClick={handleCloneTemplate}
              disabled={cloning || !customName}
              startIcon={cloning ? <CircularProgress size={16} /> : <CheckCircleIcon />}
            >
              {cloning ? t('templateCatalog.cloneDialog.cloning') : t('templateCatalog.cloneDialog.cloneButton')}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
}
