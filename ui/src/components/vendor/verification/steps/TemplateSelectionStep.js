/**
 * Template Selection Step
 * 
 * Shows standards-based policy templates filtered by Trust Profile framework.
 * Users can select a pre-built template or choose "Custom" for manual configuration.
 */

import React, { useMemo } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Chip,
  Alert,
} from '@mui/material';
import BuildIcon from '@mui/icons-material/Build';

import { POLICY_TEMPLATES, getTemplatesByFramework } from '../../../../data/policyTemplates';

const TemplateSelectionStep = ({ trustProfile, selectedTemplate, onSelectTemplate }) => {
  // Filter templates by trust framework
  const availableTemplates = useMemo(() => {
    if (!trustProfile?.trust_framework_type) {
      return POLICY_TEMPLATES;
    }
    return getTemplatesByFramework(trustProfile.trust_framework_type);
  }, [trustProfile]);

  // Add "Custom" template option
  const customTemplate = {
    id: 'custom',
    name: 'Custom Policy',
    description: 'Build a custom verification policy from scratch',
    trustFramework: 'custom',
    standardReference: null,
    icon: '🔧',
    category: 'Custom',
    config: null,
  };

  const allTemplates = [...availableTemplates, customTemplate];

  const handleSelectTemplate = (template) => {
    onSelectTemplate(template);
  };

  if (!trustProfile) {
    return (
      <Alert severity="warning">
        Please select a Trust Profile first.
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Choose a Template
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Start with a standards-based template for common verification scenarios, or create a custom policy.
      </Typography>

      {availableTemplates.length === 0 && (
        <Alert severity="info" sx={{ mb: 3 }}>
          No pre-built templates available for {trustProfile.trust_framework_type?.toUpperCase()} framework.
          You can still create a custom policy.
        </Alert>
      )}

      <Grid container spacing={2}>
        {allTemplates.map((template) => (
          <Grid item xs={12} sm={6} md={4} key={template.id}>
            <Card
              sx={{
                height: '100%',
                border: 2,
                borderColor: selectedTemplate?.id === template.id ? 'primary.main' : 'transparent',
                transition: 'all 0.2s',
                '&:hover': {
                  borderColor: 'primary.light',
                  boxShadow: 4,
                },
              }}
            >
              <CardActionArea
                onClick={() => handleSelectTemplate(template)}
                sx={{ height: '100%', alignItems: 'stretch' }}
              >
                <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  {/* Icon & Title */}
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h3" component="span" sx={{ mr: 1.5 }}>
                      {template.icon}
                    </Typography>
                    <Typography variant="h6" component="div" sx={{ flex: 1 }}>
                      {template.name}
                    </Typography>
                  </Box>

                  {/* Description */}
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    paragraph
                    sx={{ flex: 1, minHeight: 60 }}
                  >
                    {template.description}
                  </Typography>

                  {/* Tags */}
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 'auto' }}>
                    <Chip
                      label={template.category}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                    {template.standardReference && (
                      <Chip
                        label={template.standardReference}
                        size="small"
                        variant="outlined"
                      />
                    )}
                    {template.id === 'custom' && (
                      <Chip
                        icon={<BuildIcon />}
                        label="Customizable"
                        size="small"
                        variant="outlined"
                      />
                    )}
                  </Box>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Selected Template Info */}
      {selectedTemplate && selectedTemplate.id !== 'custom' && (
        <Alert severity="info" sx={{ mt: 3 }}>
          <Typography variant="body2" gutterBottom>
            <strong>Selected:</strong> {selectedTemplate.name}
          </Typography>
          {selectedTemplate.standardReference && (
            <Typography variant="body2">
              <strong>Standard:</strong> {selectedTemplate.standardReference}
            </Typography>
          )}
          <Typography variant="body2" sx={{ mt: 1 }}>
            You can customize the claims and settings in the next steps.
          </Typography>
        </Alert>
      )}

      {selectedTemplate?.id === 'custom' && (
        <Alert severity="info" sx={{ mt: 3 }}>
          <Typography variant="body2">
            You'll configure all policy settings manually in the next steps.
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default TemplateSelectionStep;
