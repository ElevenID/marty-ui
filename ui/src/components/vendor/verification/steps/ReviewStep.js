/**
 * Review Step
 * 
 * Final review of all policy configuration before submission.
 * Allows users to navigate back to specific steps to make edits.
 */

import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Divider,
  Grid,
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import TimerIcon from '@mui/icons-material/Timer';
import VerifiedIcon from '@mui/icons-material/Verified';

const ReviewStep = ({ policyConfig, trustProfile, template, onEdit }) => {
  // Helper to format seconds to human-readable
  const formatDuration = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days} day${days > 1 ? 's' : ''}`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
    return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  };

  const holderBindingLabels = {
    device_key: 'Device Key',
    session_nonce: 'Session Nonce',
    biometric: 'Biometric',
    none: 'None',
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review & Submit
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Review all configuration details before creating the policy.
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          You can edit any section by clicking the "Edit" button on that card.
        </Typography>
      </Alert>

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
              Basic Information
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Policy Name
              </Typography>
              <Typography variant="body1" gutterBottom>
                {policyConfig.name || <em>Not set</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Description
              </Typography>
              <Typography variant="body1" gutterBottom>
                {policyConfig.description || <em>Not set</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Purpose Statement
              </Typography>
              <Typography variant="body1">
                {policyConfig.purpose || <em>Not set</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Trust Profile */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <SecurityIcon sx={{ mr: 1 }} color="primary" />
              Trust Profile
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              Edit
            </Button>
          </Box>

          {trustProfile ? (
            <Box>
              <Typography variant="body1" gutterBottom>
                {trustProfile.name}
              </Typography>
              <Chip
                label={trustProfile.trust_framework_type?.toUpperCase()}
                size="small"
                color="primary"
                sx={{ mr: 1 }}
              />
              {trustProfile.is_default && (
                <Chip label="Default" size="small" variant="outlined" />
              )}
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              <em>No trust profile selected</em>
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Template */}
      {template && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6">
                Template
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
                Edit
              </Button>
            </Box>

            <Typography variant="body1" gutterBottom>
              {template.icon} {template.name}
            </Typography>
            {template.standardReference && (
              <Chip label={template.standardReference} size="small" variant="outlined" />
            )}
          </CardContent>
        </Card>
      )}

      {/* Credential Types & Claims */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6">
              Credential Types & Claims
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              Edit
            </Button>
          </Box>

          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Accepted Credential Types
          </Typography>
          <Box sx={{ mb: 2 }}>
            {policyConfig.accepted_credential_types.length > 0 ? (
              policyConfig.accepted_credential_types.map((type) => (
                <Chip key={type} label={type} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">
                <em>None specified</em>
              </Typography>
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Required Claims ({policyConfig.required_claims.length})
          </Typography>
          <List dense>
            {policyConfig.required_claims.map((claim, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body2" component="span">
                        {claim.claim_name}
                      </Typography>
                      {claim.accept_predicate && (
                        <Chip label="Predicate OK" size="small" color="success" variant="outlined" />
                      )}
                    </Box>
                  }
                  secondary={`From: ${claim.credential_type}`}
                />
              </ListItem>
            ))}
          </List>

          {policyConfig.required_claims.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              <em>No claims specified</em>
            </Typography>
          )}

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: 'flex', gap: 1 }}>
            {policyConfig.prefer_predicates && (
              <Chip label="Prefer Predicates" size="small" color="info" variant="outlined" />
            )}
            {policyConfig.single_presentation && (
              <Chip label="Single Presentation" size="small" variant="outlined" />
            )}
          </Box>
        </CardContent>
      </Card>

      {/* Freshness & Binding */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <TimerIcon sx={{ mr: 1 }} color="primary" />
              Freshness & Security
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Holder Binding
              </Typography>
              <Typography variant="body1">
                {holderBindingLabels[policyConfig.holder_binding] || policyConfig.holder_binding}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Revocation Check
              </Typography>
              <Typography variant="body1">
                {policyConfig.freshness_requirements.require_revocation_check ? (
                  <Chip label="Required" size="small" color="success" />
                ) : (
                  <Chip label="Not Required" size="small" />
                )}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Max Credential Age
              </Typography>
              <Typography variant="body1">
                {formatDuration(policyConfig.freshness_requirements.max_credential_age_seconds)}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Max Proof Age
              </Typography>
              <Typography variant="body1">
                {formatDuration(policyConfig.freshness_requirements.max_proof_age_seconds)}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Standard Reference */}
      {policyConfig.metadata?.standard_reference && (
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
                <VerifiedIcon sx={{ mr: 1 }} color="primary" />
                Compliance Standard
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
                Edit
              </Button>
            </Box>

            <Typography variant="body1">
              {policyConfig.metadata.standard_reference}
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default ReviewStep;
