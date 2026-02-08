/**
 * Review Step - Credential Template Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing and activation settings.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  FormControlLabel,
  Switch,
  Divider,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

const ReviewStep = ({ data, onChange, onEdit }) => {
  const secondsToDays = (seconds) => Math.floor(seconds / 86400);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review & Activate
      </Typography>
      <Typography color="text.secondary" paragraph>
        Review all configuration details before creating the credential template.
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="primary" />
              Basic Information
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Template Name
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>Not set</em>}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Credential Type
              </Typography>
              <Typography variant="body1">
                {data.credential_type}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                VCT
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {data.vct}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  Description
                </Typography>
                <Typography variant="body1">
                  {data.description}
                </Typography>
              </Grid>
            )}
          </Grid>
        </CardContent>
      </Card>

      {/* Claims */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <DescriptionIcon color="primary" />
              Claims ({data.claims?.length || 0})
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              Edit
            </Button>
          </Box>

          {data.claims && data.claims.length > 0 ? (
            <List dense>
              {data.claims.map((claim, index) => (
                <ListItem key={index} sx={{ px: 0 }}>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography
                          variant="body2"
                          sx={{ fontFamily: 'monospace', fontWeight: 'medium' }}
                        >
                          {claim.name}
                        </Typography>
                        <Chip label={claim.type} size="small" />
                        {claim.required && (
                          <Chip label="Required" size="small" color="primary" />
                        )}
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No claims defined
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Trust & Compliance */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              Trust & Compliance
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Trust Profile
              </Typography>
              <Typography variant="body1">
                {data.trust_profile_id ? `ID: ${data.trust_profile_id}` : <em>Not selected</em>}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Compliance Profile
              </Typography>
              <Typography variant="body1">
                {data.compliance_profile_id || <em>None</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Crypto & Validity */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <VpnKeyIcon color="primary" />
              Cryptography & Validity
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Signing Algorithm
              </Typography>
              <Typography variant="body1">
                {data.signing_algorithm || 'ES256'}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Default Validity
              </Typography>
              <Typography variant="body1">
                {secondsToDays(data.validity_rules?.ttl_seconds || 31536000)} days
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Maximum Validity
              </Typography>
              <Typography variant="body1">
                {secondsToDays(data.validity_rules?.max_validity_seconds || 63072000)} days
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Revocation
              </Typography>
              <Typography variant="body1">
                {data.revocation_profile_id || <em>None</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Divider sx={{ my: 3 }} />

      {/* Activation Options */}
      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, mb: 2 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.generate_artifacts_automatically !== false}
              onChange={(e) => onChange({ generate_artifacts_automatically: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                Generate cryptographic artifacts automatically
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically create signing keys and certificates for this template
              </Typography>
            </Box>
          }
        />
      </Box>

      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.activate_immediately !== false}
              onChange={(e) => onChange({ activate_immediately: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                Activate immediately
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Make this template active and ready for credential issuance
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
