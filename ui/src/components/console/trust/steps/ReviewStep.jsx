/**
 * Review Step - Trust Profile Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing via back navigation and activation toggle.
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
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';

const FRAMEWORK_LABELS = {
  icao: 'ICAO 9303 (eMRTD/ePassport)',
  aamva: 'AAMVA (mDL - ISO 18013-5)',
  eudi: 'EUDI (EU Digital Identity Wallet)',
  custom: 'Custom',
};

const FORMAT_LABELS = {
  jwt_vc: 'JWT VC',
  sd_jwt_vc: 'SD-JWT VC',
  mdoc: 'mDoc',
  ldp_vc: 'LDP VC',
};

const ReviewStep = ({ data, onChange, onEdit }) => {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review & Activate
      </Typography>
      <Typography color="text.secondary" paragraph>
        Review all configuration details before creating the trust profile.
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
                Profile Name
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>Not set</em>}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  Description
                </Typography>
                <Typography variant="body1" gutterBottom>
                  {data.description}
                </Typography>
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Framework Type
              </Typography>
              <Typography variant="body1">
                {FRAMEWORK_LABELS[data.framework_type] || data.framework_type}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Supported Formats
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {(data.supported_formats || []).map((format) => (
                  <Chip
                    key={format}
                    label={FORMAT_LABELS[format] || format}
                    size="small"
                    color="primary"
                    variant="outlined"
                  />
                ))}
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Trust Sources */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              Trust Sources
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              Edit
            </Button>
          </Box>

          {data.trusted_issuers && data.trusted_issuers.length > 0 ? (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {data.trusted_issuers.length} trusted issuer{data.trusted_issuers.length !== 1 ? 's' : ''} configured
              </Typography>
              <List dense>
                {data.trusted_issuers.slice(0, 3).map((issuer, index) => (
                  <ListItem key={index} sx={{ px: 0 }}>
                    <ListItemText
                      primary={
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                          {issuer.did}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
                {data.trusted_issuers.length > 3 && (
                  <Typography variant="body2" color="text.secondary">
                    ... and {data.trusted_issuers.length - 3} more
                  </Typography>
                )}
              </List>
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No trust sources configured (can be added later)
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Validation Rules */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6">
              Validation Rules
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Allowed Algorithms
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {(data.validation_rules?.allowed_algorithms || []).map((alg) => (
                  <Chip key={alg} label={alg} size="small" />
                ))}
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Self-Signed Credentials
              </Typography>
              <Typography variant="body1">
                {data.validation_rules?.allow_self_signed ? 'Allowed' : 'Not allowed'}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Minimum Key Size (RSA)
              </Typography>
              <Typography variant="body1">
                {data.validation_rules?.min_key_size || 2048} bits
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Key Usage Validation
              </Typography>
              <Typography variant="body1">
                {data.validation_rules?.require_key_usage !== false ? 'Required' : 'Not required'}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Divider sx={{ my: 3 }} />

      {/* Activation Explanation */}
      <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 2 }}>
        <Typography variant="body2" gutterBottom>
          <strong>What happens after creation?</strong>
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Active trust profiles are immediately available for verification workflows. You'll be redirected to create a credential template that uses this profile.
        </Typography>
      </Alert>

      {/* Activation Toggle */}
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
                Make this trust profile active and ready to use upon creation
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
