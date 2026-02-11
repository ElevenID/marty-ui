/**
 * Review Step
 * 
 * Final review of all flow configuration before submission.
 * Includes activation toggle and allows users to edit specific sections.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemText,
  FormControlLabel,
  Switch,
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import DeployIcon from '@mui/icons-material/RocketLaunch';
import GppGoodIcon from '@mui/icons-material/GppGood';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import VerifiedIcon from '@mui/icons-material/Verified';

const FLOW_TYPE_LABELS = {
  verification: 'Verification Flow',
  issuance: 'Issuance Flow',
  issuance_oid4vci: 'OID4VCI Issuance Flow',
  combined: 'Combined Flow',
};

const PRECONDITION_LABELS = {
  application_approved: 'Application Approved',
  identity_verified: 'Identity Verified',
  manual_admin_approval: 'Manual Admin Approval',
  external_verification: 'External Verification Result',
};

const PRECONDITION_ICONS = {
  application_approved: <CheckCircleIcon />,
  identity_verified: <GppGoodIcon />,
  manual_admin_approval: <AdminPanelSettingsIcon />,
  external_verification: <VerifiedIcon />,
};

const ReviewStep = ({ data, onEdit, onToggleActivation }) => {
  const { 
    flowType, 
    name, 
    description, 
    flowSteps, 
    preconditions = [],
    selectedDeployment, 
    defaultPolicyId, 
    activateImmediately 
  } = data;

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review & Submit
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Review all configuration details before creating the flow.
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
              Basic Information
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Flow Type
              </Typography>
              <Typography variant="body1" gutterBottom>
                {FLOW_TYPE_LABELS[flowType] || flowType}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Flow Name
              </Typography>
              <Typography variant="body1" gutterBottom>
                {name || <em>Not set</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Description
              </Typography>
              <Typography variant="body1">
                {description || <em>Not set</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Flow Steps */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <AccountTreeIcon sx={{ mr: 1 }} color="primary" />
              Flow Steps ({flowSteps.length})
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              Edit
            </Button>
          </Box>

          {flowSteps.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              <em>No steps defined</em>
            </Typography>
          ) : (
            <List dense>
              {flowSteps.map((step, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip label={index + 1} size="small" color="primary" />
                        <Typography variant="body2" component="span">
                          {step.name}
                        </Typography>
                      </Box>
                    }
                    secondary={`Type: ${step.type}`}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Preconditions */}
      {flowType === 'issuance_oid4vci' && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
                <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
                Preconditions ({preconditions.length})
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
                Edit
              </Button>
            </Box>

            {preconditions.length === 0 ? (
              <Alert severity="warning">
                <Typography variant="body2">
                  No preconditions configured. The flow will require manual triggering.
                </Typography>
              </Alert>
            ) : (
              <List dense>
                {preconditions.map((condition, index) => (
                  <ListItem key={index}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {PRECONDITION_ICONS[condition] || <CheckCircleIcon />}
                          <Typography variant="body2" component="span">
                            {PRECONDITION_LABELS[condition] || condition}
                          </Typography>
                        </Box>
                      }
                      secondary={`Condition ${index + 1} of ${preconditions.length}`}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </CardContent>
        </Card>
      )}

      {/* Deployment Binding */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <DeployIcon sx={{ mr: 1 }} color="primary" />
              Deployment Binding
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Deployment Profile
              </Typography>
              <Typography variant="body1" gutterBottom>
                {selectedDeployment ? (
                  <>
                    {selectedDeployment.name}
                    {selectedDeployment.is_active && (
                      <Chip
                        label="Active"
                        size="small"
                        color="success"
                        variant="outlined"
                        sx={{ ml: 1 }}
                      />
                    )}
                  </>
                ) : (
                  <em>None (configure later)</em>
                )}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Default Presentation Policy
              </Typography>
              <Typography variant="body1">
                {defaultPolicyId ? (
                  `Policy ID: ${defaultPolicyId}`
                ) : (
                  <em>None (configure later)</em>
                )}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Activation Toggle */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Activation
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={activateImmediately}
                onChange={(e) => onToggleActivation(e.target.checked)}
                color="primary"
              />
            }
            label="Activate immediately after creation"
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            {activateImmediately
              ? 'Flow will be active and available for use immediately'
              : 'Flow will be created but remain inactive until manually enabled'}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ReviewStep;
