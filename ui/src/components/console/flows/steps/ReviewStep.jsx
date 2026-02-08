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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import DeployIcon from '@mui/icons-material/RocketLaunch';

const FLOW_TYPE_LABELS = {
  verification: 'Verification Flow',
  issuance: 'Issuance Flow',
  combined: 'Combined Flow',
};

const ReviewStep = ({ data, onEdit, onToggleActivation }) => {
  const { flowType, name, description, flowSteps, selectedDeployment, defaultPolicyId, activateImmediately } = data;

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

      {/* Deployment Binding */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <DeployIcon sx={{ mr: 1 }} color="primary" />
              Deployment Binding
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
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
