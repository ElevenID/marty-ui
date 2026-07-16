import {
  Alert,
  Box,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemText,
  Stack,
  Typography,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';

function titleize(value) {
  return String(value || '').replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

const ReviewStep = ({ capabilities, data }) => {
  const sequence = capabilities?.sequences?.[data.flowType] || [];
  const dependencies = [
    ['Credential template', data.credentialTemplateId],
    ['Application template', data.applicationTemplateId],
    ['Presentation policy', data.defaultPolicyId],
    ['Production destination', data.deliveryDestinationProfileId],
    ['Deployment profile', data.selectedDeployment?.name || data.selectedDeployment?.id],
  ].filter(([, value]) => value);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>Review draft</Typography>
      <Alert severity="info" sx={{ mb: 3 }}>
        Creating this flow does not activate it. Validate and test the saved draft before activation.
      </Alert>

      <Stack spacing={3}>
        <Box>
          <Typography variant="overline" color="text.secondary">Definition</Typography>
          <Typography variant="h6">{data.name}</Typography>
          <Typography variant="body2" color="text.secondary">{data.description || 'No description'}</Typography>
          <Stack direction="row" gap={1} sx={{ mt: 1 }}>
            <Chip label={titleize(data.flowType)} size="small" />
            <Chip label={data.approvalStrategy} size="small" variant="outlined" />
            <Chip label="DRAFT" size="small" color="warning" variant="outlined" />
          </Stack>
        </Box>

        <Divider />

        <Box>
          <Stack direction="row" alignItems="center" gap={1}>
            <AccountTreeIcon color="action" />
            <Typography variant="subtitle2">Resolved sequence</Typography>
          </Stack>
          <List dense disablePadding sx={{ mt: 1 }}>
            {sequence.map((stepName, index) => (
              <ListItem key={stepName} disableGutters>
                <Chip label={index + 1} size="small" sx={{ mr: 1.5, width: 28 }} />
                <ListItemText primary={titleize(stepName)} secondary={stepName} />
              </ListItem>
            ))}
          </List>
        </Box>

        <Divider />

        <Box>
          <Typography variant="subtitle2" gutterBottom>Bound objects</Typography>
          <List dense disablePadding>
            {dependencies.map(([label, value]) => (
              <ListItem key={label} disableGutters>
                <CheckCircleOutlineIcon color="success" fontSize="small" sx={{ mr: 1.5 }} />
                <ListItemText primary={label} secondary={String(value)} />
              </ListItem>
            ))}
          </List>
        </Box>
      </Stack>
    </Box>
  );
};

export default ReviewStep;
