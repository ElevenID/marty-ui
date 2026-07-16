import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Grid,
  Stack,
  Typography,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BadgeIcon from '@mui/icons-material/Badge';
import CreditCardIcon from '@mui/icons-material/CreditCard';
import ExtensionIcon from '@mui/icons-material/Extension';
import FactCheckIcon from '@mui/icons-material/FactCheck';
import LoginIcon from '@mui/icons-material/Login';
import PublishedWithChangesIcon from '@mui/icons-material/PublishedWithChanges';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

const FLOW_TYPES = [
  { value: 'oid4vci_pre_authorized', name: 'Wallet issuance', category: 'Issue', icon: BadgeIcon },
  { value: 'oid4vci_authorization_code', name: 'Authorized issuance', category: 'Issue', icon: LoginIcon },
  { value: 'mdl_issuance', name: 'Mobile document issuance', category: 'Issue', icon: CreditCardIcon },
  { value: 'application_approval_issuance', name: 'Application approval', category: 'Issue', icon: FactCheckIcon },
  { value: 'physical_document_issuance', name: 'Physical document issuance', category: 'Issue', icon: CreditCardIcon },
  { value: 'oid4vp_presentation', name: 'Credential verification', category: 'Verify', icon: VerifiedUserIcon },
  { value: 'mdl_presentation', name: 'Mobile document verification', category: 'Verify', icon: VerifiedUserIcon },
  { value: 'siopv2', name: 'Self-issued sign-in', category: 'Verify', icon: LoginIcon },
  { value: 'credential_renewal', name: 'Credential renewal', category: 'Lifecycle', icon: PublishedWithChangesIcon },
  { value: 'credential_revocation', name: 'Credential revocation', category: 'Lifecycle', icon: PublishedWithChangesIcon },
  { value: 'combined', name: 'Issue and verify', category: 'Combined', icon: AccountTreeIcon },
];

const FlowTypeStep = ({ capabilities, selectedType, onSelectType, onOpenCustomBuilder }) => {
  const physicalCapability = capabilities?.physical_document_issuance;

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" gap={2} sx={{ mb: 3 }}>
        <Box>
          <Typography variant="h6">Choose a flow</Typography>
          <Typography variant="body2" color="text.secondary">
            Standard flows use the fixed MIP 0.3 sequence shown during review.
          </Typography>
        </Box>
        <Button startIcon={<ExtensionIcon />} onClick={onOpenCustomBuilder}>
          Custom extension
        </Button>
      </Stack>

      {physicalCapability && !physicalCapability.supported && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Physical document issuance is visible but unavailable until its signer and production connector are configured.
        </Alert>
      )}

      <Grid container spacing={1.5}>
        {FLOW_TYPES.map((type) => {
          const Icon = type.icon;
          const disabled = type.value === 'physical_document_issuance' && physicalCapability?.supported === false;
          return (
            <Grid item xs={12} sm={6} md={4} key={type.value}>
              <Card
                variant="outlined"
                sx={{
                  height: '100%',
                  borderColor: selectedType === type.value ? 'primary.main' : 'divider',
                  bgcolor: selectedType === type.value ? 'action.selected' : 'background.paper',
                }}
              >
                <CardActionArea
                  data-testid={`flow-type-${type.value}`}
                  onClick={() => onSelectType(type.value)}
                  disabled={disabled}
                  aria-selected={selectedType === type.value}
                  sx={{ height: '100%' }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Stack direction="row" alignItems="center" gap={1.5}>
                      <Icon color={disabled ? 'disabled' : 'primary'} />
                      <Box sx={{ minWidth: 0 }}>
                        <Typography variant="subtitle2">{type.name}</Typography>
                        <Chip label={disabled ? 'Unavailable' : type.category} size="small" variant="outlined" sx={{ mt: 0.75 }} />
                      </Box>
                    </Stack>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          );
        })}
      </Grid>
    </Box>
  );
};

export default FlowTypeStep;
