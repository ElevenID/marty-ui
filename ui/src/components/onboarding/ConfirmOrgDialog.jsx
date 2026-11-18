/**
 * Confirm Organization Selection Dialog
 * 
 * Dialog to confirm organization selection before joining
 */

import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Paper,
  Button,
  Alert,
} from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useTranslation } from 'react-i18next';
import MembershipModeChip from './MembershipModeChip';

const ConfirmOrgDialog = ({
  open,
  onClose,
  organization,
  submitting,
  onConfirm,
}) => {
  const { t } = useTranslation('onboarding');
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningAmberIcon color="warning" />
          {t('confirmOrg.title')}
        </Box>
      </DialogTitle>
      <DialogContent>
        {organization && (
          <>
            <Alert severity="warning" sx={{ mb: 3 }}>
              {t('confirmOrg.warning')}
            </Alert>
            <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
              <Typography variant="h6">{organization.name}</Typography>
              {organization.description && (
                <Typography variant="body2" color="text.secondary">
                  {organization.description}
                </Typography>
              )}
              <Box sx={{ mt: 1 }}>
                <MembershipModeChip mode={organization.membership_mode} />
              </Box>
            </Paper>
            {organization.membership_mode === 'approval' && (
              <Alert severity="info" sx={{ mt: 2 }}>
                {t('confirmOrg.approvalInfo')}
              </Alert>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('confirmOrg.cancel')}</Button>
        <Button
          variant="contained"
          onClick={onConfirm}
          disabled={submitting}
        >
          {submitting ? t('confirmOrg.processing') : t('confirmOrg.confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ConfirmOrgDialog;
