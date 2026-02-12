/**
 * Domain Matched Organizations Modal
 * 
 * Modal displayed after registration when the user's email domain
 * matches one or more organizations' allowed email domains.
 * 
 * Allows users to:
 * - Auto-join organizations with "auto" policy
 * - Request approval for organizations with "approval" policy
 * - Dismiss the modal to join manually later
 */

import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  CardActions,
  Alert,
  Chip,
  CircularProgress,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HowToRegIcon from '@mui/icons-material/HowToReg';
import MailOutlineIcon from '@mui/icons-material/MailOutline';
import InfoIcon from '@mui/icons-material/Info';
import { useTranslation, Trans } from 'react-i18next';

const DomainMatchModal = ({
  open,
  onClose,
  matches,
  loading,
  onJoinOrganization,
  email,
}) => {
  const { t } = useTranslation('onboarding');
  
  if (!matches || matches.length === 0) {
    return null;
  }

  const getDomain = (emailAddress) => {
    if (!emailAddress || !emailAddress.includes('@')) return '';
    return emailAddress.split('@')[1];
  };

  const getPolicyLabel = (policy) => {
    return t(`domainMatch.policies.${policy}`, policy);
  };

  const getPolicyColor = (policy) => {
    switch (policy) {
      case 'auto':
        return 'success';
      case 'approval':
        return 'warning';
      case 'closed':
        return 'error';
      default:
        return 'default';
    }
  };

  const getButtonText = (policy) => {
    switch (policy) {
      case 'auto':
        return t('domainMatch.buttons.joinNow');
      case 'approval':
        return t('domainMatch.buttons.requestToJoin');
      case 'closed':
        return t('domainMatch.buttons.closed');
      default:
        return 'Join';
    }
  };

  const getButtonIcon = (policy) => {
    switch (policy) {
      case 'auto':
        return <CheckCircleIcon />;
      case 'approval':
        return <HowToRegIcon />;
      default:
        return null;
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <MailOutlineIcon color="primary" />
          {t('domainMatch.title')}
        </Box>
      </DialogTitle>
      <DialogContent>
        <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 3 }}>
          <Typography variant="body2">
            {t('domainMatch.info', { count: matches.length })}{' '}
            <Trans i18nKey="domainMatch.domain" ns="onboarding" values={{ domain: getDomain(email) }}>
              <strong>{{ domain: getDomain(email) }}</strong> domain.
            </Trans>
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {matches.map((org) => (
            <Card key={org.id} variant="outlined">
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 1 }}>
                  <Typography variant="h6">{org.name}</Typography>
                  <Chip
                    label={getPolicyLabel(org.domain_join_policy)}
                    color={getPolicyColor(org.domain_join_policy)}
                    size="small"
                  />
                </Box>
                {org.domain_join_policy === 'auto' && (
                  <Typography variant="body2" color="text.secondary">
                    <Trans i18nKey="domainMatch.autoDescription" ns="onboarding" values={{ role: org.default_role }}>
                      You will be automatically added as a <strong>{{ role: org.default_role }}</strong>
                    </Trans>
                  </Typography>
                )}
                {org.domain_join_policy === 'approval' && (
                  <Typography variant="body2" color="text.secondary">
                    {t('domainMatch.approvalDescription')}
                  </Typography>
                )}
              </CardContent>
              <CardActions>
                <Button
                  variant="contained"
                  color={org.domain_join_policy === 'auto' ? 'primary' : 'secondary'}
                  startIcon={loading ? <CircularProgress size={16} /> : getButtonIcon(org.domain_join_policy)}
                  onClick={() => onJoinOrganization(org)}
                  disabled={loading || org.domain_join_policy === 'closed'}
                  fullWidth
                >
                  {loading ? t('domainMatch.buttons.processing') : getButtonText(org.domain_join_policy)}
                </Button>
              </CardActions>
            </Card>
          ))}
        </Box>

        <Alert severity="warning" sx={{ mt: 3 }}>
          <Typography variant="body2">
            {t('domainMatch.skipWarning')}
          </Typography>
        </Alert>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          {t('domainMatch.skipButton')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DomainMatchModal;
