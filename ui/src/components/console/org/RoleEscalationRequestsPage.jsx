import { Alert, Box, Button, Typography } from '@mui/material';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import ResourcePage from '../../common/ResourcePage';
import { usePermissions } from '../../../hooks/usePermissions';

/** Keep existing bookmarks useful without invoking the unsupported request API. */
export default function RoleEscalationRequestsPage() {
  const { t } = useTranslation('console');
  const { can, isLoading } = usePermissions();
  const canViewTeam = !isLoading && can('team', 'view');
  const canViewRoles = !isLoading && can('role', 'view');

  return (
    <ResourcePage title={t('org.roleEscalation.title')}>
      <Alert severity="info" sx={{ mb: 2 }}>
        {t('org.roleEscalation.unavailable')}
      </Alert>
      <Typography variant="body1" sx={{ mb: 2 }}>
        {t('org.roleEscalation.management')}
      </Typography>
      {(canViewTeam || canViewRoles) && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
          {canViewTeam && (
            <Button component={Link} to="/console/org/team" variant="outlined">
              {t('org.roleEscalation.teamLink')}
            </Button>
          )}
          {canViewRoles && (
            <Button component={Link} to="/console/org/roles" variant="outlined">
              {t('org.roleEscalation.rolesLink')}
            </Button>
          )}
        </Box>
      )}
    </ResourcePage>
  );
}
