/**
 * Team Page
 * 
 * Manage organization team members and roles.
 * Embeds the existing Team component.
 */

import { Box } from '@mui/material';
import { Team } from '../../vendor';
import { ResourcePage } from '../../common';

const ORG_TABS = [
  { label: 'Organization', path: '/console/org/settings' },
  { label: 'Team', path: '/console/org/team' },
  { label: 'Webhooks', path: '/console/org/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Org', path: '/console/org' },
  { label: 'Team', path: '/console/org/team' },
];

function TeamPage() {
  return (
    <ResourcePage
      title="Team"
      description="Manage team members and their access roles."
      tabs={ORG_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <Team />
      </Box>
    </ResourcePage>
  );
}

export default TeamPage;
