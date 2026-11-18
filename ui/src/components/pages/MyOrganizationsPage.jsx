/**
 * My Organizations Page
 *
 * Displays all organizations the current user belongs to with membership details.
 * Allows switching to an organization or managing memberships.
 */

import { useAsyncData } from '../../hooks/useAsyncData';
import { useNotifications } from '../../hooks/useNotifications';
import { useAsyncActionScope } from '../../hooks/useAsyncActionScope';

import OrganizationMembershipHub from '../organizations/OrganizationMembershipHub';
import { getMyOrganizations } from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';

/**
 * My Organizations Page Component
 */
export function MyOrganizationsPage({
  managePath = '/organizations',
  discoverPath = '/organizations/discover',
  joinPath = '/organizations/join',
}) {
  const beginAction = useAsyncActionScope();
  const { activeOrgId, setActiveOrgId } = useConsole();
  const { showError } = useNotifications();
  const { data: organizations = [], loading, error } = useAsyncData(() => getMyOrganizations(), []);

  const handleSwitchToOrg = async (orgId) => {
    const action = beginAction();
    try {
      await action.run(setActiveOrgId, orgId);
    } catch (err) {
      if (!action.isCurrent() || err?.name === 'AbortError') return;
      console.error('Failed to switch organization:', err);
      showError('Failed to switch organization. Please try again.');
    }
  };

  return (
    <OrganizationMembershipHub
      organizations={organizations}
      loading={loading}
      error={error}
      activeOrgId={activeOrgId}
      onSwitchToOrg={handleSwitchToOrg}
      managePath={managePath}
      discoverPath={discoverPath}
      joinPath={joinPath}
    />
  );
}

export default MyOrganizationsPage;
