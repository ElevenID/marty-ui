/**
 * Use cases for organization applications page.
 */

import { listOrganizationApplications } from '../../services/applicantApi';
import { requireOrganizationId } from '../../services/queryUtils';
import { mergeApplicantsIntoApplications } from './orgApplicationsFlow';

export async function loadOrganizationApplications({
  organizationId,
  getApplications = listOrganizationApplications,
} = {}) {
  const orgId = requireOrganizationId(organizationId, 'loading organization applications');
  const applicationsPage = await getApplications(orgId);
  return mergeApplicantsIntoApplications(applicationsPage.items);
}
