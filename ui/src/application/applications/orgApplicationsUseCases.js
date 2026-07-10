/**
 * Use cases for organization applications page.
 */

import {
  listApplicants,
  listOrganizationApplications,
} from '../../services/applicantApi';
import { requireOrganizationId } from '../../services/queryUtils';
import { mergeApplicantsIntoApplications } from './orgApplicationsFlow';

export async function loadOrganizationApplications({
  organizationId,
  getApplications = listOrganizationApplications,
  getApplicants = listApplicants,
} = {}) {
  const orgId = requireOrganizationId(organizationId, 'loading organization applications');
  const [appsResult, applicants] = await Promise.all([
    getApplications(orgId),
    getApplicants(orgId),
  ]);
  return mergeApplicantsIntoApplications(appsResult.applications || [], applicants);
}
