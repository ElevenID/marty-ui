/**
 * Use cases for organization applications page.
 */

import {
  listApplicants,
  listOrganizationApplications,
} from '../../services/applicantApi';
import { mergeApplicantsIntoApplications } from './orgApplicationsFlow';

export async function loadOrganizationApplications({
  organizationId,
  getApplications = listOrganizationApplications,
  getApplicants = listApplicants,
} = {}) {
  const [appsResult, applicants] = await Promise.all([
    getApplications(organizationId),
    getApplicants(organizationId),
  ]);
  return mergeApplicantsIntoApplications(appsResult.applications || [], applicants);
}
