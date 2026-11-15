/**
 * Native organization membership review.
 * Inventory remains compatible with runtimes that ignore the status filter.
 */
import { apiRequest, get } from './api';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const PAGE_SIZE = 500;
const MEMBER_STATUSES = new Set(['active', 'pending', 'invited', 'deactivated']);

function nonemptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function requireCurrent(isCurrent) {
  if (!isCurrent()) {
    const error = new Error('Membership request scope changed.');
    error.name = 'AbortError';
    throw error;
  }
}

function validMember(member, organizationId) {
  return member && typeof member === 'object'
    && nonemptyString(member.id)
    && member.organization_id === organizationId
    && MEMBER_STATUSES.has(member.status)
    && (member.status !== 'pending' || (
      nonemptyString(member.user_id)
      && (member.email == null || typeof member.email === 'string')
      && Array.isArray(member.roles)
      && member.roles.every(role => role && nonemptyString(role.id) && nonemptyString(role.name)
        && (role.display_name == null || typeof role.display_name === 'string'))
    ));
}

/** Load every native page before presenting a complete pending inventory. */
export async function getPendingRequests(organizationId, { isCurrent = () => true } = {}) {
  const orgId = requireOrganizationId(organizationId, 'loading pending memberships');
  const requests = [];
  const seen = new Set();
  let offset = 0;

  while (true) {
    requireCurrent(isCurrent);
    const query = buildDefinedQueryString({ status: 'pending', limit: PAGE_SIZE, offset });
    const page = await get(withQuery('/v1/organizations/' + encodeURIComponent(orgId) + '/members', query));
    requireCurrent(isCurrent);
    if (!Array.isArray(page) || page.length > PAGE_SIZE
      || page.some(member => !validMember(member, orgId))) {
      throw new Error('Membership requests returned an invalid response.');
    }
    for (const member of page) {
      if (seen.has(member.id)) {
        throw new Error('The membership inventory changed while loading. Refresh and try again.');
      }
      seen.add(member.id);
      if (member.status === 'pending') requests.push(member);
    }
    if (page.length < PAGE_SIZE) return { requests };
    // Advance by raw rows, including non-pending records from older runtimes.
    offset += page.length;
  }
}

/** Approve exactly this organization's pending membership, without altering roles. */
export async function approveMembershipRequest(organizationId, memberId) {
  const orgId = requireOrganizationId(organizationId, 'approving a membership');
  if (!nonemptyString(memberId) || ['null', 'undefined'].includes(memberId.trim().toLowerCase())) {
    throw new Error('Membership is required for approval.');
  }
  const id = memberId.trim();
  const member = await apiRequest(
    '/v1/organizations/' + encodeURIComponent(orgId) + '/members/' + encodeURIComponent(id) + '/approve',
    { method: 'POST' },
  );
  if (!member || member.id !== id || member.organization_id !== orgId || member.status !== 'active') {
    throw new Error('Membership approval returned an invalid response.');
  }
  return member;
}
