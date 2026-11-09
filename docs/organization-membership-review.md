# Native organization membership review

The console's Membership Requests page uses persisted organization members. A
join request is a member whose status is `pending`; an invitation is a distinct
member whose status is `invited`.

## List pending requests

`GET /v1/organizations/{org_id}/members?status=pending&limit=100&offset=0`

The request requires `team:view` in the selected organization and returns a JSON
array of member objects. `status` accepts `pending`, `invited`, `active`, or
`deactivated`. Omitting it retains the existing unfiltered member inventory.
Filtering precedes pagination. Members are ordered by creation time and member
ID, so offset pages have a deterministic order. The default limit is 100, the
maximum is 500, and zero is accepted. There is no total-count field.

Use each result's `id` as the membership identifier. `user_id` identifies the
account and must not be substituted for the membership ID.

## Approve a pending request

`POST /v1/organizations/{org_id}/members/{member_id}/approve`

The request requires `team:manage` in the selected organization and has an empty
body. It cannot assign a role, replace account information, or reactivate an
invitation or deactivated membership. Successful approval returns the member
object with status `active` and a `joined_at` timestamp, preserving its user,
email, and assigned roles.

The membership row is locked before checking its status. Before any persisted
changes, approval also acquires the organization's `FOR KEY SHARE NOWAIT` row
lock, matching the lock needed by the audit record's foreign key. Joins acquire
the organization lock before the membership lock, so approval must not wait on
that organization row while holding the membership. If the parent row lock is
unavailable, approval explicitly rolls back, releasing the member lock, and
returns 503. The pending membership, caches, audit records, and outbox remain
unchanged; the caller can retry after contention clears.

Activation, the reviewer-attributed `team.member.approved` audit record, and the
`member.approved.event` outbox message commit in one transaction. User and API-key
reviewers retain their respective actor identities in the audit record. Member
and permission caches are invalidated after commit. Two concurrent decisions
cannot both approve the same pending request.

An absent or differently scoped member returns 404. A membership that is no
longer pending returns 409 with `ORGANIZATION.MEMBERSHIP_NOT_PENDING`; a repeated
request creates no second approval event. Requests without the required
organization access or grant return 403. A body containing role assignments or
other content returns 400. Storage, audit, or outbox failure also returns 503
without committing activation.

Approval is the only added review transition. No rejection or role-request API
is introduced. Team snapshots include active members and invited members in
their respective existing fields; pending join requests do not count as pending
invitations.

## Validation

The native unit and HTTP boundary tests cover status transitions, tenant and
permission checks, forged forwarding, payload rejection, event attribution, and
the public schema. The PostgreSQL regression is part of the existing
`organization_application` CI obligation. That obligation requires
`ORGANIZATION_POSTGRES_TEST_URL`, runs the complete application integration test
executable serially, and checks the selected libtest cases and results. Missing
required runtime inputs fail that CI obligation before execution.

The database regression exercises simultaneous approvals, persisted state,
filtered pagination, invitation separation, deactivated-member rejection,
cross-tenant API-key rejection, API-key audit attribution, cache invalidation,
and rollback after an outbox failure. It also holds the organization lock as a
join would, checks prompt approval failure and member-lock release without
writes or cache invalidation, and retries successfully after contention clears.

Run this regression against a dedicated test database: its rollback check
temporarily adds a test-organization-specific outbox constraint. An ordinary
local test run without `ORGANIZATION_POSTGRES_TEST_URL` does not qualify the
PostgreSQL behavior, even if its harness reports success.
