'use strict';
const assert=require('node:assert/strict');
// Current platform runtime only; external connector workers have independent ownership.
const PLATFORM_RUNTIME_ROLES=Object.freeze(['applicant', 'auth', 'compliance-profile', 'credential-template', 'deployment-profile', 'device-registration', 'event-stream', 'flow', 'gateway', 'issuance', 'issuance-native', 'notification', 'organization', 'passport-beta-bureau', 'passport-callback-signer', 'presentation-policy', 'revocation-profile', 'signing-keys', 'trust-profile', 'ui-prod', 'verification']);
function assertPlatformRuntimeRoles(roles){
 assert(Array.isArray(roles),'Platform runtime roles required');
 assert.deepEqual([...roles].sort(),[...PLATFORM_RUNTIME_ROLES].sort(),'PLATFORM_RUNTIME_ROLE_SET_CHANGED');
}
module.exports={PLATFORM_RUNTIME_ROLES,assertPlatformRuntimeRoles};
