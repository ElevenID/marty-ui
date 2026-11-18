// SPDX-License-Identifier: AGPL-3.0-only
// Imported before the application graph. Proof codes live in memory only.
import {LOGOUT_STARTED_EVENT} from '../../services/authEvents';
const scopePattern=/^\/console\/identity\/associations\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/;
let captured=null;
if(typeof window!=='undefined'&&scopePattern.test(window.location.pathname)) {
 const path=window.location.pathname,match=/^#code=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/.exec(window.location.hash);
 // Strip query and fragment even when invalid. Never carry a proof through login.
 window.history.replaceState(window.history.state,'',path);
 if(match)captured=Object.freeze({path,code:match[1]});
}
export function readAssociationConsentCode(organizationId,challengeId) {
 const path=`/console/identity/associations/${organizationId}/${challengeId}`;
 return captured?.path===path?captured.code:null;
}
export function clearAssociationConsentCode() {captured=null;}
if(typeof window!=='undefined')window.addEventListener(LOGOUT_STARTED_EVENT,clearAssociationConsentCode);
