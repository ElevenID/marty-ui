// SPDX-License-Identifier: AGPL-3.0-only
import {beforeEach,expect,it,vi} from 'vitest';
const org='10000000-0000-4000-8000-000000000001',challenge='20000000-0000-4000-8000-000000000002';
const path=`/console/identity/associations/${org}/${challenge}`;
beforeEach(()=>{vi.resetModules();window.sessionStorage.clear();window.localStorage.clear();});
it('scrubs URL code and query before app initialization, keeps it in memory and binds it to exact scope',async()=>{
 window.history.replaceState({},'',`${path}?tracking=ignored#code=${'A'.repeat(43)}`);
 const module=await import('./consentCode');
 expect(window.location.pathname).toBe(path);expect(window.location.hash).toBe('');expect(window.location.search).toBe('');
 expect(module.readAssociationConsentCode(org,challenge)).toBe('A'.repeat(43));
 expect(module.readAssociationConsentCode(org,org)).toBeNull();expect(window.sessionStorage.length).toBe(0);expect(window.localStorage.length).toBe(0);
 module.clearAssociationConsentCode();expect(module.readAssociationConsentCode(org,challenge)).toBeNull();
});
it.each(['code=short',`code=${'A'.repeat(42)}B`,`code=${'A'.repeat(43)}&code=${'A'.repeat(43)}`,`code=%41${'A'.repeat(42)}`])('scrubs invalid fragment without accepting it: %s',async fragment=>{
 window.history.replaceState({},'',`${path}#${fragment}`);const module=await import('./consentCode');
 expect(window.location.hash).toBe('');expect(module.readAssociationConsentCode(org,challenge)).toBeNull();
});
it('does not alter fragments on unrelated product routes',async()=>{
 window.history.replaceState({},'','/console/profile#section');await import('./consentCode');expect(window.location.hash).toBe('#section');
});
it('drops the in-memory code synchronously when logout begins',async()=>{
 window.history.replaceState({},'',`${path}#code=${'A'.repeat(43)}`);const module=await import('./consentCode');
 expect(module.readAssociationConsentCode(org,challenge)).not.toBeNull();
 window.dispatchEvent(new Event('elevenid:logout-started'));expect(module.readAssociationConsentCode(org,challenge)).toBeNull();
});
