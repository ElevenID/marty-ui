// SPDX-License-Identifier: AGPL-3.0-only
// Actual source modules and Chromium against a synthetic same-origin HTTPS Gateway.
// Does not qualify a deployed IdP or canonical Core database admission.
import assert from 'node:assert/strict';
import {createServer as httpsServer} from 'node:https';
import {mkdtemp,readFile,writeFile,unlink,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {tmpdir} from 'node:os';
import {dirname,isAbsolute,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {build} from 'vite';
import react from '@vitejs/plugin-react';
const modulePath=process.argv[2],executablePath=process.argv[3];assert.ok(isAbsolute(modulePath??''));
if(executablePath!==undefined)assert.ok(isAbsolute(executablePath));
assert.equal(JSON.parse(await readFile(join(dirname(modulePath),'package.json'),'utf8')).version,'1.59.1');
const {chromium}=await import(pathToFileURL(modulePath).href);
const root=fileURLToPath(new URL('../',import.meta.url));
const directory=await mkdtemp(join(tmpdir(),'association-browser-'));
assert.equal(dirname(resolve(directory)),resolve(tmpdir()));
const entry='.association-consent-fixture-'+randomUUID()+'.jsx',entryPath=join(root,entry);
let server,browser;const errors=[],requests=[],mutations=[];
const org='10000000-0000-4000-8000-000000000001',challenge='20000000-0000-4000-8000-000000000002',code='A'.repeat(43);
let userId='learner-one',committed=false,active=true,operationId;
function reply(res,value){const body=JSON.stringify(value);res.writeHead(200,{'content-type':'application/json','cache-control':'no-store',
 'referrer-policy':'no-referrer','content-length':Buffer.byteLength(body)});res.end(body);}
try {
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
  '-addext','subjectAltName=IP:127.0.0.1','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem')],{stdio:'ignore'});
 await writeFile(entryPath,`import '/src/application/associations/consentCode.js';
 import React,{StrictMode} from 'react';import {createRoot} from 'react-dom/client';
 import {BrowserRouter,Route,Routes} from 'react-router';
 import AssociationConsentPage from '/src/components/identity/AssociationConsentPage.jsx';
 window.__associationInitialHref=location.href;
 window.__associationWriteFetches=0;const nativeFetch=window.fetch;
 window.fetch=(...args)=>{if(String(args[0]).endsWith('/confirm'))window.__associationWriteFetches++;return Reflect.apply(nativeFetch,window,args);};
 createRoot(document.getElementById('root')).render(<StrictMode><BrowserRouter><Routes>
 <Route path="/console/identity/associations/:organizationId/:challengeId" element={<AssociationConsentPage/>}/>
 </Routes></BrowserRouter></StrictMode>);`);
 const dist=join(directory,'dist');
 await build({root,configFile:false,plugins:[react()],cacheDir:join(directory,'vite-cache'),
  build:{outDir:dist,emptyOutDir:true,rollupOptions:{input:entryPath,output:{entryFileNames:'fixture.js'}}}});
 server=httpsServer({key:await readFile(join(directory,'key.pem')),cert:await readFile(join(directory,'cert.pem'))},(req,res)=>{
  void(async()=>{
   requests.push({url:req.url,referer:req.headers.referer??''});assert.ok(!req.url.includes(code));
   if(req.url==='/v1/auth/me')return reply(res,{authenticated:true,user:{user_id:userId}});
   const base=`/v1/organizations/${org}/external-association-challenges/${challenge}/`;
   if(req.url?.startsWith(base)) {
    let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>4096)throw Error('oversize fixture body');}
    const body=JSON.parse(raw),action=req.url.slice(base.length);
    assert.equal(req.method,'POST');assert.equal(req.headers.origin,origin);
    assert.equal(req.headers.authorization,undefined);assert.equal(req.headers['x-api-key'],undefined);
    if(action==='confirm') {
     mutations.push(body);assert.equal(body.code,code);assert.equal(body.expected_revision,1);
     assert.deepEqual(Object.keys(body).sort(),['code','expected_revision','operation_id']);
     if(committed)assert.deepEqual(body,mutations[0]);else {operationId=body.operation_id;committed=true;}
     // Chromium may replay a transport request whose connection failed before
     // response headers. Every replay must retain the one original intent.
     req.socket.destroy();return;
    }
    if(action==='receipt') {
     assert.equal(body.operation_id,operationId);assert.ok(committed);
     return reply(res,{kind:'receipt',receipt:{operation_id:operationId,challenge_id:challenge,action:'confirm',revision:2,phase:'confirmed'}});
    }
    assert.equal(action,'inspect');assert.deepEqual(body,{});
    return reply(res,{kind:'current',record:{challenge_id:challenge,source_id:'learning-source',binding_id:'binding-one',
     revision:committed?2:1,phase:committed?'confirmed':'pending',current:active,expired:false,expires_at_ms:expiry,
     application_id:'application-one',subject_id:'subject-one',identity:null,can_relink:false}});
   }
   if(req.url?.startsWith('/console/identity/associations/')) {
    const html=`<!doctype html><html><head><meta name="referrer" content="no-referrer"></head>
     <body><div id="root"></div><script type="module" src="/fixture.js"></script></body></html>`;
    res.writeHead(200,{'content-type':'text/html','cache-control':'no-store','referrer-policy':'no-referrer'});res.end(html);return;
   }
   if(req.url==='/fixture.js') {
    res.writeHead(200,{'content-type':'text/javascript','cache-control':'no-store'});res.end(await readFile(join(dist,'fixture.js')));return;
   }
   res.writeHead(404);res.end();
  })().catch(error=>{errors.push(error.message);res.destroy();});
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`https://127.0.0.1:${server.address().port}`,expiry=Date.now()+120000;
 browser=await chromium.launch({headless:true,...executablePath?{executablePath}:{}});const context=await browser.newContext({ignoreHTTPSErrors:true}),page=await context.newPage();
 page.on('pageerror',error=>errors.push(error.message));
 const path=`/console/identity/associations/${org}/${challenge}`;
 await page.goto(`${origin}${path}#code=${code}`);await page.getByRole('button',{name:'Confirm connection'}).waitFor();
 assert.equal(mutations.length,0);assert.equal(new URL(page.url()).hash,'');
 assert.equal(await page.evaluate(()=>window.__associationInitialHref),origin+path);
 assert.equal(await page.evaluate(()=>sessionStorage.length),0);
 userId='learner-two';await page.getByRole('button',{name:'Confirm connection'}).click();
 await page.getByRole('link',{name:'Sign in'}).waitFor();assert.equal(mutations.length,0);
 assert.equal(await page.evaluate(()=>sessionStorage.length),0);
 userId='learner-one';await page.getByRole('button',{name:'Check connection'}).click();
 await page.getByRole('button',{name:'Confirm connection'}).click();
 await page.getByText('The reply was not confirmed.',{exact:false}).waitFor();assert.ok(mutations.length>=1);
 assert.equal(await page.evaluate(()=>window.__associationWriteFetches),1);
 assert.equal(new Set(mutations.map(m=>m.operation_id)).size,1);const wireAttempts=mutations.length;
 const saved=await page.evaluate(()=>Object.values(sessionStorage));assert.equal(saved.length,1);assert.ok(!saved[0].includes(code));
 assert.equal(JSON.parse(saved[0]).operationId,operationId);
 await page.reload();await page.getByText('This connection is active.',{exact:true}).waitFor();assert.equal(mutations.length,wireAttempts);
 active=false;await page.reload();await page.getByText('This connection is no longer active.',{exact:true}).waitFor();
 assert.equal(mutations.length,wireAttempts);assert.ok(requests.every(r=>!r.url.includes(code)&&!r.referer.includes(code)));
 assert.deepEqual(errors,[]);await context.close();
 console.log(JSON.stringify({passed:5,failed:0,browser:browser.version(),applicationWriteFetches:1,wireAttempts,uniqueOriginalOperations:1,
  scope:'actual Chromium/source page and transport; synthetic HTTPS Gateway only',
  checks:['fragment removed before application initialization; no automatic writes','reviewed actor mismatch prevents persistence/write',
   'one uncertain confirmation retains metadata without code','reload recovers original receipt without retry','historical receipt does not restore inactive current connection']}));
}finally {
 await browser?.close();await new Promise(resolve=>server?server.close(resolve):resolve());
 await unlink(entryPath).catch(error=>{if(error.code!=='ENOENT')throw error;});
 assert.equal(dirname(resolve(directory)),resolve(tmpdir()));await rm(directory,{recursive:true});
}
