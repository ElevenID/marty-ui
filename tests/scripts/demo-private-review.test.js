"use strict";
// Controlled source/transport fixtures only. Dummy bytes are NOT video or a functional proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module'),{createHash}=require('node:crypto');
const {createPrivateReviewRecording,privateReviewSurfaceDecision}=require('./demo-recording');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function temp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'d05-private-review-control-'));t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('d05-private-review-control-'));assert.equal(fs.realpathSync(root),root);fs.rmSync(root,{recursive:true});});for(const name of ['artifacts','media'])fs.mkdirSync(path.join(root,name));return root;}
function binding(root){return {scope:'PRIVATE_REVIEW_ONLY',scenario:'membership-badge-login',captureId:'c'.repeat(36),runId:'r'.repeat(36),mediaDirectory:path.join(root,'media'),releaseQualified:false,recordingQualified:false,publicationEligible:false};}
function context(){const pages=[];return {pages:()=>pages,exposeBinding:async function(name,fn){if(name==='__martyPrivateReviewPointerEvent')this.transport=fn;else this.surface=fn;},addInitScript:async function(fn,arg){this.init=fn;this.arg=arg;},addPage(role,file){const page={context:()=>this,video:()=>({path:async()=>file})};pages.push(page);return page;}};}
function pageHarness(c,{extra=[]}={}){
 const listeners={},sent=[],surface=[],observers=[],created=[];
 function style(){const values=new Map();return {getPropertyValue:k=>values.get(k)?.value||'',getPropertyPriority:k=>values.get(k)?.priority||'',setProperty(k,value,priority){values.set(k,{value,priority});},get cssText(){return [...values].map(([k,v])=>k+':'+v.value+(v.priority?'!'+v.priority:'')).join(';');},set cssText(text){values.clear();for(const row of text.split(';')){const i=row.indexOf(':');if(i<0)continue;const [value,priority]=row.slice(i+1).split('!');values.set(row.slice(0,i),{value,priority:priority||''});}}};}
 class Element{constructor(fact={}){this.fact=fact;this.tagName=fact.tag||'DIV';this.style=style();this.dataset={};this.children=[];this.childNodes=fact.text?[{nodeType:3,nodeValue:fact.text}]:[];}getAttributeNames(){return Object.keys(this.fact.attributes||{});}getAttribute(name){return this.fact.attributes?.[name]||'';}removeAttribute(name){delete this.fact.attributes?.[name];}append(){}replaceChildren(){this.replaced=true;}attachShadow(){return {};}}
 const html=new Element({tag:'HTML'}),body=new Element({tag:'BODY'}),nodes=[html,body,...extra.map(row=>new Element(row))];
 const document={readyState:'complete',body,documentElement:html,querySelectorAll:()=>nodes,createElement:tag=>{const node=new Element({tag:tag.toUpperCase()});created.push(node);return node;},addEventListener:(name,fn)=>{listeners[name]=fn;}};
 const page={context:()=>c};
 const sandbox={document,Element,getComputedStyle:(node,pseudo)=>({backgroundImage:pseudo==='::before'?node.fact.beforeBackgroundImage||'none':pseudo==='::after'?node.fact.afterBackgroundImage||'none':node.fact.backgroundImage||'none',content:pseudo==='::before'?node.fact.beforeContent||'none':node.fact.afterContent||'none'}),MutationObserver:class{constructor(fn){this.fn=fn;observers.push(this);}observe(){}disconnect(){}},requestAnimationFrame:()=>{},performance:{now:()=>42},__martyPrivateReviewSurfaceEvent:event=>{surface.push(event);c.surface({page},event);return Promise.resolve();},__martyPrivateReviewPointerEvent:event=>{sent.push(event);return Promise.resolve();}};
 vm.runInNewContext(c.init.content,sandbox);
 return {listeners,sent,surface,html,nodes,created,mutate(index,patch){const node=nodes[index];Object.assign(node.fact,patch);if(patch.text!==undefined)node.childNodes=[{nodeType:3,nodeValue:patch.text}];observers[0].fn([{target:node,type:'attributes',attributeName:'title'}]);},shadow(){nodes[1].attachShadow({mode:'closed'});}};
}
test('owned automated-input disclosure overrides both important veil text properties',async t=>{
 const root=temp(t),capture=createPrivateReviewRecording(binding(root),{artifactDir:path.join(root,'artifacts')}),c=context();await capture.prepareContext(c,'wallet');const page=pageHarness(c);
 const veil=page.created.find(node=>node.tagName==='STYLE');assert(veil.textContent.includes('color:transparent!important'));assert(veil.textContent.includes('-webkit-text-fill-color:transparent!important'));
 const disclosure=page.created.find(node=>node.textContent?.includes('Automated browser input'));assert(disclosure);
 // These actual source-applied inline-important declarations outrank the
 // universal author-important veil; this is a controlled cascade check only.
 for(const key of ['color','-webkit-text-fill-color']){assert.equal(disclosure.style.getPropertyValue(key),'#fff');assert.equal(disclosure.style.getPropertyPriority(key),'important');}
 assert.equal(disclosure.style.getPropertyPriority('font'),'important');assert.equal(disclosure.style.getPropertyValue('visibility'),'visible');assert.equal(disclosure.style.getPropertyValue('opacity'),'1');
});
test('default without owned capability creates no recording helper or media',()=>{assert.equal(createPrivateReviewRecording(null,{artifactDir:'unused'}),null);});
test('private media directory cannot overlap functional artifacts',t=>{const root=temp(t),b=binding(root);assert.throws(()=>createPrivateReviewRecording({...b,mediaDirectory:path.join(root,'artifacts')},{artifactDir:path.join(root,'artifacts')}));assert.throws(()=>createPrivateReviewRecording({...b,publicationEligible:true},{artifactDir:path.join(root,'artifacts')}));});
test('labels-only policy precedes pages, masks fields independently of body visibility and rejects synthetic pointer events',async t=>{
 const root=temp(t),capture=createPrivateReviewRecording(binding(root),{artifactDir:path.join(root,'artifacts')}),c=context();await capture.prepareContext(c,'wallet');
 const page=pageHarness(c,{extra:[{tag:'INPUT',text:'secret nonce'},{tag:'DIV',text:'private@example.invalid'},{tag:'BUTTON',text:'Approve'}]});
 assert.equal(page.nodes[2].style.getPropertyValue('opacity'),'0');assert.equal(page.nodes[3].style.getPropertyValue('color'),'transparent');assert.equal(page.nodes[4].style.getPropertyValue('color'),'#f8fafc');
 page.mutate(1,{attributes:{style:'visibility:visible'}});assert.equal(page.nodes[2].style.getPropertyValue('opacity'),'0');assert.equal(page.nodes[3].style.getPropertyValue('color'),'transparent');
 page.listeners.pointerdown({isTrusted:false,clientX:1,clientY:2,button:0});assert.equal(page.sent.length,0);
 page.listeners.pointerdown({isTrusted:true,clientX:10,clientY:20,button:0});assert.equal(page.sent.length,1);assert.equal(page.sent[0].trusted,true);
 const late=context();late.addPage('wallet','unused');await assert.rejects(capture.prepareContext(late,'wallet'),/precede pages/);
});
for(const [fault,patch]of Object.entries({secretText:{text:'new arbitrary protocol state nonce'},secretAttribute:{attributes:{title:'SECRET_TOKEN'}},dataAttribute:{attributes:{'data-state':'unbounded-state'}},iframe:{tag:'IFRAME'},background:{backgroundImage:'url(https://private.invalid/SECRET)'},pseudo:{beforeContent:'"SECRET"'},pseudoBeforeBackground:{beforeContent:'""',beforeBackgroundImage:'url(secret)'},pseudoAfterBackground:{afterContent:'""',afterBackgroundImage:'url(secret)'},shadow:{shadow:true}}))test('finite visible-surface policy rejects '+fault,()=>{
 assert(privateReviewSurfaceDecision({tag:'DIV',leaf:true,dynamic:true,...patch}).blocked);
});
for(const fault of ['late-text','late-attribute','late-background','pseudo-background','closed-shadow','iframe'])test('browser guard blanks and records a failed policy for '+fault,async t=>{
 const root=temp(t),capture=createPrivateReviewRecording(binding(root),{artifactDir:path.join(root,'artifacts')}),c=context();await capture.prepareContext(c,'wallet');const page=pageHarness(c,{extra:[{tag:'BUTTON',text:'Approve'}]});
 if(fault==='closed-shadow')page.shadow();else page.mutate(2,fault==='late-text'?{text:'SECRET'}:fault==='late-attribute'?{attributes:{title:'SECRET'}}:fault==='late-background'?{backgroundImage:'url(secret)'}:fault==='pseudo-background'?{beforeContent:'""',beforeBackgroundImage:'url(secret)'}:{tag:'IFRAME'});
 // Tag mutation uses the same actual element tag in the DOM model.
 if(fault==='iframe'){page.nodes[2].tagName='IFRAME';page.mutate(2,{});}
 assert(page.surface.some(event=>event.state==='BLOCKED'));assert.equal(page.html.style.getPropertyValue('display'),'none');assert(page.html.replaced);
});
for(const fault of ['failed-functional','failed-cleanup','outside-sink','missing-click','policy-blocked','policy-missing','none'])test('private finalization refuses unsafe boundary: '+fault,async t=>{
 const root=temp(t),b=binding(root),capture=createPrivateReviewRecording(b,{artifactDir:path.join(root,'artifacts')}),w=context(),l=context();await capture.prepareContext(w,'wallet');await capture.prepareContext(l,'login');
 const video=(name)=>{const f=path.join(root,'media',name+'.webm');fs.writeFileSync(f,'SYNTHETIC DUMMY BYTES NOT A VIDEO');return f;};
 const wp=w.addPage('wallet',fault==='outside-sink'?path.join(root,'foreign.webm'):video('wallet')),lp=l.addPage('login',video('login'));capture.trackPage('wallet',wp);capture.trackPage('login',lp);
 if(fault!=='missing-click')w.transport({page:wp},{role:'wallet',kind:'pointerdown',trusted:true,x:10,y:20,button:0,elapsedMs:42});
 w.surface({page:wp},{role:'wallet',state:'POLICY_ACTIVE',code:null});if(fault!=='policy-missing')l.surface({page:lp},{role:'login',state:'POLICY_ACTIVE',code:null});if(fault==='policy-blocked')l.surface({page:lp},{role:'login',state:'BLOCKED',code:'UNSUPPORTED_OPAQUE_SURFACE'});
 const finish=()=>capture.finish({ready:fault!=='failed-functional',cleanupComplete:fault!=='failed-cleanup'});
 if(fault!=='none'){await assert.rejects(finish);assert(!fs.existsSync(path.join(root,'media/cursor-evidence.json')));return;}
 const result=await finish();assert.equal(result.scope,'PRIVATE_REVIEW_ONLY');assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);assert.equal(result.publicationEligible,false);assert.equal(result.cursorTelemetry,'ACTUAL_TRUSTED_DOM_POINTER_EVENTS_NOT_OS');assert.equal(result.visibleSurfacePolicy,'FAIL_CLOSED_SAFE_UI_LABELS_ONLY');assert.equal(result.renderedPrivacyQualified,false);assert(!Object.hasOwn(result,'redactionAppliedBeforePages'));assert(!Object.hasOwn(result,'realUiCaptured'));assert.equal(Object.keys(result.rawMedia).length,2);assert(fs.readdirSync(path.join(root,'artifacts')).length===0);
});
function bridge({fault,ack=true}={}){
 const filename=path.join(__dirname,'demo-live-evidence.js'),real=createRequire(filename),base=path.join(os.homedir(),'.codex/private/private-review-bridge'),helper=path.join(base,'helper.js'),receipt=path.join(base,'functional-runtime.json'),bytes=Buffer.from('CONTROLLED SOURCE');
 const runtime={kind:'FUNCTIONAL_RUNTIME_V2',profileSha256:'a'.repeat(64),receiptSha256:'b'.repeat(64),scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
 runtime.ob3Readiness={readinessScope:'OB3_FUNCTIONAL_ONLY',fullStackQualified:false};runtime.ob3Configuration={path:path.join(base,'membership-badge-login.json'),sha256:'d'.repeat(64),bytes:20};
 const wallet={instanceId:'WALLET',origin:'http://127.0.0.1:8787'};
 const capability={configuration:runtime.ob3Configuration,scope:'PRIVATE_REVIEW_ONLY',runId:'RUN',scenario:'membership-badge-login',supportingLane:null,runtimeProfileSha256:runtime.profileSha256,runtimeReceiptSha256:runtime.receiptSha256,walletInstanceId:wallet.instanceId,priorFunctionalReport:{path:path.join(base,'prior.json'),sha256:hash(bytes),bytes:bytes.length}};
 if(fault==='configuration')capability.configuration={...runtime.ob3Configuration,sha256:'f'.repeat(64)};if(fault==='full-runtime')runtime.ob3Readiness.fullStackQualified=true;
 if(fault==='wallet')capability.walletInstanceId='FOREIGN';if(fault==='runtime')capability.runtimeReceiptSha256='f'.repeat(64);if(fault==='run')capability.runId='FOREIGN';if(fault==='prior-hash')capability.priorFunctionalReport.sha256='f'.repeat(64);
 const environment={RECORD_VIDEO:fault==='record-video'?'1':'0',DEMO_EXECUTION_EVIDENCE_RUN_ID:'RUN',DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT:receipt,DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256:runtime.receiptSha256,DEMO_EXECUTION_EVIDENCE_HELPER:helper,DEMO_EXECUTION_EVIDENCE_HELPER_SHA256:hash(bytes),DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT:'CONTROL',DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256:'CONTROL',DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_INPUT:'CONTROL',DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256:'CONTROL',MARTY_TEST_WALLET_ORIGIN:wallet.origin};
 const protocol={validateFunctionalRuntimeContext:()=>runtime,functionalRuntimeContext:()=>runtime,validatePrivateReviewCaptureContext:value=>{if(fault==='recorder-refusal')throw Error('RECORDER_REFUSED');return value;}};
 const mocks={lstatSync:()=>({isSymbolicLink:()=>false}),statSync:()=>({isFile:()=>true,size:bytes.length}),readFileSync:()=>bytes};
 const requireBoundary=name=>name==='node:fs'?mocks:path.basename(name)==='externalLiveEvidence.js'?protocol:path.basename(name)==='canvasNativeRuntime.js'?{loadFunctionalRuntimeObservation:()=>({})}:path.basename(name)==='ownedWalletRuntime.js'?{loadOwnedWalletRuntime:()=>({context:wallet}),ownedWalletAuthority:()=>({}),validateOwnedWalletContext:()=>wallet}:real(name),m={exports:{}};
 vm.runInThisContext('(function(require,module,exports,__filename,__dirname){'+fs.readFileSync(filename,'utf8')+'\n})',{filename})(requireBoundary,m,m.exports,filename,__dirname);
 return {api:m.exports,environment,capability,client:{functionalRuntimeBinding:runtime,ownedWalletBinding:wallet,...(ack?{privateReviewCaptureBinding:capability}:{})}};
}
for(const fault of ['none','wallet','runtime','run','prior-hash','record-video','recorder-refusal','lane','configuration','full-runtime'])test('owned private capability binding boundary: '+fault,()=>{
 const b=bridge({fault}),args={scenario:'membership-badge-login',supportingLane:fault==='lane'?'expired-offer':null};
 if(fault==='none')assert.equal(b.api.privateReviewCaptureContext(b.client,args,b.environment),b.capability);
 else assert.throws(()=>b.api.privateReviewCaptureContext(b.client,args,b.environment));
});
test('environment alone cannot enable private review capture',()=>{const b=bridge({ack:false});b.environment.DEMO_PRIVATE_REVIEW_CAPTURE='PRIVATE_REVIEW_ONLY';assert.equal(b.api.privateReviewCaptureContext(b.client,{scenario:'membership-badge-login'},b.environment),null);});

// Synthetic delivery/bytes only; these controls do not align a video clock.
test('private cursor evidence retains each exact captured source role without video-frame qualification',async t=>{
 const root=temp(t),capture=createPrivateReviewRecording(binding(root),{artifactDir:path.join(root,'artifacts')}),contexts={};
 for(const role of ['wallet','login']){
  const c=context();contexts[role]=c;await capture.prepareContext(c,role);
  const file=path.join(root,'media',role+'.webm');fs.writeFileSync(file,'SYNTHETIC DUMMY NOT VIDEO');const page=c.addPage(role,file);capture.trackPage(role,page);
  c.surface({page},{role,state:'POLICY_ACTIVE',code:null});c.transport({page},{role,kind:'pointerdown',trusted:true,x:10,y:20,button:0,elapsedMs:42});
 }
 const report=await capture.finish({ready:true,cleanupComplete:true}),cursor=JSON.parse(fs.readFileSync(report.cursorEvidence.path));
 assert.deepEqual(cursor.events.map(event=>event.role),['wallet','login']);assert(cursor.events.every(event=>Object.hasOwn(report.rawMedia,event.role)));assert.equal(cursor.telemetry,'ACTUAL_TRUSTED_DOM_POINTER_EVENTS_NOT_OS');assert.equal(report.renderedPrivacyQualified,false);assert.equal(report.recordingQualified,false);
});
test('private cursor refuses prepared but uncaptured source role instead of misassigning its coordinates',async t=>{
 const root=temp(t),capture=createPrivateReviewRecording(binding(root),{artifactDir:path.join(root,'artifacts')});
 for(const role of ['wallet','login','operator']){
  const c=context();await capture.prepareContext(c,role);const file=path.join(root,'media',role+'.webm');if(role!=='operator')fs.writeFileSync(file,'SYNTHETIC DUMMY NOT VIDEO');const page=c.addPage(role,file);if(role!=='operator')capture.trackPage(role,page);
  c.surface({page},{role,state:'POLICY_ACTIVE',code:null});c.transport({page},{role,kind:'pointerdown',trusted:true,x:10,y:20,button:0,elapsedMs:42});
 }
 await assert.rejects(capture.finish({ready:true,cleanupComplete:true}),/actual captured video/);assert(!fs.existsSync(path.join(root,'media/cursor-evidence.json')));
});
