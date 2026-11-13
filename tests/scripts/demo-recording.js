const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const VIDEO_SIZE = Object.freeze({ width: 1920, height: 1080 });

// These are driver landmarks, not video timestamps or captured OS mouse events.
// Editors must bind every crop and added cursor to the actual source frames.
function createActionRecording({
  enabled = false,
  scenario,
  eyebrow = 'Synthetic business scenario - ElevenID admin portal',
  pageName = 'application',
  now = () => performance.now(),
  onEvent = () => {},
} = {}) {
  if (!scenario || typeof scenario !== 'string') throw new TypeError('Recording scenario is required');
  const origin = now();
  const evidence = {
    schemaVersion: 1,
    scenario,
    pageName,
    clock: 'MONOTONIC_DRIVER_ELAPSED_FROM_PAGE_READY',
    videoFrameAlignmentEstablished: false,
    editorMustAlignToSourceFrames: true,
    pointerTimingBasis: 'DRIVER_LANDMARKS_NOT_OS_CLICK_TELEMETRY',
    events: [],
  };
  const recording = {
    enabled,
    evidence,
    events: evidence.events,
    mark(action, phase, detail = {}) {
      if (!enabled) return;
      evidence.events.push({
        ...detail,
        action,
        phase,
        elapsedSeconds: (now() - origin) / 1000,
        observedAt: new Date().toISOString(),
      });
      onEvent(evidence);
    },
    async hold(page, locator, milliseconds = 2200, { action = 'inspect', phase = 'control' } = {}) {
      // Functional runs still require the real target. Only editorial dwell is optional.
      await locator.waitFor({ state: 'visible', timeout: 30000 });
      await locator.scrollIntoViewIfNeeded();
      if (!enabled) return;
      const bounds = typeof locator.boundingBox === 'function' ? await locator.boundingBox() : null;
      recording.mark(action, `${phase}-visible`, bounds ? { bounds } : {});
      await page.waitForTimeout(milliseconds);
      recording.mark(action, `${phase}-hold-end`);
    },
    async click(page, locator, { action, phase = 'control', durationMs = 2200 } = {}) {
      if (!action) throw new TypeError('Recording action is required');
      await recording.hold(page, locator, durationMs, { action, phase });
      // Bounds are measured again after the hold in case layout changed.
      const bounds = enabled && typeof locator.boundingBox === 'function' ? await locator.boundingBox() : null;
      recording.mark(action, `${phase}-click-dispatched`, bounds ? { bounds } : {});
      await locator.click();
      recording.mark(action, `${phase}-click-completed`);
    },
    async explain(page, action, reason, { title = `Admin action: ${action}`, durationMs = 3200 } = {}) {
      if (!enabled) return;
      recording.mark(action, 'scenario-context', { reason });
      await showStep(page, title, reason, { enabled, eyebrow, durationMs });
    },
  };
  return recording;
}

function createArtifactDir(root, defaultName, env = process.env) {
  const configured = String(env.DEMO_ARTIFACT_DIR || '').trim();
  const artifactDir = configured
    ? path.resolve(configured)
    : path.join(root, 'tests', 'artifacts', defaultName);
  fs.mkdirSync(artifactDir, { recursive: true });
  return artifactDir;
}

async function showStep(page, title, detail, options = {}) {
  if (!options.enabled) return;
  await page.evaluate(({ title: headingText, detail: detailText, eyebrowText }) => {
    document.getElementById('elevenid-recording-step')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'elevenid-recording-step';
    Object.assign(overlay.style, {
      position: 'fixed',
      zIndex: '2147483647',
      left: '32px',
      bottom: '132px',
      width: 'min(620px, calc(100vw - 64px))',
      padding: '18px 22px',
      borderRadius: '6px',
      background: 'rgba(17, 24, 39, 0.97)',
      color: '#f8fafc',
      boxShadow: '0 18px 48px rgba(0, 0, 0, 0.34)',
      fontFamily: 'Arial, sans-serif',
      pointerEvents: 'none',
    });
    const eyebrow = document.createElement('div');
    eyebrow.textContent = eyebrowText;
    Object.assign(eyebrow.style, { fontSize: '13px', fontWeight: '700', color: '#7dd3fc', textTransform: 'uppercase' });
    const heading = document.createElement('div');
    heading.textContent = headingText;
    Object.assign(heading.style, { marginTop: '6px', fontSize: '26px', fontWeight: '700', lineHeight: '1.2' });
    const copy = document.createElement('div');
    copy.textContent = detailText;
    Object.assign(copy.style, { marginTop: '8px', fontSize: '16px', lineHeight: '1.45', color: '#e2e8f0' });
    overlay.append(eyebrow, heading, copy);
    document.body.appendChild(overlay);
  }, {
    title,
    detail,
    eyebrowText: options.eyebrow || 'ElevenID LLC Credential Platform v2026.07.0',
  });
  await page.waitForTimeout(options.durationMs || 2200);
  await page.evaluate(() => document.getElementById('elevenid-recording-step')?.remove()).catch(() => {});
}

function buildVerificationDisplay(result, options = {}) {
  const actor = String(options.actor || '').trim();
  const testId = String(options.testId || '').trim().toUpperCase();
  const evaluatedState = String(options.evaluatedState || '').trim().toUpperCase();
  const comparison = String(options.comparison || '').trim();
  if (!actor) throw new TypeError('Verification display actor is required');
  if (!/^[A-Z0-9-]{6,48}$/.test(testId)) {
    throw new TypeError('Verification display testId must be a stable presentation-safe identifier');
  }

  const normalizedDecision = String(result?.decision || result?.evaluation || '').trim().toLowerCase();
  const decision = normalizedDecision === 'allow' || normalizedDecision === 'allowed'
    ? 'ALLOWED'
    : normalizedDecision === 'deny' || normalizedDecision === 'denied'
      ? 'DENIED'
      : 'UNRESOLVED';
  const reason = String(result?.decisionReason || '').trim()
    || (decision === 'ALLOWED'
      ? 'Policy evaluation completed without a denial reason.'
      : 'No machine decision reason was returned.');

  if (evaluatedState && !/^[A-Z][A-Z0-9_-]{1,31}$/.test(evaluatedState)) {
    throw new TypeError('Verification display evaluatedState must be presentation-safe');
  }

  return Object.freeze({ actor, testId, decision, reason, evaluatedState, comparison });
}

async function showVerificationResult(page, result, options = {}) {
  if (!options.enabled) return;
  const display = buildVerificationDisplay(result, options);
  await page.evaluate((model) => {
    document.getElementById('elevenid-verification-result')?.remove();
    const overlay = document.createElement('section');
    overlay.id = 'elevenid-verification-result';
    overlay.setAttribute('aria-label', 'Verification result');
    Object.assign(overlay.style, {
      position: 'fixed',
      zIndex: '2147483647',
      right: '48px',
      top: '170px',
      width: 'min(780px, calc(100vw - 96px))',
      padding: '28px 32px',
      borderRadius: '10px',
      border: '1px solid rgba(148, 163, 184, 0.55)',
      borderLeft: `10px solid ${model.decision === 'ALLOWED' ? '#22c55e' : model.decision === 'DENIED' ? '#f97316' : '#94a3b8'}`,
      background: 'rgba(15, 23, 42, 0.98)',
      color: '#f8fafc',
      boxShadow: '0 24px 64px rgba(0, 0, 0, 0.40)',
      fontFamily: 'Arial, sans-serif',
      pointerEvents: 'none',
    });
    const eyebrow = document.createElement('div');
    eyebrow.textContent = 'TEST EVIDENCE - STATUS-AWARE VERIFICATION';
    Object.assign(eyebrow.style, {
      fontSize: '14px',
      fontWeight: '700',
      letterSpacing: '0.08em',
      color: '#bae6fd',
    });
    const decision = document.createElement('div');
    decision.textContent = model.decision;
    Object.assign(decision.style, {
      marginTop: '10px',
      fontSize: '48px',
      fontWeight: '800',
      lineHeight: '1',
      color: model.decision === 'ALLOWED' ? '#86efac' : model.decision === 'DENIED' ? '#fdba74' : '#cbd5e1',
    });
    const reason = document.createElement('div');
    reason.textContent = model.reason;
    Object.assign(reason.style, { marginTop: '16px', fontSize: '24px', lineHeight: '1.35', color: '#f1f5f9' });
    const context = document.createElement('div');
    context.textContent = [
      model.evaluatedState ? `Evaluated lifecycle state: ${model.evaluatedState}` : '',
      model.comparison,
    ].filter(Boolean).join(' | ');
    Object.assign(context.style, {
      marginTop: '14px',
      padding: '12px 14px',
      borderRadius: '6px',
      background: 'rgba(30, 41, 59, 0.95)',
      fontSize: '19px',
      fontWeight: '700',
      color: '#e0f2fe',
    });
    const metadata = document.createElement('div');
    Object.assign(metadata.style, {
      display: 'grid',
      gridTemplateColumns: '110px 1fr',
      gap: '8px 16px',
      marginTop: '24px',
      paddingTop: '18px',
      borderTop: '1px solid rgba(148, 163, 184, 0.35)',
      fontSize: '18px',
    });
    for (const [label, value] of [['Actor', model.actor], ['Test ID', model.testId]]) {
      const key = document.createElement('strong');
      key.textContent = label;
      key.style.color = '#94a3b8';
      const content = document.createElement('span');
      content.textContent = value;
      content.style.fontFamily = label === 'Test ID' ? 'monospace' : 'Arial, sans-serif';
      metadata.append(key, content);
    }
    overlay.append(eyebrow, decision, reason);
    if (context.textContent) overlay.append(context);
    overlay.append(metadata);
    document.body.appendChild(overlay);
  }, display);
  await page.waitForTimeout(options.durationMs || 3000);
  await page.evaluate(() => document.getElementById('elevenid-verification-result')?.remove()).catch(() => {});
}

async function maskProtocolField(page, label, enabled) {
  if (!enabled) return;
  await page.getByLabel(label).evaluate((element) => {
    element.style.color = 'transparent';
    element.style.caretColor = 'transparent';
    element.style.textShadow = '0 0 10px #64748b';
  });
}

async function finalizeVideo(video, artifactDir, filename) {
  if (!video) return null;
  const rawPath = await video.path();
  const finalPath = path.join(artifactDir, filename);
  fs.rmSync(finalPath, { force: true });
  await video.saveAs(finalPath);
  if (path.resolve(rawPath) !== path.resolve(finalPath)) fs.rmSync(rawPath, { force: true });
  return finalPath;
}

// One finite source policy, reused by the browser init owner and pure controls.
// Unknown labels are withheld initially; unsupported/dynamic surfaces fail closed.
function privateReviewSurfaceDecision(fact) {
  const labels=new Set(['Receive','Present','Approve','Cancel','Sign in','Sign In','Login','Continue','Email','Password','Credential offer URI','Presentation request URI','Credentials','Request','Membership badge','Marty Verified Member','Marty Verified Member Open Badge','Sign out','Log out','Create account','Use a credential','Sign in with a credential','Credential login','Try again','Back','Submit','Next','Select organization','Organizations','Applications','Dashboard','Account','Profile','Allow','Deny','Retry']);
  const text=String(fact.text||'').trim(),tag=String(fact.tag||'').toUpperCase();
  if(fact.shadow||tag.includes('-'))return {blocked:'UNSUPPORTED_SHADOW_OR_CUSTOM_ELEMENT'};
  if(['IFRAME','FRAME','OBJECT','EMBED','CANVAS','SVG','IMG','VIDEO','AUDIO','MATH'].includes(tag))return {blocked:'UNSUPPORTED_OPAQUE_SURFACE'};
  if(fact.backgroundImage&&fact.backgroundImage!=='none')return {blocked:'UNSUPPORTED_BACKGROUND'};
  if([fact.beforeBackgroundImage,fact.afterBackgroundImage].some(value=>value&&value!=='none'))return {blocked:'UNSUPPORTED_PSEUDO_BACKGROUND'};
  if([fact.beforeContent,fact.afterContent].some(value=>value&&!['none','normal','""',"''"].includes(value)))return {blocked:'UNSUPPORTED_PSEUDO_CONTENT'};
  for(const [name,value]of Object.entries(fact.attributes||{})){
    if(!value)continue;
    if(['title','alt','placeholder','aria-label','aria-description','aria-valuetext'].includes(name)&&!labels.has(value))return {blocked:'UNSAFE_VALUE_ATTRIBUTE'};
    if(name.startsWith('data-')&&!['true','false'].includes(value))return {blocked:'UNSUPPORTED_DATA_ATTRIBUTE'};
    if(name==='srcdoc'||name==='style'&&/url\s*\(|attr\s*\(/i.test(value))return {blocked:'UNSUPPORTED_ATTRIBUTE_CONTENT'};
  }
  if(fact.dynamic&&text&&!labels.has(text))return {blocked:'DYNAMIC_UNKNOWN_TEXT'};
  return {blocked:null,showLabel:Boolean(text&&labels.has(text)&&fact.leaf&&!['INPUT','TEXTAREA','SELECT'].includes(tag)),hideValue:['INPUT','TEXTAREA','SELECT'].includes(tag)};
}

function installPrivateReviewPage({role},decide) {
  let active=false,blocked=false,checking=false;const owned=new WeakSet(),ownedStyles=new WeakMap(),priorText=new WeakMap();
  const emit=value=>globalThis.__martyPrivateReviewSurfaceEvent({role,...value}).catch(()=>{});
  const stop=code=>{
    if(blocked)return;blocked=true;
    // Unsupported content is removed synchronously; this is a FAILED rerun,
    // never substituted functional UI or a claim that raw pixels were qualified.
    const root=document.documentElement;if(root){root.replaceChildren();for(const name of root.getAttributeNames())root.removeAttribute(name);root.style.cssText='display:none!important;opacity:0!important;background:#000!important;color:transparent!important';}
    emit({state:'BLOCKED',code});
  };
  const set=(node,key,value)=>{if(node.style.getPropertyValue(key)!==value||node.style.getPropertyPriority(key)!=='important')node.style.setProperty(key,value,'important');};
  const scan=dynamic=>{
    if(blocked){const root=document.documentElement;if(root&&(root.style.getPropertyValue('display')!=='none'||root.style.getPropertyPriority('display')!=='important'))root.style.setProperty('display','none','important');return;}
    if(checking||!document.documentElement)return;checking=true;
    try{
      const nodes=[...document.querySelectorAll('*')];if(nodes.length>5000){stop('SURFACE_BOUND_EXCEEDED');return;}
      for(const node of nodes){
        if(owned.has(node)||['SCRIPT','STYLE','LINK','META','HEAD','TITLE'].includes(node.tagName))continue;
        const style=getComputedStyle(node),direct=[...node.childNodes].filter(child=>child.nodeType===3).map(child=>child.nodeValue||'').join('').trim();
        const fact={tag:node.tagName,shadow:Boolean(node.shadowRoot),text:direct,leaf:node.children.length===0,dynamic:dynamic&&direct!==priorText.get(node),attributes:Object.fromEntries(node.getAttributeNames().filter(name=>name!=='style'||node.style.cssText!==ownedStyles.get(node)).map(name=>[name,node.getAttribute(name)])),backgroundImage:style.backgroundImage,beforeContent:getComputedStyle(node,'::before').content,afterContent:getComputedStyle(node,'::after').content,beforeBackgroundImage:getComputedStyle(node,'::before').backgroundImage,afterBackgroundImage:getComputedStyle(node,'::after').backgroundImage};
        const decision=decide(fact);if(decision.blocked){stop(decision.blocked);return;}priorText.set(node,direct);
        for(const [key,value]of [['color',decision.showLabel?'#f8fafc':'transparent'],['-webkit-text-fill-color',decision.showLabel?'#f8fafc':'transparent'],['text-shadow','none'],['background-image','none'],['animation','none'],['transition','none']])set(node,key,value);
        if(decision.hideValue)set(node,'opacity','0');
        ownedStyles.set(node,node.style.cssText);
      }
      if(!active&&document.body&&document.readyState!=='loading'){
        active=true;const disclosure=document.createElement('div');owned.add(disclosure);disclosure.textContent='PRIVATE REVIEW ? Safe UI labels only ? Automated browser input ? Render privacy qualification pending';
        disclosure.style.cssText='position:fixed;left:12px;top:8px;z-index:2147483647;background:#0f172a;padding:6px;pointer-events:none';
        // Owned disclosure must override the universal veil, including its
        // text-fill property; ordinary inline color loses to !important.
        for(const [key,value]of [['color','#fff'],['-webkit-text-fill-color','#fff'],['font','12px Arial,sans-serif'],['line-height','1.4'],['visibility','visible'],['opacity','1']])set(disclosure,key,value);
        document.body.append(disclosure);
        const pointer=document.createElement('div');owned.add(pointer);pointer.style.cssText='position:fixed;display:none;width:14px;height:14px;border:2px solid #f59e0b;border-radius:50%;z-index:2147483647;pointer-events:none;transform:translate(-50%,-50%)';document.body.append(pointer);
        for(const kind of ['pointermove','pointerdown','pointerup'])document.addEventListener(kind,event=>{if(blocked||event.isTrusted!==true)return;pointer.style.display='block';pointer.style.left=event.clientX+'px';pointer.style.top=event.clientY+'px';globalThis.__martyPrivateReviewPointerEvent({role,kind,trusted:true,x:event.clientX,y:event.clientY,button:event.button,elapsedMs:performance.now()}).catch(()=>{});},true);
        emit({state:'POLICY_ACTIVE',code:null});
      }
    }catch{stop('UNINSPECTABLE_SURFACE');}finally{checking=false;}
  };
  // Closed shadow creation is caught before content can enter it. Frames and
  // other opaque surfaces are denied by the same finite policy, not inspected.
  const attach=Element.prototype.attachShadow;Element.prototype.attachShadow=function(...args){stop('UNSUPPORTED_SHADOW_OR_CUSTOM_ELEMENT');return Reflect.apply(attach,this,args);};
  const observer=new MutationObserver(records=>{
    const external=records.some(row=>!owned.has(row.target)&&!(row.type==='attributes'&&row.attributeName==='style'&&row.target.style.cssText===ownedStyles.get(row.target)));
    if(external)scan(active);
  });observer.observe(document,{childList:true,subtree:true,characterData:true,attributes:true});
  document.addEventListener('DOMContentLoaded',()=>scan(false),true);document.addEventListener('load',()=>scan(active),true);document.addEventListener('input',()=>scan(active),true);document.addEventListener('change',()=>scan(active),true);
  const tick=()=>{scan(active);if(!blocked)requestAnimationFrame(tick);};
  // Apply the value/unknown-text veil at document start independently of body
  // visibility. A body style override cannot expose leaf values or unknown text.
  const veil=()=>{if(!document.documentElement)return;const style=document.createElement('style');owned.add(style);style.textContent='*{color:transparent!important;-webkit-text-fill-color:transparent!important;text-shadow:none!important}input,textarea,select{opacity:0!important}';document.documentElement.append(style);scan(false);};
  if(document.documentElement)veil();else new MutationObserver((_records,o)=>{if(document.documentElement){o.disconnect();veil();}}).observe(document,{childList:true});
  requestAnimationFrame(tick);
}

function createPrivateReviewRecording(binding,{artifactDir}={}) {
  if(!binding)return null;
  assert.equal(binding.scope,'PRIVATE_REVIEW_ONLY');assert.equal(binding.scenario,'membership-badge-login');
  for(const key of ['releaseQualified','recordingQualified','publicationEligible'])assert.equal(binding[key],false);
  const directory=path.resolve(binding.mediaDirectory);assert.equal(directory,binding.mediaDirectory);
  assert(fs.statSync(directory).isDirectory());assert.equal(fs.realpathSync(directory),directory);
  let current=path.parse(directory).root;
  for(const part of directory.slice(current.length).split(/[\\/]/)){if(!part)continue;current=path.join(current,part);assert(!fs.lstatSync(current).isSymbolicLink());}
  const within=(parent,child)=>{const relative=path.relative(parent,child);return relative===''||relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);};
  assert(!within(path.resolve(artifactDir),directory)&&!within(directory,path.resolve(artifactDir)),'Private media and functional artifacts must be disjoint');
  const contexts=new Map(),videos=new Map(),events=[],surfaceEvents=[],activeRoles=new Set(),pointerOrigin=performance.now();let finalized=false,eventOverflow=false,surfaceFailure=false;
  return {
    contextOptions:{viewport:VIDEO_SIZE,recordVideo:{dir:directory,size:VIDEO_SIZE}},
    async prepareContext(context,role,{sensitiveTexts=[]}={}){
      assert(['wallet','login','operator','applicant'].includes(role));assert(!contexts.has(context));assert.equal(context.pages().length,0,'Redaction must precede pages');contexts.set(context,role);
      await context.exposeBinding('__martyPrivateReviewPointerEvent',({page},event)=>{
        assert.equal(page.context(),context);assert.equal(event.role,role);assert.equal(event.trusted,true);
        assert.deepEqual(Object.keys(event).sort(),['role','kind','trusted','x','y','button','elapsedMs'].sort());assert(['pointermove','pointerdown','pointerup'].includes(event.kind));
        for(const key of ['x','y','button','elapsedMs'])assert(Number.isFinite(event[key]));assert(event.x>=0&&event.y>=0&&event.elapsedMs>=0);if(events.length>=4096){eventOverflow=true;return;}
        // Driver-received monotonic elapsed time, not video-frame or OS timing.
        events.push({type:event.kind,x:event.x,y:event.y,at:performance.now()-pointerOrigin});
      });
      await context.exposeBinding('__martyPrivateReviewSurfaceEvent',({page},event)=>{
        try{assert.equal(page.context(),context);assert.equal(event.role,role);assert.deepEqual(Object.keys(event).sort(),['role','state','code'].sort());assert(['POLICY_ACTIVE','BLOCKED'].includes(event.state));assert(event.code===null||/^[A-Z_]{1,64}$/.test(event.code));assert(surfaceEvents.length<256);surfaceEvents.push({...event});if(event.state==='POLICY_ACTIVE')activeRoles.add(role);}
        catch(error){surfaceFailure=true;throw error;}
      });
      // The same pure policy body is injected, without a second implementation.
      await context.addInitScript({content:'('+installPrivateReviewPage.toString()+')('+JSON.stringify({role})+','+privateReviewSurfaceDecision.toString()+');'});
    },
    trackPage(role,page){assert.equal(contexts.get(page.context()),role);assert(!videos.has(role),'One captured page per role');const video=page.video();assert(video,'Private captured video required');videos.set(role,video);},
    async finish({ready,cleanupComplete}){
      assert(!finalized);assert(!surfaceFailure,'Private surface evidence invalid or overflowed');assert(!surfaceEvents.some(event=>event.state==='BLOCKED'),'Private visible-surface policy refused');assert([...videos.keys()].every(role=>activeRoles.has(role)),'Each page requires an active visible-surface policy');assert(!eventOverflow,'Private cursor evidence bound exceeded');assert.equal(ready,true,'Current functional rerun must pass');assert.equal(cleanupComplete,true,'Owned cleanup must pass');assert(videos.has('wallet')&&videos.has('login'));assert(events.some(event=>event.type==='pointerdown'),'Actual delivered browser clicks required');
      const rawMedia={},seenMedia=new Set();
      for(const [role,video]of videos){
        const filename=path.resolve(await video.path());assert.equal(path.dirname(filename),directory);assert(!seenMedia.has(filename),'Captured roles require distinct page videos');seenMedia.add(filename);const stat=fs.lstatSync(filename);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1&&stat.size>0&&stat.size<=2**31);assert.equal(path.extname(filename),'.webm');
        const hash=crypto.createHash('sha256');for await(const chunk of fs.createReadStream(filename))hash.update(chunk);
        rawMedia[role]={path:filename,sha256:hash.digest('hex'),bytes:stat.size};
      }
      const cursorPath=path.join(directory,'cursor-evidence.json');const cursor={captureId:binding.captureId,runId:binding.runId,telemetry:'ACTUAL_TRUSTED_DOM_POINTER_EVENTS_NOT_OS',events};
      fs.writeFileSync(cursorPath,JSON.stringify(cursor)+'\n',{flag:'wx',mode:0o600});const bytes=fs.readFileSync(cursorPath);finalized=true;
      const policyPath=path.join(directory,'surface-policy-evidence.json'),policy={captureId:binding.captureId,runId:binding.runId,policy:'FAIL_CLOSED_SAFE_UI_LABELS_ONLY',renderedPrivacyQualified:false,events:surfaceEvents};fs.writeFileSync(policyPath,JSON.stringify(policy)+'\n',{flag:'wx',mode:0o600});const policyBytes=fs.readFileSync(policyPath);
      return {scope:'PRIVATE_REVIEW_ONLY',captureId:binding.captureId,runId:binding.runId,rawMedia,cursorEvidence:{path:cursorPath,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length},visibleSurfacePolicy:'FAIL_CLOSED_SAFE_UI_LABELS_ONLY',surfacePolicyEstablishedBeforePages:true,surfacePolicyEvidence:{path:policyPath,sha256:crypto.createHash('sha256').update(policyBytes).digest('hex'),bytes:policyBytes.length},renderedPrivacyQualified:false,cursorTelemetry:'ACTUAL_TRUSTED_DOM_POINTER_EVENTS_NOT_OS',releaseQualified:false,recordingQualified:false,publicationEligible:false};
    },
  };
}

module.exports = {
  VIDEO_SIZE,
  createPrivateReviewRecording,
  privateReviewSurfaceDecision,
  buildVerificationDisplay,
  createActionRecording,
  createArtifactDir,
  finalizeVideo,
  maskProtocolField,
  showStep,
  showVerificationResult,
};
