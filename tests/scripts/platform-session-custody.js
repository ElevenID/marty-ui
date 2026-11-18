'use strict';
// Run-owned platform session cleanup; no external provider authorities.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const DEFAULT_MARTY_ORIGIN='https://beta.elevenidllc.com';
class ContractFailure extends Error {
  constructor(code, summary, options = {}) {
    super(summary, options);
    this.name = 'ContractFailure';
    this.code = code;
  }
}

function fail(code, summary) {
  throw new ContractFailure(code, summary);
}

function requireCondition(condition, code, summary) {
  if (!condition) fail(code, summary);
}

function createPlatformCaptureCustody(runSuffix, directory = process.env.DEMO_PRIVATE_RECOVERY_DIRECTORY) {
  requireCondition(path.isAbsolute(directory || '') && fs.lstatSync(directory).isDirectory()
    && !fs.lstatSync(directory).isSymbolicLink(), 'platform_private_custody_missing', 'Capture requires its protected owned recovery mount.');
  requireCondition(/^[A-Za-z0-9-]{8,100}$/.test(runSuffix), 'platform_run_identity_invalid', 'Private custody needs the exact fresh run.');
  const files = new Set(), secretFiles = new Map(), journal = path.join(directory,runSuffix+'.custody.json');
  const write = (filename,value,exclusive,secret=false) => {
    const fd=fs.openSync(filename,exclusive?'wx':'w',0o600);
    try {
      if(secret) {const stat=fs.fstatSync(fd);secretFiles.set(filename,{dev:stat.dev,ino:stat.ino});}
      fs.writeFileSync(fd,value);fs.fsyncSync(fd);
    } finally {fs.closeSync(fd);}
  };
  write(journal,JSON.stringify({runSuffix,state:'OPEN',roles:[]}),true);
  const checkpoint = state => {
    const stat=fs.lstatSync(journal);assert(stat.isFile()&&!stat.isSymbolicLink());
    const next=journal+'.next';write(next,JSON.stringify({runSuffix,state,roles:[...files]}),true);fs.renameSync(next,journal);
  };
  return {
    hasRetained(role) {return files.has(role);},
    retain(role,value) {
      requireCondition(['betaAdminSession'].includes(role)
        && typeof value==='string' && value.length>0 && Buffer.byteLength(value)<=131072,
      'platform_private_custody_invalid','Only bounded owned authority can enter capture recovery.');
      const filename=path.join(directory,runSuffix+'-'+role+'.json');
      if(files.has(role)) {
        const expected=secretFiles.get(filename),actual=fs.lstatSync(filename);
        requireCondition(expected&&actual.dev===expected.dev&&actual.ino===expected.ino,
          'platform_private_custody_changed','Private recovery file ownership changed.');
        requireCondition(fs.lstatSync(filename).isFile()&&!fs.lstatSync(filename).isSymbolicLink(),
          'platform_private_custody_changed','Owned recovery file changed.');
        const next=filename+'.next';write(next,value,true,true);fs.renameSync(next,filename);
        secretFiles.set(filename,secretFiles.get(next));secretFiles.delete(next);
      } else {files.add(role);checkpoint('OPEN');write(filename,value,true,true);}
      checkpoint('OPEN');
    },
    retire() {
      for(const [filename,expected] of secretFiles) {
        const actual=fs.lstatSync(filename);
        requireCondition(actual.dev===expected.dev&&actual.ino===expected.ino,
          'platform_private_custody_changed','Private recovery file ownership changed.');
        requireCondition(fs.lstatSync(filename).isFile()&&!fs.lstatSync(filename).isSymbolicLink(),
          'platform_private_custody_changed','Owned recovery file changed.');
        fs.unlinkSync(filename);
      }
      checkpoint('RETIRED'); return true;
    },
  };
}

async function createOriginalCookieSessionContext(requestFactory,cookies) {
  const original=cookies.map(cookie=>cookie.name+'='+cookie.value).join('; ');
  const isolated=await requestFactory.newContext({storageState:{cookies:[],origins:[]},ignoreHTTPSErrors:false});
  const send=(method,url,options={})=>isolated[method](url,{...options,
    headers:{...options.headers,Cookie:original}});
  return {isolated,session:{cookies:async()=>cookies.map(cookie=>({...cookie})),addCookies:async()=>{},
    request:{get:(url,options)=>send('get',url,options),post:(url,options)=>send('post',url,options),delete:(url,options)=>send('delete',url,options)}}};
}

async function retirePlatformSession(context, custody) {
  const origin=DEFAULT_MARTY_ORIGIN,cookies=await context.cookies(origin);
  requireCondition(cookies.length>0,'capture_beta_session_missing','Owned beta session custody is missing.');
  let custodyFailure;try {custody.retain('betaAdminSession',JSON.stringify(cookies));} catch(error) {custodyFailure=error;}
  const original=cookies.map(cookie=>cookie.name+'='+cookie.value).join('; ');
  let response,logoutFailure;
  try {response=await context.request.post(origin+'/v1/auth/logout',{maxRedirects:0,timeout:15000});} catch(error) {logoutFailure=error;}
  const old=await context.request.get(origin+'/v1/auth/me',{headers:{Cookie:original},maxRedirects:0,timeout:15000});
  const body=await old.json();
  requireCondition(!logoutFailure&&[302,303,307].includes(response?.status()),'capture_beta_logout_failed','Owned beta logout did not complete.');
  requireCondition(old.status()===200&&body.authenticated===false&&body.user==null,
    'capture_beta_session_authorized','Original beta session is not retired.');
  if(custodyFailure) throw custodyFailure;
  return {logoutStatus:response.status(),oldCookieAuthenticated:false};
}

module.exports={createPlatformCaptureCustody,createOriginalCookieSessionContext,retirePlatformSession};
