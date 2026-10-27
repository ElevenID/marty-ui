'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
// IO only: callers retain their distinct Compose or governed-host boundary.
function readBoundedSecretFile(filePath,{root,maxBytes=4096,sha256}={}){
 try{
  assert(typeof filePath==='string'&&path.isAbsolute(filePath));assert(typeof root==='string'&&path.isAbsolute(root));
  const absolute=path.resolve(filePath),relative=path.relative(path.resolve(root),absolute);
  assert(relative&&!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative));
  let current=path.parse(absolute).root;
  for(const segment of absolute.slice(current.length).split(path.sep)){current=path.join(current,segment);assert(!fs.lstatSync(current).isSymbolicLink());}
  const before=fs.lstatSync(absolute);assert(before.isFile()&&before.size>0&&before.size<=maxBytes);
  const bytes=fs.readFileSync(absolute);const after=fs.lstatSync(absolute);
  assert(after.isFile()&&!after.isSymbolicLink()&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeMs===after.mtimeMs);
  assert(bytes.length===before.size&&bytes.length<=maxBytes);
  const observed=crypto.createHash('sha256').update(bytes).digest('hex');
  if(sha256!==undefined)assert(typeof sha256==='string'&&/^[a-f0-9]{64}$/.test(sha256)&&observed===sha256);
  const value=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes).replace(/\r?\n$/,'');assert(value.length>0);
  return {value,sha256:observed};
 }catch{throw new Error('Bounded secret file is unavailable, changed or outside its explicit boundary');}
}
module.exports={readBoundedSecretFile};
