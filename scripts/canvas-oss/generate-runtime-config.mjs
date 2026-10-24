#!/usr/bin/env node
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CANVAS_ORIGIN, KEY_NAMES, renderRuntimeConfiguration, validateRuntimeConfiguration } from './runtime-config-contract.mjs';

const outputArg=process.argv[2];
if(!outputArg) throw new Error('Usage: generate-runtime-config.mjs OUTPUT_DIRECTORY');
const output=resolve(outputArg);
if(existsSync(output) && readdirSync(output).length>0) throw new Error('Refusing to overwrite non-empty Canvas runtime config directory');
const origin=process.env.CANVAS_OSS_ORIGIN || CANVAS_ORIGIN;
if(origin !== CANVAS_ORIGIN) throw new Error('Portable acceptance Canvas origin must be https://canvas-test.elevenidllc.com');
const offsets=[-7,0,7];
const keys=KEY_NAMES.map((name,index)=>{
  const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const date=new Date(Date.now()+offsets[index]*24*60*60*1000).toISOString();
  return [name,JSON.stringify({...privateKey.export({format:'jwk'}),kid:`canvas-oss-${date}`,alg:'RS256',use:'sig'})];
});
const files=renderRuntimeConfiguration({encryptionKey:randomBytes(32).toString('hex'),jwtKey:randomBytes(32).toString('hex'),keys});
validateRuntimeConfiguration(files);
mkdirSync(output,{recursive:true});
for(const [name,contents] of Object.entries(files)) writeFileSync(resolve(output,name),contents,{encoding:'utf8',mode:0o644});
writeFileSync(resolve(output,'generation.json'),JSON.stringify({schema_version:1,canvas_origin:CANVAS_ORIGIN,
  operator_configuration_only:true,canvas_source_files_modified:false,custom_plugins:[],
  configuration_sha256:Object.fromEntries(Object.entries(files).map(([name,value])=>[name,createHash('sha256').update(value).digest('hex')]))},null,2)+'\n',
{encoding:'utf8',mode:0o644});
console.log('Generated ephemeral Canvas operator configuration');
