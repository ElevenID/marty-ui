#!/usr/bin/env node
import {readFileSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {CONFIGURATION_NAMES,validateRuntimeConfiguration} from './runtime-config-contract.mjs';

try {
  if(process.argv.length !== 3) throw new Error('Usage: validate-runtime-config.mjs <mounted Canvas config directory>');
  const directory=resolve(process.argv[2]), files={}, hashes={};
  for(const name of CONFIGURATION_NAMES) {
    const filename=resolve(directory,name), stat=lstatSync(filename);
    if(!stat.isFile() || stat.isSymbolicLink() || stat.size>262144) throw new Error('Canvas configuration is missing, oversized or not a regular file');
    const bytes=readFileSync(filename);files[name]=bytes.toString('utf8');
    hashes[name]=createHash('sha256').update(bytes).digest('hex');
  }
  console.log(JSON.stringify({...validateRuntimeConfiguration(files),configurationSha256:hashes}));
} catch {console.error('Mounted Canvas configuration does not match the reviewed generator contract');process.exitCode=1;}
