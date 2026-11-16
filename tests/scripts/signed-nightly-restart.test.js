"use strict";
const {test}=require('node:test');const assert=require('node:assert/strict');
const {configuration}=require('./signed-nightly-restart');
const row=()=>({Id:'a'.repeat(64),Name:'/product',Image:'sha256:'+'b'.repeat(64),Path:'/bin/service',Args:[],
 Config:{Env:['K=V'],Labels:{service:'product'}},HostConfig:{Dns:null,DnsOptions:null,DnsSearch:null,Memory:123,
 Mounts:[{Type:'bind',Source:'C:/Users/test/public.json',Target:'/public.json',ReadOnly:true}]},
 Mounts:[{Type:'bind',Source:'C:/Users/test/public.json',Destination:'/public.json',RW:false}],
 NetworkSettings:{Networks:{owned:{NetworkID:'c'.repeat(64)}}}});
test('only canonical bind aliases and empty DNS representations compare equal',()=>{const a=row(),b=row();b.HostConfig.Dns=[];b.HostConfig.Mounts[0].Source='/run/desktop/mnt/host/c/Users/test/public.json';configuration(a,b);assert.equal(a.HostConfig.Dns,null);});
test('ordinary config, CID, populated DNS, mount and network changes refuse',()=>{
 for(const change of [b=>b.Config.Env.push('OTHER=changed'),b=>b.Id='d'.repeat(64),b=>b.HostConfig.Dns=['1.1.1.1'],b=>b.Mounts[0].RW=true,b=>b.NetworkSettings.Networks.owned.NetworkID='d'.repeat(64)]){const b=row();change(b);assert.throws(()=>configuration(row(),b));}
});
test('Desktop label additions require pinned historical boundary and closed names',()=>{const a=row(),b=row();b.Config.Labels['desktop.docker.io/ports.scheme']='v2';assert.throws(()=>configuration(a,b));configuration(a,b,true);b.Config.Labels.unknown='value';assert.throws(()=>configuration(a,b,true));});
