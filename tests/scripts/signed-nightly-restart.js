"use strict";
// One reviewed Desktop recovery, preserving the failed original journal and independent readback.
const assert = require('node:assert/strict');
const {isDeepStrictEqual} = require('node:util');
const PINS = Object.freeze({
  "operator": "e0808e97de1b9a0bbb79e78226a9421449d8a55a923d8af8f10ef43a1e6625d8",
  "continuation": "d0986177670c342d1ad6747fdf1dfe8141c23dc4209e10d24e65dffbd240b38e",
  "platformStart": "764e955de6e1f203fbced0c7fc1acf8a03f1ec12cd19b61d536e30265db99dfe",
  "dnsRestore": "5004541457a3d9766ea2b1d6bfe0ef98b0c4055fdf9357c0819eb6593523681a",
  "readbackOperator": "e5434a3f9e01cbb07964bdb8177d3eaaf8652e85d1d4eaf8fd4b3c084a441140",
  "plan": "cc83be719c5e837933d53f550b41e482bbb4d741ba1c1d6919ac1b2fe5b170aa",
  "before": "a96c7f9f7725afb58056337d3e68ad6ab7979db266ba276227d9d39ee18ef5bb",
  "after": "4c81b1d23d7f7205905cda426903bf3a43a4fb3dfa5171e4f4cd841e7e295aba",
  "backupIntegrity": "1ec1c530320fcb5d560170c900b3a958285b9cec9c27a21394a9c5c717bd8813",
  "readback": "1676387f0abe19ac76212ba9f2deee5570ae054163d6d60087335899a05c1cb0",
  "journal": "3a094688217e2a3634c1ef8f304a5d64472d8feac7628d02b6a1d8baad697b9f",
  "desktopStopped": "9a449dcab3de14851f71dda45c5e33b40bc3e75c6aa381bb08be6aacab78c94c",
  "dnsProof": "596b139787e8c158d29c3374c042299fe79267a793678d930911461477d27406",
  "volumes": "ce3f693177a139e0b05144b1ba0076ab0dade8823d2a06a776c7f53cd4824378"
});
function equal(a,b,reason) { assert(isDeepStrictEqual(a,b), reason); }
function source(value) {return require('./functional-debug-runtime').comparableBinaryMounts([{source:value}])[0].source;}
function host(value) {
  const result = structuredClone(value);
  for (const item of result.Mounts || []) if (item.Type==='bind') item.Source=source(item.Source);
  for (const field of ['Dns','DnsOptions','DnsSearch']) {
    if (result[field] === null || (Array.isArray(result[field]) && result[field].length === 0)) result[field] = [];
  }
  if (Array.isArray(result.Mounts)) {
    const items=Object.fromEntries(result.Mounts.map(item=>[item.Target,item]));
    assert.equal(Object.keys(items).length,result.Mounts.length); result.Mounts=items;
  }
  return result;
}
function mounts(values) {
  assert(Array.isArray(values));
  const result = Object.fromEntries(values.map(value => [value.Destination, value.Type==='bind'?{...value,Source:source(value.Source)}:value]));
  assert.equal(Object.keys(result).length, values.length, 'Duplicate mount destination');
  return result;
}
function configuration(original, row, pinnedHistoricalLabels = false) {
  if (pinnedHistoricalLabels) {
    row = structuredClone(row);
    for (const key of Object.keys(row.Config.Labels)) {
      if (Object.hasOwn(original.Config.Labels,key)) continue;
      assert(/^desktop\.docker\.io\/(?:mounts\/\d+\/(?:Source|SourceKind|Target)|ports\.scheme|ports\/\d+\/(?:tcp|udp))$/.test(key), 'Unknown historical label addition');
      delete row.Config.Labels[key];
    }
  }
  for (const field of ['Id','Name','Image','Path','Args','Config']) equal(row[field], original[field], 'Recovery changed '+field);
  equal(host(row.HostConfig), host(original.HostConfig), 'Recovery changed HostConfig');
  equal(mounts(row.Mounts), mounts(original.Mounts), 'Recovery changed mounts');
  const networks = value => Object.fromEntries(Object.entries(value.NetworkSettings.Networks).map(([name, endpoint])=>[name, endpoint.NetworkID]));
  equal(networks(row), networks(original), 'Recovery changed networks');
}
function restartSuccessor(ref, byRole, roles, tools) {
  const value = tools.boundJson(ref);
  assert.equal(value.schema, 'marty.functional-signed-desktop-recovery/v1');
  equal(Object.keys(value).sort(), ['schema','previousObservation',...Object.keys(PINS)].sort(), 'Unknown recovery authority field');
  assert.equal(value.previousObservation.sha256,'128d55ad0b910430b2a90c915c89c0c068583092055b1a98fc58522c9f85a6d0');
  tools.boundJson(value.previousObservation);
  const get = key => {assert.equal(value[key].sha256, PINS[key], 'Unreviewed recovery '+key); return tools.boundJson(value[key]);};
  for (const key of ['operator','continuation','platformStart','dnsRestore','readbackOperator']) {
    assert.equal(value[key].sha256, PINS[key]); tools.verifyBoundFile(value[key], 1024*1024);
  }
  const proof=get('readback'), journal=get('journal'), plan=get('plan'), before=get('before'), after=get('after');
  const integrity=get('backupIntegrity'), dns=get('dnsProof'), stopped=get('desktopStopped');
  assert.equal(proof.state,'ORIGINAL_CONTAINERS_RESTORED_READBACK_VERIFIED');
  assert.equal(proof.originalJournalState,'FAILED_OR_UNKNOWN');
  assert.equal(journal.state,'FAILED_OR_UNKNOWN'); assert.equal(journal.failurePhase,'START_ORIGINAL_CONTAINER_ACK');
  for (const [field,key] of [['operatorSourceSha256','operator'],['readbackSourceSha256','readbackOperator'],['continuationSourceSha256','continuation'],['platformStartRecoverySourceSha256','platformStart'],['defaultDnsRestoreSourceSha256','dnsRestore'],['planSha256','plan'],['journalSha256','journal'],['backupIntegritySha256','backupIntegrity']]) assert.equal(proof[field],PINS[key]);
  assert.equal(proof.after.sha256,PINS.after); assert.equal(proof.normalizationProof.sha256,PINS.dnsProof);
  for (const field of ['configurationUnchangedExceptDefaultDnsEncoding','baselineHealthRestored','baoUnsealedSameClusters','desktopRestartPerformed','freshBackupComplete','runtimeReadOnly','runtimeRebindRequired']) assert.equal(proof[field],true);
  equal([proof.containers,proof.running,proof.volumes],[156,66,32]); // Historical checkpoint, not a permanent live global cohort.
  assert.notEqual(proof.daemonOwnerBefore.startTicks,proof.daemonOwnerAfter.startTicks);
  assert.notEqual(proof.daemonOwnerBefore.mountNamespace,proof.daemonOwnerAfter.mountNamespace);
  assert.equal(journal.desktopStopIntent,true); assert.equal(journal.desktopStartIntent,true); assert.equal(journal.wslShutdownIntent,false);
  assert.equal(journal.sourceSha256,PINS.operator); assert.equal(journal.planSha256,PINS.plan); assert.equal(journal.freshBackupComplete,true);
  assert.equal(plan.inputSha256,PINS.before); assert.equal(plan.volumesSha256,PINS.volumes); get('volumes');
  equal(Object.keys(before).sort(),Object.keys(after).sort()); assert.equal(Object.keys(after).length,156);
  assert.equal(new Set(journal.originalRunning).size,66); equal([...journal.originalRunning].sort(), [...plan.startOrder].sort());
  equal([...journal.stopIntents].sort(),[...journal.originalRunning].sort());
  assert.equal(stopped.state,'DESKTOP_POSITIVELY_STOPPED_AFTER_NONZERO_STOP_CLI');
  assert.equal(stopped.dockerDesktopDistroRunning,false); assert.equal(stopped.desktopProcessCount,0); assert.equal(stopped.ubuntuRunning,true);
  assert.equal(stopped.backupIntegritySha256,PINS.backupIntegrity);
  assert.equal(Object.keys(integrity).length,17);
  for (const item of Object.values(integrity)) assert(Number.isSafeInteger(item.bytes)&&item.bytes>0&&/^[a-f0-9]{64}$/.test(item.sha256));
  assert.equal(dns.before.sha256,PINS.before); assert.equal(dns.allOtherConfigurationByteValuesUnchanged,true); assert.equal(dns.dockerConfigurationMutated,false);
  for (const change of dns.changedFields) {
    assert(['Dns','DnsOptions','DnsSearch'].includes(change.field)); assert.equal(change.from,null); equal(change.to,[]);
    assert(before[change.cid]&&after[change.cid]);
  }
  const result=new Map(byRole);
  for (const role of roles) {
    const original=byRole.get(role), previous=before[original.Id], current=after[original.Id];
    assert(previous&&current,'Main role absent from recovery');
    // Added Desktop UI labels are accepted only in this exact hash-pinned historical preimage.
    configuration(original,previous,true); configuration(previous,current);
    assert.equal(current.State.Running,true); assert.equal(current.State.OOMKilled,false); assert(current.State.Health?.Status==='healthy'||(role==='canvas-sync-worker'&&!current.State.Health));
    assert(Number.isSafeInteger(current.State.Pid)&&current.State.Pid>0);
    assert(Date.parse(previous.State.StartedAt)>=Date.parse(original.State.StartedAt));
    assert(Date.parse(current.State.StartedAt)>Date.parse(previous.State.StartedAt),'Recovered generation must be newer');
    result.set(role,current);
  }
  return result;
}
module.exports={restartSuccessor,configuration,PINS};
