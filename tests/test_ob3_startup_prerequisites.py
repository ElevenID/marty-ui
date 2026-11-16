"""Source-only link between the maintained startup graph and future Compose."""
import hashlib,json,pathlib
import pytest
import yaml

ROOT=pathlib.Path(__file__).resolve().parents[1]
PAIRS=[('canvas-sync-worker','signing-keys'),('compliance-profile','organization'),
       ('deployment-profile','organization'),('device-registration','organization')]

def validate(proof,raw):
 assert set(proof)=={'schema','composeSourcePath','composeSha256','installedModelChanged','requirements'}
 assert proof['schema']=='marty.ob3-startup-prerequisites/v1'
 assert proof['composeSourcePath']=='docker-compose.beta.yml'
 assert proof['installedModelChanged'] is False
 assert proof['composeSha256']==hashlib.sha256(raw).hexdigest()
 assert proof['requirements']==[dict(dependentRole=d,prerequisiteRole=p,readiness='DOCKER_HEALTHY') for d,p in PAIRS]
 model=yaml.safe_load(raw)
 for dependent,prerequisite in PAIRS:
  assert model['services'][dependent]['depends_on'][prerequisite]=={'condition':'service_healthy'}

def test_shared_ob3_startup_graph_matches_actual_future_compose_bytes_and_edges():
 proof=json.loads((ROOT/'scripts/ob3-startup-prerequisites.json').read_bytes())
 validate(proof,(ROOT/'docker-compose.beta.yml').read_bytes())

@pytest.mark.parametrize('fault',['hash','condition','missing-edge','extra-edge','installed-model-claim'])
def test_shared_ob3_startup_graph_rejects_source_drift(fault):
 proof=json.loads((ROOT/'scripts/ob3-startup-prerequisites.json').read_bytes())
 raw=(ROOT/'docker-compose.beta.yml').read_bytes()
 if fault=='hash':raw+=b'\n# drift\n'
 elif fault in ('condition','missing-edge'):
  model=yaml.safe_load(raw)
  if fault=='condition':model['services']['compliance-profile']['depends_on']['organization']['condition']='service_started'
  else:del model['services']['compliance-profile']['depends_on']['organization']
  raw=yaml.safe_dump(model).encode();proof['composeSha256']=hashlib.sha256(raw).hexdigest()
 elif fault=='extra-edge':proof['requirements'].append(dict(dependentRole='gateway',prerequisiteRole='organization',readiness='DOCKER_HEALTHY'))
 else:proof['installedModelChanged']=True
 with pytest.raises((AssertionError,KeyError)):validate(proof,raw)
