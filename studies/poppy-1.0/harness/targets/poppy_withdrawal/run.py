"""Local-only Datalayer 0.35.0 sign-out experiment; independent recorder process."""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

import httpx
from reactor import PluginManifest
from personal_agent_protocol.__version__ import __version__
from personal_agent_protocol import SessionClient
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.company import ActionResult, build_company, company_app
from personal_agent_protocol.demo.kit import ClockPlugin
from personal_agent_protocol.demo.manzanita import CONFIG, DOMAIN, ManzanitaPlugin
from personal_agent_protocol.__tests__.test_company_refusals import signed_in
from personal_agent_protocol.models import Approval

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/studies/poppy'))
from test_datalayer_035 import StudyWorld, EXCHANGE

class RealClock:
    def __init__(self): self.offset = 0; self.frozen = None
    def now(self): return self.frozen or datetime.now(timezone.utc) + timedelta(seconds=self.offset)
    def advance(self, seconds): self.offset += seconds

class Executor:
    action = 'orders.exchange'
    def __init__(self, recorder): self.recorder = recorder
    async def perform(self, operation, account_id):
        body = {'operation_id': operation.operation_id, 'revision': operation.revision,
                'account_id': account_id, 'terms': operation.terms}
        async with httpx.AsyncClient(trust_env=False, timeout=30) as h:
            (await h.post(self.recorder + '/arrive', json=body)).raise_for_status()
            (await h.post(self.recorder + '/effect', json=body)).raise_for_status()
        return ActionResult(summary='Synthetic exchange recorded.', data={'operation_id': operation.operation_id})

async def world(recorder, mutant=False):
    w = StudyWorld()
    w.clock = RealClock()
    # Rebuild the host/reactor so every component uses the advancing clock.
    from personal_agent_protocol.demo.kit import PersonalAgentHost, ScriptedApprovals, ScriptedInput, personal_agent_reactor
    w.host = PersonalAgentHost(w.atlas, w.clock, protected_input=ScriptedInput(), approvals=ScriptedApprovals(always=True))
    w.reactor = personal_agent_reactor(w.host, network=w.network, http_client=w.http)
    from personal_agent_protocol import SessionHttpClient
    w.transport = SessionHttpClient(reactor=w.reactor, http_client=w.http)
    plugin = ManzanitaPlugin(); plugin.executor = Executor(recorder)
    from dataclasses import replace
    cfg = replace(CONFIG, protocol_versions=('0.4', '1.0'))
    w.shop = build_company(cfg, http_client=w.network.client(), address_resolver=w.network.resolve,
       plugins=[(PluginManifest(name='withdrawal-host',version='1'),plugin), (PluginManifest(name='withdrawal-clock',version='1'),ClockPlugin(w.clock))])
    if mutant:
        async def ignore_sign_out(families):
            # Known-bad host: revocation does nothing and its clock stops, so
            # expiration cannot eventually impose a withdrawal bound either.
            w.clock.frozen = w.clock.now()
            return 0
        w.shop._sign_out = ignore_sign_out
    w.network.add(DOMAIN, company_app(w.shop))
    token = await signed_in(w)
    return w, token, ApiClient(transport=w.transport)

async def proposal(api, w, token):
    r = await api.call('POST',EXCHANGE,session=w.session,token=token,body={})
    assert r.status == 403 and r.operation is not None
    return r.operation

async def action(api,w,token,op,key, prepared=None):
    try:
        r=await api.call('POST',EXCHANGE,session=w.session,token=token,body={},idempotency_key=key,
           approval=prepared or Approval(operation_id=op.operation_id,revision=op.revision,approver='user'))
        return {'status':r.status,'body':r.body}
    except ApiError as e: return {'status':e.status_code,'error':e.code}
    except Exception as e: return {'exception':type(e).__name__}

async def revoke_and_refresh(w):
    from personal_agent_protocol.accounts import RefreshTokenClient
    client=RefreshTokenClient(reactor=w.reactor,http_client=w.http)
    raw=(await client._store().get(w.refresh_reference)).get_secret_value()
    ctx=w.account_context()
    auth=await SessionClient(reactor=w.reactor,http_client=w.http).client_authentication(client_id=ctx.client_id,issuer=ctx.issuer)
    revoked=await w.http.post(ctx.revocation_endpoint,data={'token':raw,'token_type_hint':'refresh_token',**auth})
    auth=await SessionClient(reactor=w.reactor,http_client=w.http).client_authentication(client_id=ctx.client_id,issuer=ctx.issuer)
    refreshed=await w.http.post(ctx.token_endpoint,data={'grant_type':'refresh_token','refresh_token':raw,**auth})
    payload=refreshed.json()
    return {'revocation_status':revoked.status_code,'refresh_status':refreshed.status_code,'refresh_error':payload.get('error')}

async def effect_rows(h, rec, op):
    r=await h.get(rec+'/events'); r.raise_for_status()
    return [x for x in r.json()['events'] if x['body']['operation_id']==op.operation_id]

async def run_case(rec, mode, trial):
    bad=mode=='broken'; w,t,api=await world(rec,bad)
    async with httpx.AsyncClient(trust_env=False,timeout=35) as h:
        control=await proposal(api,w,t)
        before=await effect_rows(h,rec,control)
        answer=await action(api,w,t,control,f'{mode}-{trial}-control')
        after=await effect_rows(h,rec,control)
        if before or len(after)!=1 or answer.get('status')!=200:
            return {'mode':mode,'trial':trial,'verdict':'INCONCLUSIVE','reason':'positive control missing','control':answer,'effects':len(after)}
        marker=f'{mode}-{trial}'
        start=(await h.post(f'{rec}/mark/{marker}-before-revoke')).json()['ns']
        rr=await revoke_and_refresh(w)
        end=(await h.post(f'{rec}/mark/{marker}-after-refresh')).json()['ns']
        if rr['revocation_status'] != 200:
            w1='INCONCLUSIVE'
        elif rr['refresh_status']==400 and rr['refresh_error']=='invalid_grant':
            w1='PASS'
        elif rr['refresh_status']==200:
            w1='FAIL'
        else:
            w1='INCONCLUSIVE'
        if mode=='target' and w1!='PASS':
            return {'mode':mode,'trial':trial,'control_effects':len(after),'revocation_and_refresh':rr,'w1_check':w1,
                    'recorder_ns':{'before_revoke':start,'after_refresh':end}}
        if bad: await asyncio.sleep(.25)
        before_new=(await h.get(rec+'/events')).json()['events']
        try:
            proposed=await api.call('POST',EXCHANGE,session=w.session,token=t,body={},idempotency_key=f'{marker}-new')
            new_response={'status':proposed.status,'has_operation':proposed.operation is not None}
            if proposed.operation is not None:
                new_response['execution']=await action(api,w,t,proposed.operation,f'{marker}-new-execute')
        except ApiError as e:
            new_response={'status':e.status_code,'error':e.code}
        finish=(await h.post(f'{rec}/mark/{marker}-after-new-action')).json()['ns']
        after_new=(await h.get(rec+'/events')).json()['events']
        if mode=='target' and len(after_new)>len(before_new):
            return {'mode':mode,'trial':trial,'control_effects':len(after),'revocation_and_refresh':rr,'w1_check':w1,
                    'new_action_response':new_response,'new_action_effects':len(after_new)-len(before_new),'w2_check':'FAIL'}
        return {'mode':mode,'trial':trial,'control_effects':len(after),'control_operation':control.operation_id,
                'revocation_and_refresh':rr,'w1_check':w1,'new_action_response':new_response,
                'new_action_effects':len(after_new)-len(before_new),
                'event_count_before_new':len(before_new),'event_count_after_new':len(after_new),
                'recorder_ns':{'before_revoke':start,'after_refresh':end,'after_action':finish},
                'refusal_upper_bound_ms':(finish-start)/1e6 if new_response.get('status')==401 and not (len(after_new)-len(before_new)) else None}

async def prepared_case(rec, mutant=False):
    w,t,api=await world(rec,mutant)
    async with httpx.AsyncClient(trust_env=False,timeout=35) as h:
        control=await proposal(api,w,t)
        ca=await action(api,w,t,control,'prepared-control')
        ce=await effect_rows(h,rec,control)
        if ca.get('status')!=200 or len(ce)!=1:
            return {'verdict':'INCONCLUSIVE','reason':'positive control missing'}
        op=await proposal(api,w,t)
        prepared=Approval(operation_id=op.operation_id,revision=op.revision,approver='user')
        before=await effect_rows(h,rec,op)
        rr=await revoke_and_refresh(w)
        got=await action(api,w,t,op,'prepared-after-revoke',prepared)
        after=await effect_rows(h,rec,op)
        return {'verdict':'OBSERVATION','control_effects':len(ce),'control_operation':control.operation_id,
                'operation':op.operation_id,'before_effects':len(before),
                'revocation_and_refresh':rr,'agent_response':got,'after_effects':len(after)}

async def inflight(rec):
    w,t,api=await world(rec)
    async with httpx.AsyncClient(trust_env=False,timeout=35) as h:
        control=await proposal(api,w,t); ca=await action(api,w,t,control,'flight-control'); ce=await effect_rows(h,rec,control)
        if ca.get('status')!=200 or len(ce)!=1: return {'verdict':'INCONCLUSIVE','reason':'positive control missing'}
        op=await proposal(api,w,t)
        (await h.post(f'{rec}/arm/{op.operation_id}',params={'stage':'before_effect'})).raise_for_status()
        task=asyncio.create_task(action(api,w,t,op,'flight-action'))
        for _ in range(300):
            state=(await h.get(f'{rec}/barrier/{op.operation_id}')).json()
            if state.get('entered'): break
            await asyncio.sleep(.02)
        else: raise RuntimeError('performing barrier not entered')
        marker=(await h.post(rec+'/mark/inflight-before-revoke')).json()['ns']
        concurrent=await action(api,w,t,op,'flight-concurrent')
        if concurrent.get('status') != 503:
            raise RuntimeError('performing state not externally confirmed: '+json.dumps(concurrent))
        rr=await revoke_and_refresh(w)
        (await h.post(f'{rec}/release/{op.operation_id}')).raise_for_status()
        result=await task
        rows=await effect_rows(h,rec,op)
        return {'verdict':'OBSERVATION','control_effects':len(ce),'control_operation':control.operation_id,
                'operation':op.operation_id,'barrier_entered':True,'concurrent_response':concurrent,'recorder_before_revoke_ns':marker,
                'revocation_and_refresh':rr,'agent_response':result,'effects':len(rows),'effect_events':rows}

async def no_control(rec):
    # The executor's recorder is unreachable; the independent recorder checks that
    # no effect for this control exists. Do not attempt withdrawal after this.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); dead=sock.getsockname()[1]
    w,t,api=await world(f'http://127.0.0.1:{dead}')
    op=await proposal(api,w,t)
    result=await action(api,w,t,op,'recorder-down-control')
    async with httpx.AsyncClient(trust_env=False) as h:
        observed=await effect_rows(h,rec,op)
    if result.get('status')==200 or observed: raise RuntimeError('recorder-down control unexpectedly succeeded')
    return {'verdict':'INCONCLUSIVE','reason':'positive control recorder unavailable',
            'control_response':result,'independent_effect_count':len(observed)}

async def main():
    assert __version__=='0.35.0'
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='withdrawal-recorder-') as d:
        rec=f'http://127.0.0.1:{port}'
        env={**os.environ,'RECORDER_DB':d+'/effects.db','PYTHONPATH':str(ROOT),'PYTHONUNBUFFERED':'1'}
        p=subprocess.Popen([sys.executable,'-m','uvicorn','targets.poppy_withdrawal.recorder:app','--host','127.0.0.1','--port',str(port),'--log-level','warning'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            async with httpx.AsyncClient(trust_env=False) as h:
                for _ in range(200):
                    try:
                        if (await h.get(rec+'/ready')).status_code==200: break
                    except httpx.HTTPError: await asyncio.sleep(.05)
                else: raise RuntimeError('recorder not ready')
            results={'configuration':{'sdk':'0.35.0','store':'MemoryCompanyStore','transport':'in-process ASGI; effect recorder loopback HTTP','access_token_lifetime_seconds':3600,'clock':'SDK wall clock with device polling offset; intervals from recorder monotonic clock'},'broken':[],'target':[]}
            results['no_control']=await no_control(rec)
            for i in range(3): results['broken'].append(await run_case(rec,'broken',i))
            if not all(x.get('w1_check')=='FAIL' and x.get('new_action_effects')==1 for x in results['broken']): raise RuntimeError('broken control not detected: '+json.dumps(results['broken']))
            results['prepared_broken']=await prepared_case(rec,True)
            # Target trials stop on a W1 failure, before any further target work.
            for i in range(3):
                result=await run_case(rec,'target',i); results['target'].append(result)
                if result.get('w1_check')!='PASS' or result.get('w2_check')=='FAIL':
                    results['stopped']='target W1 or W2 failed or inconclusive'; break
            if 'stopped' not in results:
                results['prepared']=await prepared_case(rec)
                results['inflight']=await inflight(rec)
            async with httpx.AsyncClient(trust_env=False) as h:
                results['recorder_marks']=(await h.get(rec+'/marks')).json()['marks']
                results['recorder_events']=(await h.get(rec+'/events')).json()['events']
            if results['target'] and (results['target'][-1].get('w1_check')=='FAIL' or results['target'][-1].get('w2_check')=='FAIL'):
                internal=ROOT/'internal'/'poppy-withdrawal-stop.json'
                internal.parent.mkdir(parents=True,exist_ok=True)
                internal.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
            Path(sys.argv[1]).write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
        finally:
            p.terminate(); p.wait(timeout=5)
            p.stderr.close()

if __name__=='__main__': asyncio.run(main())
