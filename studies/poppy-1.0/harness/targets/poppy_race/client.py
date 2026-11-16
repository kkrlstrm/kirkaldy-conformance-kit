"""Self-contained test client. Company and recorder are remote containers."""
import asyncio, json, multiprocessing, os, time
import httpx, uvicorn
from personal_agent_protocol import DiscoveryClient, SessionClient, SessionHttpClient
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.demo.kit import personal_agent_reactor
from personal_agent_protocol.extensions import negotiate_extensions
from personal_agent_protocol.models import Approval
from personal_agent_protocol.__tests__.test_company_end_to_end import World, PAIRWISE, TENANT
from personal_agent_protocol.__tests__.test_company_refusals import signed_in
from poppy_docker.network import Routing

URL='https://manzanita.example/api/orders/ord_7Hk2/exchanges'
REC='http://recorder:8002'

class RemoteShop:
    async def approve_device(self, code, account_id):
        async with httpx.AsyncClient(trust_env=False) as h:
            r=await h.post(f'http://company:8000/_test/approve_device/{code}')
            r.raise_for_status()

class RemoteWorld(World):
    async def signed_out_session(self):
        self.company=await DiscoveryClient(reactor=self.reactor,http_client=self.http,protocol_versions=('0.4','1.0')).discover('manzanita.example')
        assert self.company.session_version=='1.0'
        return await SessionClient(reactor=self.reactor,http_client=self.http).start(client_id=self.atlas.client_id,pairwise_user_id=PAIRWISE,issuer=self.company.oauth_metadata.issuer,tenant_id=TENANT,company=self.company,extensions=negotiate_extensions(self.company.document.extensions,supported=self.atlas.supported_extensions))

async def request(api, session, token, op=None, key='request'):
    try:
        r=await api.call('POST',URL,session=session,token=token,body={},idempotency_key=key,
            approval=None if op is None else Approval(operation_id=op.operation_id,revision=op.revision,approver='user'))
        return r
    except ApiError as e:
        return {'status':e.status_code,'code':e.code}

def child(world, session, token, op, key, queue, target="company"):
    os.environ["COMPANY_TARGET"]=target
    async def run():
        world.network.socket_transport=Routing()
        http=world.network.client()
        reactor=personal_agent_reactor(world.host, network=world.network,http_client=http)
        api=ApiClient(transport=SessionHttpClient(reactor=reactor,http_client=http))
        result=await request(api, session, token, op, key)
        queue.put({'pid':os.getpid(), 'status': result.get('status') if isinstance(result,dict) else result.status})
        await http.aclose()
    try: asyncio.run(run())
    except Exception as e: queue.put({'pid':os.getpid(),'error':type(e).__name__,'detail':str(e)})

async def wait_ready(url):
    async with httpx.AsyncClient(trust_env=False) as h:
        for _ in range(200):
            try:
                r=await h.get(url)
                if r.status_code==200: return
            except httpx.HTTPError: pass
            await asyncio.sleep(.1)
    raise RuntimeError('service not ready: '+url)

async def main():
    started=time.monotonic()
    world=RemoteWorld()
    world.network.socket_transport=Routing()
    world.shop=RemoteShop()
    config=uvicorn.Config(world.atlas.website(), host='0.0.0.0', port=8001, log_level='warning')
    server=uvicorn.Server(config)
    serving=asyncio.create_task(server.serve())
    while not server.started: await asyncio.sleep(.02)
    await wait_ready('http://company:8000/_test/ready')
    await wait_ready(REC+'/ready')
    token=await signed_in(world)
    session=world.session
    api=ApiClient(transport=world.transport)
    control=(await request(api,session,token,key='control-propose')).operation
    control_result=await request(api,session,token,control,'control-execute')
    if isinstance(control_result,dict) or control_result.status != 200:
        print('RESULT '+json.dumps({'case':'no-control','verdict':'inconclusive','reason':'positive control could not reach recorder','control_response':control_result}),flush=True)
        server.should_exit=True
        await serving
        return
    op=(await request(api,session,token,key='propose')).operation
    async with httpx.AsyncClient(trust_env=False) as h:
        case=os.environ.get('CASE','concurrency')
        await h.post(REC+'/arm/'+op.operation_id, params={'stage': 'before_effect' if case=='concurrency' else case})
        print('BARRIER_ARMED '+json.dumps({'operation_id':op.operation_id,'case':case}),flush=True)
        ctx=multiprocessing.get_context('fork')
        queue=ctx.Queue()
        first=ctx.Process(target=child,args=(world,session,token,op,'race-first',queue)); first.start()
        for _ in range(200):
            state=(await h.get(REC+'/barrier/'+op.operation_id)).json()
            if state.get('entered'): break
            await asyncio.sleep(.05)
        else: raise RuntimeError('first executor never entered')
        if case == 'concurrency':
            bad=os.environ.get('BAD_STORE')=='1'
            target=os.environ.get('SECOND_COMPANY','company')
            if bad:
                await h.post(f'http://{target}:8000/_test/fault/on')
            second=ctx.Process(target=child,args=(world,session,token,op,'race-second',queue,target)); second.start()
            if bad:
                for _ in range(200):
                    state=(await h.get(REC+'/barrier/'+op.operation_id)).json()
                    if state.get('arrivals',0)>=2: break
                    await asyncio.sleep(.05)
                else: raise RuntimeError('bad store did not admit second execution')
                await h.post(f'http://{target}:8000/_test/fault/off')
                assert first.is_alive() and second.is_alive()
                await h.post(REC+'/release/'+op.operation_id)
                first_result=await asyncio.to_thread(queue.get,True,10)
                second_result=await asyncio.to_thread(queue.get,True,10)
            else:
                second_result=await asyncio.to_thread(queue.get,True,10)
                assert second_result.get('status')==503, second_result
                assert first.is_alive()
                await h.post(REC+'/release/'+op.operation_id)
                first_result=await asyncio.to_thread(queue.get,True,10)
            first.join(5); second.join(5)
            assert first.exitcode==0 and second.exitcode==0
        else:
            print('CRASH_READY '+json.dumps({'operation_id':op.operation_id,'stage':case}),flush=True)
            for _ in range(600):
                state=(await h.get(REC+'/barrier/'+op.operation_id)).json()
                if state.get('restarted'): break
                await asyncio.sleep(.05)
            else: raise RuntimeError('no externally confirmed restart')
            first_result=await asyncio.to_thread(queue.get,True,10)
            first.join(5)
            second_result={'status':'not_run'}
        replay=await request(api,session,token,op,'replay')
        if case=='before_effect' and os.environ.get('BAD_STORE')=='1':
            await request(api,session,token,op,'bad-second-replay')
        recovery=None
        if os.environ.get('RECOVERY_CHECK')=='1':
            # A late downstream observation is a host decision, not an SDK callback.
            assert case=='after_effect'
            before=(await h.get('http://company:8000/_test/operation/'+op.operation_id)).json()
            assert before['status']=='performing'
            await asyncio.sleep(1.0)
            delayed=await request(api,session,token,op,'replay-delayed')
            delayed_status=delayed.get('status') if isinstance(delayed,dict) else delayed.status
            before_rows=(await h.get(REC+'/events')).json()['events']
            observed=[x for x in before_rows if x['body']['operation_id']==op.operation_id]
            assert len(observed)==1 and delayed_status==503
            settled=(await h.post('http://company:8000/_test/settle/'+op.operation_id)).json()
            assert settled['status']=='performed'
            answered=await request(api,session,token,op,'after-settle')
            answered_status=answered.get('status') if isinstance(answered,dict) else answered.status
            assert answered_status==200
            recovery={'before_status':before['status'],'retry_status':503,'delayed_retry_status':delayed_status,
                'late_recorder_evidence':observed,'host_settle':settled,'after_settle_status':answered_status,
                'after_settle_body':answered.body}
        rows=(await h.get(REC+'/events')).json()['events']
        matching=[r for r in rows if r['body']['operation_id']==op.operation_id]
        control_rows=[r for r in rows if r['body']['operation_id']==control.operation_id]
        replay_status=replay.get('status') if isinstance(replay,dict) else replay.status
        result={'case':case,'verdict':('fail' if len(matching)>1 else ('pass' if case=='concurrency' else 'observation_only')),
            'duration_seconds':round(time.monotonic()-started,3),'control_effects':len(control_rows),
            'first':first_result,'second':second_result,'replay_status':replay_status,
            'operation_id':op.operation_id,'revision':op.revision,'events':matching,'all_events':rows,'recovery':recovery}
        expected_count=2 if os.environ.get('BAD_STORE')=='1' else (0 if case=='before_effect' else 1)
        expected_status=503 if case in ('before_effect','after_effect') or (case=='before_ack' and os.environ.get('BAD_STORE')=='1') else 200
        assert len(control_rows)==1 and len(matching)==expected_count and replay_status==expected_status, result
        print('RESULT '+json.dumps(result,sort_keys=True),flush=True)
    server.should_exit=True
    await serving

if __name__=='__main__': asyncio.run(main())
