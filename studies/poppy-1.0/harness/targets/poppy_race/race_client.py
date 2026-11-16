"""Two SDK Company processes reach the same initial operation CAS before release."""
import asyncio, json, multiprocessing, os, time
import httpx, uvicorn
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.__tests__.test_company_refusals import signed_in
from poppy_docker.client import RemoteWorld, RemoteShop, Routing, request, wait_ready, child, REC

def worker(world, session, token, op, key, queue, target, launch):
    launch.wait(10)
    child(world,session,token,op,key,queue,target)

async def main():
    started=time.monotonic()
    mode=os.environ.get('RACE_CLIENT_MODE','good')
    trials=1 if mode=='no-control' else 3
    world=RemoteWorld(); world.network.socket_transport=Routing(); world.shop=RemoteShop()
    server=uvicorn.Server(uvicorn.Config(world.atlas.website(),host='0.0.0.0',port=8001,log_level='warning'))
    serving=asyncio.create_task(server.serve())
    while not server.started: await asyncio.sleep(.02)
    await wait_ready('http://company:8000/_test/ready')
    await wait_ready('http://company2:8000/_test/ready')
    await wait_ready(REC+'/ready')
    token=await signed_in(world); session=world.session; api=ApiClient(transport=world.transport)
    observations=[]
    async with httpx.AsyncClient(trust_env=False,timeout=20) as h:
        for i in range(trials):
            control=(await request(api,session,token,key=f'control-propose-{i}')).operation
            response=await request(api,session,token,control,f'control-execute-{i}')
            control_rows=(await h.get(REC+'/events')).json()['events']
            matched=[x for x in control_rows if x['body']['operation_id']==control.operation_id]
            if isinstance(response,dict) or response.status!=200 or len(matched)!=1:
                observations.append({'trial':i,'verdict':'inconclusive','reason':'positive control failed'})
                break
            op=(await request(api,session,token,key=f'race-propose-{i}')).operation
            assert control.operation_id!=op.operation_id
            await h.post(REC+'/claim-arm/'+op.operation_id)
            ctx=multiprocessing.get_context('fork'); queue=ctx.Queue(); launch=ctx.Event()
            processes=[ctx.Process(target=worker,args=(world,session,token,op,f'race-{i}-{j}',queue,target,launch))
                       for j,target in enumerate(['company'] if mode=='no-control' else ['company','company2'])]
            for proc in processes: proc.start()
            launch.set()
            outcomes=[await asyncio.to_thread(queue.get,True,20) for _ in processes]
            for proc in processes:
                proc.join(5)
                if proc.is_alive(): proc.terminate(); proc.join()
                assert proc.exitcode==0, proc.exitcode
            gate=(await h.get(REC+'/claim-state/'+op.operation_id)).json()
            rows=(await h.get(REC+'/events')).json()['events']
            effects=[x for x in rows if x['body']['operation_id']==op.operation_id]
            arrivals=gate.get('arrivals',[]); changes=gate.get('outcomes',[])
            valid=(len(arrivals)==2 and len({x['instance'] for x in arrivals})==2 and
                   len({x['version'] for x in arrivals})==1 and gate.get('released') and
                   len(changes)==2 and all(x['recorder_ns']<=gate['release_ns'] for x in arrivals))
            verdict='inconclusive' if not valid else ('fail' if len(effects)>1 else 'pass')
            observation={'trial':i,'verdict':verdict,'operation_id':op.operation_id,'revision':op.revision,
                'control_operation_id':control.operation_id,'control_events':matched,'gate':gate,
                'client_results':outcomes,'events':effects}
            observations.append(observation)
            if mode=='good':
                assert verdict=='pass' and sorted(x['success'] for x in changes)==[False,True],observation
            elif mode=='bad':
                assert verdict=='fail' and len(effects)==2 and all(x['success'] for x in changes),observation
            else:
                assert verdict=='inconclusive' and not effects and len(arrivals)==1,observation
    verdicts=[item['verdict'] for item in observations]
    overall=('inconclusive' if len(observations)!=trials or 'inconclusive' in verdicts
             else 'fail' if 'fail' in verdicts else 'pass')
    result={'check':'POPPY-OP-CAS-RACE-1','mode':mode,'duration_seconds':round(time.monotonic()-started,3),
            'verdict':overall,
            'trials':observations}
    print('RACE_RESULT '+json.dumps(result,sort_keys=True),flush=True)
    server.should_exit=True; await serving

if __name__=='__main__': asyncio.run(main())
