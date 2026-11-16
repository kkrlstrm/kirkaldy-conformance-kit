"""Actual client socket termination at the pre-response barrier."""
import asyncio, json, multiprocessing, os, time
import httpx, uvicorn
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.__tests__.test_company_refusals import signed_in
from poppy_docker.client import RemoteWorld, RemoteShop, Routing, wait_ready, request, child, REC

async def main():
    mode=os.getenv('CASE_MODE','target'); started=time.monotonic(); world=RemoteWorld()
    world.network.socket_transport=Routing(); world.shop=RemoteShop()
    server=uvicorn.Server(uvicorn.Config(world.atlas.website(),host='0.0.0.0',port=8001,log_level='warning'))
    serving=asyncio.create_task(server.serve())
    while not server.started: await asyncio.sleep(.02)
    await wait_ready('http://company:8000/_test/ready'); await wait_ready(REC+'/ready')
    token=await signed_in(world); session=world.session; api=ApiClient(transport=world.transport)
    async with httpx.AsyncClient(trust_env=False,timeout=20) as h:
        async def events(): return (await h.get(REC+'/events')).json()['events']
        async def rows(op): return [x for x in await events() if x['body']['operation_id']==op.operation_id]
        control=(await request(api,session,token,key='control-propose')).operation
        if mode=='no-control':
            assert (await h.post(REC+'/_test/down')).json()['down']
        try:
            response=await request(api,session,token,control,'control-approve'); control_status=response.get('status') if isinstance(response,dict) else response.status
        except Exception as e: control_status=type(e).__name__
        try: ce=await rows(control)
        except Exception: ce=[]
        if control_status != 200 or len(ce)!=1:
            print('LOSS_RESULT '+json.dumps({'verdict':'inconclusive','reason':'positive control unavailable','control_status':control_status,'control_events':ce}),flush=True)
        else:
            op=(await request(api,session,token,key='loss-propose')).operation
            ctx=multiprocessing.get_context('fork'); q=ctx.Queue()
            p=ctx.Process(target=child,args=(world,session,token,op,'same-approval',q,'proxy')); p.start()
            first=await asyncio.to_thread(q.get,True,20)
            p.join(5); assert p.exitcode==0
            assert first.get('error') in ('RemoteProtocolError','ReadError','TransportError'), first
            before=await rows(op); record=(await h.get('http://company:8000/_test/operation/'+op.operation_id)).json()
            assert len(before)==1 and record['status']=='performed'
            if mode=='bad':
                rr=await h.post('http://company:8000/_test/fault/on'); assert rr.json()['enabled']
            retry=await request(api,session,token,op,'retry-approval')
            status=retry.get('status') if isinstance(retry,dict) else retry.status
            body=retry if isinstance(retry,dict) else retry.body
            after=await rows(op)
            expiry=None
            if mode=='expiry':
                advanced=(await h.post('http://company:8000/_test/advance-clock')).json()
                try:
                    exp=await request(api,session,token,op,'after-expiry')
                    expiry={'clock':advanced,'response':exp if isinstance(exp,dict) else {'status':exp.status,'body':exp.body},'events':await rows(op)}
                except Exception as e: expiry={'clock':advanced,'error':type(e).__name__,'events':await rows(op)}
            print('LOSS_RESULT '+json.dumps({'verdict':'fail' if len(after)>1 or status!=200 else 'pass','mode':mode,'control_status':control_status,'control_events':ce,'operation_id':op.operation_id,'revision':op.revision,'expires_at':str(op.expires_at),'record_before_drop':record,'dropped_response':first,'child_exit':p.exitcode,'events_before':before,'retry_status':status,'retry_body':body,'expiry_observation':expiry,'events_after':after,'duration_seconds':round(time.monotonic()-started,3)},default=str,sort_keys=True),flush=True)
    server.should_exit=True; await serving
if __name__=='__main__': asyncio.run(main())
