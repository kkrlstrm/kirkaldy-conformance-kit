import os
from dataclasses import replace
import httpx
from fastapi import FastAPI
from reactor import PluginManifest
from personal_agent_protocol.company import ActionResult, build_company, company_app
from personal_agent_protocol.demo.kit import ClockPlugin, MutableClock, StorePlugin
from poppy_docker.sqlite_store import SQLiteStore, StaleSQLiteStore, CoordinatedSQLiteStore
from personal_agent_protocol.demo.manzanita import CONFIG, ManzanitaPlugin
from poppy_docker.network import client, resolve

clock = MutableClock()
plugin = ManzanitaPlugin()

class Executor:
    action = 'orders.exchange'
    async def perform(self, operation, account_id):
        async with httpx.AsyncClient(trust_env=False, timeout=30) as h:
            if os.environ.get('NO_RECORDER')=='1':
                await h.get('http://unreachable-recorder:8002/ready')
            body = {'operation_id': operation.operation_id, 'revision': operation.revision,
                    'account_id': account_id, 'terms': operation.terms}
            await h.post('http://recorder:8002/arrive', json=body)
            r = await h.post('http://recorder:8002/effect', json=body)
            r.raise_for_status()
            await h.post('http://recorder:8002/checkpoint', json=body)
            return ActionResult(summary='Synthetic exchange recorded.', data={'operation_id':operation.operation_id})
plugin.executor = Executor()
plugins=[(PluginManifest(name='integration-host', version='1'), plugin), (PluginManifest(name='integration-clock', version='1'), ClockPlugin(clock))]
if os.environ.get('STORE') == 'sqlite':
    cls=(CoordinatedSQLiteStore if os.environ.get('RACE_MODE') else
         StaleSQLiteStore if os.environ.get('BAD_STORE')=='1' else SQLiteStore)
    plugins.append((PluginManifest(name='study-sqlite-store', version='1'), StorePlugin(cls('/company-state/store.db', now=clock.now))))
shop = build_company(replace(CONFIG, protocol_versions=('0.4','1.0')), http_client=client(),
    address_resolver=resolve, plugins=plugins)
app = FastAPI()
@app.get('/_test/ready')
async def ready(): return {'ready': True, 'pid': os.getpid()}
@app.post('/_test/fault/{setting}')
async def fault(setting: str):
    if not isinstance(shop.store, StaleSQLiteStore): return {'error':'not a fixture'}
    shop.store.enabled=(setting=='on')
    return {'enabled':shop.store.enabled}
@app.get('/_test/operation/{op}')
async def operation_record(op: str):
    record=await shop.operation_record(op)
    return {'status':record.status,'outcome':None if record.outcome is None else record.outcome.to_json()}
@app.post('/_test/settle/{op}')
async def settle_record(op: str):
    record=await shop.settle(op, ActionResult(summary='Synthetic exchange recorded.',data={'operation_id':op}),succeeded=True)
    return {'status':record.status,'outcome':record.outcome.to_json()}
@app.post('/_test/approve_device/{code}')
async def approve_device(code: str):
    await shop.approve_device(code, account_id='acct_ada')
    return {'approved': True}
class BeforeAck:
    def __init__(self, application): self.application=application
    async def __call__(self, scope, receive, send):
        import re
        headers=dict(scope.get('headers', []))
        approval=headers.get(b'poppy-approval',b'').decode('ascii',errors='ignore')
        match=re.search(r'operation_id="([^"]+)"',approval)
        async def wrapped(message):
            if match and message['type']=='http.response.start' and message.get('status')==200:
                async with httpx.AsyncClient(trust_env=False,timeout=60) as h:
                    await h.post('http://recorder:8002/ack/'+match.group(1))
            await send(message)
        await self.application(scope,receive,wrapped)
app.mount('/', BeforeAck(company_app(shop)))
