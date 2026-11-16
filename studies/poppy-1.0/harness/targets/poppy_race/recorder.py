import asyncio, json, os, sqlite3, time
from fastapi import FastAPI
from pydantic import BaseModel

app=FastAPI()
path=os.environ.get('RECORDER_DB', '/state/effects.db')
os.makedirs(os.path.dirname(path), exist_ok=True)
with sqlite3.connect(path) as db:
    db.execute('create table if not exists events (seq integer primary key autoincrement, body text not null, ns integer not null)')
armed={}
class Payload(BaseModel):
    operation_id: str
    revision: str = ''
    account_id: str = ''
    terms: dict = {}
@app.get('/ready')
async def ready(): return {'ready': True}
@app.post('/arm/{op}')
async def arm(op: str, stage: str = 'before_effect'):
    armed[op]={'entered':False,'release':False,'stage':stage,'restarted':False,'arrivals':0}
    return {'armed':True}
@app.get('/barrier/{op}')
async def barrier(op: str): return armed.get(op,{})
@app.post('/release/{op}')
async def release(op: str):
    armed[op]['release']=True
    return {'released': True}
@app.post('/restart_complete/{op}')
async def restart_complete(op: str):
    armed[op]['restarted']=True
    return {'restarted':True}

async def wait_stage(op, stage):
    state=armed.get(op)
    if state is not None and state['stage']==stage:
        state['entered']=True
        state['arrivals']+=1
        while not state['release']:
            await asyncio.sleep(.02)
    return {'arrived':True}
@app.post('/arrive')
async def arrive(p: Payload): return await wait_stage(p.operation_id, 'before_effect')
@app.post('/checkpoint')
async def checkpoint(p: Payload): return await wait_stage(p.operation_id, 'after_effect')
@app.post('/ack/{op}')
async def ack(op: str): return await wait_stage(op, 'before_ack')
@app.post('/effect')
async def effect(p: Payload):
    with sqlite3.connect(path) as db:
        db.execute('insert into events(body,ns) values (?,?)',(p.model_dump_json(), time.time_ns()))
    return {'recorded':True}
@app.get('/events')
async def events():
    with sqlite3.connect(path) as db:
        return {'events':[{'seq':seq,'body':json.loads(body),'ns':ns} for seq,body,ns in db.execute('select seq,body,ns from events order by seq')]}

# An instrumented host-store barrier, reached before either SQLite CAS starts.
claims={}
@app.post('/claim-arm/{op}')
async def claim_arm(op: str):
    claims[op]={'arrivals':[], 'outcomes':[], 'released':False}
    return {'armed':True}
@app.get('/claim-state/{op}')
async def claim_state(op: str): return claims.get(op,{})
@app.post('/claim-arrival')
async def claim_arrival(body: dict):
    state=claims.get(body['operation_id'])
    if state is None: return {'armed':False}
    state['arrivals'].append({**body,'recorder_ns':time.monotonic_ns()})
    if len(state['arrivals']) == 2:
        state['released']=True
        state['release_ns']=time.monotonic_ns()
    for _ in range(250):
        if state['released']: return {'armed':True,'released':True}
        await asyncio.sleep(.02)
    return {'armed':True,'released':False}
@app.post('/claim-outcome')
async def claim_outcome(body: dict):
    state=claims.get(body['operation_id'])
    if state is None: return {'recorded':False}
    state['outcomes'].append({**body,'recorder_ns':time.monotonic_ns()})
    return {'recorded':True}
