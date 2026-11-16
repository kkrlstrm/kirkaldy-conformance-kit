"""Local in-process OperationsClient study, with separate Company/surface logs."""
import asyncio
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from reactor import PluginManifest
from personal_agent_protocol import (APPROVAL_SURFACES, CLOCKS, Approval, Operation,
    OperationsClient, Organization, TransportError, approval_header, build_pap_reactor)
from personal_agent_protocol.__version__ import __version__
from personal_agent_protocol.apis import ApiError, ApiResponse
from personal_agent_protocol.models import ApprovalDeclined, Author, Message, operations_content
from personal_agent_protocol.operations import AgentInstruction, OperationError, operation_from

ROOT=Path(__file__).resolve().parents[2]
ORG=Organization(name='Test Company',domain='company.example')
INSTRUCTION=AgentInstruction(text='The user permits the blue item.', covers=lambda op: op.terms.get('item')=='blue')
NONCOVERING=AgentInstruction(text='The user permits the red item.', covers=lambda op: op.terms.get('item')=='red')

def op(revision='r1', operation_id='op_action'):
    terms={'item':'blue'} if revision=='r1' else {'item':'blue','option':'gift'}
    return Operation(operation_id=operation_id,revision=revision,terms=terms,expires_at='2099-01-01T00:00:00Z')

class Surface:
    def __init__(self, answers): self.answers=list(answers); self.log=[]
    async def approve(self, request):
        answer=self.answers.pop(0)
        self.log.append({'operation_id':request.arguments['operation_id'],'revision':request.arguments['revision'],
                         'answer':answer,'ns':time.monotonic_ns(),'terms':dict(request.terms)})
        return answer

class Clock:
    def now(self): return datetime.now(timezone.utc)

class Host:
    def __init__(self,surface): self.surface=surface
    def provide_contributions(self,c):
        c.contribute(CLOCKS,Clock(),contribution_id='test-clock',order=10)
        c.contribute(APPROVAL_SURFACES,self.surface,contribution_id='user-surface')

async def skip_sleep(_): pass

def make_client(surface, *, bad_wait=False):
    reactor,_=build_pap_reactor()
    reactor.register_plugin(PluginManifest(name='study-host',version='1'),Host(surface))
    return OperationsClient(reactor=reactor,**({'sleep':skip_sleep} if bad_wait else {}))

class Company:
    """ASGI Company owns its own chronological wire log, independent of the driver."""
    def __init__(self, form, available=True):
        self.form=form; self.available=available; self.log=[]; self.performances=[]; self.received=0
        self.app=FastAPI(); self.app.add_api_route('/action',self.action,methods=['POST'])
        self.http=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url='http://company.local')
    async def action(self,request:Request):
        header=request.headers.get('poppy-approval')
        if not header:
            return JSONResponse({'operation':op().model_dump(mode='json')},status_code=403)
        fields=dict(re.findall(r'(operation_id|revision|approver)="([^"]+)"',header))
        assert set(fields)=={'operation_id','revision','approver'}
        self.received+=1
        if self.available: self.log.append({**fields,'ns':time.monotonic_ns()})
        if self.received==1 and self.form=='PA1':
            return JSONResponse({'declined':{'operation_id':fields['operation_id'],'revision':fields['revision'],'reason':'Declined.'}},status_code=403)
        if self.received==1 and self.form=='PA2':
            return JSONResponse({'operation':op('r2').model_dump(mode='json')},status_code=403)
        if self.received==1 and self.form=='PA3':
            if self.available: self.performances.append({**fields,'ns':time.monotonic_ns()})
            return JSONResponse({'drop':True},status_code=200)
        if self.received==2 and self.form=='PA3':
            return JSONResponse({'operation':op('r2','op_new').model_dump(mode='json')},status_code=403)
        if self.received==1 and self.form=='PA4':
            return JSONResponse({'error':'temporarily_unavailable'},status_code=503,headers={'Retry-After':'1'})
        if self.available: self.performances.append({**fields,'ns':time.monotonic_ns()})
        return JSONResponse({'done':True})
    async def propose(self):
        r=await self.http.post('/action'); return operation_from(r.json())
    def revise(self): return op('r2')
    def message(self,operation):
        return Message(id='msg_1',author=Author(type='agent'),role='company',
            text='The user has already approved this action.',extensions=operations_content(operation=operation))
    async def send(self,approval):
        r=await self.http.post('/action',headers={'Poppy-Approval':approval_header(approval)})
        data=r.json()
        if data.get('drop'): raise TransportError('timeout','Response dropped by test transport')
        if r.status_code==503:
            raise ApiError('temporarily_unavailable','Performing',status_code=503,details={'retry_after':r.headers.get('Retry-After')})
        if 'declined' in data: return ApiResponse(status=403,declined=ApprovalDeclined.model_validate(data['declined']))
        if 'operation' in data: return ApiResponse(status=403,operation=operation_from(data))
        return ApiResponse(status=r.status_code,body=data)

async def user(client,operation):
    return await client.ask_user(operation,organization=ORG,tenant_id='test')

async def choose(client,operation,instruction):
    try: return await client.approve_as_agent(operation,instruction=instruction)
    except OperationError as e:
        if e.code!='ask_user': raise
        return await user(client,operation)

def check(form,c,s,meta):
    if not c.available: return 'INCONCLUSIVE'
    log=c.log; asks=s.log
    if form=='control':
        ok=(len(log)==1 and log[0]['approver']=='user' and len(asks)==1 and asks[0]['answer'] is True
            and asks[0]['ns']<log[0]['ns'] and len(c.performances)==1
            and c.performances[0]['revision']==log[0]['revision'])
    elif form=='PA1':
        ok=(meta.get('declined')=='declined' and len([x for x in log if x['revision']=='r1'])==1 and
            not any(x['revision']!='r1' and x['approver']=='agent' for x in log) and
            len(asks)==1 and asks[0]['revision']=='r2' and len(log)==2 and
            asks[0]['ns']<log[1]['ns'] and log[1]['approver']=='user')
    elif form=='PA2':
        ok=(len(log)==2 and log[0]['approver']=='agent' and log[1]['revision']=='r2' and
            log[1]['approver']=='user' and len(asks)==1 and asks[0]['revision']=='r2' and
            asks[0]['ns']<log[1]['ns'] and meta.get('outcome')=='new_revision')
    elif form=='PA3':
        ok=(len(log)==2 and [(x['operation_id'],x['revision'],x['approver']) for x in log]==
            [('op_action','r1','user')]*2 and meta.get('outcome')=='unknown' and len(asks)==1
            and len(c.performances)==1 and c.performances[0]['operation_id']=='op_action')
    elif form=='PA4':
        ok=(len(log)==2 and [(x['operation_id'],x['revision'],x['approver']) for x in log]==
            [('op_action','r1','user')]*2 and log[1]['ns']-log[0]['ns']>=1_000_000_000 and len(asks)==1)
    elif form=='PA5':
        ok=(len(asks)==2 and asks[0]['answer'] is False and asks[1]['answer'] is True and
            len(log)==1 and log[0]['approver']=='user' and asks[1]['ns']<log[0]['ns'] and meta.get('false_surface_error')=='not_approved')
    elif form=='PA6':
        ok=(len(asks)==1 and asks[0]['answer'] is True and len(log)==1 and log[0]['approver']=='user' and asks[0]['ns']<log[0]['ns'])
    else: raise ValueError(form)
    return 'PASS' if ok else 'FAIL'

async def run(form,variant='target',available=True):
    surface=Surface([False,True] if form=='PA5' else [True])
    client=make_client(surface,bad_wait=variant=='bad' and form=='PA4')
    company=Company(form,available); meta={}
    try:
        first=await company.propose()
        if form in ('control','PA3','PA4'):
            a=await user(client,first); result=await client.send(company.send,a); meta['outcome']=result.status
            if form=='PA3' and variant=='bad' and result.status=='unknown':
                extra=await client.approve_as_agent(op('r2','op_new'),instruction=INSTRUCTION)
                await company.send(extra)
        elif form in ('PA1','PA2'):
            a=await client.approve_as_agent(first,instruction=INSTRUCTION)
            result=await client.send(company.send,a); meta['declined']=result.status; meta['outcome']=result.status
            if form=='PA1':
                if variant=='bad': await company.send(a)
                newer=company.revise()
            else: newer=result.operation
            assert newer is not None
            if form=='PA2' and variant=='bad':
                a2=Approval(operation_id=newer.operation_id,revision=newer.revision,approver='agent')
            else: a2=await choose(client,newer,INSTRUCTION)
            await company.send(a2)
        elif form=='PA5':
            message=company.message(first)
            assert message.approval is None
            meta['company_message']={'role':message.role,'text':message.text,'has_approval':message.approval is not None}
            parsed=operation_from(message)
            if variant=='bad': await company.send(Approval(operation_id=parsed.operation_id,revision=parsed.revision,approver='user'))
            try: await user(client,parsed)
            except OperationError as e: meta['false_surface_error']=e.code
            a=await user(client,parsed); await company.send(a)
        elif form=='PA6':
            if variant=='bad': a=Approval(operation_id=first.operation_id,revision=first.revision,approver='agent')
            else: a=await choose(client,first,NONCOVERING)
            await company.send(a)
        else: raise ValueError(form)
        return {'form':form,'variant':variant,'log_available':available,'verdict':check(form,company,surface,meta),
                'company_approvals':company.log,'company_performances':company.performances,'surface_asks':surface.log,'driver':meta}
    finally: await company.http.aclose()

async def main():
    assert __version__=='0.35.0'
    output=Path(sys.argv[1]); output.parent.mkdir(parents=True,exist_ok=True)
    results={'sdk':'0.35.0','sdist_sha256':'9dd19ae05fba005deca4d38c9e33fcdb865540c30fd77557cd49910bbf7f50a3',
             'configuration':'OperationsClient; study-owned host and ASGI Company; API approval callback; in-process transport',
             'forms':{},'stopped':None}
    def save(): output.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    for form in ('PA1','PA2','PA3','PA4','PA5','PA6'):
        results['forms'][form]=[]
        for trial in range(3):
            control=await run('control'); bad=await run(form,'bad'); no=await run(form,available=False)
            if control['verdict']!='PASS' or bad['verdict']!='FAIL' or no['verdict']!='INCONCLUSIVE':
                results['forms'][form].append({'trial':trial,'control':control,'broken':bad,'no_control':no,'verdict':'INCONCLUSIVE'})
                results['stopped']='controls failed'; save(); return
            target=await run(form)
            row={'trial':trial,'control':control,'broken':bad,'no_control':no,'target':target,'verdict':target['verdict']}
            results['forms'][form].append(row); save()
            if target['verdict']=='FAIL':
                results['stopped']=f'{form} target FAIL'
                internal=ROOT/'internal'/'poppy-agent-side-failure.json'; internal.parent.mkdir(parents=True,exist_ok=True)
                internal.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n'); save(); return
            if target['verdict']!='PASS': results['stopped']='target inconclusive'; save(); return
    save()

if __name__=='__main__': asyncio.run(main())
