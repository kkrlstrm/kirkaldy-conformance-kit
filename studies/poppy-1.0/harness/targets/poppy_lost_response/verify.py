"""Grade only the exact archived lost-response schedule and controls."""
import json, sys
from pathlib import Path
p=Path(sys.argv[1]); image='sha256:b722b69baf1c501e0ab7b0f10e6432e4db901747701094ad38ffc61d1c6b4f0c'
def load(n): return json.loads((p/n).read_text())
def check(r,mode):
 a=r['result']; z=r['proxy_responses']; before=a['events_before']; after=a['events_after']; control=a['control_events']
 assert r['exit']==0 and r['images']['company']==image and r['images']['recorder']==image
 assert a['mode']==mode and a['control_status']==200 and len(control)==1 and len(z)==1
 assert z[0]['status_line'].startswith('HTTP/1.1 200') and a['dropped_response']['error']=='TransportError'
 assert a['record_before_drop']['status']=='performed' and len(before)==1 and before[0]['body']['operation_id']==a['operation_id']
 if mode=='target':
  assert a['retry_status']==200 and z[0]['body']==a['retry_body'] and before==after and len(after)==1
 else: assert len(after)==2 and all(x['body']['operation_id']==a['operation_id'] for x in after)
for i in range(1,4):check(load(f'lost-response-target-{i}.json'),'target')
check(load('lost-response-bad.json'),'bad')
n=load('lost-response-no-control.json');assert n['exit']==0 and n['result']['verdict']=='inconclusive' and not n['proxy_responses'] and '/_test/down' in n['output']
e=load('lost-response-expiry.json')['result']['expiry_observation'];assert e and len(e['events'])==1
print(json.dumps({'target':'PASS','target_trials':3,'broken_host':'FAIL as expected','no_control':'INCONCLUSIVE','expiry':'observation only','all_checks':True},indent=2))
