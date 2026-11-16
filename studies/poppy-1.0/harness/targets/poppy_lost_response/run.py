"""Run a single isolated test; caller holds /tmp/kirkaldy-docker.lock."""
import json, os, re, subprocess, sys, time
mode=sys.argv[1]
if mode not in ('target','bad','no-control','expiry'): raise SystemExit('target|bad|no-control')
expected='sha256:b722b69baf1c501e0ab7b0f10e6432e4db901747701094ad38ffc61d1c6b4f0c'
actual=subprocess.check_output(['docker','image','inspect','poppy-datalayer-integration:local','--format','{{.Id}}'],text=True).strip()
assert actual==expected
project='poppy-loss-'+mode+'-'+str(os.getpid()); env={**os.environ,'STORE':'sqlite','BAD_STORE':'1' if mode=='bad' else '0','NO_RECORDER':'0','RECORDER_PORT':'18991','CASE_MODE':mode}
base=['docker','compose','-p',project,'-f','targets/poppy_race/compose.yaml','-f','targets/poppy_lost_response/compose.yaml','-f','targets/poppy_lost_response/proxy.yaml']
if mode=='no-control': base+=['-f','targets/poppy_lost_response/outage.yaml']
if mode=='expiry': base+=['-f','targets/poppy_lost_response/expiry.yaml']
start=time.monotonic()
try:
 p=subprocess.run([*base,'up','--abort-on-container-exit','--exit-code-from','client'],env=env,text=True,capture_output=True,timeout=90)
 raw=re.sub(r'(/_test/approve_device/)[^\s"]+',r'\1[redacted]',p.stdout+'\n'+p.stderr)
 found=re.findall(r'LOSS_RESULT (\{[^\n]+\})',raw)
 ids={s:subprocess.check_output([*base,'ps','-aq',s],env=env,text=True).strip() for s in ('company','recorder','client','proxy')}
 images={k:subprocess.check_output(['docker','inspect','--format','{{.Image}}',v],text=True).strip() for k,v in ids.items()}
 result={'mode':mode,'exit':p.returncode,'containers':ids,'images':images,'seconds':round(time.monotonic()-start,3),'result':json.loads(found[-1]) if found else None,'proxy_responses':[json.loads(x) for x in re.findall(r'PROXY_RESPONSE (\{[^\n]+\})',raw)],'output':raw}
 print(json.dumps(result,indent=2,sort_keys=True))
 if p.returncode or not found: sys.exit(1)
finally: subprocess.run([*base,'down'],env=env,capture_output=True,text=True)
