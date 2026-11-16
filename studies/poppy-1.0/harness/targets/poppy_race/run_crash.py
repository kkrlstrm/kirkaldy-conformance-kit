"""Run one isolated kill/restart scenario against the study's own containers."""
import json, os, re, subprocess, sys, time, urllib.request

case=sys.argv[1]
if case not in ('before_effect','after_effect','before_ack'):
    raise SystemExit('expected before_effect, after_effect or before_ack')
bad=os.environ.get('BAD_STORE')=='1'
project='poppy-study-'+case.replace('_','-')+('-bad' if bad else '')+'-'+str(os.getpid())
env={**os.environ,'CASE':case,'STORE':'sqlite','RECORDER_PORT':'18972'}
base=['docker','compose','-p',project,'-f','targets/poppy_race/compose.yaml']
def run(*args,**kwargs):
    return subprocess.run([*base,*args],env=env,text=True,check=True,capture_output=True,**kwargs).stdout.strip()
def recorder(path, method='GET'):
    req=urllib.request.Request('http://127.0.0.1:18972'+path,method=method)
    with urllib.request.urlopen(req,timeout=2) as response: return json.load(response)
start=time.monotonic()
run('up','-d')
ids={role:run('ps','-q',role) for role in ('company','recorder','client')}
try:
    for _ in range(600):
        logs=run('logs','--no-color','client')
        found=re.search(r'CRASH_READY (\{[^\n]+\})',logs)
        if found: break
        status=subprocess.run(['docker','inspect','-f','{{.State.Status}}',ids['client']],text=True,capture_output=True,check=True).stdout.strip()
        if status=='exited': raise RuntimeError('client exited before crash barrier: '+logs[-3000:])
        time.sleep(.05)
    else: raise RuntimeError('crash barrier timeout')
    op=json.loads(found.group(1))['operation_id']
    before=json.loads(subprocess.check_output(['docker','inspect',ids['company']],text=True))[0]['State']
    subprocess.run(['docker','kill','--signal=KILL',ids['company']],check=True,capture_output=True,text=True)
    killed=json.loads(subprocess.check_output(['docker','inspect',ids['company']],text=True))[0]['State']
    subprocess.run(['docker','start',ids['company']],check=True,capture_output=True,text=True)
    for _ in range(200):
        try:
            subprocess.run(['docker','exec',ids['company'],'python','-c',"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/_test/ready',timeout=1)"],check=True,capture_output=True,timeout=2)
            break
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired): time.sleep(.05)
    else: raise RuntimeError('company did not restart')
    after=json.loads(subprocess.check_output(['docker','inspect',ids['company']],text=True))[0]['State']
    if bad:
        subprocess.run(['docker','exec',ids['company'],'python','-c',"import urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/_test/fault/on',method='POST'))"],check=True,capture_output=True,timeout=5)
    recorder('/release/'+op,'POST')
    recorder('/restart_complete/'+op,'POST')
    code=subprocess.check_output(['docker','wait',ids['client']],text=True,timeout=40).strip()
    logs=run('logs','--no-color')
    results=re.findall(r'RESULT (\{[^\n]+\})',logs)
    if code!='0' or not results: raise RuntimeError('client failed '+code+' '+logs[-4000:])
    result={'case':case,'known_bad_host_store':bad,'elapsed_seconds':round(time.monotonic()-start,3),'containers':ids,
            'company_before_started_at':before['StartedAt'],'killed_exit_code':killed['ExitCode'],
            'company_after_started_at':after['StartedAt'],'explicit_restarts':1,
            'network_requests': re.findall(r'network ((?:GET|POST) [^\s]+ [0-9]{3})',logs),
            'client_result':json.loads(results[-1]),
            'complete_sanitized_output':re.sub(r'(/_test/approve_device/)[^\s"]+',r'\1[redacted]',logs)}
    print(json.dumps(result,indent=2,sort_keys=True))
finally:
    run('down')
