"""Run isolated, preserve complete sanitized output and deterministic gate observations."""
import json, os, re, subprocess, sys, time
mode=sys.argv[1]
if mode not in ('good','bad','no-control'): raise SystemExit('good, bad or no-control')
project='poppy-cas-'+mode+'-'+str(os.getpid())
env={**os.environ,'STORE':'sqlite','RACE_MODE':'bad' if mode=='bad' else 'good',
     'RACE_CLIENT_MODE':mode,'RECORDER_PORT':'18976'}
base=['docker','compose','-p',project,'-f','targets/poppy_race/compose.yaml',
      '-f','targets/poppy_race/compose-race.yaml','--profile','multi']
start=time.monotonic()
try:
    run=subprocess.run([*base,'up','--abort-on-container-exit','--exit-code-from','client'],env=env,text=True,capture_output=True,timeout=120)
    elapsed=round(time.monotonic()-start,3)
    output=run.stdout+'\n'+run.stderr
    output=re.sub(r'(/_test/approve_device/)[^\s"]+',r'\1[redacted]',output)
    found=re.findall(r'RACE_RESULT (\{[^\n]+\})',output)
    if run.returncode or not found: raise RuntimeError('Docker run failed:\n'+output[-6000:])
    ids={s:subprocess.check_output([*base,'ps','-aq',s],env=env,text=True).strip() for s in ('company','company2','client','recorder')}
    result=json.loads(found[-1])
    expected='inconclusive' if mode=='no-control' else ('fail' if mode=='bad' else 'pass')
    expected_trials=1 if mode=='no-control' else 3
    if result['verdict']!=expected or len(result['trials'])!=expected_trials:
        raise RuntimeError('incomplete or unexpected verdict: '+str(result))
    for trial in result['trials']:
        if trial['verdict']!=expected: raise RuntimeError('unexpected trial verdict: '+str(trial))
        instances={a['instance'] for a in trial['gate']['arrivals']}
        if mode!='no-control' and instances!={ids['company'][:12],ids['company2'][:12]}:
            raise RuntimeError('barrier did not use both Company containers: '+str(instances))
    print(json.dumps({'mode':mode,'elapsed_seconds':elapsed,'containers':ids,
                      'result':result,'complete_sanitized_output':output},indent=2,sort_keys=True))
finally:
    subprocess.run([*base,'down'],env=env,text=True,capture_output=True)
