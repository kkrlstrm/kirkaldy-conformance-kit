"""Verify persisted evidence and control requirements, without running a target."""
import json
import sys

d = json.load(open(sys.argv[1]))
assert not d.get('stopped'), d.get('stopped')
assert d['no_control']['verdict'] == 'INCONCLUSIVE'
assert d['no_control']['independent_effect_count'] == 0
events = d['recorder_events']
def count(op): return sum(e['body']['operation_id'] == op for e in events)
for row in d['broken']:
    assert row['w1_check'] == 'FAIL' and row['new_action_effects'] == 1
    assert count(row['control_operation']) == 1
    assert row['event_count_after_new'] - row['event_count_before_new'] == 1
    assert row['recorder_ns']['after_action'] - row['recorder_ns']['before_revoke'] >= 250_000_000
assert len(d['target']) == 3
for row in d['target']:
    assert row['w1_check'] == 'PASS' and count(row['control_operation']) == 1
    assert row['revocation_and_refresh']['refresh_error'] == 'invalid_grant'
    assert row['new_action_response'] == {'error':'invalid_token','status':401}
    assert row['new_action_effects'] == 0
    assert row['event_count_before_new'] == row['event_count_after_new']
    assert row['refusal_upper_bound_ms'] == (row['recorder_ns']['after_action']-row['recorder_ns']['before_revoke'])/1e6
p=d['prepared']; assert count(p['control_operation']) == 1 and count(p['operation']) == 0
assert p['agent_response'] == {'error':'invalid_token','status':401}
f=d['inflight']; assert count(f['control_operation']) == 1 and count(f['operation']) == 1
assert f['barrier_entered'] and f['concurrent_response']['status'] == 503
assert f['agent_response']['status'] == 200 and f['effects'] == 1
print('Verified: controls; three W1/W2 trials; W3 and W4 recorder counts.')
