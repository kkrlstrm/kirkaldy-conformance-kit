"""Private self-hosted Datalayer study; no vendor source changes or hosted calls.

Uses the pinned SDK's real CompanyService/ASGI and client/OAuth code. The host
contributes a harmless downstream executor which writes to a separate recorder process.
"""
import asyncio
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

import httpx
import pytest
pytest.importorskip('personal_agent_protocol')
from reactor import PluginManifest
from personal_agent_protocol.__version__ import __version__
from personal_agent_protocol import DiscoveryClient, SessionClient
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.errors import TransportError
from personal_agent_protocol.company import ActionResult, build_company, company_app
from personal_agent_protocol.demo.kit import ClockPlugin
from personal_agent_protocol.demo.manzanita import CONFIG, DOMAIN, ManzanitaPlugin
from personal_agent_protocol.extensions import negotiate_extensions
from personal_agent_protocol.models import Approval
from personal_agent_protocol.__tests__.test_company_end_to_end import World, PAIRWISE, TENANT
from personal_agent_protocol.__tests__.test_company_refusals import signed_in

ROOT = Path(__file__).resolve().parents[3]
EXCHANGE = 'https://manzanita.example/api/orders/ord_7Hk2/exchanges'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture
def observer(tmp_path):
    url = f'http://127.0.0.1:{free_port()}'
    proc = subprocess.Popen([sys.executable, str(ROOT/'targets/poppy_lab/lab.py'), 'recorder', '--db', str(tmp_path/'recorder.db'), '--port', url.rsplit(':',1)[1]], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError(proc.stderr.read().decode())
        try:
            with urlopen(url+'/events', timeout=1) as response:
                if response.status == 200:
                    break
        except (OSError, URLError):
            time.sleep(.02)
    else:
        proc.terminate()
        raise RuntimeError('independent recorder failed to start')
    yield url
    proc.terminate()
    proc.wait(timeout=5)
    proc.stderr.close()


class ExternalRecorderExecutor:
    action = 'orders.exchange'
    def __init__(self, observer):
        self.observer = observer
    async def perform(self, operation, account_id):
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            response = await client.post(self.observer+'/effect', json={'operation_id':operation.operation_id, 'terms':{'operation_terms':operation.terms, 'account_id':account_id, 'revision':operation.revision}})
            response.raise_for_status()
        # Keep the actual SDK execution path in flight so racing calls overlap.
        await asyncio.sleep(.15)
        return ActionResult(summary='Synthetic exchange recorded.', data={'operation_id':operation.operation_id})


class DoubleEffectExecutor(ExternalRecorderExecutor):
    """Host-level bad backend verifies the observer can detect duplicate effects."""
    async def perform(self, operation, account_id):
        await super().perform(operation, account_id)
        return await super().perform(operation, account_id)


class StudyWorld(World):
    async def signed_out_session(self):
        self.company = await DiscoveryClient(reactor=self.reactor, http_client=self.http, protocol_versions=('0.4','1.0')).discover('manzanita.example')
        assert self.company.session_version == '1.0'
        self.who = {'tenant_id':TENANT, 'issuer':self.company.oauth_metadata.issuer}
        return await SessionClient(reactor=self.reactor, http_client=self.http).start(client_id=self.atlas.client_id, pairwise_user_id=PAIRWISE, issuer=self.company.oauth_metadata.issuer, tenant_id=TENANT, company=self.company, extensions=negotiate_extensions(self.company.document.extensions, supported=self.atlas.supported_extensions))


async def make_world(observer, executor=ExternalRecorderExecutor):
    assert __version__ == '0.35.0'
    world = StudyWorld()
    plugin = ManzanitaPlugin()
    # An explicit SDK host contribution: no SDK source or verifier is modified.
    plugin.executor = executor(observer)
    config = replace(CONFIG, protocol_versions=('0.4','1.0'))
    world.shop = build_company(config, http_client=world.network.client(), address_resolver=world.network.resolve, plugins=[(PluginManifest(name='study-host',version='1'),plugin), (PluginManifest(name='study-clock',version='1'),ClockPlugin(world.clock))])
    world.plugin = plugin
    world.network.add(DOMAIN, company_app(world.shop))
    token = await signed_in(world)
    assert world.session.protocol_version == '1.0'
    return world, world.session, token, ApiClient(transport=world.transport)


async def events(observer, operation_id):
    async with httpx.AsyncClient(trust_env=False) as client:
        rows = (await client.get(observer+'/events')).json()['events']
    return [r for r in rows if r['operation_id'] == operation_id]


def evidence(tmp_path, **values):
    (tmp_path/'observations.json').write_text(json.dumps(values, indent=2, default=str)+'\n')


def approval(op):
    return Approval(operation_id=op.operation_id, revision=op.revision, approver='user')


async def ask(api, session, token, body=None):
    result = await api.call('POST', EXCHANGE, session=session, token=token, body={} if body is None else body)
    assert result.status == 403 and result.operation is not None
    return result.operation


@pytest.mark.asyncio
async def test_unapproved_then_valid_then_replay(observer, tmp_path):
    world, session, token, api = await make_world(observer)
    op = await ask(api, session, token)
    assert await events(observer, op.operation_id) == []
    first = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op), idempotency_key='first')
    assert first.status == 200
    observed = await events(observer, op.operation_id)
    assert len(observed) == 1 and observed[0]['terms']['revision'] == op.revision
    retry = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op), idempotency_key='different')
    assert retry.status == 200 and retry.body == first.body
    assert len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-01/02/16', operation_id=op.operation_id, unapproved_effects=0, first_status=first.status, retry_status=retry.status, first_body=first.body, retry_body=retry.body, effects=await events(observer,op.operation_id))


@pytest.mark.asyncio
async def test_changed_request_and_original_revision(observer, tmp_path):
    world, session, token, api = await make_world(observer)
    # The changed form can independently execute, so a rejection isn't a schema failure.
    changed_control = await ask(api, session, token, {'size':'L'})
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={'size':'L'}, approval=approval(changed_control))).status == 200
    assert len(await events(observer, changed_control.operation_id)) == 1
    op = await ask(api, session, token)
    changed = await api.call('POST', EXCHANGE, session=session, token=token, body={'size':'L'}, approval=approval(op))
    assert changed.status == 403 and changed.operation is not None
    assert changed.operation.operation_id == op.operation_id and changed.operation.revision != op.revision
    assert await events(observer, op.operation_id) == []
    # The spec permits preserving the earlier revision; this target exercises that branch.
    valid = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))
    assert valid.status == 200 and len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-04/18', changed_status=changed.status, changed_revision=changed.operation.revision, original_revision=op.revision, effects_before_original=0, original_status=valid.status, effects=await events(observer,op.operation_id), changed_control=await events(observer,changed_control.operation_id))


@pytest.mark.asyncio
async def test_expired_revision_is_not_executed(observer, tmp_path):
    world, session, token, api = await make_world(observer)
    control = await ask(api, session, token)
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(control))).status == 200
    assert len(await events(observer, control.operation_id)) == 1
    op = await ask(api, session, token)
    world.clock.value = op.expires_at + timedelta(seconds=1)
    token = await world.refreshed()
    result = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))
    assert result.status == 403 and result.operation is not None
    assert result.operation.revision != op.revision
    assert await events(observer, op.operation_id) == []
    evidence(tmp_path, case='OP-07', expired_status=result.status, approved_revision=op.revision, returned_revision=result.operation.revision, expired_effects=await events(observer,op.operation_id), control_effects=await events(observer,control.operation_id))


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid', ['revision', 'operation_id'])
async def test_unissued_approval_does_not_execute(observer, invalid, tmp_path):
    world, session, token, api = await make_world(observer)
    op = await ask(api, session, token)
    wrong = Approval(operation_id='op_unissued_000000000000' if invalid == 'operation_id' else op.operation_id, revision='rev_unissued_0000000000' if invalid == 'revision' else op.revision, approver='user')
    result = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=wrong)
    assert result.status == 403 and result.operation is not None
    assert await events(observer, op.operation_id) == []
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))).status == 200
    assert len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-06', variant=invalid, invalid_status=result.status, invalid_effects=0, control_effects=await events(observer,op.operation_id))


@pytest.mark.asyncio
async def test_approval_from_different_user_is_not_used(observer, tmp_path):
    world, session, token, api = await make_world(observer)
    other = await SessionClient(reactor=world.reactor, http_client=world.http).start(client_id=world.atlas.client_id, pairwise_user_id='usr_other_at_manzanita_000000', issuer=session.issuer, tenant_id=TENANT, protocol_version='1.0', extensions=session.extensions)
    assert other.sid != session.sid and other.sub != session.sub
    # The alternate signed Session and token can make its own approved request.
    control = await ask(api, other, token)
    assert (await api.call('POST', EXCHANGE, session=other, token=token, body={}, approval=approval(control))).status == 200
    assert len(await events(observer, control.operation_id)) == 1
    op = await ask(api, session, token)
    answer = await api.call('POST', EXCHANGE, session=other, token=token, body={}, approval=approval(op))
    assert answer.status == 403 and answer.operation is not None
    assert answer.operation.operation_id != op.operation_id
    assert await events(observer, op.operation_id) == []
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))).status == 200
    assert len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-09-user', foreign_status=answer.status, foreign_operation_id=answer.operation.operation_id, original_operation_id=op.operation_id, foreign_effects_for_original=0, original_effects=await events(observer,op.operation_id), other_user_control=await events(observer,control.operation_id))


@pytest.mark.asyncio
async def test_missing_operations_negotiation_has_no_effect(observer, tmp_path):
    world, session, token, api = await make_world(observer)
    no_extension = replace(session, extensions={})
    async with httpx.AsyncClient(trust_env=False) as client:
        before = (await client.get(observer+'/events')).json()['events']
    with pytest.raises(ApiError) as error:
        await api.call('POST', EXCHANGE, session=no_extension, token=token, body={})
    assert error.value.status_code == 403 and error.value.code == 'extension_required'
    async with httpx.AsyncClient(trust_env=False) as client:
        assert (await client.get(observer+'/events')).json()['events'] == before
    op = await ask(api, session, token)
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))).status == 200
    assert len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-12', unnegotiated_status=error.value.status_code, error=error.value.code, unnegotiated_effects=0, control_effects=await events(observer,op.operation_id))


@pytest.mark.asyncio
async def test_harness_detects_deliberate_double_effect_backend(observer, tmp_path):
    world, session, token, api = await make_world(observer, executor=DoubleEffectExecutor)
    op = await ask(api, session, token)
    assert await events(observer, op.operation_id) == []
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))).status == 200
    # The host backend is deliberately faulty. This is not a finding against Datalayer.
    assert len(await events(observer, op.operation_id)) == 2
    evidence(tmp_path, case='observer-bad-backend-control', outcome='detected_two_effects', effects=await events(observer,op.operation_id))


@pytest.mark.asyncio
async def test_unreachable_recorder_leaves_control_inconclusive(observer, tmp_path):
    world, session, token, api = await make_world(f'http://127.0.0.1:{free_port()}')
    op = await ask(api, session, token)
    try:
        await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))
    except (ApiError, TransportError, httpx.RequestError):
        pass
    # The observer path did not hold; zero observed effects is not a target verdict.
    assert await events(observer, op.operation_id) == []
    evidence(tmp_path, case='no-control', outcome='inconclusive', reason='configured downstream recorder unreachable; no valid control')


@pytest.mark.asyncio
@pytest.mark.parametrize('n', [2, 8, 32, 128])
async def test_concurrent_retries(observer, n, tmp_path):
    world, session, token, api = await make_world(observer)
    control = await ask(api, session, token)
    assert (await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(control))).status == 200
    assert len(await events(observer, control.operation_id)) == 1
    op = await ask(api, session, token)
    gate = asyncio.Event()
    async def send():
        await gate.wait()
        try:
            result = await api.call('POST', EXCHANGE, session=session, token=token, body={}, approval=approval(op))
            return result.status
        except ApiError as exc:
            return exc.status_code
    tasks = [asyncio.create_task(send()) for _ in range(n)]
    await asyncio.sleep(0)
    gate.set()
    statuses = await asyncio.gather(*tasks)
    assert all(code in (200, 503) for code in statuses), statuses
    assert 200 in statuses and 503 in statuses and len(await events(observer, op.operation_id)) == 1
    evidence(tmp_path, case='OP-03', workers=n, statuses=statuses, effects=await events(observer,op.operation_id), control_effects=await events(observer,control.operation_id))
