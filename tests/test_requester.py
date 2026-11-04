"""The stub A (`conformance/requester.py`): it never forges, it keeps fixture bytes as bytes, and
its transport presents each request once."""
import json
import urllib.error
import random
import urllib.request

import pytest

pytest.importorskip("cryptography")

from conformance import authz, requester  # noqa: E402
from conformance.mockserver import MockServer  # noqa: E402

AGREEMENT = {"counterparty": "did:web:b.example", "endpoints": ["orders", "orders-eu"],
             "aliases": {}, "tenants": ["t-17", "t-18"],
             "operations": {"crm.record.push": "exact", "notes.append": "class"},
             "binding_basis": authz.CANONICAL, "clock_tolerance_s": 60,
             "max_validity_s": 3600,
             "mappings": {"kirkaldy.map/crm-v1": {
                 "fields": {"op": "operation", "to": "recipient", "value": "amount",
                            "lines": "items", "ref": "ref"},
                 "values": {"operation": {"people.upsert": "crm.record.push"}}}}}


@pytest.mark.parametrize("variant", requester.VARIANTS)
def test_every_presentation_carries_a_token_the_stub_signed_byte_for_byte(variant):
    a = requester.StubRequester()
    plan = a.plan(variant, AGREEMENT, rng=random.Random(5))
    assert plan.gap is None, plan.gap
    issued = {i["token"] for i in a.issued}
    pinned = {a.key.kid: a.key.public_bytes()}
    ps = [s.presentation for s in plan.steps if s.op == "present"]
    ps += [p for s in plan.steps if s.op == "race" for p in s.presentations]
    assert ps
    for p in ps:
        assert isinstance(p.request, bytes)
        assert p.authorisation in issued, "a presented authorisation the stub never signed"
        assert authz.verify_authorisation(p.authorisation, pinned).ok
        assert "requester" not in json.dumps(p.headers)


def test_a_changed_body_is_presented_beside_the_unchanged_authorisation():
    a = requester.StubRequester()
    plan = a.plan("body_changed", AGREEMENT, rng=random.Random(1))
    r, changed = plan.requests["R"], plan.requests["R'"]
    assert changed.token == r.token and changed.raw != r.raw
    claims = authz.claims_of(r.token)
    assert claims["binding"]["request_digest"] == authz.binding_digest(r.raw)
    assert claims["binding"]["request_digest"] != authz.binding_digest(changed.raw)


def test_fixture_bytes_reach_the_presentation_unnormalised():
    """KRK-M37: the ambiguous fixtures are bytes no serialiser would write."""
    a = requester.StubRequester()
    dup = a.plan("duplicate_key", AGREEMENT, rng=random.Random(2)).requests["R-ambiguous"]
    assert authz.ambiguous(dup.raw) == "duplicate-key"
    num = a.plan("number_precision", AGREEMENT, rng=random.Random(2)).requests["R-2^53"]
    assert b"9007199254740993" in num.raw and authz.ambiguous(num.raw) == "unsafe-integer"
    eq = a.plan("noncanonical_equivalent", AGREEMENT, rng=random.Random(2))
    raw = eq.meta["fixture"]
    assert raw != eq.requests["R"].raw
    assert authz.binding_digest(raw) == authz.binding_digest(eq.requests["R"].raw)


def test_authorisation_ids_do_not_repeat_under_one_seed():
    ids = []
    for _ in range(2):
        a = requester.StubRequester()
        a.plan("replay_after_answer", AGREEMENT, rng=random.Random(9))
        ids += [i["authorisation_id"] for i in a.issued]
    assert len(set(ids)) == len(ids)


def test_the_transport_presents_once_and_can_drop_the_answer():
    calls = []
    t = requester.Transport(lambda p: calls.append(p.pid) or {"status": 200, "body": "ok"})
    p = authz.Presentation("p1", "orders", None, b"{}", None, {})
    assert t.send(p) == {"status": 200, "body": "ok"}
    assert t.send(p, drop_answer=True) is None
    assert calls == ["p1", "p1"] and t.sent("p1") == 2
    assert t.answers["p1"]["body"] == "ok"
    assert [e["dropped"] for e in t.wire_log] == [False, True]


def test_the_transport_records_a_raise_as_an_answer_and_never_retries():
    calls = []

    def boom(p):
        calls.append(p.pid)
        raise ConnectionError("reset")
    t = requester.Transport(boom)
    ans = t.send(authz.Presentation("p1", "orders", None, b"{}", None, {}))
    assert ans["status"] is None and "ConnectionError" in ans["raised"] and calls == ["p1"]


def test_release_together_starts_every_presentation_at_one_moment():
    m = MockServer()
    try:
        def present(p):
            urllib.request.urlopen(urllib.request.Request(
                f"{m.url}/effect/{p.pid}", data=p.request, method="POST")).read()
            return {"status": 200}
        t = requester.Transport(present)
        ps = tuple(authz.Presentation(f"p{i}", "orders", None, b"{}", None, {}) for i in range(5))
        t.release_together(ps)
        sent = [e["t_sent"] for e in t.wire_log]
        assert max(sent) - min(sent) < 0.2 and len(m.effects()) == 5
    finally:
        m.close()


def test_translate_uses_only_the_declared_mapping():
    v = {"operation": "crm.record.push", "ref": "r-1", "recipient": "x@y", "amount": 3,
         "items": ["a"]}
    b = requester.translate(v, AGREEMENT["mappings"]["kirkaldy.map/crm-v1"])
    assert b == {"op": "people.upsert", "ref": "r-1", "to": "x@y", "value": 3, "lines": ["a"]}


# --------------------------------------------------------------------------- X4 (KRK-19)

from conformance import status  # noqa: E402
from conformance.timing import VirtualClock  # noqa: E402

AUD = {"counterparty": "did:web:b.example", "endpoint": "orders", "tenant": None}


def _stub(**kw):
    a = requester.StubRequester(requester.new_issuer(), **kw)
    return a


def test_a_grant_and_both_request_forms_verify_under_the_stubs_own_keys():
    a = _stub()
    p = a.issue("agent-1", principal="alice")
    w = a.delegate(p, "agent-1", {"max_amount": 5000})
    pinned = {a.key.kid: a.key.public_bytes()}
    for g in (p, w):
        v = status.verify(g.token, pinned, status.GRANT_TYP)
        assert v.ok and v.claims["grant_id"] == g.id
    assert w.parent == p.id and a.chain(w) == [w, p]
    vals = requester.draw_values(random.Random(1))
    agent_signed = a.under(w, vals, audience=AUD)
    ak = a.agent("agent-1")
    v = authz.verify_authorisation(agent_signed.authorisation, {ak.kid: ak.public_bytes()})
    assert v.ok and v.claims["grant_id"] == w.id and v.claims["issuer"] == "agent-1"
    assert v.claims["binding"]["request_digest"] == authz.binding_digest(agent_signed.request)
    assert agent_signed.headers[requester.GRANT_HEADER] == w.token
    assert agent_signed.headers[requester.CHAIN_HEADER] == p.token
    a_signed = a.under(w, requester.draw_values(random.Random(2)), audience=AUD, signer="a")
    v = authz.verify_authorisation(a_signed.authorisation, pinned)
    assert v.ok and v.claims["grant_id"] == w.id and v.claims["issuer"] == a.issuer
    with pytest.raises(ValueError):
        a.delegate(w, "agent-1", {"max_amount": 6000})     # never wider than its parent


def test_withdrawal_is_timed_on_the_kit_clock_and_reads_back_in_bs_profile():
    vc = VirtualClock()
    a = _stub(clock=vc)
    a.serve_local()
    w = a.issue("agent-1", principal="alice")
    l = a.issue("agent-1", principal="alice")
    vc.sleep(3)
    before = a.current()["version"]
    wd = a.withdraw(w.id)
    assert wd.t_commit == vc.now() and wd.version == before + 1
    assert a.read_back({w.id: "revoked", l.id: "valid"}) == {w.id: True, l.id: True}
    code, tok = a.fetch_local()
    claims = status.verify(tok, {a.key.kid: a.key.public_bytes()}, status.STATUS_TYP).claims
    assert claims["entries"][w.id]["state"] == "revoked" and claims["version"] >= wd.version
    log = a.fetch_log()
    assert [e["client"] for e in log] == ["b"], "the baseline's reads are never in B's log"
    assert log[0]["t_start"] == vc.now() and log[0]["version"] == claims["version"]


def test_a_stale_snapshot_is_served_as_its_original_bytes_and_never_to_the_baseline():
    """An older snapshot the stub genuinely signed, unchanged."""
    a = _stub(clock=VirtualClock())
    a.serve_local()
    w = a.issue("agent-1", principal="alice")
    old = a.current()
    a.withdraw(w.id)
    a.set_source("stale", version=old["version"])
    assert a.fetch_local()[1] == old["profile_token"]
    assert a.fetch_log()[-1]["outcome"] == "stale"
    ok, tok, _ = a.baseline_read()
    assert ok and tok != old["profile_token"]
    assert a.read_back({w.id: "revoked"}) == {w.id: True}
    with pytest.raises(ValueError):
        a.set_source("stale", version=999)                  # only a snapshot it signed


def test_the_clock_offset_is_set_before_signing_and_moves_only_what_is_signed():
    """"""
    vc = VirtualClock()
    a = _stub(clock=vc)
    a.issue("agent-1", principal="alice")
    t0 = status.epoch_of(a.current()["issued_at"])
    a.set_clock_offset(300)
    rec = a.reissue()
    assert status.epoch_of(rec["issued_at"]) - t0 == pytest.approx(300, abs=0.01)
    assert rec["t_signed"] == vc.now(), "the kit clock is never offset"


def test_the_outage_modes_over_http():
    a = _stub()
    url = a.serve()
    try:
        a.hang_s = 1.0
        a.issue("agent-1", principal="alice")
        with urllib.request.urlopen(url, timeout=5) as r:
            assert r.status == 200 and r.headers["Cache-Control"] == "no-store"
        a.set_source("error")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(url, timeout=5)
        assert e.value.code == 503
        a.set_source("down")
        with pytest.raises(Exception):
            urllib.request.urlopen(url, timeout=5).read()
        assert not a.baseline_read()[0], "the outage applies to the baseline too (KRK-M59)"
        a.set_source("hang")
        with pytest.raises(Exception):
            urllib.request.urlopen(url, timeout=0.3).read()
        a.set_source("up")
        assert a.baseline_read()[0]
        outcomes = [e["outcome"] for e in a.fetch_log()]
        assert outcomes[:3] == ["ok", "error", "down"] and "hang" in outcomes
    finally:
        a.close()


def test_notices_are_signed_logged_and_droppable():
    import urllib.error  # noqa: F401
    a = _stub(clock=VirtualClock())
    got = []
    requester.LOCAL_RECEIVERS["local://b/notices"] = got.append
    try:
        a.push_to("local://b/notices")
        w = a.issue("agent-1", principal="alice")
        a.withdraw(w.id)
        v = status.verify(got[-1], {a.key.kid: a.key.public_bytes()}, status.NOTICE_TYP)
        assert v.ok and v.claims["entries"][w.id]["state"] == "revoked"
        a.set_source("push-drop")
        a.withdraw_standing("alice")
        assert a.push_log()[-1]["outcome"] == "dropped" and len(got) == 2
    finally:
        requester.LOCAL_RECEIVERS.pop("local://b/notices", None)


def test_a_binary_profile_records_the_narrowing_it_cannot_say_and_runs_it_as_reissue():
    """KRK-M62."""
    a = _stub(clock=VirtualClock(), status_profile=status.BITSTRING)
    a.serve_local()
    w = a.issue("agent-1", principal="alice")
    wd = a.narrow(w.id, {"max_amount": 100})
    assert wd.replacement and a.grants[wd.replacement].ceiling == {"max_amount": 100}
    assert any(g.get("state") == "narrowed" for g in a.format_gaps)
    assert a.read_back({w.id: "revoked", wd.replacement: "valid"}) == {
        w.id: True, wd.replacement: True}
    _, tok = a.fetch_local()
    assert status.typ_of(tok) == status.BITSTRING_TYP


def test_the_recorder_times_effects_on_the_kit_clock_and_can_hold_one():
    """Step 4 of the X4 build: commit times on the kit clock; a retriable answer for
    ``in_flight`` that commits nothing."""
    vc = VirtualClock()
    rec = MockServer(clock=vc.now)
    try:
        def post(ref):
            req = urllib.request.Request(f"{rec.url}/p19/x/effect/1", method="POST",
                                         data=json.dumps({"ref": ref}).encode())
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, None
            except urllib.error.HTTPError as e:
                return e.code, e.headers.get("Retry-After")
        assert post("r-1") == (200, None)
        rec.hold("r-2", 65)
        vc.sleep(5)
        assert post("r-2") == (503, "65")
        vc.sleep(65)
        assert post("r-2") == (200, None)
        eff = rec.effects("/p19/x")
        assert [(e["effect"]["ref"], e["t_kit"]) for e in eff] == [
            ("r-1", 10_000.0), ("r-2", 10_070.0)]
        held = rec.held("/p19/x")
        assert [(e["effect"]["ref"], e["t_kit"]) for e in held] == [("r-2", 10_005.0)]
    finally:
        rec.close()
