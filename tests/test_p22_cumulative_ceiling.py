"""P22 (KRK-22, cumulative ceiling across counterparties) against its vectors, its stubs and its
toys (`known_bad/ceiling_toys.py`): the kit's account reads as the hand-written vectors say; the
kit's holder and spenders do exactly what their issuances allow; every correct toy passes in both
roles; each flaw fails the form it is built for and nothing it is not stated to fail; the toy
whose control cannot hold gives no verdict; over-counting is information."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import ceiling, ledger, standing  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.issuer import StubIssuer  # noqa: E402
from conformance.properties import p22_cumulative_ceiling as p22  # noqa: E402
from conformance.result import Status  # noqa: E402
from conformance.timing import VirtualClock  # noqa: E402
from known_bad import ceiling_toys as ct  # noqa: E402

VEC = json.loads((Path(__file__).parent / "vectors" / "krk22" / "vectors.json").read_text())
DEV = {"trials": "dev"}
E16 = 10 ** 16


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, tag, plan=None, seed=5):
    ev = Evidence("t", t.name, "P22", tag.replace(":", "-"))
    t.start()
    try:
        return p22.probe(t, ev, run_tag=tag[:8], seed=seed, plan=plan)
    finally:
        t.stop()


def _forms(r, variant):
    return r.extra["forms"].get(variant, {})


def _failing(r):
    return {(v, f) for v, d in r.extra.get("forms", {}).items() for f, x in d.items()
            if x["ok"] is False}


# --------------------------------------------------------------------------- the vectors


def test_vectors_quantity():
    for c in VEC["quantity"]:
        assert ceiling.quantity(c["values"], c["limit"]) == c["expected"], c


def _charges(case):
    return ceiling.charges(case["effects"], case["issuance"], ceilings=case["ceilings"],
                           default_ceiling_ids=list(case["ceilings"])[:1])


def test_vectors_accounts():
    for c in VEC["accounts"]:
        acc = ceiling.account(_charges(c), ceilings=c["ceilings"], rule=c["rule"])
        for cid, want in c["totals"].items():
            assert acc[cid]["totals"] == want, (c["name"], cid, acc[cid])
        got_unc = sorted({x for cid in acc for x in acc[cid]["uncountable"]})
        assert got_unc == sorted(c["uncountable"]), c["name"]


def test_vectors_judge():
    accounts = {c["name"]: c for c in VEC["accounts"]}
    for j in VEC["judge"]:
        c = accounts[j["account"]]
        out = ceiling.judge(_charges(c), c["ceilings"], rule=c["rule"],
                            overshoot=j["overshoot"])
        assert out["within"] is j["within"], (j["name"], out)
        assert out["where"] == j["where"], (j["name"], out["where"])


def test_vectors_windows():
    for w in VEC["windows"]:
        cid = "cl-00000000000000e5"
        effects = [{"t_kit": t, "effect": {"ref": f"q{i}", "spender": "B1", "kind": "spend",
                                           "values": {"amount": {"value": cents,
                                                                 "currency": "EUR",
                                                                 "minor_units": 2}}}}
                   for i, (t, cents) in enumerate(w["charges"])]
        lim = {"kind": "amount", "value": w["limit_cents"], "currency": "EUR",
               "minor_units": 2}
        chs = ceiling.charges(effects, [{"ref": f"q{i}", "ceiling_ids": [cid]}
                                        for i in range(len(effects))],
                              ceilings={cid: {"limits": [lim]}})
        ok, worst = ceiling.window_feasible(chs, 0, cid, w["window"], w["limit_cents"] * E16,
                                            anchor_kit=w["anchor_kit"],
                                            tolerance_s=w["tolerance_s"],
                                            commit_lag_s=w["commit_lag_s"])
        assert ok is w["passes"], (w["name"], worst)


def test_vectors_attribution():
    cid = "cl-00000000000000f6"
    lim = {"kind": "amount", "value": 100000, "currency": "EUR", "minor_units": 2}
    for a in VEC["attribution"]:
        effects = [{"t_kit": float(i), "effect": {"ref": f"q{i}", "spender": "B", "kind":
                                                  "spend", "values": {"amount": {
                                                      "value": c, "currency": "EUR",
                                                      "minor_units": 2}}}}
                   for i, c in enumerate(a["spends_cents"])]
        chs = ceiling.charges(effects, [{"ref": f"q{i}", "ceiling_ids": [cid]}
                                        for i in range(len(effects))],
                              ceilings={cid: {"limits": [lim]}})
        conf = [{"kind": k, "ceiling_ids": [cid], "quantity": [
            {"kind": "amount", "value": v, "currency": "EUR", "minor_units": 2}]}
            for k, v in a["confirmations"]]
        att = ceiling.attribution(chs, conf, "B", limits=[lim], ceiling_id=cid)
        assert bool(att["over"]) is a["over"], (a["name"], att)


# --------------------------------------------------------------------------- the formats


def _grant(cons):
    return {"schema": ceiling.GRANT_V3_SCHEMA, "grant_id": "gr-" + "a" * 16,
            "issuer": "did:web:a.example", "subject": "agent-1",
            "agent_key": {"kid": "k", "public_key": "ab" * 32}, "principal": "p@a.example",
            "constraints": cons, "parent": None, "issued_at": "2026-11-03T10:00:00.000Z",
            "not_before": "2026-11-03T09:00:00Z", "not_after": "2026-11-03T21:00:00Z",
            "status": {"source": "http://127.0.0.1:9/status/list", "index": 0}}


CUM = {"ceiling_id": "cl-" + "b" * 16,
       "limits": [{"kind": "amount", "value": 100000, "currency": "EUR", "minor_units": 2}],
       "window": None, "reversals": "gross", "holder": None, "share": None}


def test_grant_v3_reads_the_cumulative_member_and_0_2_refuses_it():
    from conformance import attenuation as att
    assert ceiling.grant_v3_problem(_grant({"cumulative": CUM})) is None
    g02 = {**_grant({"cumulative": CUM}), "schema": att.GRANT_V2_SCHEMA}
    assert att.grant_v2_problem(g02)[0] == att.UNKNOWN          # safe, a gap
    bad = _grant({"cumulative": {**CUM, "budget_hint": 1}})
    assert ceiling.grant_v3_problem(bad)[0] == ceiling.UNKNOWN
    assert ceiling.grant_v3_problem(_grant({"cumulative": {**CUM, "limits": []}}))[0] == \
        ceiling.MALFORMED
    share = {"spender": "B", "share_id": "sh-" + "c" * 16, "limits": [
        {"kind": "count", "value": 3, "unit": "message"}]}
    assert ceiling.grant_v3_problem(_grant({"cumulative": {**CUM, "share": share}}))[0] == \
        ceiling.MALFORMED                                         # limits only what C limits


def test_reservation_and_statement_round_trip():
    from conformance.receipts import Keypair
    k = Keypair.generate("h")
    q = [{"kind": "amount", "value": 5, "currency": "EUR", "minor_units": 2}]
    r = ceiling.reservation_claims(holder="H", ceiling_ids=["cl-" + "b" * 16], spender="B1",
                                   quantity=q, request_id="rq-1", not_after=1000, issued_at=1,
                                   reservation_id="rs-" + "d" * 16)
    tok = standing.sign(r, k, ceiling.RESERVATION_TYP)
    v = standing.verify(tok, {k.kid: k.public_bytes()}, ceiling.RESERVATION_TYP,
                        problem_of=ceiling.reservation_problem)
    assert v.ok and v.claims == r
    s = ceiling.spend_claims(spender="B1", kind="captured", ref="rs-" + "d" * 16,
                             ceiling_ids=["cl-" + "b" * 16], quantity=q, effect_ref="rq-1",
                             at=2)
    v = standing.verify(standing.sign(s, k, ceiling.SPEND_TYP), {k.kid: k.public_bytes()},
                        ceiling.SPEND_TYP, problem_of=ceiling.spend_problem)
    assert v.ok
    assert ceiling.spend_problem({**s, "kind": "refunded"})


def test_every_fixture_means_what_it_says():
    import random
    for role in ("A", "B"):
        for variant in ("sum_across_bs", "sum_one_b"):
            for form in p22.ROLE_FORMS[role][variant]:
                for k in range(20):
                    f = p22.fixture(variant, form, random.Random(k), role=role,
                                    mechanism="reservation")
                    if role == "B":
                        f.share = f.share or 1
                    assert p22.truth(f)["checked"]
    f = p22.fixture("sum_across_bs", "sequential", random.Random(1), role="A",
                    mechanism="reservation")
    f.plan[0].values = p22.pay(f.C * 2)                           # above the per-request limit
    with pytest.raises(ValueError):
        p22.truth(f)
    f = p22.fixture("sum_across_bs", "sequential", random.Random(1), role="A",
                    mechanism="reservation")
    f.plan = [p22.Spend("B1", p22.pay(f.C // 2 + 10)), p22.Spend("B1", p22.pay(f.C // 2))]
    with pytest.raises(ValueError):                               # B1 above C/2 at the crossing
        p22.truth(f)


# --------------------------------------------------------------------------- the stubs


def _holder():
    c = VirtualClock()
    A = StubIssuer("did:web:a-test.example", clock=c, ttl_s=3600)
    A.serve_local()
    H = ledger.StubHolder(A, clock=c, expiry_s=20.0, tolerance_s=1.0, capture_lag_s=2.0)
    H.serve_local()
    return c, A, H


def test_the_stub_holder_is_idempotent_and_refuses_other_bytes():
    c, A, H = _holder()
    g = H.open_root("p@a", [p22.amount_limit(1000)])
    req = {"chain": list(g.chain), "spender": "B1", "values": p22.pay(600), "request_id": "r1"}
    a1 = H.reserve(req)
    assert a1["body"]["code"] == "authorised"
    assert H.reserve(req)["body"]["issuance"] == a1["body"]["issuance"]
    assert H.reserve({**req, "values": p22.pay(500)})["body"]["code"] == "conflict"
    assert H.reserve({**req, "request_id": "r2"})["body"]["code"] == "refused"   # over C


def test_the_stub_holder_counts_a_reservation_until_expiry_plus_tolerance_plus_lag():
    c, A, H = _holder()
    g = H.open_root("p@a", [p22.amount_limit(1000)])
    H.reserve({"chain": list(g.chain), "spender": "B1", "values": p22.pay(600),
               "request_id": "r1"})
    nxt = {"chain": list(g.chain), "spender": "B2", "values": p22.pay(600)}
    c.sleep(20.0 + 1.0 + 2.0 - 0.1)
    assert H.reserve({**nxt, "request_id": "r2"})["body"]["code"] == "refused"
    c.sleep(0.2)
    assert H.reserve({**nxt, "request_id": "r3"})["body"]["code"] == "authorised"
    assert any(x["kind"] == "expired" for x in H.confirmations("B1"))


def test_the_stub_holder_charges_every_ancestor():
    c, A, H = _holder()
    g = H.open_root("p@a", [p22.amount_limit(1000)])
    own = ledger.cumulative(ledger.new_ceiling_id(), [p22.amount_limit(1000)])
    child = ledger.delegate(A, g, "agent-2", own=own)
    H.learn(child)
    assert H.reserve({"chain": list(child.chain), "spender": "B1", "values": p22.pay(700),
                      "request_id": "r1"})["body"]["code"] == "authorised"
    assert H.reserve({"chain": list(g.chain), "spender": "B2", "values": p22.pay(700),
                      "request_id": "r2"})["body"]["code"] == "refused"


def test_the_stub_spender_executes_exactly_what_the_issuance_allows():
    """KRK-M99: no account of its own beyond the issuance; a refusal the issuance requires is
    not `stub_refused`."""
    from conformance.mockserver import MockServer
    c, A, H = _holder()
    rec = MockServer(clock=c.now)
    try:
        st = ledger.StubSpender("did:web:b1.example", recorder_url=rec.url + "/x", clock=c)
        st.bind_holder(H.anchor(), H.url)
        H.bind_spender(st.name, st.anchor())
        g = H.open_root("p@a", [p22.amount_limit(1000)])
        tok = H.reserve({"chain": list(g.chain), "spender": st.name, "values": p22.pay(600),
                         "request_id": "r1"})["body"]["issuance"]
        assert st.present({"issuance": tok, "values": p22.pay(700), "ref": "r1"})["body"][
            "code"] == "refused"                                   # beyond the reservation
        a = st.present({"issuance": tok, "values": p22.pay(600), "ref": "r1"})
        assert a["body"]["code"] == "executed"
        again = st.present({"issuance": tok, "values": p22.pay(1), "ref": "r1b"})
        assert again["body"]["code"] == "refused" and not again["body"]["stub_refused"]
        other = H.reserve({"chain": list(g.chain), "spender": "did:web:b2.example",
                           "values": p22.pay(10), "request_id": "r2"})["body"]["issuance"]
        assert st.present({"issuance": other, "values": p22.pay(10), "ref": "r2"})["body"][
            "code"] == "refused"                                   # addressed to another
        assert len(rec.effects("/x")) == 1
    finally:
        rec.close()


# --------------------------------------------------------------------------- the toys


@pytest.mark.parametrize("config", ["a-good", "b-good"])
def test_the_correct_toys_pass_at_published_counts(config):
    r = _run(ct.toy(config), config)
    assert r.status is Status.PASS, (config, r.summary)
    assert r.control_held is True
    race = r.extra["race"]
    assert race and all(k.startswith("concurrent/") for k in race), race   # not sum_one_b
    for k, v in race.items():
        assert v["overlapping_rounds"] >= 30, (k, v)
        assert v["bound_95"].startswith("at most 0.100")


@pytest.mark.parametrize("config", [f"a-{g}" for g in ct.GOOD_A if g != "good"] +
                         [f"b-{g}" for g in ct.GOOD_B if g != "good"])
def test_every_other_correct_toy_passes(config):
    r = _run(ct.toy(config), config, DEV)
    assert r.status is Status.PASS, (config, r.summary)


def _also(flaw, role):
    fails = ct.FAILS_A if role == "A" else ct.FAILS_B
    also = (ct.ALSO_FAILS_A if role == "A" else ct.ALSO_FAILS_B).get(flaw, set())
    return {fails[flaw]} | set(also)


def _stated(pair, allowed):
    v, f = pair
    return any((av in (v, "*")) and (af in (f, "*")) for av, af in allowed)


@pytest.mark.parametrize("flaw", ct.FLAWS_A)
def test_each_holder_flaw_fails_its_form_and_nothing_unstated(flaw):
    variant, form = ct.FAILS_A[flaw]
    r = _run(ct.make_a(flaw), f"a-{flaw}", DEV)
    assert r.status is Status.FAIL, (flaw, r.summary)
    assert _forms(r, variant)[form]["ok"] is False, (flaw, _forms(r, variant))
    extra = [x for x in _failing(r) if not _stated(x, _also(flaw, "A"))]
    assert not extra, (flaw, extra)


@pytest.mark.parametrize("flaw", ct.FLAWS_B)
def test_each_spender_flaw_fails_its_form_and_nothing_unstated(flaw):
    variant, form = ct.FAILS_B[flaw]
    r = _run(ct.make_b(flaw), f"b-{flaw}", DEV)
    assert r.status is Status.FAIL, (flaw, r.summary)
    assert _forms(r, variant)[form]["ok"] is False, (flaw, _forms(r, variant))
    extra = [x for x in _failing(r) if not _stated(x, _also(flaw, "B"))]
    assert not extra, (flaw, extra)


@pytest.mark.parametrize("config", ["a-no-control", "b-no-control"])
def test_no_control_gives_no_verdict(config):
    r = _run(ct.toy(config), config, DEV)
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_over_counting_is_information_in_both_roles():
    """A holder that charges a retry twice reads ``over_counted``; a spender that
    counts it twice refuses a spend that fits (``refused_within_ceiling``). Both pass."""
    r = _run(ct.toy("a-info:charges_retries"), "a-cr",
             {**DEV, "variants": ["retry"], "forms": {"retry": ["double_count"]}})
    assert r.status is Status.PASS, r.summary
    assert "over_counted" in r.extra["information"]["retry/double_count"]
    r = _run(ct.toy("b-info:charges_retries"), "b-cr",
             {**DEV, "variants": ["retry"], "forms": {"retry": ["double_count"]}})
    assert r.status is Status.PASS, r.summary
    assert "refused_within_ceiling" in r.extra["information"]["retry/double_count"]


def test_the_real_time_smoke_test_agrees_with_the_virtual_clock():
    plan = {**DEV, "variants": ["sum_across_bs", "concurrent"],
            "forms": {"sum_across_bs": ["sequential"], "concurrent": ["two_bs"]}}
    virt = _run(ct.ToyHolder("good"), "virt", plan)
    real = _run(ct.ToyHolder("good", clock="real"), "real", plan)
    assert virt.status is real.status is Status.PASS, (virt.summary, real.summary)
    bad = _run(ct.ToyHolder("bad", "check_then_set", clock="real"), "realbad", plan)
    assert bad.status is Status.FAIL
    assert _forms(bad, "concurrent")["two_bs"]["ok"] is False


def test_a_spender_that_reads_no_cumulative_member_is_not_applicable():
    """A format with no cumulative ceiling reads not applicable, with the gap a
    finding; in the kit's own format no target escapes this way (an unknown member is
    refused)."""
    class NoCeiling(ct.ToySpender):
        def ceiling_profile(self):
            return {}
    r = _run(NoCeiling("good"), "nc", DEV)
    assert r.status is Status.NOT_APPLICABLE and "cannot state a cumulative ceiling" in r.summary


def test_a_documented_hard_limit_makes_an_excess_vulnerability_class():
    r = _run(ct.make_a("per_b_counter"), "vc", {**DEV, "variants": ["sum_across_bs"]})
    assert r.extra["disclosure"] == "vulnerability"

    class Undocumented(ct.ToyHolder):
        def documents_hard_limit(self):
            return None
    r = _run(Undocumented("bad", "per_b_counter"), "vc2", {**DEV, "variants": ["sum_across_bs"]})
    assert r.status is Status.FAIL and r.extra["disclosure"] == "conformance"


def test_the_toys_are_registered_with_the_known_bad_gate():
    from conformance import knownbad
    cases = dict(knownbad.cases("P22"))
    assert cases["a-good"] is Status.PASS and cases["b-good"] is Status.PASS
    assert cases["a-no-control"] is Status.INCONCLUSIVE
    assert cases["b-no-control"] is Status.INCONCLUSIVE
    for f in ct.FLAWS_A:
        assert cases[f"a-bad:{f}"] is Status.FAIL
    for f in ct.FLAWS_B:
        assert cases[f"b-bad:{f}"] is Status.FAIL
    assert cases["a-info:charges_retries"] is Status.PASS
    assert len(cases) == len(ct.cases())
    assert knownbad._toy("P22", "b-bad:ignores_spender").flaw == "ignores_spender"


def test_every_role_form_has_a_driver():
    for role, vs in p22.ROLE_FORMS.items():
        for v, forms in vs.items():
            for f in forms:
                assert (role, v, f) in p22.FORM_FNS, (role, v, f)
                assert f in p22.FORMS[v]
