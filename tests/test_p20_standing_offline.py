"""P20 (KRK-20, standing verifiable offline) against its vectors and toys
(`known_bad/standing_toys.py`): the formats read as the hand-written vectors say, the correct B
passes at the method's counts on a virtual clock in both standing profiles, each flaw fails the
variant it is built for, the toy whose executor never reaches the recorder gives no verdict, and
a short real-time run agrees with the virtual-clock run."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import receipts, requester, standing, status  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p20_standing_offline as p20  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.standing_toys import FAILS, FLAWS, FORM, ToyStanding, make, toy  # noqa: E402

VEC = json.loads((Path(__file__).parent / "vectors" / "krk20" / "vectors.json").read_text())
DEV = {"trials": "dev"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, tag="t", *, plan=None, seed=11):
    ev = Evidence("p20", t.name, "P20", t.config.replace(":", "-"))
    t.start()
    try:
        return p20.probe(t, ev, run_tag=tag, seed=seed, plan=plan)
    finally:
        t.stop()


def _checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def _forms(r, variant):
    return r.extra["forms"][variant]


# --------------------------------------------------------------------------- the vectors


def _pinned(names):
    return {n: bytes.fromhex(VEC["keys"][n]) for n in names}


def test_vectors_verify_as_written_by_hand():
    for v in VEC["verify"]:
        got = standing.verify(v["token"], _pinned(v["pinned"]), v["typ"])
        assert got.reason == v["reason"], (v["case"], got.reason, got.detail)


def test_vectors_key_state():
    sets = {VEC["keyset"]["claims"]["version"]: VEC["keyset"]["claims"],
            VEC["keyset"]["revoked"]["version"]: VEC["keyset"]["revoked"]}
    for v in VEC["key_state"]:
        t = standing.epoch_of(v["signed_at"]) if v["signed_at"] else None
        got, _why = standing.key_state(sets[v["keyset_version"]], v["kid"], v["purpose"], t)
        assert got == v["expected"], v


def test_vectors_standing_state():
    sets = {VEC["keyset"]["claims"]["version"]: VEC["keyset"]["claims"],
            VEC["keyset"]["revoked"]["version"]: VEC["keyset"]["revoked"]}
    for v in VEC["standing"]:
        ks = sets[v["keyset_version"]]
        sv = standing.verify(v["token"], standing.keys_of(ks), standing.STANDING_TYP)
        # A signature by a key the statement does not list verifies under none of its keys; a
        # correct B reads that as the key link broken.
        claims = sv.claims if sv.ok else standing.peek(v["token"])
        assert sv.ok or sv.reason == "unpinned-key", v["case"]
        got = standing.standing_state(claims, kid=standing.header_of(v["token"])["kid"],
                                      keyset=ks, issuer=v["issuer"],
                                      principal=v["principal"], operation=v["operation"],
                                      audience=v["audience"], at=standing.epoch_of(v["at"]),
                                      T=v["T"])
        assert got["state"] == v["expected"], (v["case"], got)


def test_a_revoked_keys_claimed_time_may_be_trusted_or_refused():
    """For a revoked key's signature claimed before `since`, reading it as A's
    and refusing it are both conformant; every other vector has exactly one reading."""
    sets = {VEC["keyset"]["claims"]["version"]: VEC["keyset"]["claims"],
            VEC["keyset"]["revoked"]["version"]: VEC["keyset"]["revoked"]}
    both = 0
    for v in VEC["key_state"]:
        t = standing.epoch_of(v["signed_at"]) if v["signed_at"] else None
        ks = sets[v["keyset_version"]]
        want = {v["expected"], *v.get("also_conformant", [])}
        assert set(standing.key_readings(ks, v["kid"], v["purpose"], t)) == want, v
        strict = standing.key_state(ks, v["kid"], v["purpose"], t, strict_revoked=True)[0]
        assert strict in want, v
        both += len(want) == 2
    for v in VEC["standing"]:
        ks = sets[v["keyset_version"]]
        sv = standing.verify(v["token"], standing.keys_of(ks), standing.STANDING_TYP)
        claims = sv.claims if sv.ok else standing.peek(v["token"])
        kw = dict(kid=standing.header_of(v["token"])["kid"], keyset=ks, issuer=v["issuer"],
                  principal=v["principal"], operation=v["operation"], audience=v["audience"],
                  at=standing.epoch_of(v["at"]), T=v["T"])
        want = {v["expected"], *v.get("also_conformant", [])}
        assert set(standing.standing_readings(claims, **kw)) == want, v["case"]
        both += len(want) == 2
    assert both == 2


def test_a_b_that_refuses_a_revoked_keys_backdated_signature_passes(monkeypatch):
    """Grading accepts the stricter reading: the correct B, made to refuse a revoked key's
    signature whatever time it claims, passes `retired_key` at the method's counts."""
    lenient = standing.key_state

    def strict(keyset, kid, purpose, signed_at, *, strict_revoked=True):
        return lenient(keyset, kid, purpose, signed_at, strict_revoked=strict_revoked)
    monkeypatch.setattr(standing, "key_state", strict)
    r = _run(make(), "strict-revoked", plan={**DEV, "variants": ["retired_key"]})
    assert r.status == Status.PASS, (r.summary, r.checks)
    assert _checks(r)["retired_key"][1] is True


def test_vectors_the_kit_reads_its_signing_log_not_the_claim():
    """KRK-M74: an issuer clock ahead by 120 s makes the claim young; the signing log does not."""
    s = VEC["skew"]
    ks = VEC["keyset"]["claims"]
    kw = dict(kid="a-standing", keyset=ks, issuer=s["assertion"]["issuer"],
              principal=s["assertion"]["principal"], operation="crm.record.push",
              audience="did:web:b.example", at=standing.epoch_of(s["at"]), T=60)
    assert standing.standing_state(s["assertion"], **kw)["state"] == s["by_claim"]
    assert standing.standing_state(s["assertion"], signed_at=standing.epoch_of(s["signed_at"]),
                                   **kw)["state"] == s["by_log"]


def test_vectors_holder_chains():
    anchors = {"did:web:a.example": VEC["keyset"]["claims"]}
    for name, v in VEC["chains"].items():
        hops, problem = standing.verify_holder_chain(v["tokens"], anchors)
        if v["expected_problem"] is None:
            assert problem is None, (name, problem)
            assert [h.signer.split(":")[0] for h in hops] == ["holder", "holder", "org"]
        else:
            assert problem and v["expected_problem"] in problem, (name, problem)


# --------------------------------------------------------------------------- the toys


def test_the_correct_b_passes_every_variant_at_the_methods_counts():
    r = _run(make())
    assert r.status is Status.PASS, r.summary
    ch = _checks(r)
    for v in p20.VARIANTS:
        assert ch[v][1] is True, (v, ch[v])
    st = r.extra["statistics"]["a_unreachable"]
    assert st["late"] == 0 and isinstance(st["p90_s"], float) and not any("mean" in k for k in st)
    assert r.extra["format_gaps"] == [] and r.extra["disclosure"] == "conformance"
    assert r.extra["offline_window_s"]["min"] > 0          # it acted offline
    assert ch["recovery"] == ("recovered", True)


def test_the_correct_b_in_the_x4_status_profile_passes_what_the_profile_can_say():
    r = _run(make(x4=True), "x4")
    assert r.status is Status.PASS, r.summary
    gaps = {(g["variant"], g["form"]) for g in r.extra["format_gaps"]}
    assert gaps == set(p20.X4_GAPS), gaps
    assert "Format gaps (findings, never a pass)" in r.summary
    assert _forms(r, "deep_chain")["three_hops"]["reading"] == "depth_refused"
    assert _forms(r, "agent_not_principal")["omitted"]["ok"] is True


def test_a_b_that_learns_keys_only_at_bind_fails_revoked_key():
    """A B with no way to learn A's key changes reads not refused within W."""
    r = _run(toy("x4-bad:pinned_once"), "x4p", plan={**DEV, "variants": ["retired_key"]})
    assert r.status is Status.FAIL
    assert _forms(r, "retired_key")["revoked_key"]["reading"] == "not_refused_within_W"
    assert _forms(r, "retired_key")["retired_before_bind"]["ok"] is True


@pytest.mark.parametrize("flaw", FLAWS)
def test_each_flaw_fails_the_variant_it_is_built_for(flaw):
    variant = FAILS[flaw]
    r = _run(make(flaw), flaw, plan={**DEV, "variants": [variant]})
    assert r.status is Status.FAIL, (flaw, r.summary)
    outcome, ok = _checks(r)[variant]
    assert ok is False, (flaw, variant, outcome)
    form = FORM.get(flaw)
    if form:
        assert _forms(r, variant)[form]["ok"] is False, (flaw, _forms(r, variant))


def test_online_only_is_a_fail_of_its_own_and_never_vulnerability_class():
    r = _run(make("online_only"), "oo", plan={**DEV, "variants": ["a_unreachable"]})
    assert _checks(r)["a_unreachable"] == ("online_only", False)
    assert r.extra["disclosure"] == "conformance"


def test_flaws_that_fail_more_than_their_own_variant_say_so():
    r = _run(make("leaf_standing_only"), "lso", plan={**DEV, "variants": ["other_organisation"]})
    assert _forms(r, "other_organisation")["c_standing"]["ok"] is False
    r = _run(make("any_pinned_key"), "apk", plan={**DEV, "variants": ["other_organisation"]})
    assert _forms(r, "other_organisation")["other_issuer"]["ok"] is False
    r = _run(make("issuer_unchecked"), "iu", plan={**DEV, "variants": ["key_of_other_org"]})
    assert _checks(r)["key_of_other_org"][1] is True      # the weak-check table, design §3.3


def test_no_control_gives_no_verdict():
    r = _run(ToyStanding("no-control"), "nc")
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_slow_good_passes():
    r = _run(ToyStanding("slow-good"), "sg", plan=DEV)
    assert r.status is Status.PASS, r.summary


def test_the_bad_toy_is_no_check():
    t = ToyStanding("bad")
    assert t.flaw == "no_check"
    r = _run(t, "bad", plan={**DEV, "variants": ["agent_not_principal"]})
    assert _checks(r)["agent_not_principal"] == ("accepted", False)


def test_the_toys_are_registered_with_the_known_bad_gate():
    from conformance import knownbad
    cases = dict(knownbad.cases("P20"))
    assert cases["good"] is Status.PASS and cases["no-control"] is Status.INCONCLUSIVE
    assert cases["x4-good"] is Status.PASS and cases["x4-bad:pinned_once"] is Status.FAIL
    assert {c for c in cases if c.startswith("bad:")} == {f"bad:{f}" for f in FLAWS}
    t = knownbad._toy("P20", "bad:trusts_expiry")
    assert isinstance(t, ToyStanding) and t.flaw == "trusts_expiry"


def test_every_token_presented_is_one_the_stubs_or_their_agents_signed():
    """Never forge: every grant hop and stapled assertion verifies under a
    key one of the stub organisations, or one of their agents, holds."""
    t = make()
    seen = []
    real = t.present
    t.present = lambda p, session=None: (seen.append(p), real(p, session=session))[1]
    r = _run(t, "nf", plan={**DEV, "variants": ["deep_chain", "agent_not_principal",
                                                "key_of_other_org", "retired_key"]})
    assert r.status is Status.PASS, r.summary
    keys = {}
    for o in t.orgs.values():
        for k in (o["keyset"] or {}).get("keys", []):
            keys[k["kid"]] = bytes.fromhex(k["public_key"])
    assert seen
    for p in seen:
        toks = [p.headers[requester.GRANT_HEADER]] + [
            x for x in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if x]
        anchors = {iss: o["keyset"] for iss, o in t.orgs.items()}
        _hops, problem = standing.verify_holder_chain(toks, anchors)
        assert problem is None, problem
        s = p.headers.get(standing.STANDING_HEADER)
        if s:
            kid = standing.header_of(s)["kid"]
            agents = {standing.peek(x)["agent_key"]["kid"]: bytes.fromhex(
                standing.peek(x)["agent_key"]["public_key"]) for x in toks}
            assert kid in keys or kid in agents, kid
            assert standing.verify(s, {**keys, **agents}, standing.STANDING_TYP).ok


def test_with_no_stated_bound_the_worst_case_is_the_effective_bound():
    t = make()
    t.withdrawal_bound = lambda: {"T_s": None, "source": "unstated", "quote": "not-found",
                                  "url": "", "setting": "", "recovery_s": None,
                                  "clock_tolerance_s": 5.0, "resolution_s": 0.001}
    r = _run(t, "u", plan={"trials": {"*": 1, "static": 1, "a_unreachable": 1,
                                      "a_unreachable/worst": 0},
                           "variants": ["a_unreachable"], "forms": {"a_unreachable": ["down"]},
                           "window_s": 300})
    assert "no stated bound" in r.summary and r.extra["finding"].startswith("no stated bound")


def test_a_standing_bound_larger_than_T_is_a_finding():
    t = make()
    t.standing_bound = lambda: {"T_s": 600.0, "source": "documented", "quote": "toy"}
    r = _run(t, "sb", plan={**DEV, "variants": ["agent_not_principal"]})
    assert any("more than its withdrawal bound" in f for f in r.extra["findings"])


def test_a_real_time_run_agrees_with_the_virtual_clock_run():
    plan = {"trials": {"*": 1, "static": 1, "a_unreachable": 1, "a_unreachable/worst": 0},
            "variants": ["a_unreachable", "agent_not_principal"],
            "forms": {"a_unreachable": ["down"], "agent_not_principal": ["omitted",
                                                                      "other_principal"]},
            "window_s": 8.0, "stability_s": 2.0}
    real = _run(ToyStanding("good", T=2.0, clock="real"), "rt", plan=plan)
    virt = _run(ToyStanding("good", T=2.0), "vt", plan=plan)
    assert real.status is Status.PASS, real.summary
    assert _checks(real) == _checks(virt)


def test_the_kit_profiles_root_grants_name_b_as_their_audience():
    """P20's grant 0.2 roots carry `audience: [B]`, as P21's do, so a B that
    requires a 0.2 chain to name it (the reference implementation's default) runs P20 at its default."""
    from conformance import attenuation
    from conformance.issuer import StubIssuer
    from conformance.timing import VirtualClock

    class R:
        counterparty = "did:web:b.example"
    c = p20._Run.root_constraints(R)
    assert c["audience"] == ["did:web:b.example"]
    assert {k: v for k, v in c.items() if k != "audience"} == p20.ROOT_CONSTRAINTS
    A = StubIssuer(clock=VirtualClock())
    A.serve_local()
    g = A.issue_v2("agent-x", c, principal="p@a")
    h = A.delegate_holder(g, "c1")
    assert attenuation.inside({"operation": p20.OPERATION, "amount": {
        "value": 100, "currency": "EUR", "minor_units": 2}}, attenuation.allowed(
            [h.claims, g.claims]), at=A.now(), tolerance_s=5.0, party="did:web:b.example") \
        is None
