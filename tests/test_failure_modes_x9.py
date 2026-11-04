"""The measurement errors of P22 (X9, KRK-M96 to KRK-M112), each pinned to a test
that shows the reading its guard prevents (`docs/FAILURE-MODES.md`). All are anticipated. Kept
apart from `test_failure_modes.py` and `test_failure_modes_x1x5.py`, which P16 to P21 hash or
read, so P22's tests can change without touching theirs."""
import random

import pytest

pytest.importorskip("cryptography")

from conformance import ceiling, ledger  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p22_cumulative_ceiling as p22  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad import ceiling_toys as ct  # noqa: E402

DEV = {"trials": "dev"}
E16 = 10 ** 16
R, K1 = "cl-00000000000000a1", "cl-00000000000000b2"


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, tag, plan):
    ev = Evidence("pins", t.name, "P22", tag)
    return p22.probe(t, ev, run_tag=tag[:8], seed=9, plan=plan)


def _form(r, v, f):
    return r.extra["forms"][v][f]


def _eff(ref, spender, cents, t=1.0, **more):
    return {"t_kit": t, "effect": {"ref": ref, "spender": spender, "kind": "spend",
                                   "values": {"amount": {"value": cents, "currency": "EUR",
                                                         "minor_units": 2}}, **more}}


def _lim(cents):
    return {"kind": "amount", "value": cents, "currency": "EUR", "minor_units": 2}


def test_KRK_M96_counted_where_the_spend_landed_not_at_the_holder(monkeypatch):
    """A holder whose own account says nothing was spent still fails on the recorder's total;
    a correct holder whose account disagrees reads information, never a verdict."""
    monkeypatch.setattr(ct.ToyHolder, "account", lambda self, root: {"used": [0]})
    r = _run(ct.make_a("per_b_counter"), "f96", {**DEV, "variants": ["sum_across_bs"]})
    assert _form(r, "sum_across_bs", "sequential")["ok"] is False
    r = _run(ct.ToyHolder("good"), "f96g", {**DEV, "variants": ["sum_across_bs"],
                                            "forms": {"sum_across_bs": ["sequential"]}})
    assert r.status is Status.PASS
    assert "ledger_behind" in r.extra["information"]["sum_across_bs/sequential"]


def test_KRK_M97_refused_for_the_amount_is_not_refused_for_the_total():
    """Every spend lies inside every per-request limit (`truth`), and L runs the same amounts
    under twenty times the ceiling: a holder that refuses large spends whatever the total reads
    collateral_refusal, not held."""
    f = p22.fixture("sum_across_bs", "sequential", random.Random(3), role="A",
                    mechanism="reservation")
    f.plan[1].values = p22.pay(f.C + 1)
    with pytest.raises(ValueError, match="per-request"):
        p22.truth(f)

    class BigSpendRefuser(ct.ToyHolder):
        def _request(self, root, spender, values, **kw):
            if (values.get("amount") or {}).get("value", 0) > 30000:
                return ct._answer("refused", "above my per-request cap")
            return super()._request(root, spender, values, **kw)
    r = _run(BigSpendRefuser("good"), "f97", {**DEV, "variants": ["sum_across_bs"],
                                             "forms": {"sum_across_bs": ["sequential"]}})
    assert _form(r, "sum_across_bs", "sequential")["reading"] == "collateral_refusal"


def test_KRK_M98_a_race_that_never_overlapped_gives_no_reading():
    class OneAtATime(ct.ToyHolder):
        def max_in_flight(self):
            return 1
    r = _run(OneAtATime("bad", "check_then_set"), "f98",
             {**DEV, "variants": ["concurrent"], "forms": {"concurrent": ["two_bs"]}})
    d = _form(r, "concurrent", "two_bs")
    assert d["ok"] is None and "no_overlap" in d["reading"] + d["detail"]
    out = p22._overlap(type("R", (), {"max_in_flight": 8, "exposes_times": False,
                                      "yardstick": None})(), [{}, {}],
                       [{"t_sent": 1.0, "t_answered": 1.5}, {"t_sent": 1.6,
                                                             "t_answered": 2.0}])
    assert out["overlapped"] is False                 # the second left after the first answer


def test_KRK_M99_the_kits_stub_spender_is_no_hidden_enforcer():
    """A stub executes a valid issuance whatever the root's total (it keeps no account of the
    root), and a refusal the issuance did not require makes the trial give no reading."""
    from conformance.issuer import StubIssuer
    from conformance.mockserver import MockServer
    from conformance.timing import VirtualClock
    c = VirtualClock()
    A = StubIssuer("did:web:a-f99.example", clock=c, ttl_s=3600)
    A.serve_local()
    H = ledger.StubHolder(A, clock=c)
    H.serve_local()
    rec = MockServer(clock=c.now)
    try:
        st = ledger.StubSpender("did:web:b1.example", recorder_url=rec.url + "/x", clock=c)
        st.bind_holder(H.anchor(), H.url)
        H.bind_spender(st.name, st.anchor())
        g = H.open_root("p@a", [_lim(1000)])
        g2 = H.open_root("q@a", [_lim(1000)])
        toks = [H.reserve({"chain": list(x.chain), "spender": st.name, "values": p22.pay(900),
                           "request_id": f"r{i}"})["body"]["issuance"]
                for i, x in enumerate((g, g2))]
        for i, t in enumerate(toks):
            assert st.present({"issuance": t, "values": p22.pay(900), "ref": f"r{i}"})[
                "body"]["code"] == "executed"
    finally:
        rec.close()
    tr = type("T", (), {})()
    run = type("Run", (), {"bindings": {}, "terms": {}, "profile": {}, "role": "A",
                           "a": None})()
    side = p22._Side("W", 1000, [_lim(1000)], None, "gross")
    side.cids["root"] = (R,)
    side.ceilings[R] = {"limits": [_lim(1000)]}
    side.root = "x"
    t = p22._Trial.__new__(p22._Trial)
    t.run, t.f = run, p22.Fixture("sum_across_bs", "sequential", "A", 1000, [_lim(1000)])
    t.W, t.L = side, p22._Side("L", 20000, [_lim(20000)], None, "gross")
    t.info, t.rounds, t.not_landed, t.stub_refused, t.refused_fit = {}, [], None, ["r1"], []
    assert p22.judge_trial(t, []).outcome == "stub_refused"
    del tr


def test_KRK_M100_every_trial_has_a_fresh_root_principal_and_ceiling():
    seen = {"principal": set(), "ceiling": set(), "agent": set()}

    class Spy(ct.ToyHolder):
        def open_root(self, principal, limits, **kw):
            rid = super().open_root(principal, limits, **kw)
            seen["principal"].add(principal)
            seen["ceiling"].add(self.auths[rid]["cids"][0])
            return rid

        def request(self, root, spender, values, *, request_id, agent, **kw):
            seen["agent"].add(agent)
            return super().request(root, spender, values, request_id=request_id, agent=agent,
                                   **kw)
    _run(Spy("good"), "f100", {**DEV, "variants": ["sum_across_bs"],
                               "forms": {"sum_across_bs": ["sequential"]}})
    # control (1) + 3 trials x (W, L)
    assert len(seen["principal"]) == len(seen["ceiling"]) == 7
    assert len(seen["agent"]) == 7


def test_KRK_M101_the_kit_frees_headroom_only_as_a_fixture_step():
    calls = []

    class Spy(ct.ToyHolder):
        def cancel(self, root, issuance):
            calls.append("cancel")
            return super().cancel(root, issuance)

        def claim_reversal(self, root, effect_ref, values):
            calls.append("claim")
            return super().claim_reversal(root, effect_ref, values)
    _run(Spy("good"), "f101", {**DEV, "variants": ["sum_across_bs", "concurrent", "units"]})
    assert calls == []
    _run(Spy("good"), "f101b", {**DEV, "variants": ["reversal"],
                                "forms": {"reversal": ["claimed"]}})
    assert calls and set(calls) == {"claim"}


def test_KRK_M102_charges_are_placed_by_the_recorders_clock():
    """A statement or body time never places a charge: the recorder's kit-clock time does."""
    effs = [_eff("q1", "B1", 800, t=1018.0, at=5_000_000), _eff("q2", "B2", 800, t=1022.0,
                                                               at=0)]
    chs = ceiling.charges(effs, [{"ref": "q1", "ceiling_ids": [R]},
                                 {"ref": "q2", "ceiling_ids": [R]}], ceilings={R: {
                                     "limits": [_lim(1000)]}})
    assert [c.t_kit for c in chs] == [1018.0, 1022.0]
    ok, _w = ceiling.window_feasible(chs, 0, R, {"kind": "fixed", "period_s": 20,
                                                 "anchor_ms": 0}, 1000 * E16,
                                     anchor_kit=1000.0, tolerance_s=1.0)
    assert ok


def test_KRK_M103_a_boundary_pair_is_not_an_overspend():
    effs = [_eff("q1", "B1", 800, t=1019.0), _eff("q2", "B2", 800, t=1021.0)]
    iss = [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R]}]
    chs = ceiling.charges(effs, iss, ceilings={R: {"limits": [_lim(1000)]}})
    fixed = ceiling.window_feasible(chs, 0, R, {"kind": "fixed", "period_s": 20, "anchor_ms": 0},
                                    1000 * E16, anchor_kit=1000.0, tolerance_s=0.5)
    sliding = ceiling.window_feasible(chs, 0, R, {"kind": "rolling", "period_s": 20},
                                      1000 * E16, anchor_kit=1000.0, tolerance_s=0.5)
    assert fixed[0] is True and sliding[0] is False      # the fixed reading is the declared one
    r = _run(ct.ToyHolder("good"), "f103", {**DEV, "variants": ["window"],
                                            "forms": {"window": ["boundary"]}})
    assert _form(r, "window", "boundary")["ok"] is True


def test_KRK_M104_a_reversal_counts_only_from_the_recorder():
    effs = [_eff("q1", "B1", 500)]
    iss = [{"ref": "q1", "ceiling_ids": [R]}]
    c = {R: {"limits": [_lim(1000)]}}
    net = ceiling.account(ceiling.charges(effs, iss, ceilings=c), ceilings=c,
                          rule="net-recorded")
    assert net[R]["totals"] == [500 * E16]                # a claim the recorder never saw
    r = _run(ct.make_a("trusts_agent_reversal"), "f104",
             {**DEV, "variants": ["reversal"], "forms": {"reversal": ["claimed"]}})
    assert _form(r, "reversal", "claimed")["ok"] is False


def test_KRK_M105_totals_are_never_summed_across_units_by_the_kit():
    assert ceiling.quantity({"amount": {"value": 600, "currency": "EUR", "minor_units": 0}},
                            _lim(1000)) == 600 * 100 * E16
    assert ceiling.quantity({"amount": {"value": 600, "currency": "USD", "minor_units": 2}},
                            _lim(1000)) is None
    assert ceiling.quantity({"amount": {"value": 6.0, "currency": "EUR", "minor_units": 2}},
                            _lim(1000)) is None


def test_KRK_M106_a_commit_after_expiry_is_placed_past_the_spenders_tolerance():
    r = _run(ct.ToySpender("good"), "f106", {**DEV, "variants": ["reservation_expiry"]})
    assert _form(r, "reservation_expiry", "commit_after_expiry")["ok"] is True
    r = _run(ct.make_b("commits_after_expiry"), "f106b",
             {**DEV, "variants": ["reservation_expiry"]})
    assert _form(r, "reservation_expiry", "commit_after_expiry")["ok"] is False


def test_KRK_M107_a_partition_with_a_path_around_it_does_not_land(monkeypatch):
    from conformance import ledger as lg
    monkeypatch.setattr(lg.StubHolder, "set_reachable", lambda self, spender, mode: None)
    r = _run(ct.ToySpender("good"), "f107", {**DEV, "variants": ["partition"],
                                             "forms": {"partition": ["holder_unreachable"]}})
    d = _form(r, "partition", "holder_unreachable")
    assert d["ok"] is None and "KRK-M107" in d["detail"]


def test_KRK_M108_a_lost_report_lands_only_where_the_holder_takes_captures():
    r = _run(ct.ToyHolder("good-online"), "f108", {**DEV, "variants": ["partition"]})
    assert _form(r, "partition", "report_lost")["reading"] == "not_applicable"
    assert _form(r, "partition", "late_capture")["reading"] == "not_applicable"


def test_KRK_M109_the_sibling_has_its_own_principal_agent_and_ceiling():
    opened = []

    class Spy(ct.ToyHolder):
        def open_root(self, principal, limits, **kw):
            rid = super().open_root(principal, limits, **kw)
            opened.append((principal, self.auths[rid]["cids"][0]))
            return rid
    _run(Spy("good"), "f109", {**DEV, "variants": ["sum_across_bs"],
                               "forms": {"sum_across_bs": ["sequential"]}})
    pairs = opened[1:]
    for w, l in zip(pairs[0::2], pairs[1::2]):
        assert w[0] != l[0] and w[1] != l[1]


def test_KRK_M110_a_rate_limit_is_not_the_ceiling_holding():
    """A holder that rate-limits beyond two requests in flight passes the control (its round
    is two) and refuses part of every eight-way round, L's included: ``capacity_refused``,
    no reading, though its account would let the round overspend."""
    import threading

    class Limiter(ct.ToyHolder):
        _inflight = 0
        _lk = threading.Lock()

        def request(self, *a, **kw):
            with Limiter._lk:
                Limiter._inflight += 1
                busy = Limiter._inflight > 2
            try:
                if busy:
                    return {"status": 429, "body": {"code": "rate-limited"}}
                return super().request(*a, **kw)
            finally:
                with Limiter._lk:
                    Limiter._inflight -= 1
    r = _run(Limiter("bad", "check_then_set"), "f110",
             {**DEV, "variants": ["concurrent"], "forms": {"concurrent": ["n_way"]}})
    d = _form(r, "concurrent", "n_way")
    assert d["ok"] is None and "capacity_refused" in d["reading"] + d["detail"], d


def test_KRK_M111_a_childs_spend_is_charged_to_every_ceiling_on_its_chain():
    effs = [_eff("q1", "B1", 700), _eff("q2", "B2", 700, t=2.0)]
    iss = [{"ref": "q1", "ceiling_ids": [R]}, {"ref": "q2", "ceiling_ids": [R, K1]}]
    c = {R: {"limits": [_lim(1000)]}, K1: {"limits": [_lim(1000)]}}
    j = ceiling.judge(ceiling.charges(effs, iss, ceilings=c), c)
    assert j["within"] is False and j["totals"][R] == [1400 * E16]


def test_KRK_M112_a_ceiling_is_spent_only_once_in_force_and_the_fresh_form_keeps_the_case():
    r = _run(ct.make_a("lazy_ceiling"), "f112", {**DEV, "variants": ["sum_across_bs"]})
    assert _form(r, "sum_across_bs", "sequential")["ok"] is True       # waited
    assert _form(r, "sum_across_bs", "fresh_ceiling")["ok"] is False   # did not wait


def test_KRK_M210_every_declared_reversal_rule_is_judged_whatever_the_seed(monkeypatch):
    """`reversal/confirmed` takes the declared rules in turn, gross first, so the holder that nets
    reversals under `gross` fails on every seed. With the old seeded draw of the rule (the guard
    switched off), seed 38 draws `net-recorded` for all five trials and the flaw reads held."""
    from conformance import knownbad
    plan = {"trials": {"*": 5}, "variants": ["reversal"], "forms": {"reversal": ["confirmed"]}}

    def confirmed(seed):
        t = ct.make_a("nets_under_gross")
        with knownbad.toy_waits():
            r = p22.probe(t, Evidence("pins", t.name, "P22", f"f210-{seed}"), run_tag="f210",
                          seed=seed, plan=plan)
        return _form(r, "reversal", "confirmed")

    for seed in list(range(12)) + [38]:
        assert confirmed(seed)["ok"] is False, seed
    orig = p22._make_fixture

    def seeded_draw(run, variant, form, k=0):
        if (variant, form) == ("reversal", "confirmed"):
            rules = sorted(run.profile.get("reversals") or ["gross"])
            k = rules.index(run.rng.choice(rules))
        return orig(run, variant, form, k)

    monkeypatch.setattr(p22, "_make_fixture", seeded_draw)
    got = confirmed(38)
    assert got["ok"] is True and got["reading"] == "held"
