"""P19 (KRK-19, withdrawal within T) against its toys (`known_bad/withdrawal_toys.py`): the
correct B passes at the published trial counts on a virtual clock, each flaw fails the variant it
is built for, the toy whose executor never reaches the recorder gives no verdict, and a short
real-time smoke run agrees with the virtual-clock run."""
import pytest

pytest.importorskip("cryptography")

from conformance import authz, requester, status  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p19_withdrawal_within_t as p19  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.withdrawal_toys import FAILS, FLAWS, ToyWithdrawal, make  # noqa: E402

DEV = {"trials": "dev"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(toy, tag="t", *, plan=None, seed=11):
    ev = Evidence("p19", toy.name, "P19", toy.config.replace(":", "-"))
    toy.start()
    try:
        return p19.probe(toy, ev, run_tag=tag, seed=seed, plan=plan)
    finally:
        toy.stop()


def _checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def test_the_correct_b_passes_every_variant_at_the_published_counts():
    r = _run(make())
    assert r.status is Status.PASS, r.summary
    ch = _checks(r)
    for v in p19.VARIANTS:
        assert ch[v][1] is True, (v, ch[v])
    st = r.extra["statistics"]["withdrawn"]
    assert st["n_counted"] == 30 and st["late"] == 0 and isinstance(st["p90_s"], float)
    assert st["p99_s"] == "not estimable at N=30" and "3/30" in st["exceedance"]
    assert r.extra["statistics"]["worst_phase"]["n_counted"] == 5
    assert st["max_s"] <= 60 and r.extra["disclosure"] == "conformance"
    assert not any("mean" in k for k in st)


@pytest.mark.parametrize("flaw", FLAWS)
def test_each_flaw_fails_the_variant_it_is_built_for(flaw):
    variant = FAILS[flaw]
    plan = {"trials": {"withdrawn": 30, "*": 2}, "variants": sorted({variant, "withdrawn"})}
    if variant == "recovery":
        plan["variants"] = ["source_unreachable"]
    r = _run(make(flaw), flaw, plan=plan)
    assert r.status is Status.FAIL, (flaw, r.summary)
    outcome, ok = _checks(r)[variant]
    assert ok is False, (flaw, variant, outcome)


def test_flaws_that_fail_more_than_their_own_variant_say_so():
    """Recorded, as X3's toys were (design §13): these flaws are wider than one variant."""
    r = _run(make("checks_at_session_start"), "css", plan={**DEV, "variants": ["narrowed",
                                                                               "withdrawn"]})
    assert _checks(r)["narrowed"][1] is False and _checks(r)["withdrawn"][1] is True
    r = _run(make("fails_open"), "fo", plan={**DEV, "variants": ["stale_signed_snapshot"]})
    assert _checks(r)["stale_signed_snapshot"][1] is False


def test_no_control_gives_no_verdict():
    r = _run(ToyWithdrawal("no-control"), "nc")
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_the_bad_toy_is_no_check_and_is_never_called_never():
    r = _run(ToyWithdrawal("bad"), "bad", plan={**DEV, "variants": ["withdrawn"]})
    assert r.status is Status.FAIL
    assert _checks(r)["withdrawn"] == ("not_refused_within_W", False)
    assert "never" not in r.summary.lower().replace("never refused", "")


def test_the_toys_are_registered_with_the_known_bad_gate():
    from conformance import knownbad
    cases = dict(knownbad.cases("P19"))
    assert cases["good"] is Status.PASS and cases["no-control"] is Status.INCONCLUSIVE
    assert {c for c in cases if c.startswith("bad:")} == {f"bad:{f}" for f in FLAWS}
    toy = knownbad._toy("P19", "bad:leaf_only")
    assert isinstance(toy, ToyWithdrawal) and toy.flaw == "leaf_only"


def test_with_no_stated_bound_the_worst_case_is_reported_as_the_effective_bound():
    toy = make()
    toy.withdrawal_bound = lambda: {"T_s": None, "source": "unstated", "quote": "not-found",
                                    "url": "", "setting": "", "recovery_s": None,
                                    "clock_tolerance_s": 5.0, "resolution_s": 0.001}
    r = _run(toy, "u", plan={"trials": {"withdrawn": 3}, "variants": ["withdrawn"],
                             "window_s": 120})
    assert r.summary.startswith("Development plan") and "no stated bound; measured worst case" \
        in r.summary
    assert _checks(r)["withdrawn"] == ("refused_within_W", True)
    assert r.extra["finding"].startswith("no stated bound")
    assert r.extra["effective_bound_s"] == r.extra["statistics"]["withdrawn"]["max_s"]


def test_every_token_presented_is_one_the_stub_or_its_agents_signed():
    """Never forge: authorisations, grants and staples verify under the stub A's
    own key or an agent key the stub generated."""
    toy = make()
    seen = []
    real = toy.present
    toy.present = lambda p, session=None: (seen.append(p), real(p, session=session))[1]
    r = _run(toy, "nf", plan={**DEV, "variants": ["stale_signed_snapshot", "parent_withdrawn",
                                                 "presigned_after_withdrawal"]})
    assert r.status is Status.PASS, r.summary
    a_keys = {k: bytes(v) for k, v in toy.anchor["keys"].items()}
    for p in seen:
        g = status.verify(p.headers[requester.GRANT_HEADER], a_keys, status.GRANT_TYP)
        assert g.ok
        ak = g.claims["agent_key"]
        agent = {ak["kid"]: bytes.fromhex(ak["public_key"])}
        assert authz.verify_authorisation(p.authorisation, a_keys).ok or \
            authz.verify_authorisation(p.authorisation, agent).ok
        staple = p.headers.get(requester.STAPLE_HEADER)
        if staple:
            assert status.verify(staple, a_keys, status.STATUS_TYP).ok


def test_the_correct_b_reads_an_absent_grant_by_its_issue_time():
    """The correct toy holds a snapshot A signed 5 s ago that lists nothing. A grant
    issued 2 s ago is not yet listed there, so it is accepted until the toy's next fetch; a grant
    issued 10 s ago, before the snapshot, is absent from a snapshot signed after it, so it reads
    unknown and is refused. Under the earlier format the toy read both as valid (KRK-M46)."""
    from conformance import receipts
    from conformance.timing import VirtualClock
    toy = make()
    clk = VirtualClock(wall0=1_700_000_000.0)
    toy.set_clock(clk)
    now = clk.wall()
    toy.store.update(snap=status.snapshot_claims(
        issuer="did:web:a.example", source="s", version=3, issued_at=now - 5, ttl_s=30,
        entries={}, standing={}), fetched_at=now - 5)
    agent = receipts.Keypair.generate("agent-k")

    def grant(at):
        return status.grant_claims(
            issuer="did:web:a.example", audience="did:web:b.example", subject="agent-1",
            agent_kid=agent.kid, agent_public=agent.public_bytes(), principal="alice",
            operation="crm.record.push", ceiling={"max_amount": 10}, parent=None, issued_at=at,
            not_before=now - 3600, not_after=now + 3600, source="s", index=0)
    assert toy._status([grant(now - 2)], {"amount": 1}, None) is None
    why = toy._status([grant(now - 10)], {"amount": 1}, None)
    assert why and why.startswith("withdrawn: ") and "does not list it" in why


def test_a_role_a_adapter_and_a_forbidden_not_applicable_give_no_verdict():
    toy = make()
    toy.role = lambda: "A"
    assert _run(toy, "ra").status is Status.INCONCLUSIVE
    toy = make()
    toy.variants_not_applicable = lambda: {"source_unreachable": "we never lose the source"}
    r = _run(toy, "na")
    assert r.status is Status.INCONCLUSIVE and "may not be" in r.summary


def test_a_t_carried_in_protocol_data_never_decides_bs_verdict():
    """Protocol data is set by A, the stub."""
    toy = make()
    toy.withdrawal_bound = lambda: {"T_s": 60, "source": "carried"}
    r = _run(toy, "c", plan={"trials": {"withdrawn": 2}, "variants": ["withdrawn"],
                             "window_s": 120})
    assert "no stated bound" in r.summary and r.extra["bound"]["carried_T_s"] == 60
    assert _checks(r)["withdrawn"] == ("refused_within_W", True)


def test_real_time_smoke_agrees_with_the_virtual_clock_run():
    """The timing harness against real time: the correct toy and ``caches_decision`` at
    T = 2 s, one trial of ``withdrawn`` each, over HTTP, on time.monotonic."""
    plan = {"trials": {"withdrawn": 1}, "variants": ["withdrawn"], "window_s": 10,
            "stability_s": 3}
    got = {}
    for clock in ("real", "virtual"):
        for flaw in (None, "caches_decision"):
            r = _run(make(flaw, T=2.0, clock=clock), f"smoke-{clock}", plan=plan)
            got[(clock, flaw)] = (r.status, _checks(r)["withdrawn"])
            if clock == "real":
                assert r.extra["clock"] == "real"
    assert got[("real", None)] == (Status.PASS, ("refused_within_T", True))
    assert got[("real", "caches_decision")] == (Status.FAIL, ("refused_late", False))
    assert got[("real", None)] == got[("virtual", None)]
    assert got[("real", "caches_decision")] == got[("virtual", "caches_decision")]


def test_a_remote_b_gets_the_network_reported_and_is_never_charged_for_it():
    """An adapter whose B runs on other machines (`remote()` true) is pinged on the
    kit's clock; the result reports the round trips, and each effect after the withdrawal is
    bracketed between the recorder's receipt less the largest round trip (never before its
    presentation was sent) and the receipt. A local B has no network section and its readings
    are unchanged."""
    class Remote(ToyWithdrawal):
        def remote(self):
            return True

        def ping(self):
            return 0.25

    plan = {"trials": {"withdrawn": 3}, "variants": ["withdrawn"]}
    r = _run(Remote(), "net", plan=plan)
    assert r.status is Status.PASS, r.summary
    net = r.extra["network"]
    assert net["remote"] and net["rtt_max_s"] == 0.25 and net["effect_allowance_s"] == 0.25
    for b in net["effect_brackets"]:
        assert b["recorder_s"] - b["earliest_s"] <= 0.25 + 1e-9
    local = _run(make(), "local", plan=plan)
    assert "network" not in local.extra
    assert _checks(local)["withdrawn"] == _checks(r)["withdrawn"]


def test_the_published_counts_are_not_a_development_plan(monkeypatch):
    """`{"trials": "published"}` sets the published counts (100 for `withdrawn`) and is recorded,
    and the summary does not call the run a development plan; any other plan is one."""
    assert p19._trials_for({"trials": "published"}, "withdrawn") == 100
    assert p19._trials_for({"trials": "published"}, "narrowed") == 5
    monkeypatch.setattr(p19, "PUBLISHED_TRIALS", {"withdrawn": 3, "worst_phase": 1, "*": 1})
    r = _run(make(), "pub", plan={"trials": "published"})
    assert r.status is Status.PASS and not r.summary.startswith("Development plan"), r.summary
    assert r.extra["plan"] == {"trials": "published"}
    assert r.extra["statistics"]["withdrawn"]["n_counted"] == 3
    d = _run(make(), "dev", plan={"trials": "published", "window_s": 200})
    assert d.summary.startswith("Development plan")


# --------------------------------------------------------------------------- slow answers, recovery, progress


def test_the_correct_b_answering_slowly_passes_every_variant_at_the_published_counts():
    """``slow-good`` answers 0.6 T after an acceptance and 0.1 T after a refusal.
    Sent on the probe's own schedule, its brackets stay a few seconds wide and it passes; the
    sends never waited for an answer (many were in flight at once)."""
    r = _run(ToyWithdrawal("slow-good"), "slow")
    assert r.status is Status.PASS, r.summary
    st = r.extra["statistics"]["withdrawn"]
    assert st["inconclusive"] == 0 and st["bracket_width_s"]["max"] < 0.15 * 60
    sch = r.extra["scheduler"]
    assert sch["max_in_flight"] > 5 and sch["skipped"] == 0 and sch["timed_out"] == 0
    assert sch["limit"] == p19.MAX_IN_FLIGHT


def test_a_recovery_after_the_stated_bound_fails_as_recovered_late():
    """Every toy states a recovery bound of T/2. ``recovers_late`` refuses for
    0.75 T more once the source is back: L is accepted again within W, after the bound, and the
    continuation fails ``recovered_late`` (it no longer reads ``recovered``). The correct toy
    recovers within the bound, and one that never recovers is still ``stuck_closed``."""
    plan = {"trials": {"*": 1}, "variants": ["source_unreachable"]}
    late = _run(make("recovers_late"), "rl", plan=plan)
    assert late.status is Status.FAIL and _checks(late)["recovery"] == ("recovered_late", False)
    assert "after the stated recovery bound of 30 s" in \
        [c for c in late.checks if c.name == "recovery"][0].detail
    good = _run(make(), "rg", plan=plan)
    assert _checks(good)["recovery"] == ("recovered", True)
    assert good.extra["statistics"]["recovery"]["max_s"] <= 30
    stuck = _run(make("stuck_closed"), "rs", plan=plan)
    assert _checks(stuck)["recovery"] == ("stuck_closed", False)


class _Remote(ToyWithdrawal):
    def remote(self):
        return True

    def ping(self):
        return 0.25


class _Cut(BaseException):
    """Stands in for a run stopped from outside (a time limit, a destroyed machine)."""


def _progress(r_dir):
    import json
    (path,) = r_dir.glob("[0-9][0-9]-progress.jsonl")
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_a_run_cut_short_keeps_its_trials_and_pings_and_derive_reads_them(monkeypatch):
    """The probe writes each trial, each ping and each variant's reading to
    ``NN-progress.jsonl`` as it goes. Stopped after its fourth trial, before any summary, the
    evidence still holds the four trials, the run's pings (at each trial and every 30 s) and the
    readings of the variants that finished, and `derive` reads them without a result.json."""
    real = p19._run_trial
    calls = []

    def cut_after_four(run, variant, form, k):
        if len(calls) == 4:
            raise _Cut()
        calls.append(variant)
        return real(run, variant, form, k)
    monkeypatch.setattr(p19, "_run_trial", cut_after_four)
    toy = _Remote()
    ev = Evidence("p19", toy.name, "P19", "cut")
    toy.start()
    try:
        with pytest.raises(_Cut):
            p19.probe(toy, ev, run_tag="cut", seed=11,
                      plan={"trials": {"withdrawn": 3, "*": 1},
                            "variants": ["withdrawn", "narrowed", "standing_withdrawn"]})
    finally:
        toy.stop()
    assert not (ev.dir / "result.json").exists()
    lines = _progress(ev.dir)
    kinds = [x["kind"] for x in lines]
    assert kinds[0] == "run" and kinds[1] == "control" and "end" not in kinds
    assert kinds.count("trial") == 4
    pings = [x for x in lines if x["kind"] == "ping"]
    assert {p["at"] for p in pings} == {"trial", "interval"} and all(
        p["rtt_s"] == 0.25 for p in pings)
    trial = next(x for x in lines if x["kind"] == "trial")
    assert trial["scheduler"]["sent"] > 0 and "in_flight_at_send_max" in trial["scheduler"]
    assert all("t_answered" in p and "in_flight" in p for p in trial["presentations"])
    d = p19.derive(ev.dir)
    assert d["source"].endswith("progress.jsonl") and d["ended"] is False
    assert d["result_json"] is False
    assert sum(v["n_trials"] for v in d["variants"].values()) == 4
    assert d["network"]["n"] == len(pings) and d["network"]["rtt_s"]["max_s"] == 0.25
    assert d["incomplete"] or d["not_run"]                       # the cut shows
    done = [x["variant"] for x in lines if x["kind"] == "variant"]
    for v in done:
        assert d["variants"][v]["complete"] is True


def test_derive_on_a_complete_run_gives_the_results_readings(tmp_path):
    """The same reading from the evidence as from the probe's own summary."""
    toy = make()
    ev = Evidence("p19", toy.name, "P19", "whole")
    toy.start()
    try:
        r = p19.probe(toy, ev, run_tag="whole", seed=11,
                      plan={"trials": {"withdrawn": 3, "*": 1},
                            "variants": ["withdrawn", "source_unreachable"]})
    finally:
        toy.stop()
    (ev.dir / "result.json").write_text(r.to_json())
    d = p19.derive(ev.dir)
    assert d["ended"] is True and d["result_json"] is True
    ch = _checks(r)
    for v in ("withdrawn", "source_unreachable"):
        assert d["variants"][v]["reread"]["reading"] == ch[v][0], v
        assert d["variants"][v]["statistics"]["max_s"] == r.extra["statistics"][v]["max_s"]
    assert d["recovery"]["reread"] == {"recovered": 3}
    from conformance.runner import main
    assert main(["derive", str(ev.dir), "--out", str(tmp_path / "d.json")]) == 0
    assert (tmp_path / "d.json").read_text().startswith("{")


def test_derive_rereads_old_evidence_with_the_crossing_and_recovery_rules(tmp_path):
    """Evidence written by an earlier kit (per-variant files, no progress file): a
    recorded `within` whose bracket crosses T reads inconclusive, and a recovery is compared
    with its bound."""
    import json
    d = tmp_path / "P19"
    d.mkdir()
    (d / "01-run.json").write_text(json.dumps({
        "seed": 1, "variant_order": ["control", "withdrawn", "source_unreachable"],
        "bound": {"T_s": 10.0, "resolution_s": 1.0, "recovery_s": 8.0}, "window_s": 130,
        "plan": {"trials": {"withdrawn": 2, "*": 1}}, "channels": ["pull-list"]}))

    def trial(bracket, form=""):
        return {"form": form, "k": 0, "outcome": {"outcome": "within", "ok": True,
                                                  "time_s": bracket[1], "bracket": bracket},
                "presentations": [], "extra": {}}
    (d / "03-withdrawn.json").write_text(json.dumps({"variant": "withdrawn", "trials": [
        trial([0.0, 2.0]), trial([5.0, 15.79])]}))
    rec = trial([0.0, 3.0], "down")
    rec["extra"]["recovery"] = {"outcome": "recovered", "ok": True, "presentations": [
        {"under": "L", "t_sent": 1.85, "cls": "refused", "accepted": False},
        {"under": "L", "t_sent": 9.36, "cls": "accepted", "accepted": True}]}
    (d / "04-source_unreachable.json").write_text(json.dumps({
        "variant": "source_unreachable", "trials": [rec]}))
    got = p19.derive(d)
    w = got["variants"]["withdrawn"]
    assert w["as_recorded"]["reading"] == "refused_within_T"
    assert w["reread"]["reading"] == "inconclusive" and w["crossing"][0]["bracket"] == [5.0, 15.79]
    assert got["recovery"]["as_recorded"] == {"recovered": 1}
    assert got["recovery"]["reread"] == {"inconclusive": 1}
    assert got["not_run"] == [] and got["source"] == "per-variant files"


def test_the_dispatcher_on_the_real_clock_bounds_what_is_in_flight_and_times_out():
    """The sender a real target gets: presentations go out on schedule while earlier ones are
    still unanswered, no more than the bound at once, and one with no answer by the timeout is
    read as neither answer while its late answer is kept."""
    import json
    import time as _time
    from types import SimpleNamespace
    from conformance.timing import RealClock

    class B:
        def present(self, p, session=None):
            _time.sleep(0.6 if p.slow else 0.05)
            return {"status": 200, "body": {"code": "executed"}}

        def classify(self, ans):
            return "accepted"

    taken = []
    run = SimpleNamespace(clock=RealClock(), a=B(), variant="withdrawn",
                          take_answer=lambda pr, w0, ans, t1, w1: (
                              taken.append(pr), setattr(pr, "answered", True),
                              setattr(pr, "cls", "accepted"), setattr(pr, "t_answered", t1)),
                          refresh_effects=lambda: None, fill=lambda pr: None)

    def pres(i, slow=False):
        return SimpleNamespace(request=json.dumps({"ref": f"r{i}"}).encode(), endpoint="e1",
                               slow=slow)
    d = p19._Dispatcher(run, limit=2, timeout=0.3)
    try:
        a = d.submit(pres(1, slow=True), "W")
        b = d.submit(pres(2), "L")
        assert d.submit(pres(3), "W") is None and d.trial["skipped"] == 1   # the bound
        _time.sleep(0.1)
        c = d.submit(pres(4), "W")                     # sent while `a` is still out
        assert c is not None and c.in_flight == 1
        assert c.t_sent - a.t_sent < 0.2               # spacing is the schedule, not 0.6 s
        d.drain()
        assert b.answered and c.answered and a.timed_out and a.cls == "error"
        _time.sleep(0.5)
        d.poll()
        assert d.trial["late_answers"] == 1 and a.answer_after_timeout["answer"]["status"] == 200
        assert a not in taken and d.busy == 0
    finally:
        d.close()
        run.clock.close()
