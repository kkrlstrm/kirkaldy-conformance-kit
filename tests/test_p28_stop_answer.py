"""P28 (KRK-28, the stop's answer names what landed): the probe against its toys, the grading
table, the control, the statements an adapter makes, and the claim-basis rule on P28's forms.
Every required outcome of the known-bad gate is stated here (`known_bad.stop_toys.cases`,
`FAILS`); this file is in P28's hashed fixture set."""
import pytest

from conformance import claim_basis as cb
from conformance import knownbad
from conformance.evidence import Evidence
from conformance.properties import ALL
from conformance.properties import p28_stop_answer as p28
from conformance.result import Status
from known_bad import stop_toys as toys


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def run(a, seed=5, plan=None):
    a.start()
    try:
        return p28.probe(a, Evidence("t", a.name, "P28", a.config.replace(":", "-")),
                         run_tag="t", seed=seed, plan=plan)
    finally:
        a.stop()


def failing(r):
    return {f"{v}/{f}" for v, fr in (r.extra.get("forms") or {}).items()
            for f, d in fr.items() if d["ok"] is False}


def every_form():
    return {f"{v}/{f}" for v in p28.VARIANTS for f in p28.FORMS[v]}


# --------------------------------------------------------------------------- the gate


@pytest.mark.parametrize("config,required", toys.cases())
def test_every_gate_case_gives_its_required_outcome(config, required):
    r = run(toys.toy(config))
    assert r.status.value == required, (r.summary, r.extra.get("forms"))
    if r.status in (Status.PASS, Status.FAIL):
        assert r.control_held is True


@pytest.mark.parametrize("flaw", sorted(toys.FLAWS))
def test_each_flaw_fails_exactly_the_forms_written_for_it(flaw):
    r = run(toys.toy(f"bad:{flaw}"))
    assert failing(r) == toys.FAILS[flaw], (flaw, sorted(failing(r)))


@pytest.mark.parametrize("flaw", sorted(toys.FLAWS))
def test_each_flaw_fails_the_variant_it_is_built_for(flaw):
    assert any(f.startswith(toys.FLAWS[flaw] + "/") for f in toys.FAILS[flaw])


def test_bad_is_abandons_in_flight_and_the_case_list_is_the_gates():
    assert failing(run(toys.toy("bad"))) == toys.FAILS["abandons_in_flight"]
    assert knownbad.cases("P28") == [(c, Status(s)) for c, s in toys.cases()]
    assert "P28" in ALL and ALL["P28"] is p28
    assert set(toys.FAILS) == set(toys.FLAWS)
    assert set().union(*toys.FAILS.values()) <= every_form()


@pytest.mark.parametrize("config", ["good", "good-unstoppable", "good-conservative",
                                    "good-caller"])
def test_every_form_is_judged_in_every_trial_whatever_the_seed(config):
    """No form is chosen by the seed (KRK-M210): every form of every variant lands, every trial
    is counted, and the derived ``cause/distinct`` reads ``distinct``. The one exception is
    written: a runtime that acts on no stop never shows one in its record, so
    ``released_after_record`` has no point to release at."""
    for seed in (1, 2, 3, 103, 2**40 + 7):
        r = run(toys.toy(config), seed=seed)
        assert r.status is Status.PASS, (seed, r.summary)
        forms = r.extra["forms"]
        assert {f"{v}/{f}" for v, fr in forms.items() for f in fr} == every_form()
        for v, fr in forms.items():
            for f, d in fr.items():
                if config == "good-unstoppable" and (v, f) == ("before_dispatch",
                                                               "released_after_record"):
                    assert d["reading"] == "stop_not_recorded" and d["ok"] is None, d
                    continue
                assert d["ok"] is True, (seed, v, f, d)
                if (v, f) not in p28.DERIVED:
                    assert d["counted"] == d["trials"] == p28.TRIALS["*"], (v, f, d)
        assert r.extra["must_land_missed"] == []


def test_the_pass_modes_name_the_end_state_each_form_reached():
    m = run(toys.toy("good")).extra["modes"]
    assert m["before_dispatch"] == ["not_run_recorded"]
    assert m["partial"] == ["partial_recorded"]
    assert m["executor_answer"] == ["not_run_recorded", "unknown_raised"]
    assert m["cause"] == ["unknown_raised"]
    assert set(m["executing"]) == {"ran_recorded"}


def test_no_control_gives_no_verdict_and_says_why():
    r = run(toys.toy("no-control"))
    assert r.status is Status.INCONCLUSIVE and "never reached the kit's executor" in r.summary


# --------------------------------------------------------------------------- grading


def _truth(planned, landed, offered=True):
    return p28.Truth(planned=planned, landed=landed,
                     offered={"result": "tok"} if offered else None,
                     effects=len(landed), attempts=1)


def _r(state, items=None, result=None, cause=None, raised=False):
    got, why = p28.normalise({"state": state, "items": items, "result": result, "cause": cause,
                              "raised": raised, "raw": "x"})
    assert got is not None, why
    return got


@pytest.mark.parametrize("truth,reading,want", [
    (_truth(["a"], [], offered=False), _r("not_run"), ("not_run_recorded", True)),
    (_truth(["a"], [], offered=False), _r("ran"), ("none_recorded_as_ran", False)),
    (_truth(["a"], [], offered=False), _r("unknown", raised=True), ("unknown_raised", True)),
    (_truth(["a"], [], offered=False), _r("unknown"), ("unknown_not_raised", False)),
    (_truth(["a"], ["a"]), _r("ran", result="tok"), ("ran_recorded", True)),
    (_truth(["a"], ["a"]), _r("ran", result="ok"), ("result_discarded", False)),
    (_truth(["a"], ["a"]), _r("ran", result=None), ("result_discarded", False)),
    (_truth(["a"], ["a"], offered=False), _r("ran"), ("ran_recorded", True)),
    (_truth(["a"], ["a"]), _r("not_run", cause="stop"), ("ran_recorded_as_stopped", False)),
    (_truth(["a"], ["a"]), _r("unknown", raised=True), ("result_discarded", False)),
    (_truth(["a"], ["a"], offered=False), _r("unknown", raised=True), ("unknown_raised", True)),
    (_truth(["a"], ["a"]), _r("pending"), ("unsettled", False)),
    (_truth(["a", "b"], ["a", "b"]), _r("partial", items=["a"], result="tok"),
     ("partial_recorded_wrong", False)),
    (_truth(["a", "b", "c"], ["b"]), _r("partial", items=["b"], result="tok"),
     ("partial_recorded", True)),
    (_truth(["a", "b", "c"], ["b"]), _r("partial", items=["a"], result="tok"),
     ("partial_recorded_wrong", False)),
    (_truth(["a", "b", "c"], ["b"]), _r("ran", result="tok"), ("partial_recorded_wrong", False)),
    (_truth(["a", "b", "c"], ["b"]), _r("not_run"), ("partial_recorded_as_none", False)),
    (_truth(["a", "b", "c"], ["b"]), _r("partial", items=["b"]), ("result_discarded", False)),
])
def test_grade(truth, reading, want):
    got = p28.grade(truth, reading, "person")
    assert got[:2] == want, got


@pytest.mark.parametrize("raised,channel,want", [
    ("caller", "caller", ("unknown_raised", True)),
    ("person", "person", ("unknown_raised", True)),
    (True, "person", ("unknown_raised", True)),
    ("caller", "person", ("unknown_not_raised", False)),
    ("person", "caller", ("unknown_not_raised", False)),
    ("person", None, ("unknown_not_raised", False)),
    ("caller", None, ("unknown_not_raised", False)),
    (False, "caller", ("unknown_not_raised", False)),
    (None, "person", ("unknown_not_raised", False)),
])
def test_unknown_passes_only_through_the_channel_stated_before_the_run(raised, channel, want):
    """Unknown passes when told to a person or to the calling code, through the channel the
    adapter stated before the run; with no channel stated, it cannot pass."""
    got = p28.grade(_truth(["a"], [], offered=False), _r("unknown", raised=raised), channel)
    assert got[:2] == want, got
    if want[1]:
        assert f"raised to the {channel}" in got[2]


def test_a_discarded_result_is_still_discarded_whatever_the_channel():
    for ch in ("person", "caller", None):
        assert p28.grade(_truth(["a"], ["a"]), _r("unknown", raised=ch or True), ch)[0] == \
            "result_discarded"


def test_a_cause_is_wrong_only_where_it_names_the_other_side_of_a_stop():
    assert p28.cause_problem(_r("ran", cause="timeout"), stopped=True)
    assert p28.cause_problem(_r("unknown", cause="crash"), stopped=True)
    assert p28.cause_problem(_r("unknown", cause="stop"), stopped=False)
    assert p28.cause_problem(_r("ran", cause="none"), stopped=True) is None
    assert p28.cause_problem(_r("unknown", cause=None), stopped=True) is None
    assert p28.cause_problem(_r("unknown", cause="crash"), stopped=False) is None


@pytest.mark.parametrize("doc,why", [
    ({"state": "cancelled", "raw": "x"}, "state"),
    ({"state": "ran"}, "raw"),
    ({"state": "ran", "raw": "x", "cause": "user"}, "cause"),
    ({"state": "partial", "raw": "x", "items": "a,b"}, "items"),
    ({"state": "unknown", "raw": "x", "raised": "operator"}, "raised"),
    ("ran", "mapping"),
])
def test_a_reading_of_the_wrong_shape_is_unreadable(doc, why):
    got, problem = p28.normalise(doc)
    assert got is None and why in problem


# --------------------------------------------------------------------------- statements


class _NotAToy(toys.ToyRuntime):
    pass


_NotAToy.__module__ = "targets.example.adapter"


def test_a_virtual_clock_is_for_toys_only():
    r = run(_NotAToy("good"))
    assert r.status is Status.INCONCLUSIVE and "only a toy" in r.summary


class _DeclaresNA(toys.ToyRuntime):
    def __init__(self, na, **kw):
        super().__init__("good", **kw)
        self._na = na

    def forms_not_applicable(self):
        return dict(self._na)


def test_a_forbidden_not_applicable_is_ignored_and_recorded():
    r = run(_DeclaresNA({"executing/cancel_heard": "no such case", "late_result/after_close":
                         "no such case"}))
    assert r.status is Status.PASS
    assert r.extra["na_ignored"] == ["executing/cancel_heard", "late_result/after_close"]
    assert r.extra["forms"]["executing"]["cancel_heard"]["ok"] is True


def test_a_stated_not_applicable_form_reads_so_and_need_not_land():
    r = run(_DeclaresNA({"partial/prefix": "the toy's actions are single calls",
                         "partial/not_prefix": "the toy's actions are single calls"}))
    assert r.status is Status.PASS, r.summary
    assert {d["reading"] for d in r.extra["forms"]["partial"].values()} == {"not_applicable"}
    assert "multi" not in r.extra["control_shapes"]


class _NoTimeout(toys.ToyRuntime):
    def call_timeout_s(self):
        return None


def test_no_stated_call_timeout_leaves_cause_timeout_unlanded():
    r = run(_NoTimeout("good"))
    assert r.status is Status.INCONCLUSIVE and "cause/timeout" in r.extra["must_land_missed"]
    assert r.extra["forms"]["cause"]["timeout"]["reading"] == "not_landed"


def test_the_grace_assumed_when_none_is_stated_is_the_default():
    class NoGrace(toys.ToyRuntime):
        def stop_grace_s(self):
            return None
    r = run(NoGrace("good"))
    assert r.extra["grace_s"] == p28.DEFAULT_GRACE_S and r.extra["grace_stated"] is False
    assert r.extra["settle_s"] == max(p28.DEFAULT_GRACE_S, toys.TIMEOUT_S) + p28.MARGIN_S


@pytest.mark.parametrize("plan,n", [({"trials": "dev"}, p28.DEV_TRIALS["*"]),
                                    ({"trials": "published"}, p28.PUBLISHED_TRIALS["*"]),
                                    ({"trials": 1}, 1), ({}, p28.TRIALS["*"])])
def test_the_plan_sets_the_trial_count(plan, n):
    r = run(toys.toy("good"), plan=plan)
    assert r.extra["forms"]["executing"]["cancel_heard"]["trials"] == n


def test_a_plan_can_limit_the_variants():
    r = run(toys.toy("bad"), plan={"variants": ["before_dispatch", "partial"]})
    assert set(r.extra["forms"]) == {"before_dispatch", "partial"}
    assert r.status is Status.FAIL and failing(r) == {"partial/prefix", "partial/not_prefix"}


# --------------------------------------------------------------------------- claim basis


def test_an_adapter_that_states_nothing_reads_as_before():
    r = run(toys.toy("bad"))
    assert cb.apply(r, cb.statement(toys.toy("bad"), "P28")) is r


def test_forms_stated_not_claimed_read_not_claimed_never_fail():
    r = run(toys.toy("bad"))
    forms = [fid for fid, _c, _e in cb.forms_of(r)]
    every = cb.apply(r, cb.Statement("P28", not_claimed={cb.exact(f): "plan: not claimed"
                                                         for f in forms}))
    assert every.status.value == "not_claimed"
    only_failing = cb.apply(r, cb.Statement("P28", not_claimed={
        cb.exact(f): "plan: not claimed" for f in failing(r)}))
    assert only_failing.status is Status.PASS, only_failing.summary
    whole = cb.Statement("P28", whole="the product documents no stop")
    assert cb.apply(r, whole).status.value == "not_claimed"


def test_the_control_is_a_check_never_a_form():
    r = run(toys.toy("good"))
    assert any(c.name == "control" and c.ok for c in r.checks)
    assert all(not fid.startswith("control") for fid, _c, _e in cb.forms_of(r))


def test_through_the_runner_a_product_that_records_no_cause_can_state_it_not_claimed():
    """The runner applies the claim-basis rule outside the probe: `one_failure_state` fails only
    `cause/distinct`, so with `cause/*` stated not claimed it reads pass, and without a statement
    it fails as before."""
    from conformance import runner
    t = toys.toy("bad:one_failure_state")
    (r,) = runner.run_adapter(t, ["P28"], run_id="cb28", known_bad="mark", seed=3)
    assert r.status is Status.FAIL and "claim_basis" not in r.extra
    t = toys.toy("bad:one_failure_state")
    t.not_claimed = lambda: {"P28": {"cause/*": "plan: the product's record carries no cause"}}
    (r,) = runner.run_adapter(t, ["P28"], run_id="cb28b", known_bad="mark", seed=3)
    assert r.status is Status.PASS, r.summary
    assert r.extra["claim_basis"]["probe_as_read"]["status"] == "fail"
    assert r.extra["claim_basis"]["counts"]["not_claimed"] == len(p28.FORMS["cause"])


# --------------------------------------------------------------------------- the channel


def test_the_channel_stated_before_the_run_is_named_in_the_result():
    r = run(toys.toy("good-caller"))
    assert r.status is Status.PASS and r.extra["unknown_channel"] == "caller"
    assert "raised to the caller, the channel stated before the run" in r.summary
    r = run(toys.toy("bad:no_channel_stated"))
    assert r.extra["unknown_channel"] is None and "No channel" in r.summary
    detail = r.extra["forms"]["cause"]["crash"]["detail"]
    assert "no channel was stated before the run" in detail


def test_a_channel_outside_the_two_gives_no_verdict():
    class Odd(toys.ToyRuntime):
        def unknown_channel(self):
            return "pager"
    r = run(Odd("good"))
    assert r.status is Status.INCONCLUSIVE and "pager" in r.summary


# --------------------------------------------------------------- the stop before dispatch


class _AsyncStop(toys.ToyRuntime):
    """A runtime whose stop takes effect one second after `stop_action` returns, as an in-process
    runtime whose stop lands on a later turn of its loop: a release at once wins the race."""

    def stop_action(self, h):
        self.clock.call_at(self.clock.now() + 1.0, lambda: super(_AsyncStop, self).stop_action(h))
        return {"accepted": True, "answer": "stop requested"}


def test_the_released_form_waits_for_the_record_and_the_queued_form_reads_the_race():
    r = run(_AsyncStop("good"), plan={"variants": ["before_dispatch"]})
    assert r.status is Status.PASS, r.summary
    bd = r.extra["forms"]["before_dispatch"]
    assert bd["queued"]["modes"] == ["ran_recorded"] and "effect_after_stop" in bd["queued"]["info"]
    assert bd["released_after_record"]["modes"] == ["not_run_recorded"]
    for f in ("queued", "released_after_record"):
        assert set(bd[f]["dispatch_after_stop_s"]) == {"min", "max", "n"}
    assert bd["released_after_record"]["dispatch_after_stop_s"]["min"] >= 1.0
    assert bd["queued"]["dispatch_after_stop_s"]["max"] < 1.0


def test_a_record_that_never_shows_the_stop_leaves_the_released_form_without_a_reading():
    r = run(toys.toy("good-unstoppable"), plan={"variants": ["before_dispatch"]})
    d = r.extra["forms"]["before_dispatch"]["released_after_record"]
    assert d["reading"] == "stop_not_recorded" and d["ok"] is None
    assert "before_dispatch/released_after_record" not in r.extra["must_land_missed"]
    assert r.status is Status.PASS
