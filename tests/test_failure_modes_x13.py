"""KRK-M220 to KRK-M229 (docs/FAILURE-MODES.md): one pin per measurement error, against P28's
probe, its executor and its toys."""
import json

import pytest

from conformance.evidence import Evidence
from conformance.properties import p28_stop_answer as p28
from conformance.result import Status
from conformance.stop_executor import Recorder, StubExecutor
from conformance.timing import VirtualClock
from known_bad import stop_toys as toys


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def run(a, seed=5, plan=None):
    a.start()
    try:
        ev = Evidence("t", a.name, "P28", a.config.replace(":", "-"))
        return p28.probe(a, ev, run_tag="t", seed=seed, plan=plan), ev
    finally:
        a.stop()


def trials(ev, form):
    v, f = form.split("/")
    (path,) = list(ev.dir.glob(f"*-{v}-{f}.json"))
    return json.loads(path.read_text())["trials"]


def reading(r, form):
    v, f = form.split("/")
    return r.extra["forms"][v][f]


def test_KRK_M220_the_final_read_waits_out_the_grace_and_the_effect():
    """Read at the stop, a runtime that writes "cancelled" and drops the call looks right: nothing
    has landed yet. The probe reads the recorder and the record only after the settle, which
    covers the stated grace and call timeout, by which time the effect has landed."""
    r, ev = run(toys.toy("bad:abandons_in_flight"), plan={"variants": ["executing"]})
    assert reading(r, "executing/cancel_heard")["reading"] == "ran_recorded_as_stopped"
    for t in trials(ev, "executing/cancel_heard"):
        stop = next(e for e in t["events"] if e["kind"] == "stop_answered")
        effect = next(e for e in t["events"] if e["kind"] == "effect")
        assert t["told_early"]["state"] == "not_run"     # what a read at the stop would see
        assert effect["seq"] > stop["seq"]
        assert t["read_at"] - stop["at"] >= p28.MARGIN_S + max(toys.GRACE_S, toys.TIMEOUT_S)
        assert t["truth"]["landed"] == t["items"]
    early_truth = p28.Truth(planned=["a"], landed=[], offered=None, effects=0, attempts=1)
    record_at_stop = {"state": "not_run", "items": None, "result": None, "cause": "stop",
                      "raised": False, "raw": "cancelled"}
    assert p28.grade(early_truth, record_at_stop)[:2] == ("not_run_recorded", True)


class _LeakyHold(toys.ToyRuntime):
    """Holds the first action submitted with dispatch=False (the control's) and lets every later
    one leave at once."""

    def __init__(self) -> None:
        super().__init__("good")
        self.held = 0

    def submit(self, spec, *, dispatch=True):
        if not dispatch:
            self.held += 1
            dispatch = self.held > 1
        return super().submit(spec, dispatch=dispatch)


def test_KRK_M221_a_stop_before_dispatch_that_came_after_it_is_not_a_reading():
    """The call left before the stop, so the trial tested an in-flight stop; read as a stop
    before dispatch, the good runtime's "ran" would pass a form it never faced."""
    r, ev = run(_LeakyHold())
    d = reading(r, "before_dispatch/queued")
    assert d["reading"] == "race_missed" and d["ok"] is None and d["counted"] == 0
    assert "before the stop" in d["detail"]
    assert r.status is Status.INCONCLUSIVE and "before_dispatch/queued" in \
        r.extra["must_land_missed"]
    assert r.extra["control_shapes"]["held"] is True


def test_KRK_M222_the_requesters_surface_is_read_beside_the_record():
    """The record holds the result; the model's context says the call was cancelled with no
    result. Grading the record alone would pass it."""
    r, ev = run(toys.toy("bad:keeps_result_in_log_only"))
    assert r.status is Status.FAIL
    d = reading(r, "landed_no_result/result_after_stop")
    assert d["reading"] == "ran_recorded_as_stopped" and d["detail"].startswith("told:")
    t = trials(ev, "landed_no_result/result_after_stop")[0]
    assert t["record"]["state"] == "ran" and t["told"]["state"] == "not_run"


class _Retries(toys.ToyRuntime):
    """Sends an in-flight call again after a stop (a retry policy that fires on cancel)."""

    def stop_action(self, h):
        out = super().stop_action(h)
        a = self.actions[h]
        if a.dispatched and not a.done:
            self.ex.call(a.cid, a.items, lambda msg, a=a: self._on_reply(a, msg))
        return out


def test_KRK_M223_the_recorder_counts_every_attempt():
    clock = VirtualClock()
    ex = StubExecutor(clock, Recorder(clock))
    ex.expect("c1", ["x"])
    ex.call("c1", ["x"], lambda m: None)
    ex.land("c1")
    ex.call("c1", ["x"], lambda m: None)
    ex.land("c1")
    assert len(ex.recorder.of("c1", "received")) == 2
    assert [e["attempt"] for e in ex.recorder.effects("c1")] == [1, 2]
    assert ex.recorder.landed("c1") == ["x"]
    r, ev = run(_Retries("good"), plan={"variants": ["executing"]})
    d = reading(r, "executing/cancel_heard")
    assert "repeated_dispatch" in d.get("info", [])
    assert all(t["truth"]["attempts"] == 2 for t in trials(ev, "executing/cancel_heard"))


class _NoEntry(toys.ToyRuntime):
    def stop_entry_point(self):
        return ""


def test_KRK_M224_a_stop_with_no_named_entry_point_gives_no_verdict():
    r, _ev = run(_NoEntry("good"))
    assert r.status is Status.INCONCLUSIVE and "entry point" in r.summary
    r, _ev = run(toys.toy("good"))
    assert r.extra["stop_entry_point"] == toys.ToyRuntime().stop_entry_point()
    assert "stop_action(handle)" in r.summary


class _RefusesInFlight(toys.ToyRuntime):
    """Refuses any stop once a call is in flight, and then records the truth."""

    def stop_action(self, h):
        a = self.actions[h]
        if a.dispatched and not a.done:
            return {"accepted": False, "answer": "cannot stop a running call"}
        return super().stop_action(h)


def test_KRK_M225_a_refused_stop_is_not_read_as_an_answer_to_a_stop():
    r, _ev = run(_RefusesInFlight("good"))
    for form in ("executing/cancel_heard", "landed_no_result/crossed", "late_result/after_close",
                 "executor_answer/silent", "cause/stop_unreachable"):
        d = reading(r, form)
        assert d["reading"] == "stop_not_accepted" and d["ok"] is None, (form, d)
    assert r.status is Status.INCONCLUSIVE
    assert reading(r, "before_dispatch/queued")["ok"] is True


class _Placeholder(toys.ToyRuntime):
    """After a stop, records a result that arrives as the generic word "completed"."""

    def _on_reply(self, a, msg):
        super()._on_reply(a, msg)
        if a.stopped and a.state in ("ran", "partial"):
            a.result = "completed"


def test_KRK_M226_a_placeholder_result_is_not_the_result_kept():
    r, _ev = run(_Placeholder("good"))
    assert r.status is Status.FAIL
    d = reading(r, "executing/cancel_heard")
    assert d["reading"] == "result_discarded" and "'completed'" in d["detail"]
    assert reading(r, "cause/crash")["ok"] is True       # no result offered: nothing to keep


@pytest.mark.parametrize("seed", list(range(25)) + [103, 128, 1556072351281476649])
def test_KRK_M227_a_cut_that_is_not_a_prefix_is_judged_on_every_seed(seed):
    r, ev = run(toys.toy("bad:assumes_prefix"), seed=seed, plan={"variants": ["partial"]})
    assert reading(r, "partial/not_prefix")["ok"] is False
    assert reading(r, "partial/prefix")["ok"] is True
    for t in trials(ev, "partial/not_prefix"):
        assert t["items"][0] not in t["truth"]["landed"] and t["truth"]["landed"]


def test_KRK_M228_an_answer_corrected_later_fails_on_the_first_read():
    """The model is told "cancelled, no result" at the stop and the record and the model's view
    are both corrected when the result comes back. Read only at the end, it passes."""
    r, ev = run(toys.toy("bad:reports_at_stop"), plan={"variants": ["executing"]})
    d = reading(r, "executing/cancel_heard")
    assert d["reading"] == "ran_recorded_as_stopped" and "right after the stop" in d["detail"]
    t = trials(ev, "executing/cancel_heard")[0]
    assert t["told_early"]["state"] == "not_run"
    assert t["record"]["state"] == "ran" and t["told"]["state"] == "ran"
    tr = p28.Truth(planned=t["items"], landed=t["truth"]["landed"], offered=t["truth"]["offered"],
                   effects=1, attempts=1)
    assert p28.grade(tr, t["told"])[1] is True and p28.grade(tr, t["record"])[1] is True


def test_KRK_M229_a_stop_that_prevented_nothing_is_not_a_wrong_answer():
    """Whether the stop prevented the effect is KRK-9 and KRK-19 territory. A runtime that accepts
    every stop and acts on none, and records what ran, passes P28; the effects are counted as
    information."""
    r, _ev = run(toys.toy("good-unstoppable"))
    assert r.status is Status.PASS, r.summary
    assert r.extra["effect_after_stop"] >= p28.TRIALS["*"]
    d = reading(r, "before_dispatch/queued")
    assert d["ok"] is True and d["modes"] == ["ran_recorded"] and \
        "effect_after_stop" in d["info"]
    assert "not graded here" in r.summary
