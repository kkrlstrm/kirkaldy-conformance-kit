"""P9-P12 against variations of their toys: each test is a way the probe could read a broken
target as passing, or a correct one as failing, and pins that it does not."""
import pytest

from conformance.evidence import Evidence
from conformance.properties import ALL
from conformance.result import Status
from known_bad.toys import TOYS


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _probe(pid, toy, tag):
    toy.start()
    try:
        return ALL[pid].probe(toy, Evidence("t", toy.name, pid, tag), run_tag=tag)
    finally:
        toy.stop()


def _check(r, name):
    return next(c for c in r.checks if c.name == name)


def test_p9_runs_the_execute_path_more_than_once(monkeypatch):
    """A grant whose stored envelope expires on time, but is re-derived from the same old
    decision on the next scheduler pass, refuses exactly one attempt. One attempt reads that
    as an expiry that held."""
    monkeypatch.setattr("conformance.properties.p9_grant_validity.ATTEMPTS", 1)
    once = _probe("P9", TOYS["P9"]("bad"), "one-attempt")
    assert _check(once, "expired").ok is True, once.checks
    monkeypatch.setattr("conformance.properties.p9_grant_validity.ATTEMPTS", 2)
    twice = _probe("P9", TOYS["P9"]("bad"), "two-attempts")
    c = _check(twice, "expired")
    assert c.ok is False and "attempt 2" in c.outcome, c


def test_p9_a_short_limit_that_breaks_the_target_is_not_an_expiry(monkeypatch):
    """Shortening the limit can leave the target unable to run anything (a gate restarted on a
    bad config). Its refusal after the limit would then read as the limit holding."""
    toy = TOYS["P9"]("good")
    toy.prepare_variant = lambda v: setattr(toy, "variant", "no-control") if v == "expired" else None
    restore = toy.restore_variant
    toy.restore_variant = lambda v: (setattr(toy, "variant", "good"), restore(v))
    r = _probe("P9", toy, "broken-prep")
    c = _check(r, "expired")
    assert c.ok is None and c.outcome == "control_failed", c
    assert r.status is Status.PASS, r.summary          # the other two variants still count


def test_p10_a_change_the_target_refuses_anyway_is_not_evidence():
    """If the target rejects the changed call even when it is the approved one (a schema
    error), refusing it under another call's approval says nothing about binding (KRK-M10)."""
    good = TOYS["P10"]("good")
    good.rejects_extra_items = True
    r = _probe("P10", good, "schema")
    c = _check(r, "extra_item")
    assert c.ok is None and "does not run even when approved" in c.outcome, c
    bad = TOYS["P10"]("bad")
    bad.rejects_extra_items = True
    r = _probe("P10", bad, "schema-bad")
    assert _check(r, "extra_item").ok is None
    assert r.status is Status.FAIL, r.summary


def test_p11_executors_run_one_after_another_are_not_a_race():
    """An adapter that serializes its executors makes a target with no claim at all produce one
    side effect. Thread start times all match, so only the executors' own start times show it."""
    toy = TOYS["P11"]("bad")
    toy.serial = True
    r = _probe("P11", toy, "serial")
    assert r.status is Status.INCONCLUSIVE, r.summary
    assert _check(r, "worker").outcome == "executors never overlapped"


def test_p12_once_with_nothing_recorded_and_nothing_said_fails():
    """Not repeating the side effect is not enough: an approved action that ran, whose record
    says it did not, and that nobody was told about, is the failure in the other direction."""
    toy = TOYS["P12"]("bad")
    toy.forgets_crashed = True
    r = _probe("P12", toy, "silent")
    assert r.status is Status.FAIL, r.summary
    assert _check(r, "process-killed").outcome == "once_unrecorded_silent"


def test_p12_outcomes_are_named():
    bad = _probe("P12", TOYS["P12"]("bad"), "bad")
    assert _check(bad, "process-killed").outcome == "twice"
    good = _probe("P12", TOYS["P12"]("good"), "good")
    assert _check(good, "process-killed").outcome == "once_unrecorded_detected"
