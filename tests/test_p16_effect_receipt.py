"""P16 (KRK-16) against its toys: the correct target passes, each target that skips one check
fails on exactly the variants that expose that check, a target with no receipt path fails on the
control's grade and every variant, a target whose control cannot hold gives no verdict, and the
random counts are reproducible for a seed and vary across seeds."""
import pytest

from conformance.evidence import Evidence
from conformance.properties import ALL
from conformance.result import Status
from known_bad.receipts_toys import FLAWS, ToyEffectReceipts, make

SEED = 515151

EXPOSED = {
    "accepts_any_request": {"wrong_request", "sibling_request"},
    # Added with sibling_request (KRK-M20): membership, not binding.
    "accepts_known_request": {"sibling_request"},
    "accepts_unsigned": {"unsigned"},
    "accepts_any_key": {"unpinned_key"},
    "ignores_counts": {"count_mismatch", "honest_partial"},
    "partial_as_done": {"honest_partial"},
    "completes_on_timeout": {"missing", "agent_report"},
    "trusts_executor_report": {"agent_report"},
    "refusal_as_done": {"signed_refusal"},
    # No receipt path: the honest case completes at grade executor-report, and so does every
    # variant (KRK-M19).
    "no_receipt_check": {"honest", "wrong_request", "unsigned", "unpinned_key", "count_mismatch",
                         "honest_partial", "missing", "agent_report", "signed_refusal",
                         "signed_no_record", "disputed_no_record", "sibling_request"},
    # Added with the no-record verdict.
    "no_record_as_done": {"signed_no_record", "disputed_no_record"},
    "closes_disputed_no_record": {"disputed_no_record"},
}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _probe(toy, tag, seed=SEED):
    toy.start()
    try:
        return ALL["P16"].probe(toy, Evidence("t", toy.name, "P16", tag), run_tag=tag, seed=seed)
    finally:
        toy.stop()


def _failed(r):
    return {c.name for c in r.checks if c.ok is False}


def test_p16_is_registered():
    assert ALL["P16"].TITLE == "Effect receipt"
    assert set(EXPOSED) == set(FLAWS)


def test_p16_correct_target_passes():
    r = _probe(make(), "good")
    assert r.status is Status.PASS, (r.summary, [c.__dict__ for c in r.checks])
    assert r.control_held is True
    assert {c.name for c in r.checks if c.ok is True} == \
        set(ALL["P16"].VARIANTS) | {ALL["P16"].CONTROL}
    assert r.extra["seed"] == SEED and r.extra["control_grade"] == "signed-by-B"


@pytest.mark.parametrize("flaw", FLAWS)
def test_p16_each_skipped_check_fails_on_its_variant(flaw):
    r = _probe(make(flaw), flaw)
    assert r.status is Status.FAIL, (r.summary, [c.__dict__ for c in r.checks])
    assert _failed(r) == EXPOSED[flaw], [c.__dict__ for c in r.checks]
    # Every other variant was still read, and none of them was information only.
    assert all(c.ok is True for c in r.checks if c.name not in EXPOSED[flaw]), \
        [c.__dict__ for c in r.checks]
    control = next(c for c in r.checks if c.name == ALL["P16"].CONTROL)
    if "honest" in EXPOSED[flaw]:
        assert control.outcome == ALL["P16"].UNVERIFIED, control.__dict__
    else:
        assert control.outcome == "done_signed_by_B", control.__dict__


def test_p16_a_target_with_no_receipt_path_fails_on_the_control_grade():
    """A target with no receipt path: every answer, the honest one included, completes on the executor's
    word. The control holds (B wrote everything, the judgement accepts, the target is done), and
    the grade is a failure of its own."""
    r = _probe(make("no_receipt_check"), "no-receipt")
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert "honest (completed-without-verified-receipt)" in r.summary, r.summary
    assert r.extra["control_grade"] == "executor-report"
    assert "grade 'executor-report'" in r.control_detail, r.control_detail


def test_p16_no_verdict_when_the_honest_receipt_never_completes():
    """A target that blocks every receipt, the honest one included, refuses all eight variants.
    Without the control that would read as a pass."""
    r = _probe(ToyEffectReceipts("no-control"), "no-control")
    assert r.status is Status.INCONCLUSIVE, r.summary
    assert "honest signed receipt did not complete" in r.summary, r.summary


def test_p16_no_verdict_when_the_target_cannot_be_driven():
    toy = make()
    toy.submit_raises = True
    r = _probe(toy, "submit-raises")
    assert r.status is Status.INCONCLUSIVE and "submit raised" in r.summary, r.summary


def test_p16_a_target_that_rejects_by_raising_still_counts():
    """A product that raises on a bad receipt has refused it. The raise must not turn the
    variant into an undriven one, or the property could never fail such a product."""
    toy = make()
    toy.raises_on_reject = True
    r = _probe(toy, "raises")
    assert r.status is Status.PASS, (r.summary, [c.__dict__ for c in r.checks])
    bad = make("accepts_unsigned")
    bad.raises_on_reject = True
    r = _probe(bad, "raises-bad")
    assert r.status is Status.FAIL and _failed(r) == {"unsigned"}, r.summary


def test_p16_counts_are_reproducible_for_a_seed_and_vary_across_seeds():
    a = _probe(make("ignores_counts"), "seed-a", seed=SEED)
    b = _probe(make("ignores_counts"), "seed-b", seed=SEED)
    c = _probe(make("ignores_counts"), "seed-c", seed=SEED + 1)
    assert a.extra["counts"] == b.extra["counts"]
    assert [(x.name, x.outcome, x.ok) for x in a.checks] == \
        [(x.name, x.outcome, x.ok) for x in b.checks]
    assert a.extra["counts"] != c.extra["counts"]
    lo, hi = ALL["P16"].COUNT_RANGE
    assert all(lo <= n <= hi for n in a.extra["counts"].values())
    assert len(set(a.extra["counts"].values())) > 1      # not one fixed number per run


def test_p16_a_fresh_seed_is_drawn_and_recorded_when_none_is_given(tmp_path):
    toy = make()
    toy.start()
    r = ALL["P16"].probe(toy, Evidence("t", toy.name, "P16", "fresh"), run_tag="fresh")
    assert r.status is Status.PASS and isinstance(r.extra["seed"], int), r.summary


def test_p16_closing_a_disputed_no_record_is_its_own_fail():
    """Decision 2: the executor says it sent the request, B signs it has no record.
    A target that closes the attempt as not executed is not done, but it settled the dispute
    without a person, which fails."""
    r = _probe(make("closes_disputed_no_record"), "disputed")
    check = next(c for c in r.checks if c.name == "disputed_no_record")
    assert (check.ok, check.outcome) == (False, ALL["P16"].CLOSED_WITHOUT_PERSON), check.__dict__
    good = _probe(make(), "good-no-record")
    by = {c.name: c for c in good.checks}
    assert by["signed_no_record"].ok is True and "not-executed" in by["signed_no_record"].detail
    assert by["disputed_no_record"].ok is True and "blocked" in by["disputed_no_record"].detail
