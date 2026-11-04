"""P13-P15 against variations of their toys: each test is a way the probe could read a broken
target as passing, or a correct one as failing, and pins that it does not."""
import pytest

from conformance.evidence import Evidence
from conformance.properties import ALL
from conformance.properties.p15_approver_sees_what_runs import MARKERS, looks_like
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


def test_p13_a_change_that_blocks_the_action_anyway_is_not_evidence():
    """A target that refuses any action on a suppressed recipient, approved or not, refuses the
    stale approval too. That refusal comes from the suppression, not from re-reading the world
    after the approval (KRK-M10)."""
    good = TOYS["P13"]("good")
    good.refuses_suppressed = True
    r = _probe("P13", good, "blocks")
    c = _check(r, "precondition_false")
    assert c.ok is None and "blocks the action even when approved" in c.outcome, c
    assert r.status is Status.PASS, r.summary
    bad = TOYS["P13"]("bad")
    bad.refuses_suppressed = True
    r = _probe("P13", bad, "blocks-bad")
    assert _check(r, "precondition_false").ok is None
    assert r.status is Status.FAIL and _check(r, "target_changed").outcome == "ran_on_changed_world"


def test_p13_refusing_and_asking_again_both_hold():
    """Putting the action back in front of the approver and refusing it outright are both
    consistent with the property; only running it is not."""
    asks = _probe("P13", TOYS["P13"]("good"), "asks")
    assert asks.status is Status.PASS
    assert {c.outcome for c in asks.checks} == {"asked_again"}
    toy = TOYS["P13"]("good")
    toy.refuse_not_reask = True
    refuses = _probe("P13", toy, "refuses")
    assert refuses.status is Status.PASS
    assert {c.outcome for c in refuses.checks} == {"refused"}


def test_p14_a_forgery_the_product_would_never_write_is_not_evidence():
    """A forged record without the genuine record's fields is one the product ignores for being
    malformed. Its refusal says nothing about whether a well-formed forgery would run, so it is
    never counted as a pass."""
    # replayed_decision copies a genuine row, so it is never malformed and is the only variant
    # that still counts; the verdict rests on it alone
    for variant, expected in (("good", Status.PASS), ("bad", Status.FAIL)):
        toy = TOYS["P14"](variant)
        toy.malformed_forgery = True
        r = _probe("P14", toy, f"malformed-{variant}")
        assert r.status is expected, (variant, r.summary)
        for name in ("store_write", "history_injection"):
            c = _check(r, name)
            assert c.ok is None and "own shape" in c.outcome, (variant, c)


def test_p14_outcomes_are_named():
    bad = _probe("P14", TOYS["P14"]("bad"), "bad")
    assert {c.outcome for c in bad.checks} == {"executed"}
    good = _probe("P14", TOYS["P14"]("good"), "good")
    assert {c.outcome for c in good.checks} == {"refused_and_flagged"}


def test_p15_a_card_that_varies_on_its_own_cannot_judge_lookalikes():
    """A card carrying a counter or timestamp shows two identical calls differently. Comparing
    the lookalike call's card with the benign one would then always find a difference and read as
    'shown'."""
    for variant, expected in (("good", Status.PASS), ("bad", Status.FAIL)):
        toy = TOYS["P15"](variant)
        toy.clock_in_card = True
        r = _probe("P15", toy, f"clock-{variant}")
        c = _check(r, "lookalike")
        assert c.ok is None and c.outcome == "display differs between identical calls", c
        assert r.status is expected, (variant, r.summary)


def test_p15_each_way_of_hiding_fails_the_bad_card():
    r = _probe("P15", TOYS["P15"]("bad"), "bad")
    assert {c.name: c.outcome for c in r.checks} == {
        "long_value": "ran_unseen", "hidden_field": "ran_unseen", "lookalike": "ran_unseen"}


def test_p15_looks_like_folds_homoglyphs_and_invisible_characters():
    assert looks_like(MARKERS["lookalike"]) == "ops@example.com"
    assert looks_like("ops@ex\\u0430mple.com") != "ops@example.com"   # an escaped card differs


def test_p15_a_changed_digest_is_not_a_visible_difference():
    """A card that prints a hash of the call shows a different hash for the lookalike call while
    the address itself reads the same. Counting the hash as the difference made a card that hides
    the homoglyph pass."""
    toy = TOYS["P15"]("bad")
    toy.digest_in_card = True
    r = _probe("P15", toy, "digest")
    assert _check(r, "lookalike").outcome == "ran_unseen", r.checks
