"""KRK-19's timing method (`conformance/timing.py`) on a virtual clock and on synthetic trial
logs: the schedule, phase targeting, every trial outcome (including an onset exactly on the
boundary), the variant labels and the statistics table, which never reports a mean."""
import random

import pytest

from conformance import timing
from conformance.timing import Pres, TrialLog, VirtualClock, classify_trial

T = 60.0
TW = 1000.0


# --------------------------------------------------------------------------- clocks


def test_the_virtual_clock_fires_callbacks_in_time_order_at_their_own_times():
    vc = VirtualClock(start=0.0)
    seen = []
    vc.call_every(lambda: 10.0, lambda: seen.append(("poll", vc.now())))
    vc.call_at(15.0, lambda: seen.append(("once", vc.now())))
    vc.sleep(35.0)
    assert seen == [("poll", 10.0), ("once", 15.0), ("poll", 20.0), ("poll", 30.0)]
    assert vc.now() == 35.0


def test_a_cancelled_poller_never_fires_again_and_wall_time_follows_virtual_time():
    vc = VirtualClock(start=0.0, wall0=1_700_000_000.0)
    seen = []
    h = vc.call_every(lambda: 1.0, lambda: seen.append(vc.now()))
    vc.sleep(2.5)
    vc.cancel(h)
    vc.sleep(5)
    assert seen == [1.0, 2.0]
    assert vc.wall() == 1_700_000_007.5


def test_the_real_clock_is_monotonic_and_runs_a_poller():
    import time
    rc = timing.RealClock()
    seen = []
    h = rc.call_every(lambda: 0.02, lambda: seen.append(rc.now()))
    time.sleep(0.15)
    rc.cancel(h)
    assert len(seen) >= 3 and seen == sorted(seen)


# --------------------------------------------------------------------------- the schedule


def test_the_numbers_of_the_method():
    assert timing.window_s(60) == 180 and timing.window_s(10) == 130
    assert timing.window_s(None) == 900
    assert timing.stability_s(60) == 60 and timing.stability_s(5) == 30
    assert timing.delta_s(60) == 3.0 and timing.delta_s(1) == 0.2 and timing.delta_s(600) == 5
    assert timing.epsilon_s(None) == 0.05 and timing.epsilon_s(1.0) == 1.0


def test_the_schedule_is_jittered_spaced_by_delta_and_has_both_boundary_presentations():
    slots = timing.schedule(T, random.Random(3))
    offs = [s.offset_s for s in slots if s.kind == "regular"]
    gaps = [b - a for a, b in zip(offs, offs[1:])]
    assert all(3.0 <= g <= 4.5 + 1e-9 for g in gaps), "Δ plus a jitter in [0, Δ/2] (KRK-M54)"
    assert len(set(round(g, 3) for g in gaps)) > 5, "the jitter varies"
    kinds = {s.kind: s.offset_s for s in slots if s.kind != "regular"}
    assert kinds == {"boundary-before": pytest.approx(T - 0.05),
                     "boundary-after": pytest.approx(T + 0.05)}
    assert offs[0] == 0.0 and offs[-1] < timing.window_s(T)


def test_with_no_stated_bound_the_spacing_grows_after_two_minutes():
    slots = timing.schedule(None, random.Random(1), window=600)
    offs = [s.offset_s for s in slots]
    early = [b - a for a, b in zip(offs, offs[1:]) if a < 100]
    late = [b - a for a, b in zip(offs, offs[1:]) if a > 300]
    assert max(early) <= 1.5 and min(late) > 10 and max(late) <= 45
    assert not any(s.kind != "regular" for s in slots)


def test_phase_targets_draw_across_the_fetch_interval_or_sit_just_after_a_fetch():
    rng = random.Random(9)
    targets = [timing.phase_target(100.0, 30.0, rng, "random") for _ in range(200)]
    assert min(targets) >= 100 and max(targets) <= 130 and max(targets) - min(targets) > 20
    assert timing.phase_target(100.0, 30.0, rng, "worst") == pytest.approx(100.05)
    log = [{"t_start": 0.0, "t_end": 0.1}, {"t_start": 30.0, "t_end": 30.2},
           {"t_start": 75.0, "t_end": 75.1}]
    assert timing.fetch_intervals(log) == [30.0, 45.0]
    assert timing.last_fetch_end(log) == 75.1


# --------------------------------------------------------------------------- trial outcomes


def _log(w, l=None, effects=None, **kw):
    """w, l: lists of (offset, accepted?) for presentations after t_w."""
    pres = []
    for off, ok in w:
        pres.append(Pres("W", TW + off, cls="accepted" if ok else "refused", accepted=ok,
                         effect_t=TW + off if ok else None, endpoint="e1"))
    for off, ok in (l or [(o, True) for o, _ in w]):
        pres.append(Pres("L", TW + off + 0.01, cls="accepted" if ok else "refused",
                         accepted=ok))
    eff = [TW + off for off, ok in w if ok] + [TW + e for e in (effects or [])]
    base = dict(variant="withdrawn", form="", t_w=TW, T=T, window=timing.window_s(T),
                stability=timing.stability_s(T), presentations=pres, w_effects=eff,
                ended_at=TW + 200)
    base.update(kw)
    return TrialLog(**base)


def test_within_with_its_bracket():
    o = classify_trial(_log([(0, True), (3, True), (6.5, False), (10, False), (60, False)]))
    assert (o.outcome, o.ok) == ("within", True)
    assert o.bracket == (3.0, 6.5) and o.time_s == pytest.approx(6.5)


def test_an_onset_exactly_on_the_boundary_is_within():
    o = classify_trial(_log([(0, True), (59.95, True), (60.0, False), (60.05, False),
                             (90, False)]))
    assert (o.outcome, o.ok) == ("within", True) and o.bracket == pytest.approx((59.95, 60.0))


def test_accepted_just_after_the_boundary_is_late_with_its_time():
    o = classify_trial(_log([(0, True), (59.95, True), (60.05, True), (63, False), (100, False)]))
    assert (o.outcome, o.ok) == ("late", False)
    assert o.bracket == pytest.approx((60.05, 63.0)) and "60.05" in o.detail


def test_an_effect_committed_after_t_is_late_although_every_answer_was_a_refusal():
    """KRK-M60: refused at the answer, executed behind it (an in-flight request)."""
    o = classify_trial(_log([(0, False), (3, False), (100, False)], effects=[75.0]))
    assert (o.outcome, o.ok) == ("late", False) and o.last_effect_s == pytest.approx(75)
    assert o.time_s == pytest.approx(75)


def test_still_accepted_at_the_end_of_the_window_is_not_within_W_never_never():
    o = classify_trial(_log([(0, True), (90, True), (179, True)]))
    assert (o.outcome, o.ok) == ("not_within_W", False)
    assert "never" not in o.detail and "180" in o.detail


def test_accepted_again_after_a_refusal_is_flapped():
    o = classify_trial(_log([(0, True), (5, False), (8, True), (12, False), (50, False)]))
    assert (o.outcome, o.ok) == ("flapped", False) and o.bracket == (8.0, 12.0)


def test_the_sibling_refused_too_is_collateral_unless_the_variant_fails_safe():
    w = [(0, True), (5, False), (10, False)]
    l = [(0, True), (5, False), (10, False)]
    assert classify_trial(_log(w, l)).outcome == "collateral_refusal"
    assert classify_trial(_log(w, l, failsafe=True)).outcome == "within"


def test_a_refusal_for_another_reason_is_not_evidence():
    log = _log([(0, True), (5, False)])
    for p in log.presentations:
        if p.under == "W" and p.refused:
            p.reached = False
    assert classify_trial(log).outcome == "stopped_before_guarantee"


def test_with_no_stated_bound_the_pass_is_within_W():
    o = classify_trial(_log([(0, True), (400, True), (420, False), (500, False)], T=None,
                            window=900))
    assert (o.outcome, o.ok) == ("within_W", True) and o.time_s == pytest.approx(420)


def test_an_information_outcome_set_by_the_probe_is_kept():
    o = classify_trial(_log([(0, True)], info="fixture_not_landed", info_detail="read back"))
    assert (o.outcome, o.ok, o.detail) == ("fixture_not_landed", None, "read back")


# --------------------------------------------------------------------------- a variant


def _outcomes(times, late=0, never=0):
    out = [timing.TrialOutcome("within", True, time_s=t, bracket=(t - 1, t)) for t in times]
    out += [timing.TrialOutcome("late", False, time_s=70.0, bracket=(69, 70))] * late
    out += [timing.TrialOutcome("not_within_W", False)] * never
    return out


def test_the_variant_label_is_the_worst_trial():
    assert timing.aggregate(_outcomes([1, 2]), T) == ("refused_within_T", True)
    assert timing.aggregate(_outcomes([1], late=1), T) == ("refused_late", False)
    assert timing.aggregate(_outcomes([1], late=1, never=1), T) == ("not_refused_within_W",
                                                                    False)
    assert timing.aggregate(_outcomes([1]), None) == ("refused_within_W", True)
    assert timing.aggregate(_outcomes([1], late=1), T, fail_label="accepted_open") == (
        "accepted_open", False)
    info = [timing.TrialOutcome("collateral_refusal", None)] * 2
    assert timing.aggregate(info, T) == ("collateral_refusal", None)


def test_statistics_report_the_maximum_and_order_statistics_and_never_a_mean():
    s = timing.statistics(_outcomes([float(i) for i in range(1, 31)]), T)
    assert s["max_s"] == 30 and s["max_bracket_s"] == [29, 30]
    assert s["median_s"] == 15 and s["p90_s"] == 27
    assert s["p99_s"] == "not estimable at N=30"
    assert "3/30" in s["exceedance"]
    assert not any("mean" in k or "average" in k for k in s), "KRK-M53"
    small = timing.statistics(_outcomes([1.0, 2.0, 9.0]), T)
    assert small["p90_s"] == "not estimable at N=3" and small["max_s"] == 9
    with_late = timing.statistics(_outcomes([1.0], late=2), T)
    assert with_late["late"] == 2 and "2 of 3" in with_late["exceedance"]


def test_with_no_stated_bound_the_worst_case_is_the_effective_bound():
    s = timing.statistics(_outcomes([5.0, 12.5]), None)
    assert s["effective_bound_s"] == 12.5


def test_a_percentile_claim_is_checked_only_with_enough_trials():
    """"""
    few = _outcomes([1.0] * 10)
    assert "cannot be checked at N=10" in timing.percentile_check("p99", few, T)
    many = _outcomes([1.0] * 299 + [61.0])
    assert "p99 = 1.00 s" in timing.percentile_check("p99", many, T)
    assert timing.percentile_check("max", few, T) is None


def test_the_floor():
    assert timing.below_floor(0.5, 0.01, None) is True
    assert timing.below_floor(60, 0.01, None) is False
    assert timing.below_floor(None, 0.01, None) is False


# --------------------------------------------------------------------------- brackets that cross T
# (KRK-M48), and the recovery bound


def test_a_bracket_that_crosses_t_is_inconclusive_not_within():
    """KRK-M48. Accepted at 48 s, refused from 96 s, nothing presented in between: nothing
    accepted after T was seen, but the reading cannot say B refused by T."""
    o = classify_trial(_log([(0, True), (48, True), (96, False), (130, False)]))
    assert (o.outcome, o.ok) == ("inconclusive", None)
    assert o.bracket == (48.0, 96.0) and "crosses T = 60 s" in o.detail and "KRK-M48" in o.detail


def test_a_bracket_ending_within_the_boundary_resolution_after_t_is_within():
    """The boundary slot sits ε after T: a bracket ending there is as fine as the method reads,
    and B's stated resolution widens ε (a B might state 1 s)."""
    o = classify_trial(_log([(0, True), (59.95, True), (60.05, False), (90, False)]))
    assert (o.outcome, o.ok) == ("within", True)
    coarse = _log([(0, True), (59.0, True), (60.9, False), (90, False)], resolution_s=1.0)
    assert classify_trial(coarse).outcome == "within"
    fine = _log([(0, True), (59.0, True), (60.9, False), (90, False)])
    assert classify_trial(fine).outcome == "inconclusive"
    assert timing.crosses(59.0, 61.06, 60.0, 1.0) and not timing.crosses(59.0, 61.04, 60.0, 1.0)
    assert not timing.crosses(10.0, 90.0, None)


def test_the_bracket_starts_at_the_last_acceptance_not_at_an_unanswered_presentation():
    """A presentation with no answer (a timeout) between the last acceptance and the first
    refusal narrows nothing: the bracket runs from the acceptance."""
    log = _log([(0, True), (20, True), (40, True), (50, False), (80, False)])
    w = [p for p in log.presentations if p.under == "W"]
    w[2].cls, w[2].accepted, w[2].timed_out = "error", False, True       # the one at 40 s
    log.w_effects = [e for e in log.w_effects if e != TW + 40]
    o = classify_trial(log)
    assert o.bracket == (20.0, 50.0) and o.outcome == "within"


def test_a_variant_with_an_inconclusive_trial_passes_only_with_enough_clean_trials():
    """Any fail is the fail; otherwise an inconclusive trial withholds the
    pass unless at least `need` trials passed. At the published counts the probe runs exactly
    `need`, so one inconclusive trial withholds it."""
    inc = timing.TrialOutcome("inconclusive", None, time_s=96, bracket=(48, 96))
    five = _outcomes([1, 2, 3, 4])
    assert timing.aggregate(five + [inc], T, need=5) == ("inconclusive", None)
    assert timing.aggregate(five + [inc], T) == ("inconclusive", None)
    assert timing.aggregate(_outcomes([1, 2, 3, 4, 5]) + [inc], T, need=5) == (
        "refused_within_T", True)                                          # enough remain
    assert timing.aggregate(five + [inc] + _outcomes([], late=1), T, need=5) == (
        "refused_late", False)                                             # a fail is a fail
    assert timing.aggregate([inc, inc], T, need=2) == ("inconclusive", None)
    info = [timing.TrialOutcome("collateral_refusal", None)]
    assert timing.aggregate(_outcomes([1, 2]) + info, T, need=3) == ("refused_within_T", True)
    s = timing.statistics(five + [inc], T)
    assert s["inconclusive"] == 1 and s["n_counted"] == 4 and s["bracket_width_s"]["max"] == 48


def test_a_recorded_pass_whose_bracket_crosses_t_is_reread_as_inconclusive():
    within = timing.TrialOutcome("within", True, time_s=15.79, bracket=(5.0, 15.79))
    tight = timing.TrialOutcome("within", True, time_s=2.0, bracket=(1.9, 2.0))
    assert timing.rejudge(within, 10.0, 1.0).outcome == "inconclusive"
    assert timing.rejudge(tight, 10.0, 1.0) is tight
    late = timing.TrialOutcome("late", False, time_s=15.0, bracket=(5.0, 15.0))
    assert timing.rejudge(late, 10.0, 1.0) is late


def test_recovery_is_judged_against_the_stated_recovery_bound():
    """(send time after the source came back, accepted?, refused?) for L."""
    def j(ls, bound=30.0, w_late=None):
        return timing.judge_recovery(ls, w_late, bound, 180.0, None)["outcome"]
    assert j([(0, False, True), (10, False, True), (12, True, False)]) == "recovered"
    assert j([(0, False, True), (30.05, False, True), (45, True, False)]) == "recovered_late"
    assert j([(0, False, True), (12, False, True), (45, True, False)]) == "inconclusive"
    assert j([(0, False, True), (30.05, False, True)]) == "stuck_closed"
    assert j([(0, False, True), (12, True, False)], w_late=31.0) == "accepted_after_recovery"
    assert j([(0, False, True), (45, True, False)], bound=None) == "recovered"
    d = timing.judge_recovery([(2.0, False, True), (9.5, True, False)], None, 8.0, 130.0, 1.0)
    assert d["outcome"] == "inconclusive" and d["bracket"] == [2.0, 9.5]


def test_the_recovery_schedule_puts_its_boundary_slots_at_the_recovery_bound():
    slots = timing.schedule(60.0, random.Random(1), window=180.0, boundary_at=30.0)
    kinds = {s.kind: s.offset_s for s in slots if s.kind != "regular"}
    assert kinds == {"boundary-before": pytest.approx(29.95), "boundary-after": pytest.approx(30.05)}
