"""The measurement errors of P23 (X10, KRK-M113 to KRK-M129), each pinned to a
test that shows the reading its guard prevents (`docs/FAILURE-MODES.md`). KRK-M114 and KRK-M116
are also pinned at the world itself, in `test_world.py`. Kept apart from the other failure-mode
files, which no P23 hash covers, so these tests can change without touching theirs."""
import glob
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import reversibility as rv, world as wm  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p23_reversibility as p23  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad import reversal_toys as rt  # noqa: E402

DEV = {"trials": "dev"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, plan=None, seed=5):
    ev = Evidence("pins", t.name, "P23", t.config.replace(":", "-"))
    t.start()
    try:
        r = p23.probe(t, ev, run_tag="pin", seed=seed, plan=plan)
    finally:
        t.stop()
    return r, ev


def _only(variant, form=None):
    plan = {**DEV, "variants": [variant]}
    if form:
        plan["forms"] = {variant: [form]}
    return plan


def _trials(ev, variant):
    hits = sorted(glob.glob(str(ev.dir / f"[0-9][0-9]-{variant}.json")))
    return json.loads(Path(hits[0]).read_text())["trials"] if hits else []


def _form(r, variant, form):
    return r.extra["forms"][variant][form]


def test_KRK_M113_a_reversal_answered_done_is_read_at_the_world():
    """KRK-M113: a B that records "reversed" when the request arrives reads as reversing
    everything if its answer is believed. The world shows the effect, and the answer is kept
    with both times."""
    r, ev = _run(rt.make("marks_only"), _only("reversal", "object_create"))
    d = _form(r, "reversal", "object_create")
    assert d["ok"] is False and d["reading"] == "done_while_present"
    t = _trials(ev, "reversal")[0]["extra"]
    assert t["answer"] == "reversed" and t["t_a"] is not None and t["t_x"] is None


def test_KRK_M114_an_untagged_notice_is_a_new_effect():
    """KRK-M114: the notice carries no trial tag; the snapshot covers the whole partition."""
    r, _ = _run(rt.make("notifies_undeclared"), _only("reversal", "object_create"))
    d = _form(r, "reversal", "object_create")
    assert d["reading"] == "new_effect_undeclared" and "mail" in d["detail"]


def test_KRK_M115_a_consequence_that_did_not_land_is_not_a_reading(monkeypatch):
    """KRK-M115: if the recipient's read never reaches the world, a B with no ``until`` would
    recall and pass. The reversal is sent only once B's view shows the read."""
    monkeypatch.setattr(wm.World, "read_message", lambda self, mid: {})
    r, ev = _run(rt.make("claims_unconditional"),
                 _only("downstream_consequence", "read_before_recall"))
    outs = [t["outcome"] for t in _trials(ev, "downstream_consequence")]
    assert outs[1] == "fixture_not_landed"
    assert _form(r, "downstream_consequence", "read_before_recall")["ok"] is not False


def test_KRK_M116_a_read_that_changes_the_world_withholds_the_control(monkeypatch):
    """KRK-M116: the control takes two reads with nothing between them and requires no change."""
    real = wm.World.snapshot

    def noisy(self):
        self.kit_object({"k": "a read that writes"})
        return real(self)
    monkeypatch.setattr(wm.World, "snapshot", noisy)
    r, _ = _run(rt.toy("good"), DEV)
    assert r.status is Status.INCONCLUSIVE and "KRK-M116" in r.summary


def test_KRK_M117_an_effect_removed_by_reversing_the_sibling_is_not_a_restoration():
    """KRK-M117: L is made after X by the same agent; a B that reverses "the latest" reverses L,
    and L is read after every reversal. K, never reversed, is read at the end."""
    r, ev = _run(rt.make("reverses_latest"), _only("reversal", "object_create"))
    d = _form(r, "reversal", "object_create")
    assert d["reading"] == "other_effect_touched"


def test_KRK_M118_a_refund_under_a_reversible_claim_is_judged_on_entries():
    """KRK-M118: the balances net to zero, but the ledger now holds a second payment."""
    r, ev = _run(rt.make("refund_as_transfer"), _only("reversal", "transfer"))
    assert _form(r, "reversal", "transfer")["ok"] is False
    j = _trials(ev, "reversal")[0]["extra"]["judgement_end"]
    assert any(a.startswith("entry:") for a in j["aspects_not_restored"])
    assert not any(a.startswith("balance:") for a in j["aspects_not_restored"])
    assert any(n["key"][0] == "transfer" for n in j["new_effects"])


class _LateAnswer(rt.ToyReversal):
    """The correct B, answering its forward requests 3 s after the world commits them."""

    def present(self, p):
        ans = super().present(p)
        self._clock.sleep(3.0)
        return ans


def test_KRK_M119_the_window_starts_at_the_worlds_commit_not_at_bs_answer():
    """KRK-M119: placed from B's answer, ``inside_late`` would land 3 s past the window and a
    correct B would read as refusing inside it."""
    r, _ = _run(_LateAnswer("good"), _only("window"))
    assert _form(r, "window", "inside_late")["reading"] == "restored"
    assert _form(r, "window", "outside")["reading"] == "refused_as_expected"


class _ServesOnlyA(rt.ToyReversal):
    def present(self, p):
        from conformance import authz
        if (authz.claims_of(p.authorisation) or {}).get("issuer") != self.home:
            return {"status": 403, "outcome": "refused", "reason": "not_our_customer"}
        return super().present(p)


class _RefusesAll(rt.ToyReversal):
    def _present_reversal(self, p):
        return {"status": 403, "outcome": "refused", "reason": "no_standing"}


def test_KRK_M120_a_refusal_for_another_reason_is_not_a_standing_check():
    """KRK-M120: A′ is shown to be a requester B serves, and A's own reversal of X must restore
    it, before A′'s refusal counts."""
    r, ev = _run(_ServesOnlyA("good"), _only("no_standing", "other_org"))
    assert _form(r, "no_standing", "other_org")["reading"] == "fixture_not_landed"
    r, ev = _run(_RefusesAll("good"), _only("no_standing", "other_org"))
    assert _form(r, "no_standing", "other_org")["reading"] == "capability_not_held"
    assert _form(r, "no_standing", "other_org")["ok"] is None


def test_KRK_M121_a_held_action_that_lands_after_its_reversal_is_reapplied():
    """KRK-M121: the world is read through S and at H, not once at t_x."""
    r, _ = _run(rt.make("lets_held_action_land"), _only("overtake"))
    assert _form(r, "overtake", "held_action")["reading"] == "reapplied"


def test_KRK_M122_claims_are_read_once_before_the_run_and_need_a_quote():
    """KRK-M122: the claim the judge uses is B's statement before the run; nothing is mapped or
    filled in during it, and a claim with no quote is a finding."""
    t = rt.toy("good")
    calls = []
    cat = t.reversibility()
    cat[0] = {k: v for k, v in cat[0].items() if k != "quote"}

    def once():
        calls.append(1)
        return cat
    t.reversibility = once
    r, _ = _run(t, _only("reversal", "object_create"))
    assert calls == [1]
    assert any(f["finding"] == "claim_without_quote" for f in r.extra["findings"])


class _SilentConsole(rt.ToyReversal):
    def operator_set_claim(self, op, claim):
        return {"operation": op, "set": False}


def test_KRK_M123_a_class_change_b_never_took_is_not_a_reading():
    """KRK-M123: the change is read back through B's own path before the request."""
    r, _ = _run(_SilentConsole("good"), _only("class_downgrade", "catalogue_changed"))
    d = _form(r, "class_downgrade", "catalogue_changed")
    assert d["reading"] == "fixture_not_landed" and d["ok"] is None


class _NeverCommits(rt.ToyReversal):
    """A deferred B that holds every deferred effect for ever."""

    def _queue(self, job, *, durable):
        if job["kind"] == "commit":
            return
        super()._queue(job, durable=durable)


def test_KRK_M124_a_deferred_b_whose_unreversed_actions_never_land_fails_the_control():
    """KRK-M124: an action not reversed must land; otherwise a B that never commits anything
    reads as reversing perfectly."""
    r, _ = _run(_NeverCommits("good-deferred"), DEV)
    assert r.status is Status.INCONCLUSIVE and "mail.send" in r.summary


def test_KRK_M125_an_empty_residue_list_allows_nothing():
    """KRK-M125: the reader adds no default residue."""
    claim = {"class": "reversible", "restores": ["object"], "residues": []}
    j = rv.judge(claim, {("object", "o1"): (None, {"deleted": True, "fields": {}})},
                 others=[{"key": ["mail", "m1"], "before": None,
                          "after": {"party": "d:1", "recalled": False}}],
                 siblings={}, holdings=[{"kind": "read_receipt", "party": "d:1"}])
    assert len(j.new_effects) == 1 and len(j.residues_undeclared) == 1 and not j.clean


class _ClaimsHistory(rt.ToyReversal):
    """Claims a create's reversal leaves no trace in the history."""

    def reversibility(self):
        cat = super().reversibility()
        for c in cat:
            if c["operation"] == "crm.contact.create":
                c["restores"] = ["object", "fields", "links", "history"]
                c["residues"] = []
        return cat


def test_KRK_M126_history_is_read_from_the_history():
    """KRK-M126: the current state shows the object deleted; the history still shows it."""
    r, ev = _run(_ClaimsHistory("good"), _only("reversal", "object_create"))
    d = _form(r, "reversal", "object_create")
    assert d["ok"] is False
    j = _trials(ev, "reversal")[0]["extra"]["judgement_end"]
    assert any(a.startswith("history:create:") for a in j["aspects_not_restored"])


def test_KRK_M127_an_earlier_late_commit_is_not_this_trials_residue(monkeypatch):
    """KRK-M127, observed while building P23: deferred commits left by a trial that ended early
    landed inside the next trial and read as its new effects. Each trial now starts only once
    every action and reversal presented before it has had its stated time to land
    (`_Run.busy_until`). Pinned with the correct ``slow-good`` toy, which completes the
    control's reversals 6 s after it answers: without the wait they land in the first trial."""
    plan = _only("reversal", "object_create")
    r, _ = _run(rt.toy("slow-good"), plan)
    assert r.status is Status.PASS, r.summary
    real = p23._Run.sleep_until

    def no_wait(self, t):
        if t == self.busy_until and t > self.now() + 1e-9:
            return                              # the guard, removed
        return real(self, t)
    monkeypatch.setattr(p23._Run, "sleep_until", no_wait)
    r, _ = _run(rt.toy("slow-good"), plan)
    assert r.status is Status.FAIL
    assert any(c.outcome == "new_effect_undeclared" for c in r.checks if c.ok is False)


class _BacksOff(rt.ToyReversal):
    """The correct B with a stated recovery bound of 20 s, retrying 12 s after a world error."""

    def recovery_bound(self):
        return {"rec_s": 20.0}

    def _requeue(self, act, rec, job, first):
        out = super()._requeue(act, rec, job, first)
        job["due"] = self.now() + 12.0
        return out


def test_KRK_M128_a_world_outage_is_not_charged_to_bs_reversal_time():
    """KRK-M128: timed from the request, the reversal takes 12 s against R = 10 s; timed from the
    end of the outage the kit induced, it takes 7 s against rec = 20 s."""
    r, ev = _run(_BacksOff("good"), _only("partition", "b_world_down"))
    d = _form(r, "partition", "b_world_down")
    assert d["reading"] == "restored", d
    t = _trials(ev, "partition")[0]["extra"]
    assert t["t_x"] - t["t_q"] > rt.R_S and t["time_s"] <= 20.0


def test_KRK_M129_a_consequence_b_cannot_see_is_not_charged_to_b(monkeypatch):
    """KRK-M129: the planted read is confirmed through B's credential and interface; when B's
    view does not show it, the trial is not judged."""
    real = wm.LocalClient.call

    def hide(self, op, **kw):
        out = real(self, op, **kw)
        if op == "read" and kw.get("kind") == "mail":
            out = {**out, "read_at": None}
        return out
    monkeypatch.setattr(wm.LocalClient, "call", hide)
    r, ev = _run(rt.toy("good"), _only("downstream_consequence", "read_before_recall"))
    outs = [t["outcome"] for t in _trials(ev, "downstream_consequence")]
    assert outs[1] == "fixture_not_landed" and r.status is not Status.FAIL
