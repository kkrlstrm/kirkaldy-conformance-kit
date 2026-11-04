"""The measurement errors of P20 (X1, KRK-M67 to KRK-M79) and P21 (X5, KRK-M80 to
KRK-M92), two observed while building P20 (KRK-M93, M94), and one observed in
development readings of the reference implementation (KRK-M95, P20 and P21), each pinned to a
test that shows the reading its guard prevents (`docs/FAILURE-MODES.md`). Kept apart from
`test_failure_modes.py`, which P16 to P19 do not hash either, so these properties' tests can
change without touching theirs."""
import ast
import fnmatch
import glob
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import attenuation as att, standing  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.issuer import StubIssuer  # noqa: E402
from conformance.properties import p20_standing_offline as p20  # noqa: E402
from conformance.properties import p21_no_widening as p21  # noqa: E402
from conformance.result import Status  # noqa: E402
from conformance.timing import VirtualClock  # noqa: E402
from known_bad import attenuation_toys as at, standing_toys as sts  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEV = {"trials": "dev"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(mod, t, tag, plan):
    ev = Evidence("pins", t.name, mod.ID, t.config.replace(":", "-"))
    t.start()
    try:
        r = mod.probe(t, ev, run_tag=tag, seed=5, plan=plan)
    finally:
        t.stop()
    return r, ev


def _evidence(ev, variant):
    hits = sorted(glob.glob(str(ev.dir / f"[0-9][0-9]-{variant}.json")))
    return json.loads(Path(hits[0]).read_text()) if hits else {}


def _form(r, variant, form):
    return r.extra["forms"][variant][form]


# --------------------------------------------------------------------------- P20


def test_KRK_M67_fresh_from_the_fetch_is_not_fresh_from_A():
    c = VirtualClock()
    A = StubIssuer(clock=c)
    A.serve_local()
    s = A.assert_standing("p@a", {"op": None}, renew=False)
    c.sleep(40.0)
    A.fetch_local("/standing/p%40a", "b")
    assert A.latest_delivered("p@a", c.now() + 1) == s.t_signed   # not the fetch, 40 s later
    r, _ev = _run(p20, sts.make("age_from_fetch"), "f67",
                  {**DEV, "variants": ["stale_signed"], "forms": {"stale_signed":
                                                                  ["aged_at_fetch"]}})
    assert _form(r, "stale_signed", "aged_at_fetch")["ok"] is False


def test_KRK_M68_evidence_that_reached_B_by_a_staple_counts():
    c = VirtualClock()
    A = StubIssuer(clock=c)
    A.serve_local()
    s1 = A.assert_standing("p@a", {"op": None})
    A.fetch_local("/standing/p%40a", "b")
    c.sleep(10.0)
    s2 = A.assert_standing("p@a", {"op": None}, publish=False)
    assert A.latest_delivered("p@a") == s1.t_signed
    A.note_staple(s2, c.now())
    assert A.latest_delivered("p@a") == s2.t_signed


def test_KRK_M69_the_sibling_differs_only_in_the_evidence():
    r, ev = _run(p20, sts.make(), "f69", {**DEV, "variants": ["deep_chain"]})
    for t in _evidence(ev, "deep_chain")["trials"]:
        ex = t["extra"]
        if "W_signers" in ex and "L_signers" in ex:
            kinds = lambda xs: [x.split(":")[0] for x in xs]  # noqa: E731
            assert kinds(ex["W_signers"]) == kinds(ex["L_signers"])


def test_KRK_M70_another_organisations_evidence_lands_only_with_it_pinned():
    t = sts.make("any_pinned_key")
    t.issuers = lambda: 1
    r, _ev = _run(p20, t, "f70", {**DEV, "variants": ["key_of_other_org"]})
    assert _form(r, "key_of_other_org", "-")["reading"] == "issuer_not_supported"
    r, _ev = _run(p20, sts.make("any_pinned_key"), "f70b",
                  {**DEV, "variants": ["key_of_other_org"]})
    assert _form(r, "key_of_other_org", "-")["ok"] is False


def test_KRK_M71_a_key_change_the_adapter_applied_is_information():
    t = sts.make()
    t.keys_from = lambda: "adapter"
    r, _ev = _run(p20, t, "f71", {**DEV, "variants": ["retired_key"],
                                 "forms": {"retired_key": ["revoked_key"]}})
    assert _form(r, "retired_key", "revoked_key")["reading"] == "adapter_reading"


def test_KRK_M72_online_only_is_judged():
    r, _ev = _run(p20, sts.make("online_only"), "f72",
                  {**DEV, "variants": ["a_unreachable"]})
    assert r.status is Status.FAIL and dict((c.name, c.outcome) for c in r.checks)[
        "a_unreachable"] == "online_only"


def test_KRK_M73_the_offline_sibling_sits_behind_no_outage():
    t = sts.make()
    t.issuers = lambda: 2                    # A and A′ only: no A2
    r, ev = _run(p20, t, "f73", {**DEV, "variants": ["a_unreachable"],
                                "forms": {"a_unreachable": ["down"]}})
    assert all(x["extra"].get("sibling") is None for x in _evidence(ev, "a_unreachable")
               ["trials"])
    r, ev = _run(p20, sts.make(), "f73b", {**DEV, "variants": ["a_unreachable"],
                                          "forms": {"a_unreachable": ["down"]}})
    assert all(x["extra"].get("sibling") == "A2" for x in _evidence(ev, "a_unreachable")
               ["trials"])


def test_KRK_M74_the_reference_instant_is_the_signing_log_not_the_claim():
    r, _ev = _run(p20, sts.make("trusts_issuer_time"), "f74",
                  {**DEV, "variants": ["clock_skew"]})
    assert _form(r, "clock_skew", "issuer_ahead")["ok"] is False
    r, _ev = _run(p20, sts.make(), "f74b", {**DEV, "variants": ["clock_skew"]})
    assert _form(r, "clock_skew", "issuer_ahead")["ok"] is True


def test_KRK_M75_a_depth_limit_is_not_a_standing_check():
    t = sts.make()
    t.max_depth = lambda: 2
    r, _ev = _run(p20, t, "f75", {**DEV, "variants": ["deep_chain"]})
    assert {d["reading"] for d in r.extra["forms"]["deep_chain"].values()} == {"depth_refused"}
    t = sts.make()
    t._read = (lambda real: lambda p: ("refused three hops", None, None)
               if p.headers.get("KRK-Grant-Chain", "").count(",") >= 1 else real(p))(t._read)
    r, _ev = _run(p20, t, "f75b", {**DEV, "variants": ["deep_chain"]})
    assert _form(r, "deep_chain", "three_hops")["reading"] == "depth_refused"
    assert _form(r, "deep_chain", "root_missing")["reading"] == "depth_refused"


def test_KRK_M76_an_action_class_the_format_cannot_say_is_a_gap():
    r, _ev = _run(p20, sts.make(x4=True), "f76",
                  {**DEV, "variants": ["agent_not_principal"]})
    assert _form(r, "agent_not_principal", "other_action_class")["reading"] == "format_gap"
    assert r.status is not Status.FAIL


def test_KRK_M77_a_stale_fixture_is_stale():
    assert not p20.stale_enough(60.05, 60.0, 0.05)
    assert p20.stale_enough(60.11, 60.0, 0.05)


def test_KRK_M78_every_fixtures_own_expiry_is_far_beyond_T():
    c = VirtualClock()
    A = StubIssuer(clock=c)
    s = A.assert_standing("p@a", {"op": None})
    assert p20.not_after_far(s)
    short = A.assert_standing("p@a", {"op": None}, not_after=A.now() + 30)
    assert not p20.not_after_far(short)


def test_KRK_M79_every_hop_after_the_root_is_holder_signed():
    c = VirtualClock()
    A = StubIssuer(clock=c)
    A.serve_local()
    C = A.peer()
    root = A.issue_v2("a1", {"operations": ["op"]}, principal="p@a")
    h1 = A.delegate_holder(root, "c1", org=C)
    h2 = C.delegate_holder(h1, "c2")
    assert [s.split(":")[0] for s in p20.chain_signers(A.chain_v2(h2))] == \
        ["holder", "holder", "org"]


def test_KRK_M93_the_previous_trials_outage_is_not_this_fixtures_refusal():
    """Observed against the kit's own x4-good toy: B still held a snapshot aged by
    the previous trial's outage, so W was refused before B had the evidence under test."""
    r, ev = _run(p20, sts.make(x4=True), "f93", {"trials": {"*": 5, "static": 1,
                                                           "a_unreachable": 1,
                                                           "a_unreachable/worst": 0},
                                                "variants": ["a_unreachable", "stale_signed"],
                                                "forms": {"a_unreachable": ["down"],
                                                          "stale_signed": ["served"]}})
    assert _form(r, "stale_signed", "served")["ok"] is True, r.extra["forms"]
    assert all(t["extra"].get("fetched_stale") for t in _evidence(ev, "stale_signed")["trials"])


def test_KRK_M94_evidence_B_never_held_is_not_judged():
    """Observed: a B that reads status lists accepts a grant its snapshot predates
    (not yet listed) holding no evidence that names the principal, so t_f was
    empty. P20 waits for B's next fetch of a snapshot that lists the principal."""
    r, ev = _run(p20, sts.make(x4=True), "f94", {**DEV, "variants": ["aged_in_queue"]})
    assert r.extra["forms"]["aged_in_queue"]["-"]["ok"] is True
    assert all(t["extra"].get("fetched_listing_principal") for t in
               _evidence(ev, "aged_in_queue")["trials"])


def _PullOnly(config="good"):
    """The correct toy, reading standing as the reference implementation does: only by
    fetching, on its own poll, for the principals A's snapshot lists; never a staple, and never
    a fetch made because a request arrived (`standing_toys` ``pull-good``)."""
    assert config == "good"
    return sts.toy("pull-good")


def test_KRK_M95_a_pull_only_receiver_is_presented_after_it_could_fetch(monkeypatch):
    """Observed in development readings of the reference implementation: presented
    within milliseconds of the principal's first assertion, a receiver that only pulls refused W
    and L alike (`collateral_refusal`), and in `served` refused, accepted once it had fetched, and
    refused again (`flapped`). Presented after its fetch, the same receiver's readings are
    `refused` and within T. Without the wait (the guard off) the old readings come back."""
    plan = {"trials": {"*": 1, "static": 1, "a_unreachable": 0, "a_unreachable/worst": 0},
            "variants": ["agent_not_principal", "stale_signed"],
            "forms": {"agent_not_principal": ["other_action_class"],
                      "stale_signed": ["served"]}}
    t = _PullOnly("good")
    r, ev = _run(p20, t, "f95", plan)
    assert _form(r, "agent_not_principal", "other_action_class")["reading"] == "refused", \
        r.extra["forms"]
    assert _form(r, "stale_signed", "served")["ok"] is True, r.extra["forms"]
    static = _evidence(ev, "agent_not_principal")["trials"]
    assert static and all(all(x["extra"]["fetched_before_present"].values()) for x in static)
    assert all(x["extra"].get("fetched_stale") for x in _evidence(ev, "stale_signed")["trials"])
    monkeypatch.setattr(p20, "waits_for_fetch", lambda run: False)
    r2, _ev2 = _run(p20, _PullOnly("good"), "f95-old", plan)
    assert _form(r2, "agent_not_principal", "other_action_class")["reading"] == \
        "collateral_refusal", r2.extra["forms"]
    assert _form(r2, "stale_signed", "served")["reading"] == "flapped", r2.extra["forms"]


def test_KRK_M95_p21_waits_for_the_assertion_and_for_cs_key_statement():
    """P21: `root_exceeds_standing` presents to a pull-only receiver once it has fetched both
    root principals' assertions, every static trial does for a pull-only receiver that reads
    standing limits, and a holder chain through a hop C's agent signed once it has
    fetched C's key statement, which lists the agent. The stapling toys wait for
    nothing."""
    c = VirtualClock()
    A = StubIssuer(clock=c)
    A.serve_local()
    C = A.peer()
    k = C.agent("c1")
    assert k.kid in C.agent_kids() and k.kid not in C.trust_anchor_x1()["keys"]
    listed = {e["kid"]: e["purposes"] for e in C.keyset()["claims"]["keys"]}
    assert listed[k.kid] == ["request"]

    class R:
        pull_only, c, keys_from, extras = True, C, "statement", []
    assert p21.waits_for_fetch(R, "root_exceeds_standing", "a", 2)
    assert p21.waits_for_fetch(R, "delegation_exceeded", "holder", 3)
    assert not p21.waits_for_fetch(R, "delegation_exceeded", "holder", 2)
    assert not p21.waits_for_fetch(R, "delegation_exceeded", "a", 3)
    # A B reading standing limits learns even "none published" only by a fetch.
    R.extras = ["standing-limits"]
    assert p21.waits_for_fetch(R, "wider_child", "a", 2)
    R.pull_only = False
    assert not p21.waits_for_fetch(R, "root_exceeds_standing", "a", 2)
    assert not p21.waits_for_fetch(R, "wider_child", "a", 2)
    toy = at.make()
    assert toy.standing_channels() == ["stapled"] and toy.keys_from() == "bind"


def test_KRK_M95_KRK_M95b_p20_presents_before_the_first_fetch_and_grades_W_alone():
    """The KRK-M95 wait hides a pull-only receiver that acts before its first
    fetch. `agent_not_principal/before_first_fetch` presents W at once, before the receiver has
    fetched anything for its root principal, whose only standing covers another operation, and
    grades W's effect alone. The correct pull-only toy refuses (pass); one that acts on the chain
    alone before fetching has an effect (fail); for a stapling receiver the form is not
    applicable, and in the X4-status profile it is a format gap."""
    plan = {"trials": {"*": 1, "static": 2, "a_unreachable": 0, "a_unreachable/worst": 0},
            "variants": ["agent_not_principal"],
            "forms": {"agent_not_principal": ["before_first_fetch"]}}
    r, ev = _run(p20, sts.toy("pull-good"), "m95b-good", plan)
    assert _form(r, "agent_not_principal", "before_first_fetch")["reading"] == "refused", \
        r.extra["forms"]
    trials = _evidence(ev, "agent_not_principal")["trials"]
    assert trials and all(t["extra"]["presented_before_fetch"] for t in trials)
    assert all(not any(t["extra"]["fetched_when_sent"]) for t in trials)
    assert all(len(t["presentations"]) == p20.STATIC_ROUNDS and
               {x["under"] for x in t["presentations"]} == {"W"} for t in trials)
    bad, _ev = _run(p20, sts.toy("bad:chain_before_fetch"), "m95b-bad", plan)
    assert bad.status is Status.FAIL
    assert _form(bad, "agent_not_principal", "before_first_fetch")["reading"] == "accepted"
    good, _ev = _run(p20, sts.make(), "m95b-staples", plan)
    assert _form(good, "agent_not_principal", "before_first_fetch")["reading"] == \
        "not_applicable"
    x4, _ev = _run(p20, sts.make(x4=True), "m95b-x4", plan)
    assert _form(x4, "agent_not_principal", "before_first_fetch")["reading"] == "format_gap"


def test_KRK_M95_KRK_M95b_the_flaw_is_seen_only_before_the_first_fetch():
    """With the KRK-M95 wait, the toy that acts on the chain alone before fetching passes every
    other static form: only `before_first_fetch` exercises that window."""
    plan = {"trials": {"*": 1, "static": 1, "a_unreachable": 0, "a_unreachable/worst": 0},
            "variants": ["agent_not_principal"],
            "forms": {"agent_not_principal": ["omitted", "other_action_class",
                                              "before_first_fetch"]}}
    r, _ev = _run(p20, sts.toy("bad:chain_before_fetch"), "m95b-only", plan)
    fr = r.extra["forms"]["agent_not_principal"]
    assert fr["omitted"]["reading"] == fr["other_action_class"]["reading"] == "refused", fr
    assert fr["before_first_fetch"]["ok"] is False, fr


def test_KRK_M95_KRK_M95b_p21_presents_before_the_first_fetch_and_grades_W_alone():
    """In P21: `root_exceeds_standing/before_first_fetch` presents W, inside the
    chain and above the standing limit A publishes, before the receiver has fetched anything for
    its root principal. The correct pull-only toy refuses (held); one that bounds the request by
    the chain alone before A has answered has an effect (outside_effect); a stapling receiver
    reads not applicable."""
    plan = {**DEV, "variants": ["root_exceeds_standing"],
            "forms": {"root_exceeds_standing": ["before_first_fetch"]}}
    r, ev = _run(p21, at.toy("pull-good"), "m95b-good", plan)
    assert _form(r, "root_exceeds_standing", "before_first_fetch")["reading"] == "held"
    trials = _evidence(ev, "root_exceeds_standing")["trials"]
    assert trials and all(t["extra"]["presented_before_fetch"] for t in trials)
    assert all([x["under"] for x in t["presentations"]] == ["W"] for t in trials)
    bad, _ev = _run(p21, at.toy("bad:chain_before_fetch"), "m95b-bad", plan)
    assert bad.status is Status.FAIL
    assert _form(bad, "root_exceeds_standing", "before_first_fetch")["reading"] == \
        "outside_effect"
    good, _ev = _run(p21, at.make(), "m95b-staples", plan)
    assert _form(good, "root_exceeds_standing", "before_first_fetch")["reading"] == \
        "not_applicable"


def test_KRK_M95_KRK_M95b_p21_measures_the_poll_before_it_waits():
    """P21 measured B's fetch interval only in `narrowed_parent`, so the KRK-M95 wait before an
    earlier static trial ran with P = 0 and gave up after 6 s. The pull-only toy polls every
    T/4 (15 s): its `root_exceeds_standing` trials were presented before its fetch, and the
    flawed toy failed `amount` on the chain alone. The control now measures P from B's fetches
    of the control principal's standing, and every wait is seen."""
    plan = {**DEV, "variants": ["root_exceeds_standing"],
            "forms": {"root_exceeds_standing": ["amount", "resources"]}}
    r, ev = _run(p21, at.toy("bad:chain_before_fetch"), "m95b-poll", plan)
    assert r.extra["forms"]["root_exceeds_standing"]["amount"]["reading"] == "held", \
        r.extra["forms"]
    ctl = json.loads(next(Path(ev.dir).glob("*control.json")).read_text())
    assert ctl["fetch_intervals_s"] and max(ctl["fetch_intervals_s"]) >= 10
    trials = _evidence(ev, "root_exceeds_standing")["trials"]
    assert trials and all(all(t["extra"]["fetched_before_present"].values()) for t in trials)


def test_KRK_M95_KRK_M95c_p21_presents_chains_that_do_not_reach_a_root():
    """P21 once presented only complete chains, so a receiver that
    checks the links it is given and reads the last grant supplied as the root passed every form
    (`walks_supplied_only` passes every variant but `incomplete_chain` and two cycle forms).
    `incomplete_chain` presents a chain that stops before its root, a child with no ancestors and
    two grants naming each other: that receiver fails each, and the correct one holds each."""
    plan = {**DEV, "variants": ["incomplete_chain"]}
    good, _ev = _run(p21, at.make(), "m95c-good", plan)
    assert good.status is Status.PASS
    bad, ev = _run(p21, at.make("walks_supplied_only"), "m95c-bad", plan)
    assert bad.status is Status.FAIL
    for f in p21.FORMS["incomplete_chain"]:
        assert _form(good, "incomplete_chain", f)["reading"] == "held", f
        assert _form(bad, "incomplete_chain", f)["reading"] == "outside_effect", f
    trials = _evidence(ev, "incomplete_chain")["trials"]
    stop = [t for t in trials if t["form"] == "stops_before_root"]
    assert stop and all(len(t["extra"]["withheld"]) == 1 and len(t["extra"]["signers"]) == 2
                        for t in stop)
    rest, _ev = _run(p21, at.make("walks_supplied_only"), "m95c-rest",
                     {**DEV, "variants": [v for v in p21.VARIANTS if v not in
                                          ("incomplete_chain", "cycle")]})
    assert rest.status is Status.PASS, rest.summary


# --------------------------------------------------------------------------- P21


def test_KRK_M80_a_shape_refusal_is_not_a_width_refusal():
    assert p21.shape_refused(True, 3, False) and p21.shape_refused(True, 2, True)
    t = at.make()
    t._judge = (lambda real: lambda chain, v, s: "no three-hop chains" if len(chain) > 2
                else real(chain, v, s))(t._judge)
    r, _ev = _run(p21, t, "f80", {**DEV, "variants": ["middle_narrow"]})
    assert _form(r, "middle_narrow", "amount")["reading"] == "shape_refused"


def test_KRK_M81_the_widening_request_is_inside_the_leaf():
    for form in p21.FORMS["wider_child"]:
        f = p21.fixture("wider_child", form, random.Random(1), party="did:web:b.example",
                        dims=list(att.DIMENSIONS), max_depth=4, mapping=None, tolerance=5)
        t = p21.truth(f, now=1.8e9, at=1.8e9 + (f.present_at + 6 if f.present_at else 0),
                      tolerance_s=5, party="did:web:b.example")
        assert t["w_in_leaf"] is None and t["w_outside"], (form, t)


def test_KRK_M82_a_check_of_the_ends_is_caught_at_three_hops():
    f = p21.fixture("middle_narrow", "amount", random.Random(1), party="did:web:b.example",
                    dims=list(att.DIMENSIONS), max_depth=4, mapping=None)
    assert len(f.hops) == 3
    r, _ev = _run(p21, at.make("ends_only"), "f82", {**DEV, "variants": ["middle_narrow",
                                                                       "wider_child"]})
    assert _form(r, "middle_narrow", "amount")["ok"] is False
    assert _form(r, "wider_child", "amount")["ok"] is True


def test_KRK_M83_the_kits_intersection_imports_no_target():
    tree = ast.parse((ROOT / "conformance" / "attenuation.py").read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert mods <= {"__future__", "re", "dataclasses", "typing", "datetime"}, mods


def test_KRK_M84_a_widening_the_format_cannot_say_does_not_land():
    assert p21.gaps_for("wider_child", "resources", ["max_amount"], []) == ["resources"]
    assert p21.gaps_for("wider_child", "amount", ["max_amount"], []) == []
    t = at.make("leaf_only")
    t.constraint_profile = lambda: ["max_amount", "window"]
    r, _ev = _run(p21, t, "f84", {**DEV, "variants": ["wider_child"]})
    assert _form(r, "wider_child", "resources")["reading"] == "format_gap"
    assert _form(r, "wider_child", "amount")["ok"] is False


def test_KRK_M85_the_sibling_carries_the_same_members():
    for v in ("numeric", "unknown_constraint", "dropped_constraint"):
        for form in p21.FORMS[v]:
            f = p21.fixture(v, form, random.Random(1), party="did:web:b.example",
                            dims=list(att.DIMENSIONS), max_depth=4, mapping=None)
            if form in ("omitted", "in_parent", "in_child", "marked_critical", "near_name"):
                continue                     # the member under test is what differs
            for hw, hl in zip(f.hops, f.sib_hops):
                assert set(hw.c) == set(hl.c), (v, form)


def test_KRK_M86_amounts_compare_in_one_unit():
    assert att.amount_le({"value": 150, "currency": "EUR", "minor_units": 0},
                         {"value": 10000, "currency": "EUR", "minor_units": 2}) is False
    r, _ev = _run(p21, at.make("ignores_units"), "f86", {**DEV, "variants": ["numeric"]})
    assert _form(r, "numeric", "units")["ok"] is False


def test_KRK_M87_pattern_readings_agree_except_where_the_form_needs_them_not_to():
    def readings(pattern, rid):
        return {"prefix": att.covers(pattern, rid), "glob": fnmatch.fnmatchcase(rid, pattern),
                "literal": rid == pattern or (pattern.endswith("/*")
                                              and rid.startswith(pattern[:-1]))}
    for form in ("resources",):
        f = p21.fixture("wider_child", form, random.Random(1), party="did:web:b.example",
                        dims=list(att.DIMENSIONS), max_depth=4, mapping=None)
        rid = f.request["resources"][0]
        for p in f.hops[0].c["resources"]:
            assert len(set(readings(p, rid).values())) == 1, (p, rid)


def test_KRK_M88_a_time_widening_is_probed_after_the_parent_lapsed_with_tolerance():
    f = p21.fixture("wider_child", "time_after", random.Random(1), party="did:web:b.example",
                    dims=list(att.DIMENSIONS), max_depth=4, mapping=None, tolerance=60)
    now = 1.8e9
    early = p21.truth(f, now=now, at=now + f.present_at + 30, tolerance_s=60,
                      party="did:web:b.example")
    late = p21.truth(f, now=now, at=now + f.present_at + 61, tolerance_s=60,
                     party="did:web:b.example")
    assert early["w_outside"] is None and late["w_outside"]


def test_KRK_M89_the_chain_that_left_the_kit_is_digested():
    a = p21.chain_digest({"KRK-Grant": "x", "KRK-Grant-Chain": "y,z"})
    b = p21.chain_digest({"KRK-Grant": "x", "KRK-Grant-Chain": "y"})
    assert a != b and a.startswith("sha256:")


def test_KRK_M90_both_chains_reach_B_as_built():
    r, ev = _run(p21, at.make("unions_grants"), "f90", {**DEV, "variants": ["combined"]})
    assert _form(r, "combined", "union_dimensions")["ok"] is False
    docs = _evidence(ev, "combined")["trials"]
    assert all("W" in t["extra"]["chain_digests"] for t in docs)


def test_KRK_M91_a_parent_narrowing_counts_once_it_reads_back():
    t = at.make()
    r, _ev = _run(p21, t, "f91", {**DEV, "variants": ["narrowed_parent"]})
    assert _form(r, "narrowed_parent", "-")["ok"] is True
    import conformance.issuer as iss
    real = iss.StubIssuer.read_back
    try:
        iss.StubIssuer.read_back = lambda self, expect: {k: False for k in expect}
        r, _ev = _run(p21, at.make(), "f91b", {**DEV, "variants": ["narrowed_parent"]})
    finally:
        iss.StubIssuer.read_back = real
    assert _form(r, "narrowed_parent", "-")["reading"] == "fixture_not_landed"


def test_KRK_M92_the_mapping_is_the_one_declared():
    t = at.make()
    assert p21.mapping_from_agreement(t) == at.MAPPING
    t.mappings = lambda: {}
    r, _ev = _run(p21, t, "f92", {**DEV, "variants": ["translated_hop"]})
    assert _form(r, "translated_hop", "mapping_widens")["reading"] == "format_gap"
