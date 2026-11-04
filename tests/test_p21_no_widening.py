"""P21 (KRK-21, no widening) against its vectors and toys (`known_bad/attenuation_toys.py`): the
kit's vocabulary reads as the hand-written vectors say, the correct B passes in both modes
(``clamped`` and ``chain_refused``), each flaw fails the variant it is built for, the toy that
hangs on a cycle reads ``hung``, the toy whose executor never reaches the recorder gives no
verdict, and a B whose format carries fewer dimensions gets format gaps, never passes."""
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import attenuation as att  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p21_no_widening as p21  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.attenuation_toys import FAILS, FLAWS, FORM, ToyAttenuation, make, toy  # noqa: E402

VEC = json.loads((Path(__file__).parent / "vectors" / "krk21" / "vectors.json").read_text())
DEV = {"trials": "dev"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, tag="t", *, plan=None, seed=11):
    ev = Evidence("p21", t.name, "P21", t.config.replace(":", "-"))
    t.start()
    try:
        return p21.probe(t, ev, run_tag=tag, seed=seed, plan=plan)
    finally:
        t.stop()


def _checks(r):
    return {c.name: (c.outcome, c.ok) for c in r.checks}


def _forms(r, variant):
    return r.extra["forms"][variant]


# --------------------------------------------------------------------------- the vectors


def test_vectors_covers():
    for parent, child, want in VEC["covers"]:
        assert att.covers(parent, child) is want, (parent, child)


def test_vectors_amounts():
    for a, b, want in VEC["amount_le"]:
        assert att.amount_le(a, b) is want, (a, b)


def test_vectors_wider():
    win = {"not_before": "2026-11-02T09:00:00Z", "not_after": "2026-11-02T21:00:00Z"}
    for child, parent, want in VEC["wider"]:
        got = att.wider({"constraints": child, **win}, {"constraints": parent, **win})
        assert sorted(got) == sorted(want), (child, parent, got)


def test_vectors_chains():
    for name, v in VEC["chains"].items():
        got = att.allowed(v["chain"])
        if v["refusal"] is None:
            assert isinstance(got, att.Allowed), (name, got)
        else:
            assert isinstance(got, att.Refusal) and got.reason == v["refusal"], (name, got)


def test_vectors_inside():
    from conformance import status
    for v in VEC["inside"]:
        a = att.allowed(VEC["chains"][v["chain"]]["chain"])
        got = att.inside(v["request"], a, at=status.epoch_of(v["at"]),
                         tolerance_s=VEC["tolerance_s"], party=VEC["party"])
        if v["expected"] is None:
            assert got is None, (v, got)
        else:
            assert got and v["expected"] in got, (v, got)


def test_vectors_standing_limits():
    for v in VEC["standing"]:
        a = att.allowed(VEC["chains"][v["chain"]]["chain"], v["classes"])
        got = att.inside(v["request"], a, party=VEC["party"])
        assert (got is None) if v["expected"] is None else (v["expected"] in (got or "")), v


def test_every_fixture_means_what_it_says():
    """KRK-M81, M83: by the kit's own vocabulary, W's request is outside the intersection and
    inside the leaf, L's and W-in's inside theirs, for every form."""
    m = {"operations": {"contacts:write": [p21.OP_A, p21.OP_B]}}
    for v, forms in p21.FORMS.items():
        for f in forms:
            fx = p21.fixture(v, f, random.Random(3), party="did:web:b.example",
                             dims=list(att.DIMENSIONS), max_depth=4, mapping=m, tolerance=5)
            now = 1.8e9
            at = now + (fx.present_at + 6 if fx.present_at else 0)
            t = p21.truth(fx, now=now, at=at, tolerance_s=5, party="did:web:b.example")
            assert t["w_outside"] or (v, f) == ("cycle", "too_deep"), (v, f, t)
            assert t["l_inside"] is None, (v, f, t)
            if fx.request_in is not None:
                assert t["w_in_inside"] is None, (v, f, t)


# --------------------------------------------------------------------------- the toys


def test_the_correct_b_passes_at_the_methods_counts_clamped():
    r = _run(make())
    assert r.status is Status.PASS, r.summary
    for v in p21.VARIANTS:
        assert _checks(r)[v][1] is True, (v, _checks(r)[v])
    assert r.extra["format_gaps"] == [] and set(r.extra["dimensions_covered"]) == set(
        att.DIMENSIONS)
    assert "clamped" in r.extra["modes"]["wider_child"]


def test_the_strict_b_passes_and_says_it_refuses_the_chain():
    r = _run(ToyAttenuation("good-strict"), "strict")
    assert r.status is Status.PASS, r.summary
    for v in p21.VARIANTS:
        assert _checks(r)[v][1] is True, (v, _checks(r)[v])
    assert r.extra["modes"]["wider_child"] == ["chain_refused"]
    assert r.extra["modes"]["narrowed_parent"] == ["chain_refused"]


def _narrowed_trials(t, tag):
    """Run `narrowed_parent` alone; the result and its trials as written to the evidence."""
    ev = Evidence("p21", t.name, "P21", t.config.replace(":", "-"))
    t.start()
    try:
        r = p21.probe(t, ev, run_tag=tag, seed=11, plan={**DEV, "variants": [
            "narrowed_parent"]})
    finally:
        t.stop()
    hits = sorted(ev.dir.glob("[0-9][0-9]-narrowed_parent.json"))
    return r, (json.loads(hits[0].read_text())["trials"] if hits else [])


def test_a_strict_b_that_refuses_the_narrowed_chain_passes_as_chain_refused():
    """Once the parent is narrowed, the child is a wider hop, and a strict B refuses
    the requests inside the narrowed ceiling too. That is its ``chain_refused`` mode, a pass; the
    evidence keeps what was observed (``narrowed_as_withdrawn``)."""
    r, trials = _narrowed_trials(ToyAttenuation("good-strict"), "strict-np")
    assert r.status is Status.PASS, r.summary
    assert _checks(r)["narrowed_parent"] == ("refused_within_T", True)
    assert r.extra["modes"]["narrowed_parent"] == ["chain_refused"]
    assert "mode chain_refused" in {c.name: c for c in r.checks}["narrowed_parent"].detail
    assert trials and all(t["mode"] == "chain_refused" for t in trials)
    assert all(t["observed"] == "narrowed_as_withdrawn" for t in trials)
    assert all(t["outcome"]["outcome"] == "within" and t["outcome"]["ok"] is True
               for t in trials)
    assert all("narrowed_as_withdrawn" in t["outcome"]["detail"] for t in trials)


def test_the_clamping_b_reads_clamped_after_a_narrowing():
    r, trials = _narrowed_trials(make(), "clamp-np")
    assert _checks(r)["narrowed_parent"] == ("refused_within_T", True)
    assert r.extra["modes"]["narrowed_parent"] == ["clamped"]
    assert trials and all(t["mode"] == "clamped" and "observed" not in t for t in trials)


def test_a_b_that_ignores_the_parents_narrowing_still_fails_not_refused_within_W():
    """The narrowed-parent rule changes the strict B's reading only: a B that never refuses after the
    narrowing (``static_parent``) still fails."""
    r = _run(make("static_parent"), "sp", plan={**DEV, "variants": ["narrowed_parent"]})
    assert r.status is Status.FAIL, r.summary
    assert _checks(r)["narrowed_parent"] == ("not_refused_within_W", False)
    assert "narrowed_parent" not in r.extra["modes"]


@pytest.mark.parametrize("flaw", FLAWS)
def test_each_flaw_fails_the_variant_it_is_built_for(flaw):
    variant = FAILS[flaw]
    r = _run(make(flaw), flaw, plan={**DEV, "variants": [variant]})
    assert r.status is Status.FAIL, (flaw, r.summary)
    assert _checks(r)[variant][1] is False, (flaw, _checks(r)[variant])
    form = FORM.get(flaw)
    if form:
        assert _forms(r, variant)[form]["ok"] is False, (flaw, _forms(r, variant))


def test_flaws_that_fail_more_than_their_own_variant_say_so():
    """X5 §13 item 4: `leaf_only` fails wider_child, dropped_constraint, wildcard_default and
    root_exceeds_standing."""
    r = _run(make("leaf_only"), "lo", plan={**DEV, "variants": [
        "wider_child", "dropped_constraint", "wildcard_default", "root_exceeds_standing"]})
    for v in ("wider_child", "dropped_constraint", "wildcard_default", "root_exceeds_standing"):
        assert _checks(r)[v][1] is False, v
    r = _run(make("defaults_fill"), "df", plan={**DEV, "variants": ["wildcard_default"]})
    assert _forms(r, "wildcard_default")["default_window"]["ok"] is False


def test_a_b_that_hangs_on_a_cycle_reads_hung_not_fail():
    r = _run(make("hangs_on_cycle"), "hang", plan={**DEV, "variants": ["cycle"]})
    assert _forms(r, "cycle")["id_cycle"]["reading"] == "hung"
    assert r.status is not Status.FAIL


def test_no_control_gives_no_verdict():
    r = _run(ToyAttenuation("no-control"), "nc")
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_the_bad_toy_is_leaf_only():
    assert ToyAttenuation("bad").flaw == "leaf_only"


def test_a_format_with_fewer_dimensions_gets_gaps_never_a_pass_of_them():
    """A dimension B cannot carry is listed as a finding."""
    t = make()
    t.constraint_profile = lambda: ["max_amount", "window"]
    t.format_features = lambda: []
    r = _run(t, "few", plan={**DEV, "variants": ["wider_child", "dropped_constraint",
                                                "numeric"]})
    assert r.status is Status.PASS, r.summary
    gaps = {(g["variant"], g["form"]) for g in r.extra["format_gaps"]}
    assert ("wider_child", "resources") in gaps and ("dropped_constraint", "omitted") in gaps
    assert ("numeric", "currency") in gaps and ("wider_child", "amount") not in gaps
    assert "resources" in r.extra["dimensions_not_expressible"]
    assert _forms(r, "wider_child")["resources"]["reading"] == "format_gap"
    assert "findings, never a pass" in r.summary


def test_a_b_that_refuses_holder_hops_reads_information_for_that_position():
    t = make()
    t.accepts_holder_hops = lambda: False
    r = _run(t, "nh", plan={**DEV, "variants": ["wider_child"]})
    assert r.status is Status.PASS
    assert _forms(r, "wider_child")["amount@holder"]["reading"] == "not_applicable"


def test_the_toys_are_registered_with_the_known_bad_gate():
    from conformance import knownbad
    cases = dict(knownbad.cases("P21"))
    assert cases["good"] is Status.PASS and cases["good-strict"] is Status.PASS
    assert cases["no-control"] is Status.INCONCLUSIVE
    assert {c for c in cases if c.startswith("bad:")} == {f"bad:{f}" for f in FLAWS}
    assert isinstance(knownbad._toy("P21", "bad:ends_only"), ToyAttenuation)


def test_every_wider_grant_is_genuinely_signed():
    """Each grant presented verifies under its signer's key, A's or the holder's."""
    from conformance import requester, standing
    t = make()
    seen = []
    real = t.present_deferred
    t.present_deferred = lambda p, s, d: (seen.append(p), real(p, s, d))[1]
    r = _run(t, "sig", plan={**DEV, "variants": ["wider_child", "numeric"]})
    assert r.status is Status.PASS
    anchors = {iss: o["keyset"] for iss, o in t.orgs.items()}
    for p in seen:
        toks = [p.headers[requester.GRANT_HEADER]] + [
            x for x in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if x]
        _h, problem = standing.verify_holder_chain(toks, anchors, lenient=True)
        assert problem is None, problem


def test_stated_depth_with_no_maximum_is_a_finding_not_not_applicable(monkeypatch):
    """A B that declares `stated-depth` while `max_depth()` returns None
    reads `cycle/too_deep` as a format-gap finding, as a B that does not declare it does, never `not_applicable`; the other cycle forms are graded as before."""
    t = make()
    assert "stated-depth" in t.format_features()
    monkeypatch.setattr(t, "max_depth", lambda: None)
    r = _run(t, "no-max", plan={**DEV, "variants": ["cycle"]})
    forms = _forms(r, "cycle")
    assert forms["too_deep"]["reading"] == "format_gap" and forms["too_deep"]["ok"] is None
    assert "states no maximum chain" in forms["too_deep"]["detail"]
    assert {"variant": "cycle", "form": "too_deep", "missing": ["stated-depth"],
            "why": forms["too_deep"]["detail"]} in r.extra["format_gaps"]
    assert forms["id_cycle"]["ok"] is True and forms["self_parent"]["ok"] is True


# --------------------------------------------------------------------------- incomplete chains, holder-only, grades, disclosure class


def _holder_only_toy():
    """The correct toy, stating holder-signed delegation as its only form."""
    t = toy("good")
    t.delegation_forms = lambda: ["holder"]
    return t


@pytest.mark.parametrize("config", ["good", "good-strict", "pull-good"])
def test_m95c_the_correct_bs_refuse_every_incomplete_chain(config):
    """KRK-M95c: each correct toy refuses W in all three forms and accepts the complete
    sibling, so each form holds."""
    r = _run(toy(config), config, plan={**DEV, "variants": ["incomplete_chain"]})
    assert r.status is Status.PASS, r.summary
    forms = _forms(r, "incomplete_chain")
    assert set(forms) == set(p21.FORMS["incomplete_chain"])
    for f, d in forms.items():
        assert d["reading"] == "held" and d["ok"] is True, (config, f, d)


@pytest.mark.parametrize("config", ["bad:walks_supplied_only"])
def test_m95c_a_b_that_walks_only_the_links_it_is_given_fails_each_form(config):
    r = _run(toy(config), "walk", plan={**DEV, "variants": ["incomplete_chain"]})
    assert r.status is Status.FAIL, r.summary
    for f in p21.FORMS["incomplete_chain"]:
        assert _forms(r, "incomplete_chain")[f]["reading"] == "outside_effect", f
        assert r.extra["disclosure_forms"][f"incomplete_chain/{f}"]["class"] == "vulnerability"
    assert r.extra["disclosure"] == "vulnerability"


def test_m95c_the_withheld_ancestor_is_signed_and_never_sent():
    """The fixture means what it says only with the withheld hop counted: W's request lies
    outside the root nobody supplied (KRK-M81, M95c)."""
    fx = p21.fixture("incomplete_chain", "stops_before_root", random.Random(5),
                     party="did:web:b.example", dims=["max_amount"], max_depth=4, mapping=None)
    assert fx.present == [1, 2] and len(fx.hops) == 3
    t = p21.truth(fx, now=1.8e9, at=1.8e9, tolerance_s=5, party="did:web:b.example")
    assert "not-rooted" in t["w_outside"] and t["l_inside"] is None
    assert "above" in p21.outside_parent_bound(fx, now=1.8e9, at=1.8e9, tolerance_s=5,
                                               party="did:web:b.example")


def test_m95c_flaws_that_also_fail_a_neighbouring_variant_say_so():
    """X5 §13 item 4: `walks_supplied_only` fails `cycle/id_cycle` and `self_parent` too (each
    a chain with no root, whose last grant it reads as one), and `stops_at_seen` fails
    `incomplete_chain/mutual_no_root` too."""
    r = _run(make("walks_supplied_only"), "w2", plan={**DEV, "variants": ["cycle"]})
    assert _forms(r, "cycle")["id_cycle"]["ok"] is False
    assert _forms(r, "cycle")["self_parent"]["ok"] is False
    assert _forms(r, "cycle")["too_deep"]["ok"] is True
    r = _run(make("stops_at_seen"), "s2", plan={**DEV, "variants": ["incomplete_chain"]})
    forms = _forms(r, "incomplete_chain")
    assert forms["mutual_no_root"]["ok"] is False
    assert forms["stops_before_root"]["ok"] is True and forms["no_ancestors"]["ok"] is True


def test_a_holder_only_b_runs_holder_only_and_reads_position_a_as_a_gap():
    r = _run(_holder_only_toy(), "holder", plan={**DEV, "variants": ["wider_child", "cycle"]})
    assert r.status is Status.PASS, r.summary
    forms = _forms(r, "wider_child")
    assert forms["amount"]["reading"] == "format_gap" and \
        forms["amount"]["detail"] == p21.POSITION_A_GAP
    assert forms["amount@holder"]["reading"] == "held"
    assert {"variant": "position", "form": "a", "missing": ["a-signed-delegation"],
            "why": p21.POSITION_A_GAP} in r.extra["format_gaps"]
    assert "holder-only" in r.control_detail
    assert r.extra["grant_profile_holder_only"] is True
    assert {"max_amount", "operations", "audience", "window"} <= set(
        r.extra["dimensions_covered"])


def test_a_holder_only_b_must_land_the_must_land_forms_at_holder():
    """NA_FORBIDDEN is read at `holder` for a holder-only B: a form there with no verdict (here
    every sibling refused) leaves the result inconclusive, as it would at `a` for any other B."""
    t = _holder_only_toy()
    real = t._decide

    def refuse_after_control(p):
        if json.loads(p.request).get("amount", {}).get("value") != 10000:   # the control's
            return {"status": 403, "body": {"code": "refused", "reason": "refuses all"}}
        return real(p)
    t._decide = refuse_after_control
    r = _run(t, "must", plan={**DEV, "variants": ["numeric"],
                              "forms": {"numeric": ["negative"]}})
    assert _forms(r, "numeric")["negative@holder"]["ok"] is None
    assert r.status is Status.INCONCLUSIVE and "numeric/negative@holder" in r.summary


def test_library_decision_is_a_grade_and_its_results_say_library_level():
    assert p21.GRADES[-1] == "library-decision" and p21.GRADES[:-1] == ("recorder", "b-signed",
                                                                       "b-record", "b-response")
    t = make()
    t.evidence_grade = lambda: "library-decision"
    r = _run(t, "lib", plan={**DEV, "variants": ["incomplete_chain"]})
    assert r.status is Status.PASS, r.summary
    assert r.summary.startswith("Library-level reading") and r.extra["level"] == "library"
    t = make()
    t.evidence_grade = lambda: "library"
    assert _run(t, "lib2", plan={**DEV, "variants": ["cycle"]}).status is Status.INCONCLUSIVE


A4_CONFORMANCE = {("dropped_constraint", "empty_list"), ("dropped_constraint", "null_member"),
                  ("wildcard_default", "default_window"), ("combined", "union_dimensions"),
                  ("combined", "summed_amount"), ("combined", "two_parents"),
                  ("unknown_constraint", "in_child"), ("unknown_constraint", "marked_critical"),
                  ("numeric", "negative")}
"""Written in advance: the forms of vulnerable variants whose W lies inside every
bound a grant above the presented one states. Every other form of those variants is
vulnerability class."""


def test_a_form_is_vulnerability_class_only_outside_a_parents_stated_bound():
    for v in p21.VULNERABLE_VARIANTS:
        for f in p21.FORMS[v]:
            fx = p21.fixture(v, f, random.Random(4), party="did:web:b.example",
                             dims=list(att.DIMENSIONS), max_depth=4, mapping=None, tolerance=5)
            at = 1.8e9 + (fx.present_at + 6 if fx.present_at else 0)
            b = p21.outside_parent_bound(fx, now=1.8e9, at=at, tolerance_s=5,
                                         party="did:web:b.example")
            assert (b is None) == ((v, f) in A4_CONFORMANCE), (v, f, b)


def test_the_result_names_each_failing_forms_class():
    r = _run(make("defaults_fill"), "a4", plan={**DEV, "variants": ["wildcard_default"]})
    cls = r.extra["disclosure_forms"]
    assert cls["wildcard_default/default_window"]["class"] == "conformance"
    assert cls["wildcard_default/default_audience"]["class"] == "vulnerability"
    assert r.extra["disclosure"] == "vulnerability"
    t = make("accepts_negative")
    r = _run(t, "a4n", plan={**DEV, "variants": ["numeric"]})
    assert r.status is Status.FAIL
    assert {k: c["class"] for k, c in r.extra["disclosure_forms"].items()} == {
        "numeric/negative": "conformance", "numeric/negative@holder": "conformance"}
    assert r.extra["disclosure"] == "conformance"


def test_the_incomplete_chain_toy_is_registered_with_the_known_bad_gate():
    from conformance import knownbad
    cases = dict(knownbad.cases("P21"))
    assert cases["bad:walks_supplied_only"] is Status.FAIL
    assert not any(c.startswith("envelope") for c in cases)
    t = knownbad._toy("P21", "bad:walks_supplied_only")
    assert t.flaw == "walks_supplied_only"


# --------------------------------------------------------------------------- registered formats


def test_the_example_format_writes_grants_its_reader_verifies():
    """The example writer signs a root under A's grant key and each delegated grant under its
    parent's subject key, writes ids as ``ex:<grant id>`` and changes nothing after signing."""
    from conformance import delegation_formats as df, standing, status
    from conformance.issuer import StubIssuer
    from conformance.requester import new_issuer
    a = StubIssuer(new_issuer())
    c = a.peer()
    hops = [p21.Hop({"max_amount": p21._amt(500000), "operations": [p21.OP_A, p21.OP_B]}),
            p21.Hop({"max_amount": p21._amt(400000), "operations": [p21.OP_A]})]
    try:
        root, child = df.EXAMPLE.write_chain(None, hops, org=a, holder_org=c, holder=True,
                                             principal="pw@a.example", now=1.8e9,
                                             utc_s=status.utc_s)
        assert root.signer == f"org:{a.issuer}" and child.signer == f"holder:{root.subject}"
        assert root.id.startswith(df.EXAMPLE_PREFIX) and child.payload["up"] == root.id
        assert child.holder is c and root.holder is a
        assert standing.header_of(root.token) == {"alg": "EdDSA", "kid": a.key.kid,
                                                  "typ": df.EXAMPLE_TYP}
        v = standing.verify(root.token, {a.key.kid: a.key.public_bytes()}, df.EXAMPLE_TYP,
                            problem_of=lambda _c: None)
        assert v.ok and v.claims == root.payload and v.claims["for"] == "pw@a.example"
        tk = root.payload["to_key"]
        v = standing.verify(child.token, {tk["kid"]: bytes.fromhex(tk["x"])}, df.EXAMPLE_TYP,
                            problem_of=lambda _c: None)
        assert v.ok and v.claims["by"] == root.subject
        with pytest.raises(ValueError, match="crit"):
            df.EXAMPLE.write_chain(None, [p21.Hop({"max_amount": p21._amt(1)}, crit=["x"])],
                                   org=a, holder_org=c, holder=True, principal="p",
                                   now=1.8e9, utc_s=status.utc_s)
    finally:
        c.close()
        a.close()


def test_a_registered_format_applies_what_it_states_before_the_run():
    """Holder-only, a feature it cannot carry removed (and listed), one it states added, its depth
    limit used when B states none, and ``narrowed_parent`` a format gap for want of a status
    reference."""
    from conformance import delegation_formats as df
    t = toy("example-good")
    ev = Evidence("p21", t.name, "P21", "example")
    t.start()
    try:
        r = p21.probe(t, ev, run_tag="ex", seed=11, plan={
            **DEV, "variants": ["wider_child", "cycle", "unknown_constraint", "narrowed_parent"]})
    finally:
        t.stop()
    assert r.status is Status.PASS, r.summary
    assert r.extra["grant_profile"] == df.EXAMPLE_NAME and r.extra["grant_profile_holder_only"]
    assert r.extra["max_depth"] == df.EXAMPLE_MAX
    forms = _forms(r, "wider_child")
    assert forms["amount"]["reading"] == "format_gap" and forms["amount@holder"]["reading"] == "held"
    assert _forms(r, "unknown_constraint")["marked_critical@holder"]["reading"] == "format_gap"
    assert _forms(r, "cycle")["too_deep"]["ok"] is True
    assert _forms(r, "narrowed_parent")["-"] == {"reading": "format_gap", "ok": None,
                                                 "detail": df.EXAMPLE.status_gap}
    assert {"variant": "narrowed_parent", "form": "-", "missing": ["status"],
            "why": df.EXAMPLE.status_gap} in r.extra["format_gaps"]
    st = json.loads(next(Path(ev.dir).glob("*run.json")).read_text())["statements"]
    assert st["not_carried_by_profile"] == {"crit": df.EXAMPLE.cannot_carry["crit"]}
    assert "crit" not in st["format_features"] and "stated-depth" in st["format_features"]
    assert st["depth"]["used"] == df.EXAMPLE_MAX and st["depth"]["stated"] is None and \
        st["depth"]["profile_quote"] == df.EXAMPLE.depth_source
    cyc = json.loads(next(Path(ev.dir).glob("*cycle.json")).read_text())
    deep = [d for d in cyc["trials"] if d["form"] == "too_deep"]
    assert deep and all(len(d["extra"]["signers"]) == df.EXAMPLE_MAX + 1 for d in deep)


def test_a_reader_of_the_example_format_that_checks_the_leaf_only_fails():
    r = _run(toy("example-bad:leaf_only"), "exb", plan={**DEV, "variants": ["wider_child"]})
    assert r.status is Status.FAIL, r.summary
    assert _forms(r, "wider_child")["amount@holder"]["reading"] == "outside_effect"


def test_a_registered_format_is_opened_bound_and_closed_once(monkeypatch):
    """The run opens the format's state once, adds its anchor members to both organisations'
    trust anchors, and closes it, after a run that raised too."""
    from conformance import delegation_formats as df
    calls = []

    class Counting(df.ExampleFormat):
        name = "counting-example"

        def open(self, clock, orgs):
            calls.append(("open", len(orgs)))
            return {"run": "state"}

        def anchor(self, state, org):
            calls.append(("anchor", state["run"]))
            return super().anchor(state, org)

        def close(self, state):
            calls.append(("close", state["run"]))

    monkeypatch.setattr(df, "PROFILES", dict(df.PROFILES))
    df.register_profile("counting-example", Counting())
    t = toy("example-good")
    t.grant_profile = lambda: "counting-example"
    r = _run(t, "count", plan={**DEV, "variants": ["cycle"]})
    assert r.status is Status.PASS, r.summary
    assert calls == [("open", 2), ("anchor", "state"), ("anchor", "state"), ("close", "state")]
    calls.clear()
    t = toy("example-good")
    t.grant_profile = lambda: "counting-example"
    t.bind_recorder = lambda url: (_ for _ in ()).throw(RuntimeError("no recorder"))
    r = _run(t, "count2", plan={**DEV, "variants": ["cycle"]})
    assert r.status is Status.INCONCLUSIVE and "no recorder" in r.summary
    assert calls[0] == ("open", 2) and calls[-1] == ("close", "state")


def test_register_profile_refuses_a_taken_name_and_the_kits_own():
    from conformance import delegation_formats as df
    with pytest.raises(ValueError, match="kit's own"):
        df.register_profile("kirkaldy.grant/0.2", df.ExampleFormat())
    with pytest.raises(ValueError, match="already registered"):
        df.register_profile(df.EXAMPLE_NAME, type("Other", (df.ExampleFormat,), {})())
    with pytest.raises(ValueError, match="not a DelegationFormat"):
        df.register_profile("loose", object())
    with pytest.raises(ValueError, match="name"):
        df.register_profile(" ", df.ExampleFormat())
    df.register_profile(df.EXAMPLE_NAME, df.EXAMPLE)          # the same format again: a no-op
    assert df.get(df.EXAMPLE_NAME) is df.EXAMPLE and df.get("kirkaldy.grant/0.2") is None


def test_an_unregistered_grant_profile_gives_no_verdict():
    t = make()
    t.grant_profile = lambda: "no-such-format"
    r = _run(t, "unknown", plan={**DEV, "variants": ["cycle"]})
    assert r.status is Status.INCONCLUSIVE and "unknown grant profile" in r.summary


def test_the_example_format_toys_are_registered_with_the_known_bad_gate():
    from conformance import knownbad
    from known_bad.attenuation_toys import EXAMPLE_FLAWS, ToyExampleFormat
    cases = dict(knownbad.cases("P21"))
    assert cases["example-good"] is Status.PASS
    assert all(cases[f"example-bad:{f}"] is Status.FAIL for f in EXAMPLE_FLAWS)
    t = knownbad._toy("P21", "example-bad:leaf_only")
    assert isinstance(t, ToyExampleFormat) and t.flaw == "leaf_only"
    with pytest.raises(ValueError):
        ToyExampleFormat("walks_supplied_only")
