"""P24 (KRK-24, purpose and terms bound; design X2) against its vectors and toys
(`known_bad/mandate_toys.py`): the kit's term vocabulary reads as the hand-written vectors say;
the correct B passes in each of its modes (``refused``, ``pending``, ``clamped``); each flaw
fails exactly the forms it is built to fail and holds the rest; ``bad`` fails every term variant
and holds the limits; the toy that holds every conditioned action reads ``shape_refused`` on
``condition`` and gives no verdict; the toy whose executor never reaches the recorder gives no
verdict; a B whose format carries fewer term kinds gets format gaps, never passes."""
import json
import random
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import claim_basis, terms as tm  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p24_mandate_bound as p24  # noqa: E402
from conformance.result import Status  # noqa: E402
from known_bad.mandate_toys import (COLLATERAL, FAILS, FLAWS, ToyMandate, cases, make,  # noqa: E402
                                    toy)

VEC = json.loads((Path(__file__).parent / "vectors" / "krk24" / "vectors.json").read_text())
DEV = {"trials": "dev"}
ONE = {"trials": 1}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, tag="t", *, plan=None, seed=11):
    ev = Evidence("p24", t.name, "P24", t.config.replace(":", "-"))
    t.start()
    try:
        return p24.probe(t, ev, run_tag=tag, seed=seed, plan=plan)
    finally:
        t.stop()


def _failing(r):
    return {f"{v}/{f}" for v, fr in r.extra["forms"].items() for f, d in fr.items()
            if d["ok"] is False}


def _reading(r, v, f):
    return r.extra["forms"][v][f]


def _slots(spec):
    return [{"slot": s, "acceptable": acc, "quantity": q} for s, acc, q in spec]


# --------------------------------------------------------------------------- the vectors


def test_vectors_fill():
    for v in VEC["fill"]:
        items = [{"id": i, "quantity": q} for i, q in v["items"]]
        got = tm.reason_of(tm.fill(items, _slots(v["slots"])))
        assert got == v["expected"], v["name"]


def test_vectors_fill_unreadable():
    for v in VEC["fill_unreadable"]:
        got = tm.fill(v["items"], _slots([["s1", ["a1"], 1]]))
        assert tm.reason_of(got) == tm.UNREADABLE, v["name"]


def test_vectors_purpose():
    pm = VEC["purpose"]["map"]
    for v in VEC["purpose"]["cases"]:
        assert tm.purpose_covers(pm, v["code"], v["operation"], v["resources"]) is \
            v["expected"], v


def test_vectors_fixed():
    for v in VEC["fixed"]:
        assert tm.reason_of(tm.fixed_ok(v["request"], v["fixed"])) == v["expected"], v["name"]


def test_vectors_floor():
    for v in VEC["floor"]:
        assert tm.reason_of(tm.floor_ok(v["request"], v["floor"])) == v["expected"], v["name"]


def test_vectors_terms_problem():
    for v in VEC["terms_problem"]:
        p = tm.terms_problem(v["terms"])
        assert (p[0] if p else None) == v["expected"], (v["name"], p)


def test_vectors_seal_digests_computed_outside_the_kit():
    for v in VEC["seal"]:
        assert tm.seal(v["value"], v["salt"]) == {"_sealed": v["digest"]}, v


def test_vectors_open():
    for v in VEC["open"]:
        got = tm.open_sealed(v["terms"], v["disclosures"])
        if "unreadable" in v["expected"]:
            assert isinstance(got, tm.Unreadable) and list(got.paths) == \
                v["expected"]["unreadable"], v["name"]
        else:
            assert got == v["expected"], v["name"]


def test_meets_reads_each_kind_and_every_hop():
    pm = VEC["purpose"]["map"]
    e = {"operation": "delete", "resources": ["ds-1/r1"], "payee": "m-1",
         "items": [{"id": "a1", "quantity": 1}],
         "amount": {"value": 500, "currency": "EUR", "minor_units": 2}}
    assert tm.meets(e, [{"purpose": {"code": "research-admin"}}], purpose_map=pm) is None
    assert tm.reason_of(tm.meets(e, [{"purpose": {"code": "research"}}], purpose_map=pm)) == \
        tm.NOT_COVERED
    assert tm.reason_of(tm.meets(e, [{"purpose": {"code": "research"}}])) == tm.UNREADABLE
    # every hop applies: the child admits the action, the root does not
    assert tm.reason_of(tm.meets(e, [{"purpose": {"code": "research-admin"}},
                                     {"purpose": {"code": "research"}}], purpose_map=pm)) == \
        tm.NOT_COVERED
    assert tm.reason_of(tm.meets(e, [{"floor": {"amount": {"value": 501, "currency": "EUR",
                                                           "minor_units": 2}}}])) == tm.LESS
    assert tm.reason_of(tm.meets(e, [{"confirm": {"operations": ["delete"],
                                                  "by": "principal"}}])) == tm.UNCONFIRMED
    assert tm.reason_of(tm.meets(e, [{"goal_id": "gl-" + "1" * 16}],
                                 linked={"serves": "gl-" + "2" * 16})) == tm.OTHER_GOAL
    assert tm.meets(e, [{"goal_id": "gl-" + "1" * 16}], linked={"serves": "gl-" + "1" * 16}) \
        is None
    assert tm.reason_of(tm.meets(e, [{}], requires=["serves"])) == tm.OTHER_GOAL
    assert tm.reason_of(tm.meets(e, [{}], requires=["purpose"])) == tm.NOT_COVERED
    assert tm.meets(e, [{"text": "delete anything"}]) is None
    assert tm.reason_of(tm.meets(e, [{"x-krk-1": 1}])) == tm.UNREADABLE


def test_clamp_items_keeps_the_goal_and_drops_the_rest():
    s = _slots([["s1", ["a1"], 2], ["s2", ["b1"], 1]])
    items = [{"id": "a1", "quantity": 3}, {"id": "b1", "quantity": 1}, {"id": "z", "quantity": 1}]
    got = tm.clamp_items(items, s)
    assert tm.fill(got, s) is None and sum(i["quantity"] for i in got) == 3
    assert tm.clamp_items([{"id": "a1", "quantity": 1}], s) is None    # less: nothing to clamp


def test_grant_v4_is_refused_by_a_0_2_reader_and_read_by_0_4():
    from conformance import attenuation as att
    claims = {"schema": tm.GRANT_V4_SCHEMA, "grant_id": "gr-" + "a" * 16, "issuer": "i",
              "subject": "s", "agent_key": {"kid": "k", "public_key": "0" * 64},
              "principal": "p", "constraints": {}, "parent": None,
              "issued_at": "2026-11-03T09:00:00.000Z", "not_before": "2026-11-03T09:00:00Z",
              "not_after": "2026-11-03T21:00:00Z", "status": {"source": "s", "index": 0},
              "terms": {"goal_id": "gl-" + "b" * 16}}
    assert tm.grant_v4_problem(claims) is None
    assert att.grant_v2_problem(claims) is not None
    assert tm.grant_v4_problem({**claims, "terms": {"x-krk-1": 1}})[0] == tm.UNKNOWN
    no_terms = {k: v for k, v in claims.items() if k != "terms"}
    assert tm.grant_v4_problem(no_terms) is not None


# --------------------------------------------------------------------------- fixtures


def _ctx():
    t = ToyMandate()
    return p24.Ctx(party="did:web:b.example", dims=t.constraint_profile(),
                   kinds=t.term_profile(), pmap=t.purpose_map(), requires=t.requires_terms(),
                   bindings=t.term_bindings(), item_key="id", condition_mode="refuse",
                   disclosure=t.disclosure_profile(), holder_hops=True, confirm_binds=True,
                   tolerance=5.0)


def test_every_form_has_a_fixture_for_the_toys_statements():
    ctx = _ctx()
    for v, forms in p24.FORMS.items():
        for f in forms:
            for seed in range(3):
                fx = p24.fixture(v, f, random.Random(seed), ctx)
                assert fx.W and fx.L, (v, f)
                assert fx.W.mandate == "W" and fx.L.mandate == "L", (v, f)


def test_not_acceptable_keeps_every_count():
    """KRK-M153's shape: the substitution keeps each slot's count and the total."""
    ctx = _ctx()
    for seed in range(10):
        fx = p24.fixture("goal_items", "not_acceptable", random.Random(seed), ctx)
        slots = fx.mandates["W"].hops[0][1]["slots"]
        have = tm.units(fx.W.values["items"])
        assert sum(have.values()) == sum(s["quantity"] for s in slots)
        assert tm.reason_of(tm.fill(fx.W.values["items"], slots)) == tm.OTHER


# --------------------------------------------------------------------------- the toys


@pytest.mark.parametrize("config,mode", [("good", None), ("good-hold", "pending"),
                                         ("good-clamp", "clamped")])
def test_the_correct_bs_pass_at_published_counts(config, mode):
    r = _run(toy(config))
    assert r.status is Status.PASS, r.summary
    assert _failing(r) == set()
    for v, fr in r.extra["forms"].items():
        for f, d in fr.items():
            if (v, f) in p24.INFORMATION_ONLY:
                assert d["reading"] == "text_ignored" and d["ok"] is None
            else:
                assert d["ok"] is True, (v, f, d)
    assert r.extra["format_gaps"] == []
    assert set(r.extra["term_kinds_covered"]) == {"purpose", "slots", "fixed", "floor",
                                                  "serves", "confirm"}
    if mode == "pending":
        assert r.extra["modes"]["condition"] == ["pending"]
        assert r.extra["modes"]["hidden_terms"] == ["pending"]
    if mode == "clamped":
        assert "clamped" in r.extra["modes"]["goal_items"]
        assert "clamped" in r.extra["forms"]["goal_items"]["extra_item"]["detail"]
        assert "clamped" in r.extra["forms"]["goal_items"]["over_quantity"]["detail"]


@pytest.mark.parametrize("flaw", FLAWS)
def test_each_flaw_fails_exactly_its_forms(flaw):
    """X3 §13 item 7, KRK-M47: a flaw fails the forms the table says, and holds every other."""
    r = _run(make(flaw), plan=DEV)
    assert r.status is Status.FAIL, r.summary
    assert _failing(r) == FAILS[flaw], (sorted(_failing(r) - FAILS[flaw]),
                                        sorted(FAILS[flaw] - _failing(r)))
    for v, fr in r.extra["forms"].items():
        for f, d in fr.items():
            fid = f"{v}/{f}"
            if fid in COLLATERAL.get(flaw, set()):
                assert d["reading"] == "collateral_refusal", (flaw, fid, d)
            elif fid not in FAILS[flaw] and (v, f) not in p24.INFORMATION_ONLY:
                assert d["ok"] is True, (flaw, v, f, d)


def test_bad_fails_every_term_variant_and_holds_the_limits():
    r = _run(toy("bad"))
    assert r.status is Status.FAIL
    checks = {c.name: c.ok for c in r.checks}
    assert checks.pop("outside_ceiling") is True
    assert all(ok is False for ok in checks.values()), checks
    assert r.extra["disclosure"] == "vulnerability"


def test_no_control_gives_no_verdict():
    r = _run(toy("no-control"), plan=ONE)
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_hold_forever_reads_shape_refused_on_condition_and_gives_no_verdict():
    """KRK-M157: a B that never completes a conditioned action is not read as requiring the
    confirmation."""
    r = _run(toy("info:hold_forever"), plan=DEV)
    assert r.status is Status.INCONCLUSIVE, r.summary
    assert r.extra["control_shapes"]["conditioned"] is False
    for f in p24.FORMS["condition"]:
        assert _reading(r, "condition", f)["reading"] == "shape_refused"
    assert "condition/unconfirmed" in r.summary


def test_late_executor_fails_condition_inside_the_stability_window():
    r = _run(make("late_executor"), plan=DEV)
    d = _reading(r, "condition", "unconfirmed")
    assert d["ok"] is False and "landed within S" in d["detail"], d
    assert r.extra["stability_s"] == p24.DEFAULT_S


def test_free_text_narrower_is_information_only():
    r = _run(make("reads_text"), plan=DEV)
    d = _reading(r, "free_text", "text_narrower")
    assert d["ok"] is None and d["reading"] in ("text_ignored", "text_applied")
    assert "free_text/text_narrower" not in _failing(r)


class _Fewer(ToyMandate):
    """A B whose format carries no terms beyond fixed values."""

    def term_profile(self):
        return ["fixed"]


def test_a_b_that_carries_fewer_term_kinds_gets_format_gaps_never_passes():
    t = _Fewer()
    r = _run(t, plan=ONE)
    assert r.status is Status.PASS, r.summary
    gaps = {f"{g['variant']}/{g['form']}" for g in r.extra["format_gaps"]}
    assert "goal_items/partial" in gaps and "condition/unconfirmed" in gaps
    assert "purpose/mismatch" in gaps and "hidden_terms/slot_hidden" in gaps
    assert _reading(r, "fixed", "differs")["ok"] is True
    assert _reading(r, "goal_items", "partial") == {
        "reading": "format_gap", "ok": None, "detail": "B's format carries no slots term"}
    assert set(r.extra["term_kinds_not_expressible"]) >= {"slots", "purpose", "confirm"}
    assert r.extra["term_kinds_covered"] == ["fixed"]


class _PurposeNoMap(ToyMandate):
    def purpose_map(self):
        return None


def test_a_b_that_declares_purpose_and_states_no_map_is_inconclusive():
    """Design §6.5: a declared term kind whose core forms cannot land gives no verdict."""
    r = _run(_PurposeNoMap(), plan=ONE)
    assert r.status is Status.INCONCLUSIVE, r.summary
    assert "purpose/mismatch" in r.summary
    assert "KRK-M150" in _reading(r, "purpose", "mismatch")["detail"]


def test_disclosure_class_per_form():
    r = _run(make("leaf_terms_only"), plan=ONE)
    assert r.extra["disclosure_forms"]["restated_terms/fixed_changed"]["class"] == "conformance"
    assert r.extra["disclosure"] == "conformance"
    r = _run(make("subset_only"), plan=ONE)
    assert r.extra["disclosure_forms"]["goal_items/partial"]["class"] == "vulnerability"
    assert r.extra["disclosure"] == "vulnerability"


def test_the_runners_claim_basis_reads_p24_forms():
    """A P24 result judged on claimed forms only (`claim_basis.apply`, outside the probe)."""
    r = _run(make("subset_only"), plan=ONE)
    st = claim_basis.Statement("P24", not_claimed={
        "goal_items/*": "not claimed (test)", "restated_terms/slot_dropped": "not claimed (test)"})
    got = claim_basis.apply(r, st)
    assert got.status is Status.PASS, got.summary
    assert got.extra["disclosure"] == "conformance"
    st = claim_basis.Statement("P24", not_claimed={"goal_items/partial": "not claimed (test)"})
    assert claim_basis.apply(r, st).status is Status.FAIL


def test_the_gate_cases():
    got = dict(cases())
    assert got["good"] == got["good-hold"] == got["good-clamp"] == "pass"
    assert got["bad"] == "fail" and got["bad:late_executor"] == "fail"
    assert got["info:hold_forever"] == got["no-control"] == "inconclusive"
    assert {c for c in got if c.startswith("bad:")} == \
        {f"bad:{f}" for f in FLAWS if f != "limits_only"}


def test_p24_is_in_no_earlier_property_closure():
    """The new modules are imported by P24 alone."""
    from conformance import versions
    from conformance.properties import ALL
    mine = {"conformance/terms.py", "conformance/mandator.py", "conformance/role_mandate.py",
            "conformance/properties/p24_mandate_bound.py"}
    for pid in ALL:
        if pid == "P24":
            continue
        assert not mine & set(versions.probe_files(pid)), pid
        assert not set(versions.fixture_files(pid)) & set(versions.fixture_files("P24")), pid
    assert mine <= set(versions.probe_files("P24"))
