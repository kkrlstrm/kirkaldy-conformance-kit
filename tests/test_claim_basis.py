"""The claim-basis rule (spec §3.4, §3.2, Appendix B;
`conformance.claim_basis`): a target is judged only on the forms it claims. A target that fails
only on forms it does not claim reads pass; one that fails on a claimed form still fails; an
adapter that states nothing is run exactly as before; the disclosure class is never raised; and
the rule sits outside every probe's closure, so no probe or fixture version moves."""
import json

import pytest

from conformance import claim_basis as cb
from conformance import knownbad, runner, validity, versions
from conformance.properties import ALL, ALL_BISSUER
from conformance.result import Check, Result, Status

pytest.importorskip("cryptography")

from known_bad.attenuation_toys import toy as p21_toy  # noqa: E402
from known_bad.toys import TOYS  # noqa: E402

P21_PLAN = {"trials": "dev", "variants": ["incomplete_chain", "cycle", "wider_child"]}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _p21(config):
    t = p21_toy(config)
    t.implements = lambda: ["P21"]
    return t


def _stated(t, not_claimed=None, basis=None):
    if not_claimed is not None:
        t.not_claimed = lambda: not_claimed
    if basis is not None:
        t.claim_basis = lambda: basis
    return t


def _doc(tmp_path, run_id, pid):
    (path,) = list((tmp_path / run_id).glob(f"*/{pid}/result.json"))
    return json.loads(path.read_text())


def _forms_result(**kw):
    """A small result in P21's shape: two variants, a failing form in each."""
    forms = {"cycle": {"id_cycle": {"reading": "outside_effect", "ok": False, "detail": "x"},
                       "too_deep": {"reading": "held", "ok": True, "detail": "y"}},
             "numeric": {"negative@holder": {"reading": "outside_effect", "ok": False,
                                             "detail": "z"},
                         "currency@holder": {"reading": "held", "ok": True, "detail": "w"}}}
    checks = [Check("cycle", "outside_effect", False, "id_cycle: x"),
              Check("numeric", "outside_effect", False, "negative@holder: z")]
    extra = {"forms": forms, "disclosure": "vulnerability",
             "disclosure_forms": {"numeric/negative@holder": {"class": "vulnerability"},
                                  "cycle/id_cycle": {"class": "conformance"}}}
    extra.update(kw.pop("extra", {}))
    return Result(target="t", property_id="P21", status=Status.FAIL, summary="probe says fail",
                  control_held=True, control_detail="held", checks=checks, extra=extra, **kw)


# -------------------------------------------------------------------- the rule, in isolation

def test_no_statement_returns_the_result_itself_unchanged():
    r = _forms_result()
    assert cb.apply(r, cb.Statement("P21")) is r
    assert cb.result_doc(r) == r.to_doc()


def test_fails_only_on_unclaimed_forms_reads_pass_and_keeps_the_reading_as_information():
    r = _forms_result()
    st = cb.Statement("P21", not_claimed={"cycle/id_cycle": "not in -00",
                                          "numeric/negative@holder": "no lower bound"})
    got = cb.apply(r, st)
    assert got.status is Status.PASS and got.control_held is True
    neg = got.extra["forms"]["numeric"]["negative@holder"]
    assert neg["ok"] is None and neg["ok_as_read"] is False and neg["not_claimed"]
    assert got.extra["disclosure"] == "conformance"
    assert got.extra["claim_basis"]["probe_as_read"]["status"] == "fail"
    assert got.summary.startswith("Claimed forms only: no violation")
    assert r.status is Status.FAIL                      # the probe's own result is not mutated


def test_a_failing_claimed_form_still_fails_and_its_class_is_kept():
    r = _forms_result()
    got = cb.apply(r, cb.Statement("P21", not_claimed={"cycle/id_cycle": "not in -00"}))
    assert got.status is Status.FAIL
    assert {c.name: c.ok for c in got.checks} == {"cycle": True, "numeric": False}
    assert got.extra["disclosure"] == "vulnerability"
    assert "numeric/negative@holder (outside_effect)" in got.summary


def test_the_class_is_lowered_when_the_only_vulnerable_form_is_unclaimed_and_never_raised():
    r = _forms_result()
    got = cb.apply(r, cb.Statement("P21", not_claimed={"numeric/negative@holder": "n"}))
    assert got.status is Status.FAIL and got.extra["disclosure"] == "conformance"
    low = _forms_result(extra={"disclosure": "conformance"})
    got = cb.apply(low, cb.Statement("P21", not_claimed={"numeric/negative@holder": "n"}))
    assert got.extra["disclosure"] == "conformance"


def test_a_pattern_without_a_slash_is_the_whole_check():
    got = cb.apply(_forms_result(), cb.Statement("P21", not_claimed={"cycle": "c",
                                                                     "numeric": "n"}))
    assert got.status == cb.NOT_CLAIMED and got.to_doc()["status"] == "not_claimed"
    assert got.control_held is None


def test_claimed_forms_with_no_reading_give_no_verdict_not_a_pass():
    r = _forms_result()
    for v in r.extra["forms"].values():
        for e in v.values():
            if e["ok"] is True:
                e.update(ok=None, reading="format_gap")
    got = cb.apply(r, cb.Statement("P21", not_claimed={"*/id_cycle": "a", "*negative*": "b"}))
    assert got.status is Status.INCONCLUSIVE and got.control_held is True


def test_inconclusive_and_not_applicable_are_never_turned_into_a_verdict():
    r = Result.inconclusive("t", "P21", "control did not hold", checks=[
        Check("cycle", "outside_effect", False, "")])
    got = cb.apply(r, cb.Statement("P21", not_claimed={"cycle": "c"}))
    assert got.status is Status.INCONCLUSIVE and "claim_basis" in got.extra


def test_each_form_carries_its_claim_basis_or_its_reason():
    basis = {"P21": {"cycle/*": {"quote": "MUST reject", "location": "-00:812-815",
                                 "source": "specification draft-x-00"}}}
    t = type("A", (), {"not_claimed": lambda self: {"P21": {"numeric/negative*": "none"}},
                       "claim_basis": lambda self: basis})()
    st = cb.statement(t, "P21")
    got = cb.apply(_forms_result(), st)
    forms = got.extra["claim_basis"]["forms"]
    assert forms["cycle/id_cycle"]["claim_basis"]["location"] == "-00:812-815"
    assert forms["numeric/negative@holder"] == {"not_claimed": "none", "reading": "outside_effect",
                                                "ok_as_read": False}
    assert forms["numeric/currency@holder"] == {"claim_basis": None}
    assert got.extra["claim_basis"]["claimed_without_stated_basis"] == ["numeric/currency@holder"]
    assert cb.statement(t, "P20").empty()


def test_a_claim_basis_needs_a_quote_a_location_and_a_kind_of_source():
    t = type("A", (), {"claim_basis": lambda self: {"x": {"quote": "q", "location": "l",
                                                          "source": "a blog"}}})()
    with pytest.raises(ValueError, match="source"):
        cb.statement(t, "P21")
    t = type("A", (), {"claim_basis": lambda self: {"x": {"quote": "q"}}})()
    with pytest.raises(ValueError, match="quote, a location and a source"):
        cb.statement(t, "P21")


def test_the_rule_is_in_no_probe_or_fixture_closure():
    for pid in list(ALL) + list(ALL_BISSUER):
        assert "conformance/claim_basis.py" not in versions.probe_files(pid), pid
        assert "conformance/claim_basis.py" not in versions.fixture_files(pid), pid
    assert cb.rule_version() == versions.digest(["conformance/claim_basis.py"])


# -------------------------------------------------------------- through the runner, on toys

def test_KRK_M148_a_toy_that_fails_only_on_unclaimed_forms_reads_pass(tmp_path, monkeypatch):
    """`walks_supplied_only` fails the three `incomplete_chain` forms and two `cycle` forms. With
    exactly those stated not claimed it reads pass; the probe's own fail is kept as information,
    and the result names the claim-basis rule in its renewal condition."""
    monkeypatch.setenv("ACK_P21_PLAN", json.dumps(P21_PLAN))
    t = _stated(_p21("bad:walks_supplied_only"),
                {"P21": {"incomplete_chain": "not claimed (test)",
                         "cycle/id_cycle": "not claimed (test)",
                         "cycle/self_parent": "not claimed (test)"}})
    (r,) = runner.run_adapter(t, ["P21"], run_id="cb1", known_bad="mark", seed=3)
    assert r.status is Status.PASS, r.summary
    doc = _doc(tmp_path, "cb1", "P21")
    assert doc["status"] == "pass" and doc["claim_basis"]["probe_as_read"]["status"] == "fail"
    assert doc["claim_basis"]["counts"]["not_claimed"] == 5
    assert doc["extra"]["disclosure"] == "conformance"
    assert doc["claim_rule_version"] == cb.rule_version()
    assert "claim_rule_version" in doc["renewal"]["lapses_on_change"]
    assert "claim_basis" not in doc["extra"]


def test_KRK_M148_a_toy_that_fails_on_a_claimed_form_still_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("ACK_P21_PLAN", json.dumps(P21_PLAN))
    t = _stated(_p21("bad:walks_supplied_only"),
                {"P21": {"cycle/id_cycle": "not claimed (test)",
                         "cycle/self_parent": "not claimed (test)"}})
    (r,) = runner.run_adapter(t, ["P21"], run_id="cb2", known_bad="mark", seed=3)
    assert r.status is Status.FAIL
    assert r.extra["disclosure"] == "vulnerability"
    assert all(f.startswith("incomplete_chain/") for f in r.extra["disclosure_forms"])
    assert {c.name: c.ok for c in r.checks}["cycle"] is True


def test_an_adapter_that_states_nothing_writes_exactly_what_it_wrote_before(tmp_path,
                                                                            monkeypatch):
    monkeypatch.setenv("ACK_P21_PLAN", json.dumps({**P21_PLAN, "variants": ["cycle"]}))
    (r,) = runner.run_adapter(_p21("bad:walks_supplied_only"), ["P21"], run_id="cb3",
                              known_bad="mark", seed=3)
    doc = _doc(tmp_path, "cb3", "P21")
    assert doc == json.loads(r.to_json())
    assert "claim_basis" not in doc and "claim_rule_version" not in doc
    assert "claim_rule_version" not in doc["renewal"]["lapses_on_change"]
    assert r.status is Status.FAIL


def test_a_property_not_claimed_at_all_is_not_probed(tmp_path):
    t = _stated(TOYS["P5"]("bad"), {"P5": "the target states nothing about its own grant"})
    t.implements = lambda: ["P5"]
    (r,) = runner.run_adapter(t, ["P5"], run_id="cb4")   # no known-bad record needed
    doc = _doc(tmp_path, "cb4", "P5")
    assert doc["status"] == "not_claimed" and doc["control_held"] is None and doc["checks"] == []
    assert r.status == "not_claimed" and r.status.value == "not_claimed"


def test_a_check_level_property_judges_claimed_checks_only(tmp_path):
    base = TOYS["P5"]("bad")
    base.start()
    from conformance.evidence import Evidence
    try:
        r = ALL["P5"].probe(base, Evidence("x", base.name, "P5", "bad"), run_tag="x")
    finally:
        base.stop()
    failing = [c.name for c in r.checks if c.ok is False]
    assert r.status is Status.FAIL and failing
    got = cb.apply(r, cb.Statement("P5", not_claimed={cb.exact(n): "t" for n in failing}))
    assert got.status is not Status.FAIL


# --------------------------------------------------------------------- the gate and validity

def test_every_known_bad_run_checks_the_rule_on_its_own_toys():
    rec = knownbad.run_one("P5", seed=1)
    claims = {c["config"]: c for c in rec["cases"] if c["config"].startswith("claims:")}
    assert {"claims:fails-only-unclaimed", "claims:fails-on-a-claimed-form",
            "claims:no-statement"} <= set(claims)
    assert all(c["ok"] for c in claims.values()), claims
    assert claims["claims:fails-on-a-claimed-form"]["got"] == "fail"
    assert claims["claims:fails-only-unclaimed"]["got"] != "fail"
    assert rec["claim_rule_version"] == cb.rule_version() and rec["ok"]


def test_a_rule_that_fails_a_target_on_an_unclaimed_form_fails_the_gate(monkeypatch):
    monkeypatch.setattr(cb, "apply", lambda r, st: r)          # a rule that ignores statements
    rec = knownbad.run_one("P5", seed=1)
    bad = [c for c in rec["cases"] if c["config"] == "claims:fails-only-unclaimed"]
    assert bad and bad[0]["ok"] is False and rec["ok"] is False


def test_a_stated_run_needs_a_record_made_with_the_current_rule(tmp_path, monkeypatch):
    t = _stated(TOYS["P5"]("good"), {"P5": {"nothing-matches": "t"}})
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0
    path = tmp_path / "known-bad" / "records.jsonl"
    rec = json.loads(path.read_text().splitlines()[-1])
    rec.pop("claim_rule_version")
    path.write_text(json.dumps(rec) + "\n")                    # a record from before the rule
    with pytest.raises(knownbad.KnownBadMissing, match="claim_rule_version"):
        runner.run_adapter(t, ["P5"], run_id="cb5")
    (r,) = runner.run_adapter(TOYS["P5"]("good"), ["P5"], run_id="cb6")   # unstated: as before
    assert r.status is Status.PASS
    assert runner.main(["known-bad", "--record", "--force", "-p", "P5"]) == 0
    (r,) = runner.run_adapter(t, ["P5"], run_id="cb7")
    doc = _doc(tmp_path, "cb7", "P5")
    assert doc["known_bad"]["claim_rule_version"] == cb.rule_version()
    assert validity.known_bad_problem(doc) is None


def test_a_claimed_only_verdict_lapses_when_the_rule_changes(tmp_path):
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0
    t = _stated(TOYS["P5"]("good"), {"P5": {"nothing-matches": "t"}})
    runner.run_adapter(t, ["P5"], run_id="cb8")
    (path,) = list((tmp_path / "cb8").glob("*/P5/result.json"))
    v = runner.check_validity(str(path), target_version=json.loads(path.read_text())
                              ["target_version"])
    assert v.checked["claim_rule_version"]["current"] == cb.rule_version()
    assert "claim_rule_version" not in " ".join(v.reasons)
    doc = json.loads(path.read_text())
    doc["claim_rule_version"] = "sha256:an-older-rule"
    path.write_text(json.dumps(doc))
    v = runner.check_validity(str(path), target_version=doc["target_version"])
    assert v.state in (validity.LAPSED, validity.NO_VERDICT)
    assert any("claim" in why for why in v.reasons)


# ------------------------------------------------- housekeeping

def test_an_inconclusive_from_a_must_land_form_stays_inconclusive_when_it_is_unclaimed():
    """The probe made this result inconclusive only because a form that must land did not. With
    that form stated not claimed, and every claimed form holding, it is still inconclusive: the
    rule never turns an inconclusive into a verdict (the fail-safe direction)."""
    forms = {"cycle": {"id_cycle": {"reading": "held", "ok": True, "detail": "x"},
                       "self_parent": {"reading": "fixture_not_landed", "ok": None,
                                       "detail": "did not land"}}}
    summary = "no variant failed, but forms that must land did not: ['cycle/self_parent']."
    r = Result.inconclusive("t", "P21", summary, control_held=True, control_detail="held",
                            checks=[Check("cycle", "held", True, "id_cycle: x")],
                            extra={"forms": forms, "disclosure": "conformance"})
    got = cb.apply(r, cb.Statement("P21", not_claimed={"cycle/self_parent": "not in -00"}))
    assert got.status is Status.INCONCLUSIVE and got.summary == summary
    assert got.extra["forms"]["cycle"]["self_parent"]["not_claimed"] == "not in -00"
    assert got.extra["claim_basis"]["probe_as_read"]["status"] == "inconclusive"
    got = cb.apply(r, cb.Statement("P21", not_claimed={"cycle/self_parent": "n"}), published=True)
    assert got.status is Status.INCONCLUSIVE


def test_a_published_run_is_refused_before_any_probe_when_a_form_has_no_basis(monkeypatch):
    called = []
    monkeypatch.setattr(ALL["P21"], "probe", lambda *a, **k: called.append(1))
    t = _stated(_p21("good"), {"P21": {"cycle": "not claimed (test)"}})
    with pytest.raises(cb.ClaimBasisIncomplete) as e:
        runner.run_adapter(t, ["P21"], run_id="cb9", known_bad="mark", published=True)
    assert called == [] and "P21" in e.value.gaps and "every form stated not claimed" in str(e.value)
    assert "cycle/id_cycle" not in e.value.gaps["P21"]
    assert f"narrowed_parent/{cb.ANY_FORM}" in e.value.gaps["P21"]   # a variant FORMS omits
    assert "narrowed_parent/*" in str(e.value)                  # the message names every form
    monkeypatch.setenv("ACK_P21_PLAN", json.dumps({"trials": "published"}))
    with pytest.raises(cb.ClaimBasisIncomplete):                # marked by its plan
        runner.run_adapter(t, ["P21"], run_id="cb10", known_bad="mark")
    assert called == []


def test_a_default_basis_covers_every_form_and_a_check_level_property_needs_one(tmp_path):
    basis = {"quote": "MUST", "location": "s1", "source": "documentation (test)"}
    t = _stated(_p21("good"), {"P21": {"cycle": "t"}}, {"P21": {"*": basis}})
    assert cb.unstated_before_run(t, cb.statement(t, "P21")) == []
    t = _stated(TOYS["P5"]("good"), {"P5": {"nothing-matches": "t"}})
    t.implements = lambda: ["P5"]
    with pytest.raises(cb.ClaimBasisIncomplete, match="no form inventory for P5"):
        runner.run_adapter(t, ["P5"], run_id="cb11", known_bad="mark", published=True)
    t.claim_basis = lambda: {"P5": {"*": basis}}
    (r,) = runner.run_adapter(t, ["P5"], run_id="cb12", known_bad="mark", published=True)
    assert r.status is Status.PASS
    doc = _doc(tmp_path, "cb12", "P5")
    assert doc["claim_basis"]["published"] is True
    assert doc["claim_basis"]["claimed_without_stated_basis"] == []


def test_the_cli_exits_6_on_a_refused_published_run(monkeypatch, capsys):
    t = _stated(TOYS["P5"]("good"), {"P5": {"nothing-matches": "t"}})
    t.implements = lambda: ["P5"]
    monkeypatch.setattr(runner, "load", lambda spec: t)
    assert runner.main(["run", "toy", "-p", "P5", "--published", "--without-known-bad"]) == 6
    assert "every form stated not claimed" in capsys.readouterr().err


def test_a_development_run_flags_forms_without_a_basis_and_still_judges(tmp_path,
                                                                           monkeypatch, capsys):
    monkeypatch.setenv("ACK_P21_PLAN", json.dumps(P21_PLAN))
    t = _stated(_p21("bad:walks_supplied_only"),
                {"P21": {"cycle/id_cycle": "t", "cycle/self_parent": "t"}})
    (r,) = runner.run_adapter(t, ["P21"], run_id="cb13", known_bad="mark", seed=3)
    assert r.status is Status.FAIL
    assert "claimed without a stated basis (flagged" in capsys.readouterr().out
    doc = _doc(tmp_path, "cb13", "P21")
    assert doc["claim_basis"]["published"] is False
    assert doc["claim_basis"]["claimed_without_stated_basis"]
    assert doc["claim_basis"]["probe_as_read"]["derived"]["dimensions_covered"] is not None


def test_a_published_verdict_on_a_form_without_a_basis_reads_inconclusive():
    """The backstop for a form the inventory did not foresee: after the probe, a published pass or
    fail that rests on a form claimed without a basis gives no verdict."""
    basis = {"quote": "q", "location": "l", "source": "specification x"}
    st = cb.Statement("P21", not_claimed={"cycle/id_cycle": "n"},
                      basis={"numeric/negative@holder": basis})
    got = cb.apply(_forms_result(), st, published=True)
    assert got.status is Status.INCONCLUSIVE and "with no stated claim basis" in got.summary
    assert got.extra["claim_basis"]["claimed_without_stated_basis"] == [
        "cycle/too_deep", "numeric/currency@holder"]
    assert cb.apply(_forms_result(), st).status is Status.FAIL       # development: judged
    st.basis["*"] = basis
    assert cb.apply(_forms_result(), st, published=True).status is Status.FAIL


@pytest.mark.parametrize("pid,config", [("P20", "good"), ("P21", "good"), ("P22", "a-good"),
                                        ("P22", "b-good"), ("P23", "good")])
def test_the_inventory_holds_every_form_a_toy_writes(pid, config):
    toy = knownbad._toy(pid, config)
    from conformance.evidence import Evidence
    kw = {"run_tag": f"inv-{config}"}
    if runner._takes_seed(ALL[pid].probe):
        kw["seed"] = 1
    with knownbad.toy_waits():
        toy.start()
        try:
            r = ALL[pid].probe(toy, Evidence("inv", toy.name, pid, config), **kw)
        finally:
            toy.stop()
    inv = cb.inventory(pid, toy)
    have = {f for f, _c in inv}
    open_ = {c for f, c in inv if f.endswith(cb.ANY_FORM)}
    forms = cb.forms_of(r)
    assert forms
    assert [f for f, c, _e in forms if f not in have and c not in open_] == []
    assert cb.inventory("P5") is None and cb.inventory("P19") is None


def _p21_dims():
    forms = {"wider_child": {"amount": {"reading": "held", "ok": True, "detail": ""},
                             "operations": {"reading": "held", "ok": True, "detail": ""}}}
    return Result(target="t", property_id="P21", status=Status.PASS, summary="ok",
                  control_held=True, control_detail="held",
                  checks=[Check("wider_child", "held", True, "")],
                  extra={"forms": forms, "constraint_profile": ["max_amount", "operations"],
                         "grant_profile_holder_only": False, "disclosure": "conformance",
                         "dimensions_covered": ["max_amount", "operations"]})


def test_P21_dimensions_covered_counts_claimed_forms_only():
    got = cb.apply(_p21_dims(), cb.Statement("P21", not_claimed={"wider_child/operations": "n"}))
    assert got.status is Status.PASS
    assert got.extra["dimensions_covered"] == ["max_amount"]
    assert got.extra["claim_basis"]["probe_as_read"]["derived"]["dimensions_covered"] == [
        "max_amount", "operations"]


def test_P22_information_keeps_claimed_forms_only():
    forms = {"sum_across_bs": {"sequential": {"reading": "held", "ok": True, "detail": ""}},
             "retry": {"double_count": {"reading": "held", "ok": True, "detail": ""}}}
    info = {"sum_across_bs/sequential": ["collateral_refusal"], "retry/double_count": ["no_overlap"]}
    r = Result(target="t", property_id="P22", status=Status.PASS, summary="ok", control_held=True,
               control_detail="held", checks=[Check("sum_across_bs", "held", True, ""),
                                              Check("retry", "held", True, "")],
               extra={"forms": forms, "information": info, "disclosure": "conformance"})
    got = cb.apply(r, cb.Statement("P22", not_claimed={"retry/*": "n"}))
    assert got.extra["information"] == {"sum_across_bs/sequential": ["collateral_refusal"]}
    assert got.extra["claim_basis"]["probe_as_read"]["derived"]["information"] == info


def test_P23_clauses_are_read_from_claimed_forms_only():
    forms = {"reversal": {"object_create": {"reading": "dropped", "ok": False, "detail": "d"},
                          "object_update": {"reading": "reversed", "ok": True, "detail": ""}},
             "no_standing": {"other_org": {"reading": "refused", "ok": True, "detail": ""}}}
    clauses = {"a": {"reading": "fail", "failed": ["reversal"], "passed": []},
               "b": {"reading": "not_applicable", "failed": [], "passed": []},
               "c": {"reading": "fail", "failed": ["reversal/object_create: dropped"],
                     "passed": ["no_standing"]}}
    r = Result(target="t", property_id="P23", status=Status.FAIL, summary="probe says fail",
               control_held=True, control_detail="held",
               checks=[Check("reversal", "dropped", False, "object_create: d"),
                       Check("no_standing", "refused", True, "")],
               extra={"forms": forms, "clauses": clauses, "disclosure": "conformance"})
    got = cb.apply(r, cb.Statement("P23", not_claimed={"reversal/object_create": "n"}))
    assert got.status is Status.PASS
    assert got.extra["clauses"]["a"] == {"reading": "pass", "failed": [], "passed": ["reversal"]}
    assert got.extra["clauses"]["c"] == {"reading": "pass", "failed": [],
                                         "passed": ["no_standing"]}
    assert got.extra["claim_basis"]["probe_as_read"]["derived"]["clauses"] == clauses
    kept = cb.apply(r, cb.Statement("P23", not_claimed={"no_standing": "n"}))
    assert kept.status is Status.FAIL
    assert kept.extra["clauses"]["c"]["failed"] == ["reversal/object_create: dropped"]


def test_a_summary_names_the_count_and_at_most_five_unclaimed_ids():
    r = _forms_result()
    extra_forms = {f"f{i}": {"reading": "held", "ok": True, "detail": ""} for i in range(7)}
    r.extra["forms"]["numeric"].update(extra_forms)
    st = cb.Statement("P21", not_claimed={"numeric/f*": "n", "cycle/id_cycle": "n"})
    got = cb.apply(r, st)
    head = got.summary.split(" As the probe read every form:")[0]
    assert "8 of 11 forms not claimed" in head and "and 3 more" in head
    assert sum(head.count(f"numeric/f{i}") for i in range(7)) + head.count("cycle/id_cycle") == 5
    assert len(got.extra["claim_basis"]["forms"]) == 11


# ------------------------------------- must-land misses, the control, published runs must state

def test_a_pass_that_rests_on_a_missed_must_land_form_reads_inconclusive():
    """Every failing form stated not claimed, but the probe listed a form that must land and did
    not: the claimed-only reading is inconclusive, never pass. A claimed failing form still fails;
    with nothing listed the reading is pass, as before."""
    st = cb.Statement("P21", not_claimed={"cycle/id_cycle": "n", "numeric/negative@holder": "n"})
    assert cb.apply(_forms_result(), st).status is Status.PASS
    r = _forms_result(extra={cb.MUST_LAND_FIELD: ["cycle/self_parent"]})
    got = cb.apply(r, st)
    assert got.status is Status.INCONCLUSIVE and got.control_held is True
    assert "must land did not" in got.summary and "cycle/self_parent" in got.summary
    one = cb.Statement("P21", not_claimed={"cycle/id_cycle": "n"})
    assert cb.apply(r, one).status is Status.FAIL               # a claimed form still fails
    every = cb.Statement("P21", not_claimed={"*": "n"})
    assert cb.apply(r, every).status == cb.NOT_CLAIMED


def _control_result():
    """A result in P25's and P26's shape: the control written as a check beside the forms."""
    forms = {"actor_shown": {"agent": {"reading": "outside_effect", "ok": False, "detail": "x"}},
             "principal_shown": {"organisation": {"reading": "held", "ok": True, "detail": "y"}}}
    checks = [Check("control", "held", True, "the control held"),
              Check("actor_shown", "outside_effect", False, "agent: x"),
              Check("principal_shown", "held", True, "organisation: y")]
    return Result(target="t", property_id="P25", status=Status.FAIL, summary="probe says fail",
                  control_held=True, control_detail="held", checks=checks,
                  extra={"forms": forms, "disclosure": "conformance"})


def test_the_control_check_is_the_control_not_a_claimed_form():
    r = _control_result()
    assert cb.CONTROL_CHECK not in {f for f, _c, _e in cb.forms_of(r)}
    st = cb.Statement("P25", not_claimed={"actor_shown": "n", "principal_shown": "n"})
    got = cb.apply(r, st)
    assert got.status == cb.NOT_CLAIMED, got.summary        # was pass, on the control alone
    assert "control" not in got.extra["claim_basis"]["forms"]
    got = cb.apply(r, cb.Statement("P25", not_claimed={"actor_shown": "n"}))
    assert got.status is Status.PASS                         # a real claimed form holds
    assert any(c.name == "control" and c.ok is True for c in got.checks)


def test_the_gate_checks_both_on_every_propertys_toys():
    rec = knownbad.run_one("P5", seed=1)
    claims = {c["config"]: c for c in rec["cases"] if c["config"].startswith("claims:")}
    assert claims["claims:every-form-unclaimed"]["got"] == "not_claimed"
    assert claims["claims:must-land-missed"]["ok"]
    need = claims["claims:fails-only-unclaimed"]["required"]
    assert claims["claims:must-land-missed"]["required"] == (
        "inconclusive" if need == "pass" else need)
    assert all(c["ok"] for c in claims.values()), claims


def test_a_rule_that_reads_the_control_as_a_form_fails_the_gate(monkeypatch):
    real = cb.forms_of
    monkeypatch.setattr(cb, "forms_of", lambda r: real(r) + [
        (c.name, c.name, None) for c in r.checks if c.name == cb.CONTROL_CHECK])
    monkeypatch.setattr(cb, "CONTROL_CHECK", "no-such-check")
    rec = knownbad.run_one("P26", seed=1)
    bad = [c for c in rec["cases"] if c["config"] == "claims:every-form-unclaimed"]
    assert bad and bad[0]["ok"] is False and rec["ok"] is False


def test_a_published_run_of_an_adapter_that_states_nothing_is_refused(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(ALL["P5"], "probe", lambda *a, **k: called.append(1))
    t = TOYS["P5"]("good")
    t.implements = lambda: ["P5"]
    assert not hasattr(t, "not_claimed") or not t.not_claimed()
    with pytest.raises(cb.ClaimBasisIncomplete, match="no claim basis stated for P5") as e:
        runner.run_adapter(t, ["P5"], run_id="cb494", known_bad="mark", published=True)
    assert called == [] and "no claim basis stated for P5" in e.value.gaps["P5"][0]
    monkeypatch.setattr(runner, "load", lambda spec: t)
    assert runner.main(["run", "toy", "-p", "P5", "--published", "--without-known-bad"]) == 6
    assert "no claim basis stated for P5" in capsys.readouterr().err


def test_a_development_run_of_an_adapter_that_states_nothing_is_unchanged(tmp_path):
    t = TOYS["P5"]("good")
    t.implements = lambda: ["P5"]
    (r,) = runner.run_adapter(t, ["P5"], run_id="cb494d", known_bad="mark")
    assert r.status is Status.PASS
    assert "claim_basis" not in _doc(tmp_path, "cb494d", "P5")


def test_a_property_stated_not_claimed_whole_needs_nothing_more():
    t = _stated(TOYS["P5"]("good"), {"P5": "the target states nothing about it"})
    assert cb.before_run(t, cb.statement(t, "P5")) == []


def test_record_rerecords_a_property_whose_record_was_made_under_another_rule(
        tmp_path, capsys):
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0
    path = tmp_path / "known-bad" / "records.jsonl"
    rec = json.loads(path.read_text().splitlines()[-1])
    rec["claim_rule_version"] = "sha256:an-older-rule"
    path.write_text(json.dumps(rec) + "\n")
    assert knownbad.status("P5", cb.rule_version())["state"] == knownbad.STALE
    assert runner.main(["known-bad", "--status", "-p", "P5"]) == 1
    assert "claim_rule_version" in capsys.readouterr().out
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0      # no --force needed
    recs = [json.loads(x) for x in path.read_text().splitlines()]
    assert len(recs) == 2 and recs[-1]["claim_rule_version"] == cb.rule_version()
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0      # now current: kept
    assert len(path.read_text().splitlines()) == 2


def test_p24_and_p26_write_the_forms_that_must_land_and_did_not():
    from conformance.evidence import Evidence
    from conformance.properties import p24_mandate_bound as p24, p26_translation as p26
    from known_bad import mandate_toys, translation_toys
    t = mandate_toys.toy("info:hold_forever")
    t.start()
    try:
        r = p24.probe(t, Evidence("m", t.name, "P24", "hold"), run_tag="m", seed=5,
                      plan={"trials": 1, "variants": ["condition", "outside_ceiling",
                                                      "unknown_term"]})
    finally:
        t.stop()
    assert r.status is Status.INCONCLUSIVE
    assert r.extra[cb.MUST_LAND_FIELD] == ["condition/unconfirmed", "condition/agent_confirmed"]

    class Documented(translation_toys.ToyTranslation):
        def documented_widenings(self):
            return {"currency/rate_undeclared": "\"uses a built-in table\""}
    a = Documented("bad", "built_in_rate", "T")
    a.start()
    try:
        r = p26.probe(a, Evidence("m", a.name, "P26", "doc"), run_tag="m", seed=3,
                      plan={"trials": "dev"})
    finally:
        a.stop()
    assert r.status is Status.INCONCLUSIVE
    assert r.extra[cb.MUST_LAND_FIELD] == ["currency/rate_undeclared"]
    good = translation_toys.toy("good@T")
    good.start()
    try:
        r = p26.probe(good, Evidence("m", good.name, "P26", "good"), run_tag="m", seed=3,
                      plan={"trials": "dev"})
    finally:
        good.stop()
    assert r.status is Status.PASS and r.extra[cb.MUST_LAND_FIELD] == []
