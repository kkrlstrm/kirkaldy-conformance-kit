"""P18B (KRK-18, authority at B): the required outcomes of the B-issuer toys, in each of the three
shapes. Every flaw fails exactly the variant forms it was built for, in every shape where the form
applies (KRK-M47); the correct toys pass; ``bad`` (``no_check``) fails; ``no-control`` gives no
verdict; ``restates_silently`` gives no verdict with the ``restated_changed`` finding. This file is in
P18B's `FIXTURES`, so editing it changes P18B's fixture version."""
import json

import pytest

from conformance import bissuer
from conformance.evidence import Evidence
from conformance.properties import ALL, ALL_BISSUER
from conformance.properties import p18b_payload_bound_b as p18b
from conformance.result import Status
from known_bad.bissuer_binding_toys import (FINDINGS, FLAWS, applies, cases, make, toy)
from known_bad.bissuer_core import SHAPES

SEED = 616161

REPLAYS = {"replay_after_answer", "retry_after_lost_answer", "replay_new_key",
           "replay_after_restart", "replay_after_failover", "replay_other_endpoint"}
CRASH = "crash_between_use_and_effect"
PARTS_FORMS = {"split_declared", "validity_beyond_memory"}
"""Forms with use records over parts or past a retention; the consent-id and rar-token toys
have them, the revision toy does not (its objects list no parts; rule 6)."""


def _two(rev, other):
    return {"revision": set(rev), "consent-id": set(other), "rar-token": set(other)}


def _all(s):
    return _two(s, s)


EXPECTED = {
    "terms_not_compared": _two({"body_changed"}, {"body_changed", "split_undeclared"}),
    "member_outside_terms": _all({"unbound_member"}),
    "last_member_wins": _all({"duplicate_key"}),
    "float_terms": _all({"number_precision"}),
    "fold_at_execution": _all({"unicode_fold"}),
    "class_suffices": _all({"class_for_exact"}),
    "every_acceptance_runs": _two(REPLAYS | {"race_same", CRASH},
                                  REPLAYS | {"race_same", CRASH} | PARTS_FORMS),
    "duplicate_as_refusal": _all(REPLAYS),
    "dedupes_on_client_key": _all({"replay_new_key"}),
    "use_record_in_memory": _all({"replay_after_restart", "replay_after_failover"}),
    "per_instance_use": _all({"replay_after_failover"}),
    "per_endpoint_use": _all({"replay_other_endpoint"}),
    "tenant_not_checked": _all({"replay_other_tenant"}),
    "accepts_foreign_object": _all({"replay_other_counterparty"}),
    "holder_not_checked": _all({"other_holder"}),
    "check_then_set": _all({"race_same", CRASH}),
    "accepts_subset": _two(set(), {"split_undeclared"}),
    "parts_and_whole": _two(set(), {"split_declared"}),
    "ignores_expiry": _all({"expired"}),
    "forgets_before_expiry": _two(set(), {"validity_beyond_memory"}),
    "consumes_on_refusal": _all({"refused_then_retry"}),
    "effect_before_mark": _all({CRASH}),
    "mark_before_effect_says_done": _all({CRASH}),
    "executes_request_not_terms": _two({"body_changed", "unbound_member"}, {"unbound_member"}),
    "writes_unaccepted": _all({"resource_reconciliation"}),
}
"""Each flaw's exact failing checks per shape (the variant forms, and the run-level
``resource_reconciliation``)."""
NO_CHECK = _two(REPLAYS | {"body_changed", "class_for_exact", CRASH, "expired", "other_holder",
                           "race_same", "replay_other_tenant"},
                REPLAYS | {"body_changed", "class_for_exact", CRASH, "expired", "other_holder",
                           "race_same", "replay_other_tenant", "split_declared",
                           "split_undeclared", "validity_beyond_memory"})
OUTCOMES = {("duplicate_as_refusal", "retry_after_lost_answer"): "denied_done",
            ("mark_before_effect_says_done", CRASH): "claims_done",
            ("writes_unaccepted", "resource_reconciliation"): "effect_without_acceptance",
            ("holder_not_checked", "other_holder"): "ran_wrong_audience",
            ("accepts_foreign_object", "replay_other_counterparty"): "ran_wrong_audience",
            ("last_member_wins", "duplicate_key"): "ran_ambiguous",
            ("class_suffices", "class_for_exact"): "ran_under_class",
            ("ignores_expiry", "expired"): "ran_expired",
            ("consumes_on_refusal", "refused_then_retry"): "consumed_by_refusal"}


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


_CACHE = {}


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    """One probe run per gate configuration, shared by the tests of this module."""
    import conformance.evidence as E
    base = tmp_path_factory.mktemp("p18b")

    def go(config):
        if config not in _CACHE:
            saved, E.RESULTS = E.RESULTS, base
            t = toy(config)
            t.start()
            try:
                _CACHE[config] = p18b.probe(
                    t, Evidence("t", t.name, "P18B", config.replace(":", "-")), run_tag="t",
                    seed=SEED)
            finally:
                t.stop()
                E.RESULTS = saved
        return _CACHE[config]
    return go


def fails(r):
    return {c.name for c in r.checks if c.ok is False}


def test_registered_apart_from_all():
    assert ALL_BISSUER["P18B"] is p18b and "P18B" not in ALL
    assert p18b.TITLE == "Payload bound, single use (authority at B)"
    assert set(p18b.VARIANTS) == set(ALL["P18"].VARIANTS) | {"other_holder"}


def test_flaw_table_is_complete():
    assert set(EXPECTED) == set(FLAWS)
    assert FINDINGS == ("restates_silently",)
    for flaw in FLAWS:
        for shape in SHAPES:
            assert bool(EXPECTED[flaw][shape]) == applies(flaw, shape), (flaw, shape)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("variant", ["good", "slow-good"])
def test_the_correct_toys_pass(shape, variant, run):
    r = run(f"{shape}:{variant}")
    assert r.status is Status.PASS, (r.summary, [c.__dict__ for c in r.checks if c.ok is not True])
    na = {c.name for c in r.checks if c.outcome == "not_applicable"}
    assert ("split_undeclared" in na) == (shape == "revision")
    assert ("split_declared" in na) == (shape == "revision")
    assert {"translated_declared", "mapping_undeclared"} <= na


@pytest.mark.parametrize("shape", SHAPES)
def test_no_check_fails_and_is_not_inconclusive(shape, run):
    r = run(f"{shape}:bad")
    assert r.status is Status.FAIL and r.control_held is True
    assert fails(r) == NO_CHECK[shape], sorted(fails(r) ^ NO_CHECK[shape])


@pytest.mark.parametrize("shape", SHAPES)
def test_no_control_gives_no_verdict(shape, run):
    r = run(f"{shape}:no-control")
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary
    assert "0 effects in B's store" in r.summary


@pytest.mark.parametrize("shape", SHAPES)
def test_silent_restatement_gives_no_verdict_and_a_finding(shape, run):
    r = run(f"{shape}:finding:restates_silently")
    assert r.status is Status.INCONCLUSIVE
    assert "did not label them a counter-proposal" in r.summary
    assert [f["finding"] for f in r.extra["findings"]] == ["restated_changed"]
    assert r.extra["findings"][0]["class"] == "conformance"


@pytest.mark.parametrize("config", [c for c, _ in cases() if ":bad:" in c])
def test_each_flaw_fails_exactly_its_forms(config, run):
    shape, _, flaw = config.split(":", 2)
    r = run(config)
    assert r.status is Status.FAIL and r.control_held is True, r.summary
    assert fails(r) == EXPECTED[flaw][shape], sorted(fails(r) ^ EXPECTED[flaw][shape])
    for (f, name), outcome in OUTCOMES.items():
        if f == flaw:
            (c,) = [c for c in r.checks if c.name == name]
            assert c.outcome == outcome, c.__dict__


def test_cases_name_every_shape_and_flaw():
    got = dict(cases())
    for shape in SHAPES:
        assert got[f"{shape}:good"] == "pass" and got[f"{shape}:slow-good"] == "pass"
        assert got[f"{shape}:bad"] == "fail" and got[f"{shape}:no-control"] == "inconclusive"
        assert got[f"{shape}:finding:restates_silently"] == "inconclusive"
        for flaw in FLAWS:
            assert (f"{shape}:bad:{flaw}" in got) == applies(flaw, shape)


# ---------------------------------------------------------------------------- labelling (§5.3)


@pytest.mark.parametrize("shape", SHAPES)
def test_every_result_is_labelled(shape, run):
    for cfg in (f"{shape}:good", f"{shape}:bad", f"{shape}:no-control"):
        r = run(cfg)
        assert r.summary.startswith(bissuer.SUMMARY_SENTENCE), r.summary
        assert "driven-page hook" in r.summary
        assert r.extra["authority"] == {"issuer": "B", "profile": "b-issuer/0.1",
                                        "shape": shape, "hook": "driven-page"}
        text = json.dumps(r.to_doc())
        for word in bissuer.FORBIDDEN_WORDS:
            assert word not in text
    r = run(f"{shape}:good")
    assert r.extra["grade_label"] == "B-store-read, authority at B"
    assert all("authority at B" in c.detail for c in r.checks if c.ok is not None
               and c.name not in ("resource_reconciliation",))


# ---------------------------------------------------------------------------- the NA rules


def test_split_undeclared_is_the_probes_own_na_for_revision_only():
    assert "split_undeclared" not in p18b.na_forbidden("revision")
    assert "split_undeclared" in p18b.na_forbidden("consent-id")
    assert "split_undeclared" in p18b.na_forbidden("rar-token")
    assert ("revision", "split_undeclared") in p18b.STRUCTURAL_NA


@pytest.mark.parametrize("shape,variant", [("consent-id", "split_undeclared"),
                                           ("revision", "other_holder"),
                                           ("rar-token", "replay_after_restart")])
def test_a_forbidden_na_declaration_is_refused(shape, variant, tmp_path):
    t = make(shape)
    t.variants_not_applicable = lambda: {variant: "the adapter says so"}
    t.start()
    try:
        r = p18b.probe(t, Evidence("t", t.name, "P18B", "na"), run_tag="na", seed=1)
    finally:
        t.stop()
    assert r.status is Status.INCONCLUSIVE and variant in r.summary


def test_an_unrecorded_grade_is_refused():
    t = make("revision")
    t.evidence_grade = lambda: "recorder"
    t.start()
    try:
        r = p18b.probe(t, Evidence("t", t.name, "P18B", "grade"), run_tag="g", seed=1)
    finally:
        t.stop()
    assert r.status is Status.INCONCLUSIVE and "not built in phase 1a" in r.summary
