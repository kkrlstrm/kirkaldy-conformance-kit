"""P23 (KRK-23, reversibility as declared): the class vocabulary against hand-written vectors, the
stub A's formats, and the probe against its toys. The four correct toys pass at the published
counts on the virtual clock (decided before any run: a conservative and
a deferred B pass); each flaw fails the variant it was built for; ``no-control`` gives no verdict.

Where a flaw fails more than the variant it was built for, `ALSO_FAILS` says so: a B that answers
"reversed" without acting fails every variant that expects a restoration (design §13 item 3)."""
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from conformance import authz, reversibility as rv  # noqa: E402
from conformance.evidence import Evidence  # noqa: E402
from conformance.properties import p23_reversibility as p23  # noqa: E402
from conformance.result import Status  # noqa: E402
from conformance.reverser import ReversalRequester  # noqa: E402
from conformance.timing import VirtualClock  # noqa: E402
from known_bad import reversal_toys as rt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
V = json.loads((ROOT / "tests/vectors/krk23/vectors.json").read_text())
DEV = {"trials": "dev"}
RESTORING = {"reversal", "window", "partition", "compensation_effect", "duplicate",
             "downstream_consequence", "class_downgrade"}
ALSO_FAILS = {
    "slow_reversal": RESTORING, "marks_only": RESTORING, "async_dropped": RESTORING,
    "partial_items": {"reversal", "partition"},
    "reverses_latest": RESTORING | {"overtake"},
    "notifies_undeclared": RESTORING | {"b_initiated"},
    "refund_as_transfer": {"reversal", "downstream_consequence"},
    "done_on_world_error": {"partition", "window"},
    "forgets_queued": {"partition", "window"},
    "compensates_wrong": {"compensation_effect", "downstream_consequence", "duplicate",
                          "reversal"},
    "compensates_with_notice": {"compensation_effect", "downstream_consequence", "duplicate",
                                "reversal"},
    "double_compensation": {"duplicate", "compensation_effect"},
    "ignores_class": {"class_ceiling", "class_downgrade"},
}
"""Every variant each flaw fails, where that is more than the one it was built for."""


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _run(t, plan=None, seed=5):
    ev = Evidence("t", t.name, "P23", t.config.replace(":", "-"))
    t.start()
    try:
        return p23.probe(t, ev, run_tag="t", seed=seed, plan=plan)
    finally:
        t.stop()


def _key(s):
    k, i = s.split(":", 1)
    return (k, i)


# --------------------------------------------------------------------------- vectors


@pytest.mark.parametrize("a,b,want", V["ceiling"])
def test_ceiling_order(a, b, want):
    assert rv.class_le(a, b) is want


@pytest.mark.parametrize("op,request_values,want", V["class_for"])
def test_class_for(op, request_values, want):
    assert rv.class_for(V["claims"], op, request_values) == want


@pytest.mark.parametrize("claim,want", V["claim_problem"])
def test_claim_problem(claim, want):
    got = rv.claim_problem(claim)
    if want is None:
        assert got is None, got
    else:
        assert got is not None and want in got, (got, want)


@pytest.mark.parametrize("case", V["window"])
def test_window(case):
    assert rv.window_open(case["claim"], t_e=case["t_e"], t_q=case["t_q"], events=case["events"],
                          tol_s=case["tol"], eps_s=case["eps"]) == case["expect"]


@pytest.mark.parametrize("case", V["judge"], ids=[c["name"] for c in V["judge"]])
def test_judge(case):
    j = rv.judge(case["claim"], {_key(k): tuple(v) for k, v in case["footprint"].items()},
                 others=case["others"],
                 siblings={_key(k): tuple(v) for k, v in case["siblings"].items()},
                 holdings=case["holdings"], counter_ops=case.get("counter_ops", 0),
                 x_transfer=case.get("x_transfer"), x_tokens=case.get("x_tokens", ()),
                 history_trace=case.get("history_trace"))
    e = case["expect"]
    assert j.restored is e["restored"]
    assert j.aspects_not_restored == e["aspects_not_restored"]
    assert len(j.new_effects) == e["new_effects"]
    assert len(j.residues_undeclared) == e["residues_undeclared"]
    assert j.counter_effects == e["counter_effects"]
    assert j.other_touched == e.get("other_touched", [])
    assert j.x_relanded == e.get("x_relanded", [])


def test_the_reader_adds_no_residue():
    """KRK-M125: a claim's residues are B's, never the kit's."""
    c = {"operation": "x", "class": "reversible", "means": {"operation": "r"},
         "window": {"seconds": 5}, "restores": ["object"]}
    assert rv.claim_problem(c) is None and "residues" not in c


# --------------------------------------------------------------------------- formats


def test_authorisation_0_2_carries_the_ceiling_and_verifies():
    A = ReversalRequester(clock=VirtualClock())
    p = A.forward({"note": "n"}, operation="crm.contact.create", max_class="reversible",
                  endpoint="/actions", agent="ag1")
    v = rv.verify_v2(p.authorisation, {A.key.kid: A.key.public_bytes()})
    assert v.ok, v.detail
    c = v.claims
    assert c["schema"] == rv.AUTHZ_V2_SCHEMA and c["max_class"] == "reversible"
    assert c["agent"] == {"id": "ag1", "grants": ["crm.contact.create"]}
    assert c["binding"]["request_digest"] == authz.binding_digest(p.request)
    assert authz.verify_authorisation(p.authorisation, {A.key.kid: A.key.public_bytes()}).reason \
        == "malformed"                              # 0.1's reader does not take 0.2
    assert rv.verify_v2(p.authorisation, {}).reason == "unpinned-key"


def test_a_reversal_names_its_original_and_is_signed_by_whoever_asks():
    A = ReversalRequester(clock=VirtualClock())
    A2 = A.peer()
    p = A.forward({"note": "n"}, operation="crm.contact.create", max_class="irreversible",
                  endpoint="/actions", agent="ag1")
    r = A.request_reversal(p, means={"operation": "krk.reverse"}, agent="ag1")
    r2 = A2.request_reversal(p, means={"operation": "krk.reverse"}, agent="ag9")
    body = json.loads(r.request)
    oc = authz.claims_of(p.authorisation)
    assert body["reverses"] == {"authorisation_id": oc["authorisation_id"],
                                "request_digest": authz.binding_digest(p.request)}
    assert authz.claims_of(r.authorisation)["reverses"] == body["reverses"]
    assert authz.claims_of(r2.authorisation)["issuer"] == A2.issuer != A.issuer
    assert rv.verify_v2(r2.authorisation, {A2.key.kid: A2.key.public_bytes()}).ok
    assert json.loads(r.request)["request_id"] != json.loads(
        A.request_reversal(p, means={"operation": "krk.reverse"}, agent="ag1").request)["request_id"]
    again = A.repeat(r)
    assert (again.request, again.authorisation) == (r.request, r.authorisation) and again.pid != r.pid


def test_a_class_in_the_request_is_the_agents_genuine_statement():
    v = ReversalRequester.claim_in_request({"a": 1}, "reversible")
    assert v["class"] == "reversible" and v["a"] == 1


# --------------------------------------------------------------------------- the toys


@pytest.mark.parametrize("config", ["good", "good-deferred", "good-conservative", "slow-good"])
def test_the_correct_toys_pass_at_published_counts(config):
    r = _run(rt.toy(config), plan={"trials": "published"})
    assert r.status is Status.PASS, (r.summary, [(c.name, c.outcome, c.detail[:200])
                                                 for c in r.checks])
    assert r.control_held is True
    assert r.extra["forms"]["reversal"]["object_create"]["trials"] == 100
    assert {k: v["reading"] for k, v in r.extra["clauses"].items()} == \
        {"a": "pass", "b": "pass", "c": "pass"}
    st = r.extra["statistics"]["reversal/object_create"]
    assert st["n_counted"] == 100 and st["late"] == 0 and "mean" not in json.dumps(st)


def test_the_conservative_toy_passes_by_refusing_and_is_graded_on_the_ceiling():
    """Declaring an operation irreversible and refusing its reversal passes."""
    r = _run(rt.toy("good-conservative"), plan=DEV)
    f = r.extra["forms"]
    assert f["reversal"]["message"]["reading"] == "not_applicable"
    assert f["downstream_consequence"]["funds_moved"]["reading"] == "not_applicable"
    assert f["class_ceiling"]["irreversible_op"]["ok"] is True
    assert f["class_ceiling"]["compensable_op"]["reading"] == "not_applicable"


def test_the_deferred_toy_cancels_before_landing_and_its_unreversed_actions_land():
    r = _run(rt.toy("good-deferred"), plan=DEV)
    assert r.status is Status.PASS, r.summary
    m = r.extra["forms"]["reversal"]["message"]
    assert m["ok"] is True and m["operation"] == "mail.send"
    d = r.extra["forms"]["downstream_consequence"]["read_before_recall"]
    assert d["ok"] is True                    # the paired trial before any consequence


def test_no_control_gives_no_verdict():
    r = _run(rt.toy("no-control"))
    assert r.status is Status.INCONCLUSIVE and "control did not hold" in r.summary


def test_bad_fails_the_ceiling_and_answers_done_while_the_effect_remains():
    r = _run(rt.toy("bad"), plan=DEV)
    assert r.status is Status.FAIL
    failed = {c.name: c.outcome for c in r.checks if c.ok is False}
    assert failed["class_ceiling"] == "outside_class_effect"
    assert failed["reversal"] == "done_while_present"


@pytest.mark.parametrize("flaw", rt.FLAWS)
def test_each_flaw_fails_the_variant_it_was_built_for_and_no_other(flaw):
    r = _run(rt.make(flaw), plan=DEV)
    assert r.status is Status.FAIL, r.summary
    failed = {c.name for c in r.checks if c.ok is False}
    assert rt.FAILS[flaw] in failed
    assert failed == ALSO_FAILS.get(flaw, {rt.FAILS[flaw]}), failed


@pytest.mark.parametrize("flaw,variant,form", [
    ("partial_items", "reversal", "multi_item"), ("object_only", "reversal", "object_delete"),
    ("update_as_delete", "reversal", "object_update"),
    ("refund_as_transfer", "reversal", "transfer"),
    ("recreates_new_id", "reversal", "object_delete"),
    ("reports_done_on_partial", "partition", "refuse_one_item"),
    ("memory_only", "partition", "b_restart"),
    ("keyed_on_request_id", "duplicate", "new_request_id"),
    ("keyed_on_object", "duplicate", "after_reapply"),
    ("agent_grant_ignored", "no_standing", "agent_without_reversal"),
    ("compensable_as_reversible", "class_ceiling", "compensable_op"),
    ("absent_means_reversible", "class_ceiling", "class_absent"),
    ("class_from_request", "class_ceiling", "class_claimed_in_request"),
    ("class_at_bind", "class_downgrade", "catalogue_changed"),
    ("class_per_operation", "class_downgrade", "condition_in_request"),
    ("checks_class_at_arrival", "class_downgrade", "changed_between_arrival_and_commit"),
    ("applies_new_window_to_old", "class_downgrade", "window_shortened_after_execution"),
])
def test_a_form_specific_flaw_fails_its_form(flaw, variant, form):
    r = _run(rt.make(flaw), plan={**DEV, "variants": [variant]})
    d = r.extra["forms"][variant][form]
    assert d["ok"] is False, d


def test_the_clauses_are_reported_apart():
    r = _run(rt.make("class_at_bind"), plan=DEV)
    cl = {k: v["reading"] for k, v in r.extra["clauses"].items()}
    assert cl == {"a": "pass", "b": "fail", "c": "pass"}
    r = _run(rt.make("any_requester"), plan=DEV)
    assert {k: v["reading"] for k, v in r.extra["clauses"].items()} == \
        {"a": "pass", "b": "pass", "c": "fail"}


def test_a_truthfulness_failure_counts_in_clause_c_wherever_it_is_seen():
    r = _run(rt.make("marks_only"), plan={**DEV, "variants": ["reversal"]})
    c = r.extra["clauses"]["c"]
    assert c["reading"] == "fail" and any("done_while_present" in x for x in c["failed"])


def test_a_variant_the_target_declares_not_applicable_is_skipped_but_the_control_is_not():
    t = rt.toy("good")
    t.variants_not_applicable = lambda: {"control": "no"}
    assert _run(t).status is Status.INCONCLUSIVE
    t = rt.toy("good")
    t.variants_not_applicable = lambda: {"b_initiated": "no operator console"}
    r = _run(t, plan=DEV)
    assert r.status is Status.PASS
    assert any(c.name == "b_initiated" and c.outcome == "not_applicable" for c in r.checks)


def test_a_lower_evidence_grade_drives_no_restoration_variant():
    t = rt.toy("good")
    t.evidence_grade = lambda: "b-response"
    r = _run(t, plan=DEV)
    assert r.extra["forms"]["reversal"]["object_create"]["reading"] == "not_applicable"
    assert r.extra["forms"]["class_ceiling"]["irreversible_op"]["ok"] is True


def test_findings_name_a_malformed_claim_and_a_missing_standing_rule():
    t = rt.toy("good")
    cat = t.reversibility()
    cat.append({"operation": "crm.contact.merge", "class": "reversible"})   # no window, no means
    t.reversibility = lambda: cat
    t.reversal_standing = lambda: None
    r = _run(t, plan={**DEV, "variants": ["class_ceiling"]})
    kinds = {f["finding"] for f in r.extra["findings"]}
    assert {"malformed_claim", "no_standing_rule"} <= kinds
    mal = next(f for f in r.extra["findings"] if f["finding"] == "malformed_claim")
    assert mal["read_as"] == "irreversible"


def test_the_world_is_bound_with_a_credential_the_kit_does_not_use():
    t = rt.toy("good")
    _run(t, plan={**DEV, "variants": ["reversal"], "forms": {"reversal": ["object_create"]}})
    assert t.w is not None and t.w.credential.startswith("wc-")


def test_a_toy_on_a_virtual_clock_must_be_a_toy():
    class Real(rt.ToyReversal):
        pass
    Real.__module__ = "targets.somewhere"
    r = _run(Real("good"))
    assert r.status is Status.INCONCLUSIVE and "virtual clock" in r.summary
