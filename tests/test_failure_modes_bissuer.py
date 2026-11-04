"""Pins for the B-issuer profile's measurement failure modes (`docs/FAILURE-MODES.md`, KRK-M130 to
KRK-M147) that phase 1a builds. Each test shows the guard, and
where a guard can be switched off, the wrong reading it prevents. All are anticipated: none was
observed against a target, because no B-issuer target has been run. KRK-M135 to KRK-M138,
KRK-M144 and KRK-M146 belong to P19B, P20B and P16B and are pinned when those are built."""
import pytest

from conformance import bissuer, runner
from conformance.evidence import Evidence
from conformance.properties import p18b_payload_bound_b as p18b
from conformance.result import Status
from known_bad.binding_toys import ToyBinding
from known_bad.bissuer_binding_toys import make, toy


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _probe(t, tag="t", seed=5):
    t.start()
    try:
        return p18b.probe(t, Evidence("t", t.name, "P18B", tag), run_tag=tag, seed=seed)
    finally:
        t.stop()


def _check(r, name):
    (c,) = [c for c in r.checks if c.name == name]
    return c


def test_KRK_M130_an_adapter_at_b_is_never_graded_by_the_a_issued_probe():
    a = toy("revision:good")
    a.implements = lambda: ["P18"]
    (r,) = runner.run_adapter(a, ["P18"], run_id="f130", known_bad="mark")
    assert r.status is Status.INCONCLUSIVE and "run P18B" in r.summary
    assert runner.authority_refusal(ToyBinding("good"), "P18") is None
    assert "run P18" in runner.authority_refusal(ToyBinding("good"), "P18B")


def test_KRK_M131_the_result_names_the_hook_and_never_a_persons_consent():
    r = _probe(make("consent-id"))
    assert r.status is Status.PASS
    assert r.summary.startswith(bissuer.SUMMARY_SENTENCE)
    assert "through a driven-page hook" in r.summary
    assert "person's consent" not in r.to_json()


def test_KRK_M132_a_silent_restatement_is_not_accepted(monkeypatch):
    t = make("revision", "restates_silently")
    r = _probe(t, "f132")
    assert r.status is Status.INCONCLUSIVE and "rule 8" in r.summary
    # the error: accept whatever B signed, and judge the effect against B's terms only
    monkeypatch.setattr(p18b.PairB, "_acceptable", lambda self, *a, **k: True)
    r2 = _probe(make("revision", "restates_silently"), "f132-off")
    assert r2.status is Status.PASS                      # a B that rewrites every request passes


def test_KRK_M133_the_hook_kinds_and_the_decline_check():
    r = _probe(make("rar-token", issues_on_decline=True), "f133")
    assert _check(r, "decline_check").outcome == "consent_not_enforced"
    assert _check(r, "decline_check").ok is None           # information here; P20B grades it
    assert _check(_probe(make("rar-token"), "f133-ok"), "decline_check").outcome == \
        "consent_enforced"
    t = make("revision")
    t.hook().kind = "store-write"
    r3 = _probe(t, "f133-kind")
    assert r3.status is Status.INCONCLUSIVE and "KRK-M133" in r3.summary


def test_KRK_M134_a_store_the_restart_rebuilt_does_not_hide_the_first_effect(monkeypatch):
    r = _probe(make("revision", reset_effects_on_restart=True), "f134")
    assert _check(r, "replay_after_restart").outcome == "ran_twice"
    # the error: count only what B's store shows after the restart
    real = p18b.PairB.effects

    def latest_only(self):
        self.seen = {}
        return real(self)
    monkeypatch.setattr(p18b.PairB, "effects", latest_only)
    r2 = _probe(make("revision", reset_effects_on_restart=True), "f134-off")
    assert _check(r2, "replay_after_restart").outcome == "ran_once"


def test_KRK_M139_a_driver_that_consents_on_its_own_voids_the_reading():
    r = _probe(make("consent-id", driver_reconsents=True), "f139")
    assert r.status is Status.INCONCLUSIVE and "KRK-M139" in r.summary


def test_KRK_M140_b_objects_are_verified_by_the_kit_against_published_keys():
    t = make("revision", signs_with_unpublished_key=True)
    r = _probe(t, "f140")
    assert r.status is Status.INCONCLUSIVE and "did not verify" in r.summary
    assert t.verify_calls == 0                    # B's own verifier is never asked
    good = make("revision")
    assert _probe(good, "f140-ok").status is Status.PASS and good.verify_calls == 0


def test_KRK_M141_a_supersession_is_read_from_bs_own_signed_object(monkeypatch):
    r = _probe(make("revision", no_counter=True), "f141")
    c = _check(r, "body_changed")
    assert c.outcome == "fixture_not_landed" and "KRK-M141" in c.detail
    assert r.status is Status.INCONCLUSIVE        # body_changed must land
    # the error: take the kit's counter-proposal as the supersession; a correct B, whose
    # revision was still current, then reads as running changed terms
    monkeypatch.setattr(p18b.bissuer.BObjectLog, "superseded", lambda self, oid: True)
    r2 = _probe(make("revision", no_counter=True), "f141-off")
    assert _check(r2, "body_changed").outcome == "ran_changed"


def test_KRK_M142_the_second_instance_must_not_share_the_targets_keys():
    r = _probe(make("consent-id", peer_shares_keys=True), "f142")
    c = _check(r, "replay_other_counterparty")
    assert c.outcome == "fixture_not_landed" and "KRK-M142" in c.detail
    assert r.status is Status.INCONCLUSIVE


def test_KRK_M143_bs_account_of_an_effect_is_never_counted():
    r = _probe(toy("revision:no-control"), "f143")
    assert r.status is Status.INCONCLUSIVE and "0 effects in B's store" in r.summary
    t = make("revision")
    t.evidence_grade = lambda: "B-answer"
    r2 = _probe(t, "f143-answer")
    for v in p18b.COUNTING:
        c = _check(r2, v)
        assert c.ok is None and c.outcome in ("not_driven", "not_applicable"), v
        if v in ("replay_after_answer", "race_same", "other_holder", "replay_after_restart"):
            assert c.outcome == "not_driven", v


def test_KRK_M145_a_reset_by_the_tester_reads_inconclusive():
    r = _probe(make("rar-token", reset_between_pairs=True), "f145")
    assert r.status is Status.INCONCLUSIVE and "KRK-M145" in r.summary
    assert r.extra["resets"]


def test_KRK_M147_background_writers_and_the_baseline_are_declared():
    assert _probe(make("revision", background="declared", prior_history=True),
                  "f147").status is Status.PASS
    r = _probe(make("revision", background="undeclared"), "f147-undeclared")
    c = _check(r, "resource_reconciliation")
    assert c.outcome == "effect_without_acceptance" and r.status is Status.FAIL
    # the guard that keeps the baseline out: changes before the run are never counted
    rb = _probe(make("revision", prior_history=True), "f147-baseline")
    assert _check(rb, "resource_reconciliation").ok is True
