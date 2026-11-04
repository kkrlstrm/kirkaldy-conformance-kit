"""KRK-M190 to KRK-M209 (docs/FAILURE-MODES.md): one pin
per measurement error, against P26's probe, its kit parties and its toys."""
import base64
import copy
import hashlib
import json

import pytest

from conformance import translation as tr
from conformance import translation_formats as fmt
from conformance import translator_stub as ts
from conformance.evidence import Evidence
from conformance.properties import p26_translation as p26
from conformance.result import Status
from known_bad import translation_toys as toys


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def run(a, seed=3, trials="dev"):
    a.start()
    try:
        return p26.probe(a, Evidence("t", a.name, "P26", a.config.replace(":", "-")),
                         run_tag="t", seed=seed, plan={"trials": trials})
    finally:
        a.stop()


def reading(r, form):
    v, f = form.split("/")
    return r.extra["forms"][v][f]


def _payload(raw):
    body = raw.split(b".")[1]
    return json.loads(base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4)))


def T(base="good", flaw=None, topo="T"):
    return toys.ToyTranslation(base, flaw, topo)


def test_KRK_M190_the_profile_is_the_targets_never_the_kits():
    class NoProfile(toys.ToyTranslation):
        def translation_profile(self):
            return None
    r = run(NoProfile("good", None, "T"))
    assert r.status is Status.INCONCLUSIVE and "never supplies one" in r.summary
    r = run(T())
    assert r.extra["profile_digest"] == tr.profile_digest(toys.TOY_PROFILE)
    assert r.extra["profile_owner"] == "did:web:toy-translator.example"


def test_KRK_M191_a_member_the_decoder_cannot_read_is_never_read_as_narrowing():
    class Decoder(toys.ToyTranslation):
        def read_translated(self, raw):
            d = super().read_translated(raw)
            if len(d["members"].get("scope", [])) > 1:        # cannot decode a list of two
                d["members"].pop("scope")
                d["unreadable"] = sorted(d["unreadable"] + ["scope"])
            return d
    r = run(Decoder("bad", "grants_requested", "T"))
    d = reading(r, "scope/operation_added")
    assert d["reading"] == "unreadable_translation" and d["ok"] is None   # never "held"
    assert r.control_held is True
    rec = ts.Recorder()
    rp = ts.FaithfulReceiver(toys.TOY_PROFILE, toys.TOY_SEMANTICS, rec, receiver="r")
    ans = rp.enact({"members": {}, "unreadable": ["limit"]}, {"request_id": "x", "at": 0})
    assert ans["accepted"] is False and ans["gap"] == "unreadable" and not rec.effects


def test_KRK_M192_a_translator_that_refuses_the_shape_is_not_credited_with_converting():
    class RefusesAmounts(toys.ToyTranslation):
        calls = 0

        def translate(self, raw, ask):
            self.calls += 1
            o = fmt.read_authority(raw, self.ctx["a_keys"])
            if self.calls > 1 and "max_amount" in o["constraints"]:
                self._received = raw
                return {"translated": None, "refusal": "refuses every original with an amount"}
            return super().translate(raw, ask)
    r = run(RefusesAmounts("good", None, "T"))
    assert reading(r, "currency/face_value")["reading"] == "collateral_refusal"
    assert r.status is Status.INCONCLUSIVE and "currency/face_value" in r.summary


def test_KRK_M193_the_kits_image_is_its_own():
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(tr))
    imported = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            assert n.level == 0, "translation.py imports nothing from the kit"
            imported.add(n.module.split(".")[0])
        elif isinstance(n, ast.Import):
            imported |= {a.name.split(".")[0] for a in n.names}
    assert imported <= {"__future__", "hashlib", "json", "math", "re", "dataclasses",
                        "fractions", "typing"}
    pair = {"source": {"currency": "EUR", "minor_units": 2},
            "target": {"currency": "USD", "minor_units": 2}, "rate": {"num": 108, "den": 100}}
    assert tr.convert({"value": "1007", **pair["source"]}, pair, bound="max")["value"] == 1087


def test_KRK_M194_a_profile_that_moves_during_the_run_gives_no_verdict():
    class Moves(toys.ToyTranslation):
        reads = 0

        def translation_profile(self):
            self.reads += 1
            p = super().translation_profile()
            if self.reads > 1:
                p["profile"]["amounts"][1]["rate"]["num"] = 120
            return p
    r = run(Moves("good", None, "T"))
    assert r.status is Status.INCONCLUSIVE and "changed during the run" in r.summary


def test_KRK_M195_minor_units_come_from_the_profile_never_a_table():
    pair = {"source": {"currency": "JPY", "minor_units": 2},
            "target": {"currency": "USD", "minor_units": 2}, "rate": {"num": 1, "den": 150}}
    assert tr.convert({"value": "15000", "currency": "JPY", "minor_units": 2}, pair,
                      bound="max")["value"] == 100        # JPY with two, because it says so
    got = tr.convert({"value": "150", "currency": "JPY", "minor_units": 0}, pair, bound="max")
    assert isinstance(got, tr.Refusal) and got.reason == tr.INCOMPARABLE
    tables = [k for k, v in vars(tr).items() if isinstance(v, dict) and v
              and all(isinstance(x, str) and len(x) == 3 and x.isupper() for x in v)]
    assert tables == []


def test_KRK_M196_a_draw_that_cannot_separate_the_weak_check_does_not_run():
    class OneToOne(toys.ToyTranslation):
        def translation_profile(self):
            p = super().translation_profile()
            p["profile"]["amounts"] = [p["profile"]["amounts"][0]]
            return p
    r = run(OneToOne("good", None, "T"))
    d = reading(r, "currency/face_value")
    assert d["reading"] == "not_applicable" and "KRK-M196" in d["detail"]
    # face_value reads not_applicable with the probe's reason and
    # counts as present, so the result is a verdict; before, the result read inconclusive.
    assert r.status is Status.PASS and "currency/face_value" in r.extra["not_applicable_by_profile"]
    for topo in ("R", "TR"):
        r = run(T(topo=topo))
        assert not [f for v, fr in r.extra["forms"].items() for f, x in fr.items()
                    if x["reading"] == "draw_failed"]


def test_KRK_M197_a_member_without_documented_semantics_is_a_gap():
    class Unquoted(toys.ToyTranslation):
        def translated_profile(self):
            s = super().translated_profile()
            s["limit"].pop("quote")
            return s
    r = run(Unquoted("good", None, "T"))
    assert r.status is Status.INCONCLUSIVE and "not quoted" in r.summary
    rec = ts.Recorder()
    rp = ts.FaithfulReceiver(toys.TOY_PROFILE, {"exp": toys.TOY_SEMANTICS["exp"]}, rec,
                             receiver="r")
    ans = rp.enact({"members": {"exp": 10, "limit": {"value": 1, "currency": "USD",
                                                       "minor_units": 2}}, "unreadable": []},
                   {"request_id": "x", "at": 0})
    assert ans["accepted"] is False and ans["gap"] == "no_semantics" and not rec.effects


def test_KRK_M198_a_dropped_constraint_is_the_reading_not_a_format_gap_of_the_test():
    r = run(T("bad", "translate_what_maps"))
    d = reading(r, "dropped_constraint/no_counterpart")
    assert d["reading"] == "outside_effect" and d["dimension"] == ["categories"]
    assert reading(run(T()), "dropped_constraint/no_counterpart")["ok"] is True


def test_KRK_M199_presentations_never_share_a_cache_except_in_cached_image():
    r = run(T("bad", "cache_by_subject"))
    failing = sorted(f"{v}/{f}" for v, fr in r.extra["forms"].items() for f, d in fr.items()
                     if d["ok"] is False)
    assert failing == ["retranslation/cached_image"]
    for seed in (1, 99):                      # 99 was the seed that hid it before the fix
        assert reading(run(T("bad", "cache_by_subject", "TR"), seed=seed),
                       "retranslation/cached_image")["ok"] is False


def test_KRK_M200_effects_are_compared_in_the_originals_own_terms():
    rec = ts.Recorder()
    rec.commit({"request_id": "q", "amount": {"value": 1901, "currency": "JPY",
                                              "minor_units": 0}}, by="t")
    e = rec.for_request("q")[0]
    assert e["amount"] == {"value": 1901, "currency": "JPY", "minor_units": 0}
    o = {"constraints": {"max_amount": {"value": "1001", "currency": "GBP", "minor_units": 2}}}
    assert tr.effect_outside(e, o, toys.TOY_PROFILE) == []
    usd = {**e, "amount": {"value": 1001, "currency": "USD", "minor_units": 2}}
    assert tr.effect_outside(usd, o, toys.TOY_PROFILE) == ["currency"]
    same_number = {**e, "amount": {"value": 1001, "currency": "GBP", "minor_units": 2}}
    assert tr.effect_outside(same_number, o, toys.TOY_PROFILE) == ["currency"]


def test_KRK_M201_a_translator_alone_is_never_reported_end_to_end():
    r = run(T())
    assert r.status is Status.PASS and r.extra["evidence_grade"] == "translated-signed"
    assert "not end to end" in r.summary and "faithful receiver" in r.summary
    assert "not end to end" not in run(T(topo="TR")).summary


def test_KRK_M202_a_receiver_that_never_sees_the_original_is_not_graded_on_it():
    class Blind(toys.ToyTranslation):
        def original_visible(self):
            return None
    r = run(Blind("good", None, "R"))
    d = reading(r, "two_forms/amount")
    assert d["reading"] == "not_landed" and "KRK-M202" in d["detail"]
    assert r.status is Status.INCONCLUSIVE


def test_KRK_M203_absence_means_what_the_target_documents():
    class Silent(toys.ToyTranslation):
        def translated_profile(self):
            s = super().translated_profile()
            s["paths"].pop("absent")
            return s
    r = run(Silent("good", None, "T"))
    assert r.status is Status.INCONCLUSIVE and "absence" in r.summary
    rec = ts.Recorder()
    sem = {"paths": {"semantics": "enforced", "absent": "nothing", "quote": "q"}}
    rp = ts.FaithfulReceiver(toys.TOY_PROFILE, sem, rec, receiver="r")
    ans = rp.enact({"members": {}, "unreadable": []},
                   {"request_id": "x", "at": 0, "resource": "a/b"})
    assert ans["accepted"] is False and not rec.effects


def test_KRK_M204_a_round_trip_is_judged_against_the_first_original():
    r = run(T("bad", "round_trip_drift"))
    d = reading(r, "retranslation/round_trip")
    assert d["reading"] == "outside_effect" and d["dimension"] == ["max_amount"]
    assert reading(run(T()), "retranslation/round_trip")["ok"] is True
    o = {"constraints": {"max_amount": {"value": "1001", "currency": "EUR", "minor_units": 2}}}
    assert tr.source_effect_outside({"amount": {"value": 1100, "currency": "EUR",
                                                "minor_units": 2}}, o) == ["max_amount"]


def test_KRK_M205_time_carries_its_unit():
    assert tr.convert_time(1_900_000_123_456, "ms", "s", bound="end") == 1_900_000_123
    assert tr.convert_time(1_900_000_123, "s", "ms", bound="end") == 1_900_000_123_000
    assert reading(run(T("bad", "seconds_as_ms")), "units/time_units")["ok"] is False
    assert reading(run(T()), "units/time_units")["ok"] is True


def test_KRK_M206_the_rate_is_applied_in_the_profiles_direction():
    pair = toys.TOY_PROFILE["amounts"][2]                     # CHF -> USD at 7/10
    assert tr.convert({"value": "1000", "currency": "CHF", "minor_units": 2}, pair,
                      bound="max")["value"] == 700
    assert reading(run(T("bad", "rate_backwards")), "currency/rate_inverted")["ok"] is False
    assert reading(run(T()), "currency/rate_inverted")["ok"] is True


def test_KRK_M207_rounding_forms_need_a_receiver_that_resolves_the_residue():
    class Coarse(toys.ToyTranslation):
        def translated_profile(self):
            s = super().translated_profile()
            s["limit"]["resolution"] = 0
            return s
    r = run(Coarse("good", None, "T"))
    for form in ("rounding/max_up", "rounding/float_rate"):
        d = reading(r, form)
        assert d["reading"] == "not_applicable" and "KRK-M207" in d["detail"]


def test_KRK_M208_a_served_rate_is_not_read_as_the_profiles():
    class Served(toys.ToyTranslation):
        def rate_source(self):
            return "https://rates.example/sheet"
    r = run(Served("good", None, "T"))
    d = reading(r, "currency/face_value")
    assert d["reading"] == "not_landed" and "KRK-M194, M208" in d["detail"]
    assert reading(r, "rounding/max_up")["reading"] == "not_landed"
    assert r.status is Status.INCONCLUSIVE

    class ServedUnclaimed(Served):
        def not_claimed(self):
            return {"P26": {"currency/*": "plan: no claim", "rounding/*": "plan: no claim"}}
    assert run(ServedUnclaimed("good", None, "T")).status is Status.PASS


def test_KRK_M209_originals_are_signed_once_and_never_changed(monkeypatch):
    issued = []

    class Recording(ts.StandInA):
        def issue(self, claims):
            raw = super().issue(claims)
            issued.append((copy.deepcopy(claims), raw))
            return raw
    monkeypatch.setattr(ts, "StandInA", Recording)
    received = []

    class Keeps(toys.ToyTranslation):
        def translate(self, raw, ask):
            received.append(raw)
            return super().translate(raw, ask)
    r = run(Keeps("good", None, "T"))
    assert r.status is Status.PASS
    raws = [raw for _c, raw in issued]
    ids = [_payload(raw)["authority_id"] for raw in raws]
    assert len(ids) == len(set(ids))                    # each original signed once
    digests = {hashlib.sha256(x).hexdigest() for x in raws}
    assert all(hashlib.sha256(x).hexdigest() in digests for x in received)
    assert r.extra["originals_issued"] == len(raws)
