"""P26 (KRK-26, the ceiling survives translation): the image module against hand-written vectors,
and the probe against its known-bad toys in all three topologies (X11 design §4.5, §6.5)."""
import ast
import copy
import json
import math
from fractions import Fraction
from pathlib import Path

import pytest

from conformance import knownbad, translation as tr, versions
from conformance.evidence import Evidence
from conformance.properties import ALL, p26_translation as p26
from conformance.result import Status
from known_bad import translation_toys as toys

ROOT = Path(__file__).resolve().parent.parent
V = json.loads((ROOT / "tests" / "vectors" / "krk26" / "vectors.json").read_text())
SEM = V["semantics"]
PROFILE = V["profile"]


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def run(config, seed=3, trials="dev", adapter=None):
    a = adapter or toys.toy(config)
    a.start()
    try:
        return p26.probe(a, Evidence("t", a.name, "P26", config.replace(":", "-")),
                         run_tag="t", seed=seed, plan={"trials": trials})
    finally:
        a.stop()


def failing(r):
    return sorted(f"{v}/{f}" for v, fr in (r.extra.get("forms") or {}).items()
                  for f, d in fr.items() if d["ok"] is False)


def reading(r, form):
    v, f = form.split("/")
    return r.extra["forms"][v][f]


# --------------------------------------------------------------------------- vectors


def _q(s):
    n, _, d = str(s).partition("/")
    return Fraction(int(n), int(d or 1))


@pytest.mark.parametrize("vec", V["convert"], ids=lambda v: f"{v['pair']}-{v['value']}")
def test_convert_floors_a_maximum_and_ceils_a_minimum(vec):
    pair = V["pairs"][vec["pair"]]
    a = {"value": vec["value"], **pair["source"]}
    assert tr.convert(a, pair, bound="max")["value"] == vec["max"]
    assert tr.convert(a, pair, bound="min")["value"] == vec["min"]
    assert tr.convert(a, pair, bound="max")["currency"] == pair["target"]["currency"]
    if "double_floor" in vec:   # the trap the vector exists for: the kit never takes this value
        r = pair["rate"]
        approx = math.floor(float(int(vec["value"])) * (float(r["num"]) / float(r["den"])))
        assert approx == vec["double_floor"]


@pytest.mark.parametrize("vec", V["refuse"], ids=lambda v: v["reason"] + v["amount"]["currency"])
def test_convert_refuses_without_a_declared_pair_or_in_other_units(vec):
    got = tr.convert(vec["amount"], V["pairs"].get(vec["pair"] or ""), bound="max")
    assert isinstance(got, tr.Refusal) and got.reason == vec["reason"]


@pytest.mark.parametrize("vec", V["back"], ids=lambda v: f"{v['pair']}-{v['target_value']}")
def test_back_is_exact_and_convert_back_rounds_toward_the_bound(vec):
    pair = V["pairs"][vec["pair"]]
    a = {"value": vec["target_value"], **pair["target"]}
    assert tr.back_value(a, pair) == _q(vec["exact"])
    assert tr.convert_back(a, pair, bound="max")["value"] == vec["max"]
    assert tr.convert_back(a, pair, bound="min")["value"] == vec["min"]


@pytest.mark.parametrize("vec", V["direction"], ids=lambda v: v["pair"])
def test_the_rate_has_a_direction(vec):
    pair = V["pairs"][vec["pair"]]
    a = {"value": vec["value"], **pair["source"]}
    assert tr.convert(a, pair, bound="max")["value"] == vec["forward_max"]
    inverted = {**pair, "rate": {"num": pair["rate"]["den"], "den": pair["rate"]["num"]}}
    assert tr.convert(a, inverted, bound="max")["value"] == vec["backwards_max"]


@pytest.mark.parametrize("vec", V["time"], ids=lambda v: f"{v['n']}{v['from']}{v['to']}")
def test_time_ends_round_earlier_and_starts_later(vec):
    assert tr.convert_time(vec["n"], vec["from"], vec["to"], bound="end") == vec["end"]
    assert tr.convert_time(vec["n"], vec["from"], vec["to"], bound="start") == vec["start"]


@pytest.mark.parametrize("vec", V["image"], ids=lambda v: v["name"])
def test_image(vec):
    assert tr.image(vec["original"], PROFILE, SEM) == vec["expect"]


@pytest.mark.parametrize("vec", V["image_refused"], ids=lambda v: v["name"])
def test_image_refuses(vec):
    got = tr.image(vec["original"], PROFILE, SEM)
    assert isinstance(got, tr.Refusal) and got.reason == vec["reason"], got


@pytest.mark.parametrize("vec", V["no_wider"], ids=lambda v: json.dumps(v["translated"])[:40])
def test_no_wider(vec):
    assert tr.no_wider(vec["translated"], vec["original"], PROFILE, SEM) == vec["wider"]


@pytest.mark.parametrize("vec", V["effect_outside"], ids=lambda v: json.dumps(v["effect"])[:50])
def test_effect_outside(vec):
    assert tr.effect_outside(vec["effect"], vec["original"], PROFILE,
                             tolerance=vec.get("tolerance", 0)) == vec["outside"]


@pytest.mark.parametrize("vec", V["source_effect_outside"], ids=lambda v: str(v["outside"]))
def test_source_effect_outside(vec):
    assert tr.source_effect_outside(vec["effect"], vec["original"]) == vec["outside"]


def test_the_image_never_admits_more_than_the_original():
    for vec in V["image"]:
        img = tr.image(vec["original"], PROFILE, SEM)
        assert tr.no_wider(img, vec["original"], PROFILE, SEM) == [], vec["name"]


def test_profile_shape_and_digest():
    assert tr.profile_problem(PROFILE) is None
    assert tr.profile_problem(toys.TOY_PROFILE) is None
    d = tr.profile_digest(PROFILE)
    reordered = json.loads(json.dumps(PROFILE, sort_keys=True))
    assert tr.profile_digest(reordered) == d
    moved = json.loads(json.dumps(PROFILE))
    moved["amounts"][0]["rate"]["num"] = 109
    assert tr.profile_digest(moved) != d
    bad = json.loads(json.dumps(PROFILE))
    bad["amounts"].append(bad["amounts"][0])
    assert "twice" in tr.profile_problem(bad)
    with pytest.raises(TypeError):
        tr.profile_digest({**PROFILE, "x": 1.5})
    assert tr.profile_problem({**PROFILE, "unmapped": "nearest"})


def test_translation_imports_only_the_standard_library():
    """KRK-M193: the kit's image shares nothing with a target, a policy library or the kit."""
    tree = ast.parse((ROOT / "conformance" / "translation.py").read_text())
    mods = {n.names[0].name.split(".")[0] if isinstance(n, ast.Import) else (n.module or "")
            for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))}
    assert mods <= {"__future__", "hashlib", "json", "math", "re", "dataclasses", "fractions",
                    "typing"}, mods
    assert not any(isinstance(n, ast.Constant) and isinstance(n.value, float)
                   for n in ast.walk(tree))
    assert "float(" not in (ROOT / "conformance" / "translation.py").read_text()


def test_the_toys_correct_path_has_no_float():
    """The only floating point in the toys is the float_convert flaw itself."""
    src = (ROOT / "known_bad" / "translation_toys.py").read_text()
    lines = [ln for ln in src.splitlines() if "float(" in ln]
    assert lines and all("float(" in ln and ("r[\"num\"]" in ln or "float(v)" in ln)
                         for ln in lines), lines
    body = src[src.index("def _amount"):src.index("def _translate")]
    flawed = body[body.index('elif f == "float_convert"'):body.index("else:\n            scale")]
    assert "float(" not in body.replace(flawed, "")


# --------------------------------------------------------------------------- registration


def test_p26_is_registered_and_hashes_its_own_files():
    assert "P26" in ALL and ALL["P26"] is p26
    probe = versions.probe_files("P26")
    assert "conformance/translation.py" in probe and "conformance/translator_stub.py" in probe
    assert "conformance/translation_formats.py" in probe
    assert not [f for f in probe if f.startswith("known_bad/")]
    fix = versions.fixture_files("P26")
    assert fix == ["known_bad/translation_toys.py", "tests/test_p26_translation.py",
                   "tests/vectors/krk26/vectors.json"]


def test_no_other_probe_imports_the_new_modules():
    new = {"conformance/translation.py", "conformance/translator_stub.py",
           "conformance/translation_formats.py", "conformance/properties/p26_translation.py"}
    from conformance.properties import ALL_BISSUER
    for pid in [p for p in ALL if p != "P26"] + list(ALL_BISSUER):
        assert not new & set(versions.probe_files(pid)), pid


def test_the_gate_cases_are_the_toy_cases():
    assert [(c, s.value) for c, s in knownbad.cases("P26")] == toys.cases()
    names = [c for c, _ in toys.cases()]
    assert len(names) == len(set(names)) == 73
    for t in toys.TOPOLOGIES:
        assert {f"good@{t}", f"good-strict@{t}", f"no-control@{t}"} <= set(names)


def test_toy_topologies_follow_the_probe():
    for flaw, variant in toys.FLAWS.items():
        assert set(toys.VARIANT_TOPOLOGIES[variant]) == \
            {t for t, vs in p26.TOPOLOGY_VARIANTS.items() if variant in vs}
        assert variant in p26.VARIANTS
    assert set(toys.FLAWS.values()) == set(p26.VARIANTS)


# --------------------------------------------------------------------------- the toys

BUILT_FOR = {
    "face_value": ["currency/face_value"], "built_in_rate": ["currency/rate_undeclared"],
    "rate_backwards": ["currency/rate_inverted"], "asset_unchecked": ["currency/asset_substituted"],
    "two_minor_units": ["units/minor_units"], "six_decimals": ["units/token_decimals"],
    "seconds_as_ms": ["units/time_units"], "unit_name_ignored": ["units/count_unit"],
    "round_nearest": ["rounding/max_up", "rounding/min_down"],
    "float_convert": ["rounding/float_rate"],
    "translate_what_maps": ["dropped_constraint/no_counterpart"],
    "advisory_ok": ["dropped_constraint/advisory_target"],
    "crit_ignored": ["dropped_constraint/critical_lost"],
    "skips_member": ["dropped_constraint/subset_translated"],
    "copy_unmapped": ["unmappable/unmapped_value"], "widest_image": ["unmappable/many_to_one"],
    "lexical_match": ["unmappable/heuristic_match"], "default_fill": ["partial/local_default"],
    "fallback_on_error": ["partial/error_fallback"],
    "default_lifetime": ["window/outlives_original"],
    "ttl_from_issue": ["window/relative_from_issue"], "valid_from_zero": ["window/starts_early"],
    "grants_requested": ["scope/operation_added"], "audience_from_config": ["scope/audience_added"],
    "prefix_widened": ["scope/resource_broader"], "round_trip_drift": ["retranslation/round_trip"],
    "stage_rounds_up": ["retranslation/staged"], "cache_by_subject": ["retranslation/cached_image"],
    "translated_only": ["two_forms/amount", "two_forms/payee", "two_forms/window",
                        "two_forms/unbound_pair"],
    "binding_only": ["two_forms/amount", "two_forms/payee", "two_forms/window"],
}
"""§3.1's toy column: the forms each flaw is built to fail."""

FAILS = {
    'bad:advisory_ok@T': (['dropped_constraint/advisory_target'],
        []),
    'bad:advisory_ok@TR': (['dropped_constraint/advisory_target'],
        []),
    'bad:asset_unchecked@R': (['currency/asset_substituted'],
        []),
    'bad:asset_unchecked@T': (['currency/asset_substituted'],
        []),
    'bad:asset_unchecked@TR': (['currency/asset_substituted'],
        []),
    'bad:audience_from_config@T': (['partial/local_default', 'scope/audience_added'],
        []),
    'bad:audience_from_config@TR': (['partial/local_default', 'scope/audience_added'],
        []),
    'bad:binding_only@R': (['currency/asset_substituted', 'currency/face_value', 'currency/rate_inverted', 'currency/rate_undeclared', 'two_forms/amount', 'two_forms/payee', 'two_forms/window', 'window/outlives_original', 'window/relative_from_issue', 'window/starts_early'],
        []),
    'bad:built_in_rate@R': (['currency/rate_undeclared'],
        []),
    'bad:built_in_rate@T': (['currency/rate_undeclared'],
        []),
    'bad:built_in_rate@TR': (['currency/rate_undeclared'],
        []),
    'bad:cache_by_subject@T': (['retranslation/cached_image'],
        []),
    'bad:cache_by_subject@TR': (['retranslation/cached_image'],
        []),
    'bad:copy_unmapped@T': (['unmappable/heuristic_match', 'unmappable/unmapped_value'],
        []),
    'bad:copy_unmapped@TR': (['unmappable/unmapped_value'],
        []),
    'bad:crit_ignored@T': (['dropped_constraint/advisory_target', 'dropped_constraint/critical_lost', 'dropped_constraint/no_counterpart'],
        []),
    'bad:crit_ignored@TR': (['dropped_constraint/advisory_target', 'dropped_constraint/critical_lost', 'dropped_constraint/no_counterpart'],
        []),
    'bad:default_fill@T': (['partial/local_default', 'scope/audience_added'],
        []),
    'bad:default_fill@TR': (['partial/local_default', 'scope/audience_added'],
        []),
    'bad:default_lifetime@R': (['two_forms/window', 'window/outlives_original', 'window/relative_from_issue'],
        []),
    'bad:default_lifetime@T': (['units/time_units', 'window/outlives_original'],
        []),
    'bad:default_lifetime@TR': (['units/time_units', 'window/outlives_original', 'window/relative_from_issue'],
        []),
    'bad:face_value@R': (['currency/face_value'],
        []),
    'bad:face_value@T': (['currency/face_value', 'currency/rate_inverted', 'rounding/float_rate', 'rounding/min_down', 'units/minor_units', 'units/token_decimals'],
        []),
    'bad:face_value@TR': (['currency/face_value', 'rounding/float_rate', 'rounding/min_down', 'units/token_decimals'],
        []),
    'bad:fallback_on_error@T': (['partial/error_fallback'],
        []),
    'bad:fallback_on_error@TR': (['partial/error_fallback'],
        []),
    'bad:float_convert@T': (['rounding/float_rate'],
        []),
    'bad:float_convert@TR': (['rounding/float_rate'],
        []),
    'bad:grants_requested@T': (['scope/operation_added'],
        []),
    'bad:grants_requested@TR': (['scope/operation_added', 'unmappable/many_to_one'],
        []),
    'bad:lexical_match@T': (['unmappable/heuristic_match'],
        []),
    'bad:lexical_match@TR': (['unmappable/heuristic_match'],
        []),
    'bad:prefix_widened@T': (['dropped_constraint/subset_translated', 'scope/resource_broader'],
        []),
    'bad:prefix_widened@TR': (['scope/resource_broader'],
        []),
    'bad:rate_backwards@R': (['currency/face_value', 'currency/rate_inverted'],
        []),
    'bad:rate_backwards@T': (['currency/face_value', 'currency/rate_inverted', 'rounding/float_rate', 'rounding/min_down'],
        []),
    'bad:rate_backwards@TR': (['currency/face_value', 'currency/rate_inverted', 'rounding/float_rate', 'rounding/min_down'],
        []),
    'bad:round_nearest@T': (['rounding/float_rate', 'rounding/max_up', 'rounding/min_down'],
        ['currency/face_value', 'currency/rate_inverted', 'units/minor_units', 'units/token_decimals']),
    'bad:round_nearest@TR': (['rounding/float_rate', 'rounding/max_up', 'rounding/min_down'],
        []),
    'bad:round_trip_drift@T': (['retranslation/round_trip'],
        []),
    'bad:seconds_as_ms@T': (['units/time_units'],
        []),
    'bad:seconds_as_ms@TR': (['units/time_units'],
        []),
    'bad:six_decimals@T': (['units/token_decimals'],
        []),
    'bad:six_decimals@TR': (['units/token_decimals'],
        []),
    'bad:skips_member@T': (['dropped_constraint/subset_translated', 'scope/resource_broader'],
        []),
    'bad:skips_member@TR': (['dropped_constraint/subset_translated', 'scope/resource_broader'],
        []),
    'bad:stage_rounds_up@T': (['currency/rate_inverted', 'retranslation/staged', 'rounding/float_rate', 'rounding/max_up', 'units/minor_units', 'units/token_decimals'],
        ['currency/face_value']),
    'bad:stage_rounds_up@TR': (['retranslation/staged', 'rounding/float_rate', 'rounding/max_up'],
        []),
    'bad:translate_what_maps@T': (['dropped_constraint/advisory_target', 'dropped_constraint/critical_lost', 'dropped_constraint/no_counterpart'],
        []),
    'bad:translate_what_maps@TR': (['dropped_constraint/advisory_target', 'dropped_constraint/critical_lost', 'dropped_constraint/no_counterpart'],
        []),
    'bad:translated_only@R': (['currency/asset_substituted', 'currency/face_value', 'currency/rate_inverted', 'currency/rate_undeclared', 'two_forms/amount', 'two_forms/payee', 'two_forms/unbound_pair', 'two_forms/window', 'window/outlives_original', 'window/relative_from_issue', 'window/starts_early'],
        []),
    'bad:ttl_from_issue@R': (['two_forms/window', 'window/outlives_original', 'window/relative_from_issue'],
        []),
    'bad:ttl_from_issue@T': (['units/time_units', 'window/outlives_original', 'window/relative_from_issue'],
        []),
    'bad:ttl_from_issue@TR': (['units/time_units', 'window/outlives_original', 'window/relative_from_issue'],
        []),
    'bad:two_minor_units@T': (['units/minor_units', 'units/token_decimals'],
        []),
    'bad:two_minor_units@TR': (['units/minor_units', 'units/token_decimals'],
        []),
    'bad:unit_name_ignored@T': (['units/count_unit'],
        []),
    'bad:unit_name_ignored@TR': (['units/count_unit'],
        []),
    'bad:valid_from_zero@R': (['window/starts_early'],
        []),
    'bad:valid_from_zero@T': (['window/starts_early'],
        []),
    'bad:valid_from_zero@TR': (['window/starts_early'],
        []),
    'bad:widest_image@T': (['unmappable/many_to_one'],
        []),
    'bad:widest_image@TR': (['unmappable/many_to_one'],
        []),
}
"""Every flaw's failing forms, as observed under 33 seed and count combinations (seeds 1 to 30 at development counts, 2, 5 and
11 at published counts): the first list
fails every time, the second only when the draw allows (X3 §13 item 7: a flaw can fail more
than its own form). Where a flaw fails another form, it is a widening the flaw really causes
there: a number copied across a rate below 1, a stage that rounds every residue up."""


def test_every_flaw_is_built_to_fail_its_forms_in_every_topology_it_runs():
    assert set(BUILT_FOR) == set(toys.FLAWS)
    for cfg, (always, _extra) in FAILS.items():
        flaw, topo = cfg[4:].split("@")
        built = [f for f in BUILT_FOR[flaw] if f.split("/")[0] in p26.TOPOLOGY_VARIANTS[topo]]
        assert built and set(built) <= set(always), cfg
    assert set(FAILS) == {c for c, _ in toys.cases() if c.startswith("bad:")}


@pytest.mark.parametrize("config,required", toys.cases())
def test_each_toy_gives_its_required_outcome(config, required):
    r = run(config, seed=3)
    assert r.status.value == required, (r.summary, failing(r))
    if r.status in (Status.PASS, Status.FAIL):
        assert r.control_held is True
    if config.startswith("bad:"):
        always, extra = FAILS[config]
        got = set(failing(r))
        assert set(always) <= got <= set(always) | set(extra), (config, sorted(got))


@pytest.mark.parametrize("seed", [1, 99])
def test_the_failing_sets_hold_under_other_seeds(seed):
    for config, required in toys.cases():
        if not config.startswith("bad:"):
            continue
        r = run(config, seed=seed)
        always, extra = FAILS[config]
        assert set(always) <= set(failing(r)) <= set(always) | set(extra), (seed, config)


@pytest.mark.parametrize("topo", toys.TOPOLOGIES)
@pytest.mark.parametrize("base", ["good", "good-strict"])
def test_the_correct_toys_pass_at_published_counts(base, topo):
    r = run(f"{base}@{topo}", seed=5, trials="published")
    assert r.status is Status.PASS, r.summary
    held = [f"{v}/{f}" for v, fr in r.extra["forms"].items() for f, d in fr.items() if d["ok"]]
    assert held
    for v, fr in r.extra["forms"].items():
        for f, d in fr.items():
            assert d["ok"] is not False
            if d["ok"] is True:
                assert d["trials"] == 5


def test_good_strict_refuses_what_needs_a_rate_or_rounding():
    r = run("good-strict@T", seed=4)
    assert reading(r, "rounding/max_up")["reading"] == "collateral_refusal"
    assert reading(r, "currency/face_value")["ok"] is True
    assert "refused" in r.extra["modes"].get("currency", [])


def test_the_correct_toy_converts_through_the_declared_rate():
    r = run("good@T", seed=4)
    assert reading(r, "currency/rate_inverted")["ok"] is True
    assert "exact" in r.extra["modes"]["currency"]
    assert reading(r, "units/count_unit")["ok"] is True


@pytest.mark.parametrize("topo", toys.TOPOLOGIES)
def test_no_control_gives_no_verdict(topo):
    r = run(f"no-control@{topo}")
    assert r.status is Status.INCONCLUSIVE and r.control_held is False


def test_round_trip_is_not_applicable_in_tr_with_the_targets_reason():
    r = run("good@TR")
    d = reading(r, "retranslation/round_trip")
    assert d["reading"] == "not_applicable" and "reverse direction" in d["detail"]


def test_grades_and_topology_in_the_result():
    for topo, grade in (("T", "translated-signed"), ("R", "recorder"), ("TR", "recorder")):
        r = run(f"good@{topo}")
        assert r.extra["topology"] == topo and r.extra["evidence_grade"] == grade
        assert r.extra["profile_digest"] == tr.profile_digest(toys.TOY_PROFILE)
    assert set(run("good@R").extra["forms"]) == {"currency", "window", "two_forms"}
    assert "two_forms" not in run("good@T").extra["forms"]


def test_dimensions_the_format_cannot_carry_are_listed():
    r = run("good@T")
    assert r.extra["dimensions_not_carried"] == ["categories", "channels", "regions"]
    assert "cannot carry: categories, channels, regions" in r.summary


def test_disclosure_class_is_conformance_unless_the_target_documents_preservation():
    r = run("bad:face_value@T")
    assert r.extra["disclosure"] == "conformance"

    class Documents(toys.ToyTranslation):
        def documents_preserving(self):
            return True
    r = run("x", adapter=Documents("bad", "face_value", "T"))
    assert r.status is Status.FAIL and r.extra["disclosure"] == "vulnerability"
    assert r.extra["disclosure_forms"]["currency/face_value"]["class"] == "vulnerability"


def test_a_documented_widening_is_information_not_a_fail():
    class Documented(toys.ToyTranslation):
        def documented_widenings(self):
            return {"currency/rate_undeclared": "\"uses a built-in table when no rate is set\""}
    r = run("x", adapter=Documented("bad", "built_in_rate", "T"))
    d = reading(r, "currency/rate_undeclared")
    assert d["reading"] == "documented_widening" and d["ok"] is None
    assert r.status is Status.INCONCLUSIVE        # NA_FORBIDDEN form without a reading


def test_a_not_claimed_must_land_form_counts_as_present():
    """A form in NA_FORBIDDEN that the adapter states not claimed does not make the
    result inconclusive; the runner's claim-basis rule then judges the claimed forms."""
    class Unclaimed(toys.ToyTranslation):
        def documented_widenings(self):
            return {"currency/rate_undeclared": "\"uses a built-in table\""}

        def not_claimed(self):
            return {"P26": {"currency/rate_undeclared": "plan row: no claim found"}}
    r = run("x", adapter=Unclaimed("bad", "built_in_rate", "T"))
    assert r.status is Status.PASS, r.summary


def test_w_and_l_subjects_are_fresh_except_in_cached_image():
    """KRK-M199: W and L never share a subject, a session or an original; W-in reuses W's own
    original and translation (§4.1). In cached_image the wider O1 and W share one subject, which
    is the fixture. Read from the probe's own evidence (topology TR, where every presentation
    carries its original)."""
    from conformance import evidence
    r = run("good@TR")
    d = evidence.ROOT / r.evidence_dir
    seen = {}
    for path in d.glob("*-*.json"):
        doc = json.loads(path.read_text())
        if "trials" not in doc:
            continue
        for t in doc["trials"]:
            subs = []
            for which in ("first", "W", "L", "W-in"):
                p = t["presentations"].get(which) or {}
                raw = p.get("original_bytes")
                if raw:
                    import base64
                    body = raw.split(".")[1]
                    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
                    subs.append((which, claims["subject"]))
            seen[(doc["form"], t["k"])] = subs
    assert seen
    for (form, _k), subs in seen.items():
        got = dict(subs)
        if "W" in got and "L" in got:
            assert got["W"] != got["L"], (form, subs)
        if "W-in" in got:
            assert got["W-in"] == got["W"], (form, subs)
        if form == "retranslation/cached_image":
            assert got["first"] == got["W"] != got["L"]


def test_the_probe_presents_raw_bytes_and_keeps_them():
    """KRK-M37's rule here: what the target received equals what A sent, byte for byte."""
    class Rewrites(toys.ToyTranslation):
        def received(self):
            raw = super().received()
            return raw + b" " if raw else raw
    r = run("x", adapter=Rewrites("good", None, "T"))
    assert r.status is Status.INCONCLUSIVE and "differs from what A sent" in r.summary


# --------------------------------------------------------------------------- no separating pair; the control's operation

ONE_TO_ONE = [toys._pair("USD", 2, "USD", 2, 1, 1), toys._pair("EUR", 2, "USD", 2, 108, 100)]
"""A profile whose pairs cannot separate `face_value` (no rate at or below 4/5) or `minor_units`
(no source currency with more than two minor units)."""


@pytest.mark.parametrize("topo", ["T", "TR"])
def test_face_value_and_minor_units_read_not_applicable_when_no_pair_separates_them(
        topo, monkeypatch):
    monkeypatch.setitem(toys.TOY_PROFILE, "amounts", copy.deepcopy(ONE_TO_ONE))
    r = run(f"good@{topo}", seed=5)
    assert r.status is Status.PASS, r.summary
    for fid in ("currency/face_value", "units/minor_units"):
        d = reading(r, fid)
        assert d["reading"] == "not_applicable" and d["ok"] is None, d
        assert p26.NO_SEPARATING_PAIR in d["info"] and "KRK-M196" in d["detail"]
    assert sorted(r.extra["not_applicable_by_profile"]) == ["currency/face_value",
                                                            "units/minor_units"]
    assert "no declared pair separates them" in r.summary


def test_a_flaw_still_fails_elsewhere_and_the_rule_is_for_these_two_forms_only(monkeypatch):
    monkeypatch.setitem(toys.TOY_PROFILE, "amounts", copy.deepcopy(ONE_TO_ONE))
    r = run("bad:built_in_rate@T", seed=5)
    assert r.status is Status.FAIL and "currency/rate_undeclared" in failing(r)
    assert p26.NA_BY_PROFILE <= set(x for x in p26.NA_FORBIDDEN if isinstance(x, tuple))
    assert p26.NA_BY_PROFILE == {("currency", "face_value"), ("units", "minor_units")}


def test_a_stated_not_applicable_is_still_refused_for_these_forms():
    class Says(toys.ToyTranslation):
        def forms_not_applicable(self):
            return {"currency/face_value": "the adapter says so", "units/minor_units": "so"}
    r = run("x", adapter=Says("good", None, "T"))
    assert reading(r, "currency/face_value")["ok"] is True
    assert reading(r, "units/minor_units")["ok"] is True
    assert r.extra["not_applicable_by_profile"] == []


def test_a_profile_with_no_amount_pair_still_reads_inconclusive(monkeypatch):
    monkeypatch.setitem(toys.TOY_PROFILE, "amounts", [])
    r = run("good@T", seed=5)
    assert r.status is not Status.PASS
    assert r.extra.get("not_applicable_by_profile", []) == []


NO_UNIQUE_OPS = {"contacts:update": ["update"], "contacts:delete": ["delete"],
                 "contacts:write": ["update", "delete"], "contacts:read": ["read"],
                 "contacts:view": ["read"]}
"""Every source operation is realised by two target values, so none is unique."""


@pytest.mark.parametrize("topo,words", [("T", "the target issued"), ("R", "T′ signed"),
                                        ("TR", "shows no translated form")])
def test_with_no_unique_operation_the_control_says_where_it_drew_it(topo, words, monkeypatch):
    monkeypatch.setitem(toys.TOY_PROFILE["values"], "operations", copy.deepcopy(NO_UNIQUE_OPS))
    r = run(f"good@{topo}", seed=5)
    assert r.control_held is True, r.summary
    op = r.extra["control_operation"]
    assert op["unique"] is False and words in op["drawn_from"]
    assert "operation was drawn from" in r.control_detail and \
        "operation was drawn from" in r.summary


def test_with_a_unique_operation_the_control_is_unchanged():
    r = run("good@T", seed=5)
    op = r.extra["control_operation"]
    assert op["unique"] is True and op["operation"] == ["export"]
    assert "operation was drawn from" not in r.summary
