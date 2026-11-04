"""Verdict expiry (spec §3.5): a stamped result is valid only while nothing its
renewal condition lists has changed and it is under 12 months old; a result written before
expiry was recorded reads as unknown, never as valid, and never crashes the reader."""
import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest

from conformance import knownbad, runner, validity, versions
from conformance.result import Result, Status
from conformance.validity import (LAPSED, NO_VERDICT, UNKNOWN, VALID, add_months, still_valid,
                                  validity as judge)
from known_bad.receipts_toys import make

RUN_AT = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def _known_bad_store(tmp_path_factory):
    """Real known-bad runs of the two properties the runner tests probe (P16, P5), recorded
    once into a store each test then starts from."""
    base = tmp_path_factory.mktemp("kb")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("conformance.evidence.RESULTS", base)
        for pid in ("P16", "P5"):
            assert knownbad.run_one(pid, seed=1, record=True)["ok"]
    return base / "known-bad" / "records.jsonl"


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch, _known_bad_store):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    (tmp_path / "known-bad").mkdir()
    shutil.copy(_known_bad_store, tmp_path / "known-bad" / "records.jsonl")


KB = {"schema": knownbad.SCHEMA, "record_id": "P16-kb", "recorded_at": "2026-11-01T11:00:00Z",
      "probe_version": "sha256:p", "fixture_version": "sha256:f", "ok": True, "cases": 15}


def _stamped(status=Status.PASS, environment=None):
    r = Result(target="t", property_id="P16", status=status, summary="s",
               control_held=True if status in (Status.PASS, Status.FAIL) else False,
               target_version="t 1.0", config="default")
    measured = {"probe_version": "sha256:p", "fixture_version": "sha256:f",
                "adapter_version": "sha256:a",
                "environment": {"python": "3.12.1"} if environment is None else environment,
                "hashed": {"probe": ["x.py"]}}
    return validity.stamp(r, run_at=RUN_AT, seed=7, measured=measured, known_bad=KB)


CURRENT = dict(target_version="t 1.0", config="default", probe_version="sha256:p",
               fixture_version="sha256:f", adapter_version="sha256:a",
               environment={"python": "3.12.1"})


def _ask(result, now=RUN_AT + timedelta(days=1), **change):
    return judge(result, now=now, **{**CURRENT, **change})


# ------------------------------------------------------------------------------- the record

def test_stamp_records_run_time_limit_seed_and_renewal_condition():
    d = _stamped().to_doc()
    assert d["run_at"] == "2026-11-01T12:00:00Z"
    assert d["valid_until"] == "2027-11-01T12:00:00Z"
    assert d["seed"] == 7
    assert d["renewal"] == {"schema": "kirkaldy.renewal/0.1", "max_age_months": 12,
                            "lapses_on_change": ["target_version", "config", "probe_version",
                                                 "fixture_version", "adapter_version",
                                                 "environment.python"]}
    json.loads(_stamped().to_json())                     # serialisable


def test_add_months_clamps_a_day_the_month_lacks():
    leap = datetime(2028, 2, 29, tzinfo=timezone.utc)
    assert add_months(leap, 12) == datetime(2029, 2, 28, tzinfo=timezone.utc)
    assert add_months(datetime(2026, 1, 31, tzinfo=timezone.utc), 1).day == 28


# ------------------------------------------------------------------------------- valid / lapsed

def test_unchanged_and_young_is_valid():
    ok, why = still_valid(_stamped(), now=RUN_AT + timedelta(days=30), **CURRENT)
    assert ok, why


@pytest.mark.parametrize("field, new", [("target_version", "t 1.1"), ("config", "other"),
                                        ("probe_version", "sha256:p2"),
                                        ("fixture_version", "sha256:f2"),
                                        ("adapter_version", "sha256:a2")])
def test_each_change_lapses_it(field, new):
    v = _ask(_stamped(), **{field: new})
    assert v.state == LAPSED and any(r.startswith(f"{field} changed") for r in v.reasons), v
    ok, why = still_valid(_stamped(), now=RUN_AT + timedelta(days=1), **{**CURRENT, field: new})
    assert not ok and why[0] == LAPSED


def test_a_declared_environment_field_change_lapses_it():
    v = _ask(_stamped(), environment={"python": "3.13.0"})
    assert v.state == LAPSED and "environment.python changed" in v.reasons[0], v


def test_age_lapses_it_at_twelve_months_even_with_nothing_changed():
    r = _stamped()
    assert _ask(r, now=datetime(2027, 11, 1, 11, 59, 59, tzinfo=timezone.utc)).state == VALID
    v = _ask(r, now=datetime(2027, 11, 1, 12, 0, 0, tzinfo=timezone.utc))
    assert v.state == LAPSED and v.reasons[0].startswith("age:"), v


def test_a_record_cannot_extend_its_own_age_limit():
    d = _stamped().to_doc()
    d["valid_until"] = "2030-01-01T00:00:00Z"
    d["renewal"]["max_age_months"] = 60
    v = _ask(d, now=datetime(2027, 12, 1, tzinfo=timezone.utc))
    assert v.state == LAPSED and "valid until 2027-11-01T12:00:00Z" in v.reasons[0], v


def test_an_earlier_valid_until_in_the_record_is_honoured():
    d = _stamped().to_doc()
    d["valid_until"] = "2027-01-01T00:00:00Z"
    assert _ask(d, now=datetime(2027, 2, 1, tzinfo=timezone.utc)).state == LAPSED


def test_lapse_reasons_win_over_unknown_ones():
    v = _ask(_stamped(), target_version="t 2", adapter_version=None)
    assert v.state == LAPSED and any("no current value" in r for r in v.reasons), v


# ------------------------------------------------------------------------------- unknown

def test_a_listed_field_with_no_current_value_is_unknown_not_valid():
    for field in ("target_version", "probe_version", "adapter_version"):
        v = _ask(_stamped(), **{field: None})
        assert v.state == UNKNOWN and v.reasons == [
            f"{field}: no current value given, so a change cannot be ruled out"], v
    v = _ask(_stamped(), environment=None)
    assert v.state == UNKNOWN and "environment.python" in v.reasons[0]


LEGACY = {"target": "my-product", "config": "default", "property_id": "P16",
          "status": "pass", "summary": "s", "control_held": True, "control_detail": "",
          "checks": [], "target_version": "my-product 0.9.0", "vendor_claim": "",
          "evidence_dir": "results/x", "extra": {"seed": 1}}


@pytest.mark.parametrize("doc", [
    LEGACY,
    {**LEGACY, "renewal": {}},
    {**LEGACY, "renewal": None},
    {**LEGACY, "renewal": "lapses on change"},
    {**LEGACY, "renewal": {"lapses_on_change": []}},
    {},
    [],
    "not a record",
    None,
])
def test_results_written_before_expiry_read_as_unknown_and_never_crash(doc):
    ok, why = still_valid(doc, now=RUN_AT, **CURRENT)
    assert ok is False and why[0] == UNKNOWN, why


@pytest.mark.parametrize("change", [
    {"run_at": "yesterday"}, {"run_at": None}, {"run_at": "2026-11-01T12:00:00"},
    {"valid_until": 5}, {"renewal": {"lapses_on_change": ["config", 3], "max_age_months": 12}},
    {"renewal": {"lapses_on_change": ["config"], "max_age_months": "12"}},
    {"renewal": {"lapses_on_change": ["config", "colour"], "max_age_months": 12}},
    {"environment": "py"}, {"target_version": ""},
])
def test_damaged_records_read_as_unknown(change):
    d = {**_stamped().to_doc(), **change}
    v = _ask(d)
    assert v.state == UNKNOWN, v


def test_a_run_in_the_future_is_unknown():
    assert _ask(_stamped(), now=RUN_AT - timedelta(days=1)).state == UNKNOWN


def test_an_inconclusive_result_has_no_verdict_to_keep():
    v = _ask(_stamped(Status.INCONCLUSIVE))
    assert v.state == NO_VERDICT
    assert still_valid(_stamped(Status.INCONCLUSIVE), now=RUN_AT, **CURRENT)[0] is False


def test_now_must_carry_a_zone():
    with pytest.raises(TypeError):
        judge(_stamped(), now=datetime(2027, 1, 1), **CURRENT)


# ------------------------------------------------------------------------------- versions

def test_p16_probe_hash_covers_its_closure_and_not_other_properties():
    files = versions.probe_files("P16")
    assert {"conformance/properties/p16_effect_receipt.py", "conformance/receipts.py",
            "conformance/counterparty.py", "conformance/result.py"} <= set(files)
    assert not [f for f in files if "/properties/p" in f and "p16" not in f]
    assert "conformance/validity.py" not in files        # editing the reader lapses nothing


def test_p16_fixture_hash_covers_toys_outcomes_and_vectors():
    files = versions.fixture_files("P16")
    assert "known_bad/receipts_toys.py" in files and "tests/test_p16_effect_receipt.py" in files
    assert "tests/vectors/krk16/judge.json" in files
    assert versions.fixture_files("P3") == list(versions.DEFAULT_FIXTURES)


def test_adapter_hash_covers_the_whole_target_directory():
    files = versions.adapter_files("targets.toys.adapter")
    assert {"targets/toys/adapter.py", "targets/toys/__init__.py",
            "conformance/knownbad.py"} <= set(files)
    assert versions.adapter_files("known_bad.receipts_toys") == ["conformance/receipts.py",
                                                                  "known_bad/receipts_toys.py"]


def test_digest_moves_when_a_file_changes_is_added_or_renamed(tmp_path, monkeypatch):
    monkeypatch.setattr(versions, "ROOT", tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n")
    d1 = versions.digest(["a.py"])
    (tmp_path / "a.py").write_text("x = 2\n")
    d2 = versions.digest(["a.py"])
    (tmp_path / "b.py").write_text("x = 2\n")
    assert len({d1, d2, versions.digest(["a.py", "b.py"]), versions.digest(["b.py"])}) == 4
    assert versions.digest(["b.py", "a.py"]) == versions.digest(["a.py", "b.py"])


# ------------------------------------------------------------------------------- the runner + CLI

def _run(toy, run_id, seed=None):
    return runner.run_adapter(toy, ["P16"], run_id=run_id, seed=seed)[0]


def test_the_runner_stamps_every_result_and_the_cli_reads_it_valid(tmp_path, capsys):
    r = _run(make(), "cli", seed=11)
    path = tmp_path / "cli" / "toy-effect-receipts@good" / "P16" / "result.json"
    d = json.loads(path.read_text())
    assert d["seed"] == 11 and d["extra"]["seed"] == 11 and d["status"] == "pass"
    assert d["probe_version"].startswith("sha256:") and d["hashed"]["adapter_module"] == \
        "known_bad.receipts_toys"
    assert set(d["environment"]) == {"python", "package:cryptography"}
    assert d["unseeded"] and "secure source" in d["unseeded"][0]
    capsys.readouterr()

    assert runner.main(["validity", str(path), "--target-version", "toy-good"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"valid: {path}")
    assert runner.main(["validity", str(path), "--target-version", "toy-other"]) == 1
    assert "target_version changed" in capsys.readouterr().out
    assert runner.main(["validity", str(path)]) == 3                  # no target version given
    assert "target_version: no current value" in capsys.readouterr().out
    assert runner.main(["validity", str(path), "--target-version", "toy-good",
                        "--now", "2099-01-01T00:00:00Z"]) == 1
    assert runner.main(["validity", str(path), "--target-version", "toy-good",
                        "--probe-version", "sha256:other"]) == 1
    assert runner.main(["validity", str(path), "--target-version", "toy-good",
                        "--config", "bad:accepts_unsigned"]) == 1
    capsys.readouterr()
    assert runner.main(["validity", str(path), "--target-version", "toy-good", "--json"]) == 0
    ans = json.loads(capsys.readouterr().out)
    assert ans[0]["state"] == "valid" and ans[0]["checked"]["adapter_version"]["current"] == \
        d["adapter_version"]


def test_the_cli_sees_a_changed_kit_file(tmp_path, monkeypatch, capsys):
    """A result measured with one probe file, read against a tree where that file differs."""
    _run(make(), "edit", seed=3)
    path = tmp_path / "edit" / "toy-effect-receipts@good" / "P16" / "result.json"
    capsys.readouterr()
    real = versions.digest
    monkeypatch.setattr(versions, "digest", lambda files: real(files) + (
        "-edited" if "conformance/receipts.py" in files else ""))
    assert runner.main(["validity", str(path), "--target-version", "toy-good"]) == 1
    out = capsys.readouterr().out
    assert "probe_version changed" in out and "adapter_version changed" in out
    assert "fixture_version" not in out


def test_the_cli_reads_legacy_unreadable_and_inconclusive_results(tmp_path, capsys):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(LEGACY))
    assert runner.main(["validity", str(legacy), "--target-version", "my-product 0.9.0"]) == 3
    assert "validity unknown" in capsys.readouterr().out
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert runner.main(["validity", str(broken)]) == 3
    assert runner.main(["validity", str(tmp_path / "missing.json")]) == 3
    toy = make()
    toy.submit_raises = True
    r = _run(toy, "inc", seed=1)
    assert r.status is Status.INCONCLUSIVE
    inc = tmp_path / "inc" / "toy-effect-receipts@good" / "P16" / "result.json"
    assert runner.main(["validity", str(inc), "--target-version", "toy-good"]) == 4
    # Several files: the exit code is the worst answer.
    assert runner.main(["validity", str(legacy), str(inc)]) == 4


# ------------------------------------------------------------------------------- --seed

def _comparable(run_dir, run_id):
    """Everything a re-run with the same seed must reproduce: the result less its run time and
    evidence path, and every evidence file less what `UNSEEDED` says stays random (receipts are
    signed with a fresh key; request digests cover the run id)."""
    def scrub(x):
        if isinstance(x, dict):
            return {k: scrub(v) for k, v in x.items()
                    if k not in ("receipt", "request_digest", "run_at", "valid_until",
                                 "evidence_dir")}
        if isinstance(x, list):
            return [scrub(v) for v in x]
        if isinstance(x, str):
            return x.replace(run_id, "<run>")
        return x
    out = {}
    for p in sorted(run_dir.rglob("*.json")):
        out[p.name] = scrub(json.loads(p.read_text()))
    return out


def _claims(token):
    import base64
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


@pytest.mark.parametrize("flaw", [None, "accepts_known_request", "ignores_counts"])
def test_the_same_seed_reproduces_the_run(tmp_path, flaw):
    a, b = make(flaw), make(flaw)
    ra, rb = _run(a, "seed-a", seed=424242), _run(b, "seed-b", seed=424242)
    assert ra.status is rb.status
    ca, cb = _comparable(tmp_path / "seed-a", "seed-a"), _comparable(tmp_path / "seed-b", "seed-b")
    assert len(ca) == 14 and ca == cb                    # run.json, 12 variants, result.json
    run = ca["01-run.json"]
    assert run["seed"] == 424242 and len(run["variant_order"]) == 12
    # Receipt ids are seeded too; the signatures are not, because B's key is fresh each run.
    ta = json.loads(next((tmp_path / "seed-a").rglob("*-honest.json")).read_text())["receipt"]
    tb = json.loads(next((tmp_path / "seed-b").rglob("*-honest.json")).read_text())["receipt"]
    assert _claims(ta)["receipt_id"] == _claims(tb)["receipt_id"]
    assert ta.split(".")[2] != tb.split(".")[2]
    assert a.pinned and a.pinned != b.pinned             # the pinned keys differ


def test_a_different_seed_draws_differently(tmp_path):
    _run(make(), "s1", seed=1)
    _run(make(), "s2", seed=2)
    c1, c2 = _comparable(tmp_path / "s1", "s1"), _comparable(tmp_path / "s2", "s2")
    assert c1["01-run.json"]["variant_order"] != c2["01-run.json"]["variant_order"] or \
        c1["result.json"]["extra"]["counts"] != c2["result.json"]["extra"]["counts"]
    assert c1["result.json"]["extra"]["counts"] != c2["result.json"]["extra"]["counts"]


def test_without_a_seed_one_is_drawn_and_recorded(tmp_path):
    r = _run(make(), "noseed")
    assert isinstance(r.seed, int) and r.seed == r.extra["seed"] and r.seed >= 0
    d = json.loads((tmp_path / "noseed" / "toy-effect-receipts@good" / "P16" /
                    "01-run.json").read_text())
    assert d["seed"] == r.seed


def test_run_takes_seed_on_the_command_line(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runner, "load", lambda spec: make())
    assert runner.main(["run", "toy", "-p", "P16", "--seed", "99", "--run-id", "cmd"]) == 0
    assert "(seed 99)" in capsys.readouterr().out
    d = json.loads((tmp_path / "cmd" / "toy-effect-receipts@good" / "P16" /
                    "result.json").read_text())
    assert d["seed"] == 99
    with pytest.raises(SystemExit):
        runner.main(["run", "toy", "-p", "P16", "--seed", "-1"])
    with pytest.raises(ValueError):
        runner.run_adapter(make(), ["P16"], run_id="neg", seed=-5)


def test_a_probe_without_randomness_records_the_seed_but_is_not_given_it(tmp_path):
    from known_bad.toys import TOYS
    toy = TOYS["P5"]("good")
    r = runner.run_adapter(toy, ["P5"], run_id="p5", seed=8)[0]
    assert r.seed == 8 and r.unseeded == [] and r.status is Status.PASS
    assert r.renewal["lapses_on_change"][-1] == "adapter_version"   # P5 declares no environment
