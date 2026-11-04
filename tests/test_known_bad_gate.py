"""The known-bad gate (spec §3.5): a property's probe is not used, and its
verdict is not a verdict, until its known-bad fixtures have been re-run for the current probe
and fixture versions and gave their required outcomes. Also the matrix's run dates and lapse
marks."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conformance import knownbad, matrix, runner, validity, versions
from conformance.result import Result, Status
from known_bad.receipts_toys import FLAWS, make
from known_bad.toys import TOYS

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _records(tmp_path):
    path = tmp_path / "known-bad" / "records.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _toys(rec):
    """A record's toy cases, without the claim-basis rule's ``claims:`` cases."""
    return {c["config"] for c in rec["cases"] if not c["config"].startswith("claims:")}


def _edit(monkeypatch, path_fragment):
    """Make every digest over a file list that contains `path_fragment` read as edited."""
    real = versions.digest
    monkeypatch.setattr(versions, "digest", lambda files: real(files) + (
        "-edited" if any(path_fragment in f for f in files) else ""))


# ------------------------------------------------------------------------------- the run

def test_record_runs_every_toy_of_every_property_and_appends_one_record_each(tmp_path, capsys):
    assert runner.main(["known-bad", "--record"]) == 0
    recs = _records(tmp_path)
    assert [r["property_id"] for r in recs] == [f"P{i}" for i in range(1, 27)]
    for r in recs:
        assert r["schema"] == "kirkaldy.known-bad/0.1" and r["ok"] is True, r
        assert (r["probe_version"], r["fixture_version"]) == knownbad.current_versions(
            r["property_id"])
        assert all(c["ok"] and c["got"] == c["required"] for c in r["cases"]), r["cases"]
        # the claim-basis rule is checked on every property's own toys (spec §3.4, KRK-M148)
        assert r["claim_rule_version"].startswith("sha256:")
        assert {"claims:fails-only-unclaimed", "claims:fails-on-a-claimed-form",
                "claims:no-statement"} <= {c["config"] for c in r["cases"]}, r["property_id"]
        assert (versions.ROOT / r["evidence_dir"]).resolve().is_dir()
    p16 = next(r for r in recs if r["property_id"] == "P16")
    p17 = next(r for r in recs if r["property_id"] == "P17")
    from known_bad.records_toys import FLAWS as RECORD_FLAWS
    assert _toys(p17) == \
        {"good", "bad", "no-control"} | {f"bad:{f}" for f in RECORD_FLAWS}
    assert _toys(p16) == \
        {"good", "bad", "no-control"} | {f"bad:{f}" for f in FLAWS}
    p18 = next(r for r in recs if r["property_id"] == "P18")
    from known_bad.binding_toys import A_FLAWS, FLAWS as BINDING_FLAWS
    assert _toys(p18) == \
        ({"good", "bad", "no-control", "a-good", "a-no-control"}
         | {f"bad:{f}" for f in BINDING_FLAWS} | {f"a-bad:{f}" for f in A_FLAWS})
    p19 = next(r for r in recs if r["property_id"] == "P19")
    from known_bad.withdrawal_toys import FLAWS as WITHDRAWAL_FLAWS
    assert _toys(p19) == \
        {"good", "bad", "no-control", "slow-good"} | {f"bad:{f}" for f in WITHDRAWAL_FLAWS}
    p20 = next(r for r in recs if r["property_id"] == "P20")
    from known_bad.standing_toys import FLAWS as STANDING_FLAWS
    assert _toys(p20) == \
        ({"good", "bad", "no-control", "slow-good", "pull-good", "x4-good",
          "x4-bad:pinned_once"} | {f"bad:{f}" for f in STANDING_FLAWS})
    p21 = next(r for r in recs if r["property_id"] == "P21")
    from known_bad.attenuation_toys import EXAMPLE_FLAWS, FLAWS as ATTENUATION_FLAWS
    assert _toys(p21) == \
        {"good", "bad", "no-control", "good-strict", "pull-good", "example-good"} | \
        {f"bad:{f}" for f in ATTENUATION_FLAWS} | {f"example-bad:{f}" for f in EXAMPLE_FLAWS}
    p23 = next(r for r in recs if r["property_id"] == "P23")
    from known_bad.reversal_toys import FLAWS as REVERSAL_FLAWS
    assert _toys(p23) == \
        ({"good", "bad", "no-control", "good-deferred", "good-conservative", "slow-good"}
         | {f"bad:{f}" for f in REVERSAL_FLAWS})
    p24 = next(r for r in recs if r["property_id"] == "P24")
    from known_bad.mandate_toys import cases as mandate_cases
    assert _toys(p24) == {c for c, _s in mandate_cases()}
    p25 = next(r for r in recs if r["property_id"] == "P25")
    from known_bad.disclosure_toys import cases as disclosure_cases
    assert _toys(p25) == {c for c, _s in disclosure_cases()}
    p26 = next(r for r in recs if r["property_id"] == "P26")
    from known_bad.translation_toys import cases as translation_cases
    assert _toys(p26) == {c for c, _ in translation_cases()}
    assert {c["config"]: c["required"] for c in recs[0]["cases"]
            if not c["config"].startswith("claims:")} == \
        {"good": "pass", "bad": "fail", "no-control": "inconclusive"}
    assert recs[7]["toy_waits"] == {"p1_failure_direction.LATE_S": 0, "p8_wait_cost.HOLD_S": 0}


def test_record_skips_current_properties_and_force_runs_them_again(tmp_path, capsys):
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 0
    assert "P5 current: known-bad run" in capsys.readouterr().out
    assert len(_records(tmp_path)) == 1
    assert runner.main(["known-bad", "--record", "--force", "-p", "P5"]) == 0
    assert len(_records(tmp_path)) == 2


def test_without_record_it_runs_and_writes_nothing(tmp_path):
    assert runner.main(["known-bad", "-p", "P5"]) == 0
    assert _records(tmp_path) == []
    assert knownbad.status("P5")["state"] == knownbad.MISSING


def test_toy_waits_are_restored_after_the_run(monkeypatch):
    import conformance.properties.p1_failure_direction as p1
    import conformance.properties.p8_wait_cost as p8
    monkeypatch.setattr(p1, "LATE_S", 8.0)
    monkeypatch.setattr(p8, "HOLD_S", 75.0)
    with knownbad.toy_waits():
        assert p1.LATE_S == 0 and p8.HOLD_S == 0
    assert p1.LATE_S == 8.0 and p8.HOLD_S == 75.0


def test_a_toy_that_gives_the_wrong_outcome_is_a_failed_run_that_satisfies_nothing(
        tmp_path, monkeypatch, capsys):
    """Break the correct P5 toy so its probe fails: the known-bad run must say so, record a
    failed run, and the gate must stay shut."""
    real = TOYS["P5"]
    monkeypatch.setitem(TOYS, "P5", lambda v: real("bad" if v == "good" else v))
    assert runner.main(["known-bad", "--record", "-p", "P5"]) == 1
    out = capsys.readouterr().out
    assert "P5 FAILED" in out and "good: required pass, got fail" in out, out
    (rec,) = _records(tmp_path)
    assert rec["ok"] is False
    ans = knownbad.status("P5")
    assert ans["state"] == knownbad.FAILED and "did not give its required outcomes (good)" in \
        knownbad.explain(ans)
    with pytest.raises(knownbad.KnownBadMissing):
        runner.run_adapter(real("good"), ["P5"], run_id="r")


def test_a_probe_that_raises_on_a_toy_is_a_failed_case(monkeypatch):
    from conformance.properties import ALL
    monkeypatch.setattr(ALL["P5"], "probe", lambda *a, **k: 1 / 0)
    rec = knownbad.run_one("P5")
    assert rec["ok"] is False and {c["got"] for c in rec["cases"]} == {"raised"}


def test_a_file_changed_during_the_run_fails_it(monkeypatch):
    real = knownbad.current_versions
    calls = []

    def moving(pid):
        calls.append(pid)
        p, f = real(pid)
        return (p, f) if len(calls) == 1 else (p + "-moved", f)
    monkeypatch.setattr(knownbad, "current_versions", moving)
    rec = knownbad.run_one("P5")
    assert rec["ok"] is False and "changed during the run" in rec["error"]


def test_an_unreadable_store_line_is_skipped(tmp_path):
    knownbad.run_one("P5", record=True)
    with (tmp_path / "known-bad" / "records.jsonl").open("a") as f:
        f.write("{not json\n" + json.dumps({"schema": "other", "ok": True}) + "\n")
    assert len(knownbad.load()) == 1 and knownbad.status("P5")["state"] == knownbad.CURRENT


# ------------------------------------------------------------------------------- stale

def test_status_moves_from_missing_to_current_to_stale_when_the_probe_changes(
        monkeypatch, capsys):
    assert knownbad.status("P16")["state"] == knownbad.MISSING
    knownbad.run_one("P16", record=True)
    assert knownbad.status("P16")["state"] == knownbad.CURRENT
    assert runner.main(["known-bad", "--status", "-p", "P16"]) == 0
    capsys.readouterr()

    _edit(monkeypatch, "conformance/receipts.py")             # in P16's probe closure
    ans = knownbad.status("P16")
    assert ans["state"] == knownbad.STALE and ans["changed"] == ["probe_version"], ans
    assert runner.main(["known-bad", "--status", "-p", "P16"]) == 1
    out = capsys.readouterr().out
    assert re.search(r"P16 stale: the last known-bad run \(P16-\S+ at \S+Z\) was for another "
                     r"version \(probe_version recorded sha256:\S+…, now sha256:\S+…\)", out), out
    assert "run: python -m conformance known-bad --record -p P16" in out
    assert knownbad.status("P5")["state"] == knownbad.MISSING  # other properties untouched


def test_a_fixture_change_makes_it_stale_too(monkeypatch):
    knownbad.run_one("P16", record=True)
    _edit(monkeypatch, "known_bad/receipts_toys.py")
    ans = knownbad.status("P16")
    assert ans["state"] == knownbad.STALE and "fixture_version" in ans["changed"], ans


# ------------------------------------------------------------------------------- the runner

def test_the_runner_refuses_a_property_with_no_record_before_probing_it(tmp_path, monkeypatch,
                                                                         capsys):
    with pytest.raises(knownbad.KnownBadMissing) as e:
        runner.run_adapter(make(), ["P16"], run_id="refused", seed=1)
    assert "P16 missing" in str(e.value) and knownbad.command(["P16"]) in str(e.value)
    assert not list(tmp_path.glob("refused/*/*/result.json"))
    monkeypatch.setattr(runner, "load", lambda spec: make())
    assert runner.main(["run", "toy", "-p", "P16", "--run-id", "cli-refused"]) == 5
    assert "refusing to probe" in capsys.readouterr().err


def test_the_runner_refuses_a_stale_record(monkeypatch):
    knownbad.run_one("P16", record=True)
    _edit(monkeypatch, "tests/test_p16_effect_receipt.py")    # P16's required outcomes
    with pytest.raises(knownbad.KnownBadMissing) as e:
        runner.run_adapter(make(), ["P16"], run_id="stale", seed=1)
    assert "P16 stale" in str(e.value) and "fixture_version" in str(e.value)


def test_the_gate_skips_properties_the_target_does_not_probe():
    """P5's toy implements only P5; asking for all properties needs only P5's record."""
    knownbad.run_one("P5", record=True)
    toy = TOYS["P5"]("good")
    rs = runner.run_adapter(toy, None, run_id="only-p5", seed=1)
    assert [r.property_id for r in rs] == ["P5"] and rs[0].status is Status.PASS


def test_a_result_cites_its_record_and_reads_valid(tmp_path):
    rec = knownbad.run_one("P16", record=True)
    r = runner.run_adapter(make(), ["P16"], run_id="ok", seed=1)[0]
    assert r.known_bad["record_id"] == rec["record_id"] and r.known_bad["ok"] is True
    assert r.known_bad["probe_version"] == r.probe_version
    path = tmp_path / "ok" / "toy-effect-receipts@good" / "P16" / "result.json"
    assert json.loads(path.read_text())["known_bad"] == r.known_bad
    assert runner.main(["validity", str(path), "--target-version", "toy-good"]) == 0


def test_without_known_bad_the_run_happens_and_its_verdict_is_no_verdict(tmp_path, monkeypatch,
                                                                         capsys):
    monkeypatch.setattr(runner, "load", lambda spec: make())
    assert runner.main(["run", "toy", "-p", "P16", "--run-id", "marked", "--seed", "2",
                        "--without-known-bad"]) == 0
    path = tmp_path / "marked" / "toy-effect-receipts@good" / "P16" / "result.json"
    d = json.loads(path.read_text())
    assert d["status"] == "pass" and d["known_bad"] == {}
    capsys.readouterr()
    assert runner.main(["validity", str(path), "--target-version", "toy-good"]) == 4
    assert "no known-bad run was recorded" in capsys.readouterr().out


# ------------------------------------------------------------------------------- validity

RUN_AT = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
KB = {"schema": knownbad.SCHEMA, "record_id": "P16-kb", "recorded_at": "2026-11-01T11:00:00Z",
      "probe_version": "sha256:p", "fixture_version": "sha256:f", "ok": True, "cases": 15}
CURRENT = dict(target_version="t 1.0", config="default", probe_version="sha256:p",
               fixture_version="sha256:f", adapter_version="sha256:a", environment={})


def _stamped(status=Status.PASS, known_bad=KB):
    r = Result(target="t", property_id="P16", status=status, summary="s",
               control_held=True if status in (Status.PASS, Status.FAIL) else None,
               target_version="t 1.0", config="default")
    measured = {"probe_version": "sha256:p", "fixture_version": "sha256:f",
                "adapter_version": "sha256:a", "environment": {}}
    return validity.stamp(r, run_at=RUN_AT, seed=1, measured=measured, known_bad=known_bad)


@pytest.mark.parametrize("kb, why", [
    (None, "no known-bad run was recorded"),
    ({**KB, "ok": False}, "did not pass"),
    ({**KB, "probe_version": "sha256:other"}, "checked probe_version"),
    ({**KB, "fixture_version": ""}, "checked fixture_version"),
    ({**KB, "recorded_at": "2026-11-01T12:00:01Z"}, "after the run"),
    ({**KB, "recorded_at": "soon"}, "cannot be read"),
])
@pytest.mark.parametrize("status", [Status.PASS, Status.FAIL])
def test_a_verdict_without_a_prior_matching_known_bad_run_is_no_verdict(kb, why, status):
    v = validity.validity(_stamped(status, kb), now=RUN_AT + timedelta(days=1), **CURRENT)
    assert v.state == validity.NO_VERDICT and why in v.reasons[0], v


def test_no_verdict_wins_over_a_lapse():
    v = validity.validity(_stamped(known_bad=None), now=RUN_AT + timedelta(days=400),
                          **{**CURRENT, "target_version": "t 2"})
    assert v.state == validity.NO_VERDICT


def test_a_target_version_is_compared_exactly_so_dirty_lapses_it():
    v = validity.validity(_stamped(), now=RUN_AT + timedelta(days=1),
                          **{**CURRENT, "target_version": "t 1.0+dirty"})
    assert v.state == validity.LAPSED and "target_version changed" in v.reasons[0]


def test_not_applicable_needs_no_known_bad_run_and_lapses_like_a_verdict():
    na = _stamped(Status.NOT_APPLICABLE, None)
    assert validity.validity(na, now=RUN_AT + timedelta(days=1), **CURRENT).state == \
        validity.VALID
    assert validity.validity(na, now=RUN_AT + timedelta(days=1),
                             **{**CURRENT, "target_version": "t 1.1"}).state == validity.LAPSED
    assert validity.validity(na, now=datetime(2027, 11, 1, 12, tzinfo=timezone.utc),
                             **CURRENT).state == validity.LAPSED


# ------------------------------------------------------------------------------- MATRIX.md

def _p16_cell(md, row):
    lines = md.splitlines()
    header = next(l for l in lines if l.startswith("| Target"))
    col = next(i for i, c in enumerate(header.strip().strip("|").split(" | "))
               if c.strip().startswith("P16 "))
    line = next(l for l in lines if l.startswith(f"| {row} |"))
    return [c.strip() for c in line.strip().strip("|").split(" | ")][col]


def test_the_matrix_shows_each_run_date_and_its_validity(tmp_path):
    runner.run_adapter(make(), ["P16"], run_id="m-nokb", seed=1, known_bad="mark")
    knownbad.run_one("P16", record=True)
    good, bad = make(), make("accepts_unsigned")
    runner.run_adapter(good, ["P16"], run_id="m", seed=1)
    runner.run_adapter(bad, ["P16"], run_id="m", seed=1)
    today = validity.utcnow().strftime("%Y-%m-%d")
    tv = {"toy-effect-receipts@good": "toy-good",
          "toy-effect-receipts@bad:accepts_unsigned": "toy-bad:accepts_unsigned"}

    out = matrix.build("m", target_versions=tv)
    md = Path(out["markdown_path"]).read_text()
    assert re.search(rf"\[pass\]\([^)]*\) · {today} · valid", _p16_cell(md, "toy-effect-receipts@good"))
    assert re.search(rf"\[\*\*FAIL\*\*\]\([^)]*\) · {today} · valid",
                     _p16_cell(md, "toy-effect-receipts@bad:accepts_unsigned"))
    assert "Validity judged at" in md and "2 valid" in md
    cells = out["rows"]["toy-effect-receipts@good"]["cells"]["P16"]
    assert cells["validity"]["state"] == "valid"
    assert json.loads(Path(out["json_path"]).read_text())["rows"]["toy-effect-receipts@good"][
        "cells"]["P16"]["validity"]["run_date"] == today

    # Thirteen months on, both lapse, and the detail says why.
    later = validity.utcnow() + timedelta(days=400)
    md = Path(matrix.build("m", now=later, target_versions=tv)["markdown_path"]).read_text()
    assert f"· {today} · **LAPSED**" in _p16_cell(md, "toy-effect-receipts@good")
    assert "  - age: run" in md and "**validity:** **LAPSED**" in md

    # A changed target version lapses only its row.
    md = Path(matrix.build("m", target_versions={**tv, "toy-effect-receipts@good": "toy-2"})[
        "markdown_path"]).read_text()
    assert "**LAPSED**" in _p16_cell(md, "toy-effect-receipts@good")
    assert "· valid" in _p16_cell(md, "toy-effect-receipts@bad:accepts_unsigned")
    assert "target_version changed: recorded 'toy-good', now 'toy-2'" in md

    # No current target version given: unknown, never valid.
    md = Path(matrix.build("m")["markdown_path"]).read_text()
    assert _p16_cell(md, "toy-effect-receipts@good").endswith("· unknown")
    assert "No current target versions were given" in md

    # A run made before any known-bad record (with --without-known-bad): no verdict, even now
    # that a record exists, because the record came after the run.
    md = Path(matrix.build("m-nokb", target_versions=tv)["markdown_path"]).read_text()
    assert _p16_cell(md, "toy-effect-receipts@good").endswith("· no verdict")
    assert "no known-bad run was recorded" in md


def test_the_matrix_marks_a_result_written_before_expiry_unknown_with_no_date(tmp_path):
    d = tmp_path / "legacy" / "my-product@pinned" / "P16"
    d.mkdir(parents=True)
    (d / "result.json").write_text(json.dumps({
        "target": "my-product", "config": "pinned", "property_id": "P16",
        "status": "pass", "summary": "s", "control_held": True, "checks": [],
        "target_version": "my-product 0.9.0", "evidence_dir": f"results/legacy/{d.parent.name}/P16"}))
    md = Path(matrix.build("legacy", target_versions={"my-product": "my-product 0.9.0"})[
        "markdown_path"]).read_text()
    assert _p16_cell(md, "my-product@pinned").endswith("· no date · unknown")


def test_the_matrix_cli_takes_target_versions_and_skips_the_known_bad_directory(tmp_path,
                                                                                capsys):
    knownbad.run_one("P16", record=True)
    runner.run_adapter(make(), ["P16"], run_id="20000101T000000", seed=1)
    capsys.readouterr()
    assert runner.main(["matrix", "--target-version", "toy-effect-receipts@good=toy-good"]) == 0
    path = capsys.readouterr().out.strip()
    assert path.endswith("20000101T000000/MATRIX.md")         # not results/known-bad
    assert "· valid" in Path(path).read_text()
    with pytest.raises(SystemExit):
        runner.main(["matrix", "20000101T000000", "--target-version", "no-equals-sign"])


# ------------------------------------------------------------------------------- Makefile

def test_every_makefile_flow_that_runs_a_probe_records_the_known_bad_fixtures_first():
    text = (ROOT / "Makefile").read_text()
    for block in re.split(r"\n(?=[a-z0-9-]+:)", text):
        name = block.split(":", 1)[0]
        lines = [l for l in block.splitlines() if l.startswith("\t")]
        runs = [i for i, l in enumerate(lines) if "-m conformance run " in l]
        if not runs:
            continue
        kb = [i for i, l in enumerate(lines) if "-m conformance known-bad --record" in l]
        assert kb and kb[0] < runs[0], f"make {name} runs a probe before recording known-bad"
