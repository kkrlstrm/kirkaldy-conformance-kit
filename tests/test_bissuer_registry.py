"""The B-issuer registry `ALL_BISSUER` beside `ALL`. `ALL` is exactly
P1 to P26; lookups by id read both; the full known-bad gate is P1 to P26; P18B is gated when named;
the runner routes by stated authority; and the matrix keeps B-issuer results in rows of their own,
never in a column beside P18 (design §5.3)."""
import json

import pytest

from conformance import knownbad, matrix, runner, versions
from conformance.properties import ALL, ALL_BISSUER, known, module, ordered
from conformance.result import Status
from known_bad.binding_toys import ToyBinding
from known_bad.bissuer_binding_toys import toy


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def test_all_is_exactly_p1_to_p26():
    assert list(ALL) == [f"P{i}" for i in range(1, 27)]
    assert list(ALL_BISSUER) == ["P18B"]
    assert not set(ALL) & set(ALL_BISSUER)
    assert known("P18B") and known("P18") and known("P26") and not known("P27")
    assert module("P18B").ID == "P18B"
    with pytest.raises(KeyError):
        module("P99")


def test_versions_measure_p18b_and_its_closure_reaches_p18():
    probe = versions.probe_files("P18B")
    assert "conformance/properties/p18_payload_bound.py" in probe
    assert {"conformance/bissuer.py", "conformance/stand_in.py",
            "conformance/properties/p18b_payload_bound_b.py"} <= set(probe)
    assert set(versions.fixture_files("P18B")) == {
        "known_bad/bissuer_core.py", "known_bad/bissuer_binding_toys.py",
        "tests/test_p18b_payload_bound_b.py", "tests/vectors/bissuer/jcs.json"}
    for pid in ALL:
        never = {"conformance/properties/p18b_payload_bound_b.py",
                 "conformance/properties/__init__.py"}
        if pid != "P25":
            # P25's b-held profile reuses the B-issuer modules unchanged, so a change to them
            # lapses P25 by design (X6 design §6.1).
            never |= {"conformance/bissuer.py", "conformance/stand_in.py"}
        assert not set(versions.probe_files(pid)) & never
        assert not set(versions.fixture_files(pid)) & set(versions.fixture_files("P18B"))
    assert versions.current({"property_id": "P18B"})["probe_version"] == versions.digest(probe)


def test_the_gate_names_p18b_cases_and_the_full_gate_skips_it():
    got = dict(knownbad.cases("P18B"))
    assert got["revision:good"] is Status.PASS
    assert got["consent-id:finding:restates_silently"] is Status.INCONCLUSIVE
    assert got["rar-token:bad:writes_unaccepted"] is Status.FAIL
    assert "revision:bad:accepts_subset" not in got
    assert len(got) == 3 * 5 + 3 * 25 - 3
    assert ordered(list(ALL)) == [f"P{i}" for i in range(1, 27)]


def test_the_gate_records_p18b_only_when_named(tmp_path, monkeypatch):
    """A small P18B gate, cut to six cases so the test stays quick; the real gate is run by the
    build (`known-bad --record -p P18B`)."""
    small = [("revision:good", "pass"), ("revision:no-control", "inconclusive"),
             ("revision:bad:writes_unaccepted", "fail"), ("rar-token:bad", "fail"),
             ("consent-id:finding:restates_silently", "inconclusive"),
             ("consent-id:slow-good", "pass")]
    monkeypatch.setattr("known_bad.bissuer_binding_toys.cases", lambda: small)
    assert runner.main(["known-bad", "--record", "-p", "P18B"]) == 0
    recs = [json.loads(x) for x in (tmp_path / "known-bad" / "records.jsonl").read_text()
            .splitlines()]
    assert [r["property_id"] for r in recs] == ["P18B"] and recs[0]["ok"] is True
    finding = next(c for c in recs[0]["cases"] if "finding" in c["config"])
    assert finding["findings"] == ["restated_changed"]
    assert knownbad.status("P18B")["state"] == knownbad.CURRENT


def test_a_finding_case_without_its_finding_does_not_satisfy_the_gate(monkeypatch):
    monkeypatch.setattr("known_bad.bissuer_binding_toys.cases",
                        lambda: [("revision:no-control", "inconclusive")])
    monkeypatch.setattr("known_bad.bissuer_binding_toys.expected",
                        lambda config: {"finding": "restated_changed"})
    rec = knownbad.run_one("P18B")
    assert rec["ok"] is False


def test_the_runner_refuses_an_a_issued_property_for_an_adapter_at_b():
    a = toy("revision:good")
    a.implements = lambda: ["P18", "P18B"]
    (r18,) = runner.run_adapter(a, ["P18"], run_id="route", known_bad="mark")
    assert r18.status is Status.INCONCLUSIVE and "run P18B" in r18.summary
    assert "KRK-M130" in r18.summary


def test_the_runner_refuses_a_bissuer_property_for_an_adapter_at_a():
    a = ToyBinding("good")
    a.implements = lambda: ["P18", "P18B"]
    (r,) = runner.run_adapter(a, ["P18B"], run_id="route-a", known_bad="mark")
    assert r.status is Status.INCONCLUSIVE and "run P18" in r.summary


def test_the_probe_itself_refuses_issuer_a(tmp_path):
    from conformance.evidence import Evidence
    a = ToyBinding("good")
    r = ALL_BISSUER["P18B"].probe(a, Evidence("t", a.name, "P18B", "a"), run_tag="a")
    assert r.status is Status.INCONCLUSIVE and "run P18" in r.summary


def test_the_matrix_keeps_bissuer_results_in_their_own_rows(tmp_path):
    a = toy("revision:good")
    runner.run_adapter(a, ["P18B"], run_id="mx", known_bad="mark")
    b = ToyBinding("good")
    runner.run_adapter(b, ["P18"], run_id="mx", known_bad="mark")
    out = matrix.build("mx")
    md = open(out["markdown_path"]).read()
    header = next(line for line in md.splitlines() if line.startswith("| Target | Version | P1 "))
    assert "P18B" not in header and "P18 Payload bound" in header
    assert "## Authority held at B" in md
    row = next(line for line in md.splitlines() if line.startswith("| toy-b-issuer"))
    assert "P18B Payload bound, single use (authority at B)" in row and "revision" in row
    assert "toy-b-issuer@revision:good" not in out["rows"]
    assert [r["property_id"] for r in out["bissuer_rows"]] == ["P18B"]
