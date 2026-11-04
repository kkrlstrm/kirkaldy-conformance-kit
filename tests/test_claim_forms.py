"""P24's, P25's and P26's form inventories for the published-run pre-start check. They are in
`claim_basis.inventory`, the rule file, and the former `conformance/claim_forms.py` is gone. Each inventory holds every form its toys write,
in each profile or topology, and never the control; a published stated run is
refused before any probe runs when a form has no statement; and the rule file stays outside
every probe's closure."""
import pytest

from conformance import claim_basis as cb
from conformance import knownbad, runner, versions
from conformance.properties import ALL, ALL_BISSUER

pytest.importorskip("cryptography")


@pytest.fixture(autouse=True)
def _results(tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)


def _probe(pid, config):
    from conformance.evidence import Evidence
    toy = knownbad._toy(pid, config)
    kw = {"run_tag": f"inv-{config}"}
    if runner._takes_seed(ALL[pid].probe):
        kw["seed"] = 1
    with knownbad.toy_waits():
        toy.start()
        try:
            r = ALL[pid].probe(toy, Evidence("inv", toy.name, pid, config), **kw)
        finally:
            toy.stop()
    return toy, r


@pytest.mark.parametrize("pid,config", [("P24", "good"),
                                        ("P25", "good"), ("P25", "b-held-good"),
                                        ("P26", "good@T"), ("P26", "good@R"),
                                        ("P26", "good@TR")])
def test_the_inventory_holds_every_form_a_toy_writes_and_no_other(pid, config):
    toy, r = _probe(pid, config)
    have = [f for f, _c in cb.inventory(pid, toy)]
    wrote = [f for f, _c, _e in cb.forms_of(r)]
    assert wrote and len(have) == len(set(have))
    assert sorted(wrote) == sorted(have)


def test_an_adapter_with_no_profile_or_topology_gets_every_form():
    p25 = {f for f, _c in cb.inventory("P25")}
    a = {f for f, _c in cb.inventory("P25", knownbad._toy("P25", "good"))}
    b = {f for f, _c in cb.inventory("P25", knownbad._toy("P25", "b-held-good"))}
    assert p25 == a | b and a != b and "principal_shown/organisation" in a & b
    m = ALL["P26"]
    assert len(cb.inventory("P26")) == sum(len(m.FORMS[v]) for v in m.VARIANTS)
    m = ALL["P24"]
    assert len(cb.inventory("P24")) == sum(len(m.FORMS[v]) for v in m.VARIANTS) == 43
    assert "control" not in {f for f, _c in cb.inventory("P24")}


def test_the_inventories_are_the_rules_and_never_list_the_control():
    assert set(cb.FORM_LEVEL) == {"P20", "P21", "P22", "P23", "P24", "P25", "P26"}
    for pid in list(ALL) + list(ALL_BISSUER):
        inv = cb.inventory(pid)
        if pid in cb.FORM_LEVEL:
            assert inv and cb.CONTROL_CHECK not in {f for f, _c in inv}, pid
        else:
            assert inv is None, pid
    assert not (versions.ROOT / "conformance" / "claim_forms.py").exists()


@pytest.mark.parametrize("pid,config", [("P25", "good"), ("P26", "good@T")])
def test_a_published_p25_or_p26_run_is_refused_before_any_probe(pid, config, monkeypatch):
    called = []
    monkeypatch.setattr(ALL[pid], "probe", lambda *a, **k: called.append(1))
    t = knownbad._toy(pid, config)
    t.implements = lambda: [pid]
    t.not_claimed = lambda: {pid: {"actor_shown" if pid == "P25" else "currency":
                                   "not claimed (test)"}}
    with pytest.raises(cb.ClaimBasisIncomplete) as e:
        runner.run_adapter(t, [pid], run_id=f"cf-{pid}", known_bad="mark", published=True)
    assert called == [] and "every form stated not claimed" in str(e.value)
    gaps = e.value.gaps[pid]
    assert "control" not in gaps and not any(g.startswith("(no form inventory") for g in gaps)
    assert not any(g.startswith(("actor_shown/", "currency/")) for g in gaps)
    basis = {"quote": "MUST", "location": "s1", "source": "documentation (test)"}
    t.claim_basis = lambda: {pid: {"*": basis}}
    assert cb.unstated_before_run(t, cb.statement(t, pid)) == []


def test_the_rule_file_is_in_no_probe_or_fixture_closure():
    for pid in list(ALL) + list(ALL_BISSUER):
        assert "conformance/claim_basis.py" not in versions.probe_files(pid), pid
        assert "conformance/claim_basis.py" not in versions.fixture_files(pid), pid
    assert cb.RULE_FILES == ("conformance/claim_basis.py",)
    assert cb.rule_version() == versions.digest(["conformance/claim_basis.py"])


def test_a_published_p24_run_is_refused_before_any_probe(monkeypatch):
    called = []
    monkeypatch.setattr(ALL["P24"], "probe", lambda *a, **k: called.append(1))
    t = knownbad._toy("P24", "good")
    t.implements = lambda: ["P24"]
    t.not_claimed = lambda: {"P24": {"purpose": "not claimed (test)"}}
    with pytest.raises(cb.ClaimBasisIncomplete) as e:
        runner.run_adapter(t, ["P24"], run_id="cf-P24", known_bad="mark", published=True)
    gaps = e.value.gaps["P24"]
    assert called == [] and "outside_ceiling/amount" in gaps and "control" not in gaps
    assert not any(g.startswith(("purpose/", "(no form inventory")) for g in gaps)
    basis = {"quote": "MUST", "location": "s1", "source": "documentation (test)"}
    t.claim_basis = lambda: {"P24": {"*": basis}}
    assert cb.unstated_before_run(t, cb.statement(t, "P24")) == []
