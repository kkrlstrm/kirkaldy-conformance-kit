"""Adapters, claim ledgers and results kept outside the kit: ``KIRKALDY_TARGETS_PATH`` adds
adapter roots that the runner lists and loads from and `versions` hashes as it hashes its own,
``KIRKALDY_CLAIMS_DIR`` adds a ledger directory read before the kit's, and
``KIRKALDY_RESULTS_DIR`` moves results and the known-bad store. Each setting is read when its
module is imported, so the end-to-end checks run in a fresh interpreter."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import targets

ROOT = Path(__file__).resolve().parent.parent

ADAPTER = '''"""A demonstration adapter in an outside root."""
from conformance.result import Result  # noqa: F401
from targets._shared import VALUE
from .helper import X

CONFIGS = ["default", "other"]


class Demo:
    name = "demo"

    def __init__(self, config):
        self.config = config
        self.value = VALUE + X


def make(config="default"):
    return Demo(config)
'''

PROBE = '''
import json, sys
from conformance import runner, versions
a = runner.load("demo@other")
files = versions.adapter_files("targets.demo.adapter")
print(json.dumps({"targets": runner.list_targets(), "config": a.config, "value": a.value,
                  "files": files, "digest": versions.digest(files),
                  "roots": [str(r) for r in runner.target_roots()]}))
'''


def _root(base: Path) -> Path:
    r = base / "outside-targets"
    (r / "demo").mkdir(parents=True)
    (r / "_shared.py").write_text("VALUE = 40\n")
    (r / "demo" / "__init__.py").write_text("")
    (r / "demo" / "adapter.py").write_text(ADAPTER)
    (r / "demo" / "helper.py").write_text("X = 2\n")
    (r / "demo" / "NOTES.md").write_text("what this adapter reads\n")
    return r


def _python(code: str, **env: str) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if not k.startswith("KIRKALDY_")}
    e.update(env, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=e,
                          capture_output=True, text=True, timeout=120)


def test_the_path_is_read_in_order_once_without_the_kits_own_root(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    own = Path(targets.__file__).resolve().parent
    value = os.pathsep.join([str(a), str(b), "", str(a), str(own)])
    assert targets.extra_roots(value) == [a.resolve(), b.resolve()]
    assert targets.extra_roots("") == []
    with pytest.raises(NotADirectoryError, match="not a directory"):
        targets.extra_roots(str(tmp_path / "missing"))
    assert targets.roots()[0] == own


def test_a_mistyped_root_stops_the_import(tmp_path):
    p = _python("import targets", KIRKALDY_TARGETS_PATH=str(tmp_path / "no-such-root"))
    assert p.returncode != 0 and "NotADirectoryError" in p.stderr


def test_an_outside_adapter_is_listed_loaded_and_hashed_as_its_own_directory(tmp_path):
    r = _root(tmp_path)
    p = _python(PROBE, KIRKALDY_TARGETS_PATH=str(r))
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    assert "demo" in got["targets"] and "toys" in got["targets"]
    assert got["config"] == "other" and got["value"] == 42
    assert got["roots"][1] == str(r.resolve())
    files = set(got["files"])
    assert {"targets/demo/adapter.py", "targets/demo/helper.py", "targets/demo/NOTES.md",
            "targets/demo/__init__.py", "targets/_shared.py", "conformance/result.py"} <= files
    assert not any(f.startswith("/") for f in files), files
    # The same files at another path hash the same; any change to one of them moves the digest.
    other = tmp_path / "elsewhere"
    shutil.copytree(r, other)
    p2 = _python(PROBE, KIRKALDY_TARGETS_PATH=str(other))
    assert p2.returncode == 0, p2.stderr
    assert json.loads(p2.stdout)["digest"] == got["digest"]
    (other / "demo" / "NOTES.md").write_text("what this adapter reads, changed\n")
    p3 = _python(PROBE, KIRKALDY_TARGETS_PATH=str(other))
    assert json.loads(p3.stdout)["digest"] != got["digest"]
    (other / "_shared.py").write_text("VALUE = 40  # an imported helper is hashed too\n")
    (other / "demo" / "NOTES.md").write_text("what this adapter reads\n")
    p4 = _python(PROBE, KIRKALDY_TARGETS_PATH=str(other))
    assert json.loads(p4.stdout)["digest"] != got["digest"]


def test_the_targets_command_lists_an_outside_adapter_with_its_configurations(tmp_path):
    r = _root(tmp_path)
    p = _python("import sys; from conformance import runner; sys.exit(runner.main(['targets']))",
                KIRKALDY_TARGETS_PATH=str(r))
    assert p.returncode == 0, p.stderr
    assert "demo  configs: default, other" in p.stdout and "toys  configs:" in p.stdout


def test_an_adapter_in_no_root_is_refused_by_name():
    from conformance import runner
    with pytest.raises(ValueError, match="no adapter 'no-such-target'"):
        runner.load("no-such-target")


def test_results_and_ledgers_follow_their_settings(tmp_path):
    res, led = tmp_path / "results", tmp_path / "claims"
    led.mkdir()
    (led / "demo.json").write_text(json.dumps({"target": "demo", "claims": [
        {"property": "P1", "basis": "not-found", "checked": "a test", "source": "none"}]}))
    code = '''
import json, os
from conformance import claims, evidence, knownbad
ev = evidence.Evidence("r1", "demo", "P1")
ev.write("note", "x")
print(json.dumps({"results": str(evidence.RESULTS), "store": str(knownbad.store_path()),
                  "evidence": str(ev.dir), "rel": ev.relpath(),
                  "ledger": str(claims.ledger_path("demo")),
                  "toys_ledger": str(claims.ledger_path("toys")),
                  "toys_role": claims.role("toys"), "demo": claims.vendor_claims("demo")}))
'''
    p = _python(code, KIRKALDY_RESULTS_DIR=str(res), KIRKALDY_CLAIMS_DIR=str(led))
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    assert got["results"] == str(res.resolve())
    assert got["store"] == str(res.resolve() / "known-bad" / "records.jsonl")
    assert Path(got["evidence"]) == res.resolve() / "r1" / "demo" / "P1"
    assert (res / "r1" / "demo" / "P1").is_dir() and not (ROOT / "results" / "r1").exists()
    assert (ROOT / got["rel"]).resolve() == res.resolve() / "r1" / "demo" / "P1"
    assert got["ledger"] == str(led.resolve() / "demo.json")
    assert got["toys_ledger"] == str(ROOT / "claims" / "toys.json")
    assert got["toys_role"] == "reference"
    assert got["demo"]["P1"].startswith("not stated")


def test_without_the_settings_the_kits_own_directories_are_used():
    code = '''
import json
from conformance import claims, evidence
print(json.dumps([str(evidence.RESULTS), str(claims.LEDGER), [str(d) for d in claims.ledgers()]]))
'''
    p = _python(code)
    assert p.returncode == 0, p.stderr
    results, ledger, ledgers = json.loads(p.stdout)
    assert results == str(ROOT / "results") and ledger == str(ROOT / "claims")
    assert ledgers == [str(ROOT / "claims")]
