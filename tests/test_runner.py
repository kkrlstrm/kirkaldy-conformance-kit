"""The runner cleans up after a target whose start fails partway, so its helpers do not outlive
the run and hold ports that the next start needs."""
import pytest

from conformance import runner


class _HalfStarts:
    name, config = "half", "default"

    def __init__(self):
        self.helper_running = False

    def start(self):
        self.helper_running = True          # first helper is up ...
        raise RuntimeError("second helper failed to start")

    def stop(self):
        self.helper_running = False


def test_a_failed_start_is_stopped(monkeypatch, tmp_path):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    t = _HalfStarts()
    monkeypatch.setattr(runner, "load", lambda spec: t)
    with pytest.raises(RuntimeError, match="second helper"):
        runner.run("half", ["P1"], run_id="t")
    assert t.helper_running is False
