"""The test of the tests: every probe must fail its known-bad fixture, pass its known-good
one, and refuse to give a verdict when its control cannot hold."""
import pytest

from conformance.evidence import Evidence
from conformance.properties import ALL
from conformance.result import Status
from known_bad.toys import TOYS

EXPECTED = {"bad": Status.FAIL, "good": Status.PASS, "no-control": Status.INCONCLUSIVE}


@pytest.mark.parametrize("variant", sorted(EXPECTED))
@pytest.mark.parametrize("pid", sorted(ALL))
def test_probe_against_toy(pid, variant, tmp_path, monkeypatch):
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy = TOYS[pid](variant)
    toy.start()
    try:
        r = ALL[pid].probe(toy, Evidence("t", toy.name, pid, variant), run_tag="t")
    finally:
        toy.stop()
    assert r.status is EXPECTED[variant], (r.summary, [c.__dict__ for c in r.checks])
    if r.status in (Status.PASS, Status.FAIL):
        assert r.control_held is True


def test_every_property_has_a_toy():
    assert set(TOYS) == set(ALL)


def test_p6_does_not_call_blocked_what_the_host_cannot_reach_either(tmp_path, monkeypatch):
    """A sandbox that fails an attempt the unsandboxed baseline also fails has not blocked
    anything. Without the baseline, a host with no public DNS makes every sandbox look tight."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy = TOYS["P6"]("good")
    toy.baseline = lambda attempt: (False, "no route from this host")
    toy.start()
    try:
        r = ALL["P6"].probe(toy, Evidence("t", toy.name, "P6", "good"), run_tag="t")
    finally:
        toy.stop()
    assert r.status is Status.INCONCLUSIVE, r.summary


def test_p6_refuses_a_listener_the_baseline_already_hit(tmp_path, monkeypatch):
    """KRK-M16. A sandbox that blocks everything, behind an adapter whose host baseline sends
    the same tagged request to the same listener and never clears it, must not come out as
    'egress allowed'. It must come out as unmeasurable."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy = TOYS["P6"]("good")
    toy.shared_tag_baseline = True
    toy.start()
    try:
        r = ALL["P6"].probe(toy, Evidence("t", toy.name, "P6", "shared-tag"), run_tag="t")
    finally:
        toy.stop()
    assert r.status is Status.INCONCLUSIVE and "before the sandbox ran" in r.summary, r.summary


def test_p6_does_not_count_a_public_success_the_host_cannot_have(tmp_path, monkeypatch):
    """A public attempt the host's own baseline cannot make, reported as a success from inside
    the sandbox, is the adapter's exit code (KRK-M17: an adapter returned 0 on a "still
    running" stub), not egress. The listener checks still decide the verdict."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy = TOYS["P6"]("bad")
    toy.baseline = lambda attempt: ((False, "no route from this host") if attempt in
                                    ("dns_public", "https_public") else (True, "reached"))
    toy.start()
    try:
        r = ALL["P6"].probe(toy, Evidence("t", toy.name, "P6", "public-stub"), run_tag="t")
    finally:
        toy.stop()
    public = [c for c in r.checks if c.name in ("dns_public", "https_public")]
    assert r.status is Status.FAIL, r.summary
    assert public and all(c.ok is None and "not counted" in c.outcome for c in public), \
        [c.__dict__ for c in public]


def test_p1_catches_a_request_released_after_the_outage(tmp_path, monkeypatch):
    """A gateway that parks requests while its decider is paused and forwards them once it
    returns looks fail-closed at the moment the client times out."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    monkeypatch.setattr("conformance.properties.p1_failure_direction.LATE_S", 0)
    toy = TOYS["P1"]("good")
    toy.hold_and_release = True
    r = ALL["P1"].probe(toy, Evidence("t", toy.name, "P1", "held"), run_tag="t")
    assert r.status is Status.FAIL and "(late)" in r.summary, r.summary


def test_p8_refuses_to_measure_through_a_leaky_adapter(tmp_path, monkeypatch):
    """A good target behind an adapter whose status call leaks a thread must not come out as
    'each wait holds a thread'. It must come out as unmeasurable."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    toy = TOYS["P8"]("good")
    toy.leaky_client = True
    try:
        r = ALL["P8"].probe(toy, Evidence("t", toy.name, "P8", "leaky"), run_tag="t")
    finally:
        toy.stop()
    assert r.status is Status.INCONCLUSIVE and "own status calls" in r.summary, r.summary


def test_p7_does_not_mistake_a_coarse_clock_for_attribution(tmp_path, monkeypatch):
    """A record with no actor field but a coarse timestamp. Run grouped by actor, the timestamp
    is equal within each actor and different between them, and reads as attribution. Interleaved
    runs make that impossible for any field that only moves forward."""
    monkeypatch.setattr("conformance.evidence.RESULTS", tmp_path)
    for offset in range(6):                     # every phase of the clock against the run order
        toy = TOYS["P7"]("bad")
        toy.coarse_clock = True
        toy._t = 1000 + offset
        r = ALL["P7"].probe(toy, Evidence("t", toy.name, "P7", f"clock{offset}"), run_tag=f"t{offset}")
        assert r.status is Status.FAIL, (offset, r.summary)
