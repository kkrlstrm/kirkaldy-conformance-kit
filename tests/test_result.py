import pytest

from conformance import canary
from conformance.properties.p7_actor_in_audit import attribution_fields
from conformance.result import Check, ControlNotHeld, Result, Status, verdict


@pytest.mark.parametrize("status", [Status.PASS, Status.FAIL])
@pytest.mark.parametrize("held", [False, None])
def test_no_verdict_without_a_held_control(status, held):
    with pytest.raises(ControlNotHeld):
        Result(target="t", property_id="P1", status=status, summary="", control_held=held)


def test_verdict_turns_a_failed_control_into_inconclusive_whatever_the_checks_say():
    r = verdict("t", "P1", [Check("x", "fine", True)], control_held=False, control_detail="no",
                pass_summary="p", fail_summary="f")
    assert r.status is Status.INCONCLUSIVE


def test_one_violation_is_a_failure():
    r = verdict("t", "P1", [Check("a", "ok", True), Check("b", "bad", False)], control_held=True,
                control_detail="held", pass_summary="p", fail_summary="f")
    assert r.status is Status.FAIL and "b (bad)" in r.summary


def test_canary_is_found_in_encodings_a_string_redactor_misses():
    c = canary.make("x")
    import base64
    assert "base64" in canary.exposures(c, "hdr: " + base64.b64encode(c.encode()).decode())
    assert "reversed" in canary.exposures(c, c[::-1])
    assert canary.exposures(c, "nothing here") == []


def test_attribution_ignores_fields_that_vary_within_one_actor():
    h1 = {"ts": "1", "user": "alice", "req": "a"}
    h2 = {"ts": "2", "user": "alice", "req": "b"}
    a1 = {"ts": "3", "user": "alice", "req": "c"}
    a2 = {"ts": "4", "user": "alice", "req": "d"}
    assert attribution_fields(h1, h2, a1, a2) == []
    a1["actor"] = a2["actor"] = "agent"
    assert attribution_fields(h1, h2, a1, a2) == ["actor"]


def test_canary_is_found_when_the_encoding_includes_a_trailing_newline():
    import base64
    c = canary.make("x")
    shell_output = base64.b64encode((c + "\n").encode()).decode()  # what `echo $X | base64` prints
    assert c not in shell_output
    assert "decoded-from-token" in canary.exposures(c, "out: " + shell_output)
    assert "decoded-from-token" in canary.exposures(c, (c + "\n").encode().hex())
