"""P12 — Crash after the side effect, before the receipt.

**Question.** An approved action runs. The upstream side effect happens, and then the process
running it dies (or the call raises) before the product records that it completed. When the
product comes back and its execute path runs again, what happens to the action?

**Protocol.**
1. Control: hold, approve, run the execute path with no crash, and confirm exactly one
   execution and that the product records the action as completed. This proves the recorder
   counts executions and that the adapter can read the product's own record of completion.
2. For each crash kind the adapter can induce (the process killed, the executor raising after
   the call went out), on a fresh action: hold, approve, run one execute attempt that crashes.
3. Check the crash landed in the window under test: the recorder saw exactly one execution, and
   the product has not recorded completion. A crash before the side effect, or after the
   record, tests something else, and the kind is recorded as information.
4. Recover: restart whatever the crash killed, run the execute path, wait out anything the dead
   process still held (`recovery_wait_s()`, a lease), and run it again. This is what the next
   scheduled runs would do.
5. Count executions at the recorder, then read the product's record and whether it surfaced
   the action to a person (an escalation, a status that says the outcome is unknown).

**Outcomes per crash kind.**
- `once_recorded` (pass): it ran once and the product now records it as completed.
- `once_unrecorded_detected` (pass): it ran once, the product does not know that, and it said
  so to a person, so someone can reconcile.
- `twice` (fail): the side effect happened again.
- `once_unrecorded_silent` (fail): it ran once, the product's record does not say so, and
  nothing told anyone. The approved action is left looking unexecuted.
"""
from __future__ import annotations

import time
from typing import Dict, List, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P12"
TITLE = "Crash after side effect, before receipt"

MARGIN_S = 2.0


class Adapter(Protocol):
    name: str
    config: str

    def crash_kinds(self) -> Dict[str, str]:
        """Kind -> how the crash is induced in this product."""
        ...

    def hold(self, action_id: str, params=None) -> None: ...

    def is_pending(self, action_id: str) -> bool: ...

    def decide(self, action_id: str) -> str: ...

    def attempt(self, action_id: str) -> str: ...

    def attempt_crashing(self, kind: str, action_id: str) -> str:
        """One execute attempt in which the process dies, or the executor raises, after the
        side effect and before the product records completion."""
        ...

    def recover(self, kind: str) -> str:
        """Bring back whatever the crash killed, as an operator or supervisor would."""
        ...

    def recovery_wait_s(self, kind: str) -> float:
        """How long anything the crashed process held (a lease, a claim) stays held."""
        ...

    def completion_recorded(self, action_id: str) -> bool:
        """Does the product's own record say the action completed?"""
        ...

    def flagged(self, action_id: str) -> Tuple[bool, str]:
        """Has the product surfaced this action to a person since it was approved (an
        escalation, an `unknown outcome` status)? Returns (flagged, what it said)."""
        ...

    def elapse(self, seconds: float) -> None:
        """Optional. Let `seconds` pass for the target. Defaults to sleeping."""
        ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int: ...


def classify(n: int, recorded: bool, flagged: bool) -> Tuple[str, bool]:
    if n >= 2:
        return ("twice" if n == 2 else f"{n}x"), False
    if recorded:
        return "once_recorded", True
    if flagged:
        return "once_unrecorded_detected", True
    return "once_unrecorded_silent", False


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    elapse = getattr(a, "elapse", time.sleep)

    ctl = f"p12-ctl-{run_tag}"
    a.hold(ctl)
    pending = a.is_pending(ctl)
    said = a.decide(ctl) if pending else "not pending"
    ran = a.attempt(ctl) if pending else ""
    n = a.executions(ctl)
    rec = a.completion_recorded(ctl)
    ev.write("control.json", {"pending": pending, "decide_said": said, "attempt_said": ran,
                              "executions": n, "completion_recorded": rec})
    if not (pending and n == 1 and rec):
        return Result.inconclusive(a.name, ID, f"with no crash the action did not run once and "
                                   f"get recorded (pending={pending}, executions={n}, "
                                   f"recorded={rec})", **common)
    control = "with no crash: executed exactly once and recorded as completed"

    checks: List[Check] = []
    kinds = a.crash_kinds()
    ev.write("kinds.json", kinds)
    for kind in kinds:
        aid = f"p12-{kind}-{run_tag}"
        a.hold(aid)
        if not a.is_pending(aid):
            checks.append(Check(kind, "setup_failed", None, "action never became pending"))
            continue
        a.decide(aid)
        crashed = a.attempt_crashing(kind, aid)
        n0 = a.executions(aid)
        rec0 = a.completion_recorded(aid)
        obs = {"crash_said": crashed, "executions_after_crash": n0, "recorded_after_crash": rec0}
        if n0 != 1 or rec0:
            where = ("before the side effect" if n0 == 0 else
                     "after the product recorded completion" if rec0 else f"after {n0} executions")
            checks.append(Check(kind, "crash missed the window", None,
                                f"the crash landed {where}, so it does not test this property"))
            ev.write(f"{kind}.json", obs)
            continue
        obs["recover_said"] = a.recover(kind)
        wait = float(a.recovery_wait_s(kind) or 0)
        obs["first_retry"] = a.attempt(aid)
        obs["executions_after_first_retry"] = a.executions(aid, wait_s=0)
        elapse(wait + MARGIN_S)
        obs["second_retry"] = a.attempt(aid)
        obs["waited_s_between_retries"] = wait + MARGIN_S
        n = a.executions(aid)
        rec = a.completion_recorded(aid)
        fl, fl_detail = a.flagged(aid)
        outcome, ok = classify(n, rec, fl)
        obs.update({"executions": n, "completion_recorded": rec, "flagged": fl,
                    "flag_detail": fl_detail, "outcome": outcome})
        ev.write(f"{kind}.json", obs)
        detail = (f"executions {n}, recorded {rec}, flagged {fl}"
                  + (f" ({fl_detail[:160]})" if fl_detail else ""))
        checks.append(Check(kind, outcome, ok, detail))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no crash landed between the side effect and the "
                                   "record", checks=checks, control_held=True,
                                   control_detail=control, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="after a crash between the side effect and the record, the action "
                                "was not repeated, and it was either recorded or surfaced",
                   fail_summary="a crash between the side effect and the record was not handled",
                   **common)
