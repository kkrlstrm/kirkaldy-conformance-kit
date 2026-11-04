"""P3 — Approval durability.

**Question.** An action is waiting for human approval. The process holding the wait restarts.
Then the human approves. What happens?

**Protocol.**
1. Control, no restart: request an action, confirm it is pending and has not executed, approve
   it, and confirm it executes exactly once. If that fails the adapter is not driving the real
   approval path and nothing else means anything.
2. For each restart kind the adapter supports (the engine process, the host, the worker):
   request a fresh action, confirm pending and not executed, restart, approve, wait.
3. Count executions at the side-effect recorder, not by asking the product. After a restart,
   wait up to `AFTER_RESTART_WAIT_S` for the execution and record how long it took. A product
   can recover by polling on a long interval; an execution that arrives after a short window is
   late, not lost (KRK-M11: an engine woke a restarted wait on its fallback poll, and a shorter
   window read that as a lost approval).

**Outcomes per restart kind.** `executed_once` (pass), `lost` (approval accepted or refused,
action never ran), `executed_twice`, `executed_without_approval`.
"""
from __future__ import annotations

import time
from typing import List, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P3"
TITLE = "Approval durability"

AFTER_RESTART_WAIT_S = 150.0


class Adapter(Protocol):
    name: str
    config: str

    def restart_kinds(self) -> List[str]: ...

    def request(self, action_id: str) -> None:
        """Start an action that requires approval."""
        ...

    def is_pending(self, action_id: str) -> bool: ...

    def restart(self, kind: str) -> None:
        """Restart and return once the product is serving again."""
        ...

    def approve(self, action_id: str) -> str:
        """Approve as the designated approver. Returns what the product said."""
        ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int:
        """How many times the action's side effect ran, read from the kit's recorder. Waits up
        to `wait_s` for the count to become non-zero, then a little longer for duplicates."""
        ...


def _classify(n: int) -> str:
    return {0: "lost", 1: "executed_once"}.get(n, "executed_twice" if n == 2 else f"executed_{n}x")


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    ctl = f"p3-ctl-{run_tag}"
    a.request(ctl)
    pending = a.is_pending(ctl)
    early = a.executions(ctl, wait_s=0)
    said = a.approve(ctl) if pending else "not pending"
    n = a.executions(ctl)
    ev.write("control.json", {"pending": pending, "executions_before_approval": early,
                              "approve_said": said, "executions": n})
    if not (pending and early == 0 and n == 1):
        return Result.inconclusive(a.name, ID, f"without any restart the approval path did not "
                                   f"behave (pending={pending}, before={early}, after={n})", **common)
    control = "with no restart: pending, not executed, approved, executed exactly once"

    checks: List[Check] = []
    for kind in a.restart_kinds():
        aid = f"p3-{kind}-{run_tag}"
        a.request(aid)
        pend = a.is_pending(aid)
        before = a.executions(aid, wait_s=0)
        if not pend:
            checks.append(Check(f"{kind}: setup", "not_pending", None, "action never became pending"))
            continue
        a.restart(kind)
        before_approve = a.executions(aid, wait_s=0)
        said = a.approve(aid)
        t0 = time.time()
        n = a.executions(aid, wait_s=AFTER_RESTART_WAIT_S)
        took = round(time.time() - t0, 1)
        if before or before_approve:
            outcome, ok = "executed_without_approval", False
        else:
            outcome, ok = _classify(n), n == 1
        ev.write(f"{kind}.json", {"pending_before_restart": pend, "executions_before_restart": before,
                                  "executions_after_restart_before_approve": before_approve,
                                  "approve_said": said, "executions": n, "outcome": outcome,
                                  "seconds_to_count": took, "waited_up_to_s": AFTER_RESTART_WAIT_S})
        checks.append(Check(f"restart {kind}", outcome, ok, f"{said} (counted after {took}s)"))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no restart kind could be exercised",
                                   checks=checks, control_held=True, control_detail=control, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="a pending approval survived every restart and executed exactly once",
                   fail_summary="approval not durable", **common)
