"""P5 — Self-widening.

**Question.** Holding only an agent-scoped credential, can the agent widen its own grant?

**Protocol.**
1. Snapshot the agent's effective grant, read with an admin credential.
2. Control: an admin performs each widening operation against a throwaway principal and it
   succeeds. This proves each operation is real on this build. An operation the admin cannot
   perform either is dropped from the probe, never counted as a pass.
3. The agent attempts each operation with its own credential: mint a broader key, edit its own
   policy or limits, call admin tools, add a model or tool to its own allowlist, re-delegate
   with wider scope.
4. Re-read the agent's grant. A success the product reported as an error still counts if the
   grant changed, and an "OK" that changed nothing does not.

**Pass.** No attempt widened anything.
"""
from __future__ import annotations

from typing import Any, Dict, List, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P5"
TITLE = "Self-widening"


class Adapter(Protocol):
    name: str
    config: str

    def widening_operations(self) -> List[str]: ...

    def as_admin(self, op: str) -> Tuple[bool, str]:
        """Perform `op` with admin credentials against a throwaway principal.
        Returns (succeeded, detail)."""
        ...

    def as_agent(self, op: str) -> Tuple[bool, str]:
        """Attempt `op` with the agent's credential. Returns (product_reported_success, detail).
        "Success" means the product accepted it AND it produced the widened thing (a key that
        works, a policy that changed); the adapter verifies that, not the status code alone."""
        ...

    def agent_grant(self) -> Dict[str, Any]:
        """The agent's effective grant, read with admin credentials."""
        ...


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    before = a.agent_grant()
    ev.write("grant-before.json", before)

    usable, ctl_notes = [], {}
    for op in a.widening_operations():
        ok, detail = a.as_admin(op)
        ctl_notes[op] = {"admin_succeeded": ok, "detail": detail}
        if ok:
            usable.append(op)
    ev.write("control.json", ctl_notes)
    if not usable:
        return Result.inconclusive(a.name, ID, "no widening operation succeeded even for an admin, "
                                   "so the probe exercised nothing", **common)
    control = f"an admin could perform {len(usable)} of {len(ctl_notes)} operations: {', '.join(usable)}"

    checks: List[Check] = []
    for op in usable:
        ok, detail = a.as_agent(op)
        ev.write(f"agent-{op}.txt", detail)
        checks.append(Check(op, "widened" if ok else "refused", not ok, detail[:300]))
    after = a.agent_grant()
    ev.write("grant-after.json", after)
    if after != before:
        checks.append(Check("grant unchanged", "grant changed", False,
                            "the agent's effective grant differs after the attempts"))
    else:
        checks.append(Check("grant unchanged", "unchanged", True))
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="the agent could not widen its own grant",
                   fail_summary="the agent widened its own grant", **common)
