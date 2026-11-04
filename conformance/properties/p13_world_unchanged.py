"""P13 — World unchanged at execution.

**Question.** A human approved an action while the world it acts on was in one state: the record
it writes to had certain contents, the recipient was not suppressed, the item existed. Before the
action runs, that state changes outside the product. Does the action still run, against a world
the approver never saw?

P10 asks whether the *call* changed after approval and P9 whether the *grant* lapsed. This asks
about the third thing an approval rests on: the state of the world outside the product. A product
that replays recorded decisions and never re-reads outside state (the usual durable-execution
contract) is expected to fail here by design; where the re-read has to live is then the finding.

**Variants.**
- `target_changed`: the object the action acts on is modified by someone else after the
  approval (another writer updates the record), so the action would act on contents the approver
  did not see.
- `precondition_false`: a fact the approval rested on becomes false after the approval (the
  recipient is added to a suppression list, the account is closed).

**Protocol.**
1. Control, the execute path is real: prepare a fresh world, hold the action, approve it, run
   the execute path, and confirm exactly one execution at the side-effect recorder.
2. For each variant, confirm the changed world does not by itself stop the action: prepare a
   fresh world, apply the change, then hold, approve and run. The approval now rests on the
   changed world, so the action should run once. If it does not, a refusal under the stale
   approval would come from the change itself (the record is gone, the write is invalid), not
   from a re-read, and the variant is recorded as information (KRK-M10, refused for the wrong
   reason).
3. For each variant, on a fresh world: hold, approve, confirm nothing ran, apply the change
   outside the product, then run the execute path `ATTEMPTS` times. A product may refuse the
   first attempt and run the second.
4. Count executions at the recorder and ask whether the action is pending again.

**Outcomes per variant.** `refused` and `asked_again` (pass): the product stopped, or put the
action back in front of a person. `ran_on_changed_world` (fail): it ran under an approval given
for a world that no longer exists.
"""
from __future__ import annotations

from typing import Dict, List, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P13"
TITLE = "World unchanged at execution"

VARIANTS = ("target_changed", "precondition_false")
ATTEMPTS = 2


class Adapter(Protocol):
    name: str
    config: str

    def world_variants(self) -> Dict[str, str]:
        """Variant (one of VARIANTS) -> how this target's world is changed for it."""
        ...

    def world_variants_missing(self) -> Dict[str, str]:
        """Optional. Variant -> why this target cannot express it."""
        ...

    def prepare_world(self, action_id: str) -> str:
        """Create the outside state this action will act on, fresh for this id. Returns what
        was created."""
        ...

    def change_world(self, variant: str, action_id: str) -> str:
        """Change that outside state by the path `variant` names, as a writer other than the
        product would. Returns what was done."""
        ...

    def hold(self, action_id: str) -> None: ...

    def is_pending(self, action_id: str) -> bool: ...

    def decide(self, action_id: str) -> str: ...

    def attempt(self, action_id: str) -> str: ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int: ...

    def reached_guarantee(self, variant: str, product_said: str) -> bool:
        """Optional. False if a refusal came from something other than re-reading the world."""
        ...


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    reached = getattr(a, "reached_guarantee", lambda v, s: True)

    def straight_run(aid: str, change_first: str = "") -> Dict[str, object]:
        made = a.prepare_world(aid)
        changed = a.change_world(change_first, aid) if change_first else ""
        a.hold(aid)
        pending = a.is_pending(aid)
        said = a.decide(aid) if pending else "not pending"
        ran = a.attempt(aid) if pending else ""
        return {"world": made, "changed_first": changed, "pending": pending,
                "decide_said": said, "attempt_said": ran, "executions": a.executions(aid)}

    ctl = straight_run(f"p13-ctl-{run_tag}")
    ev.write("control.json", ctl)
    if not (ctl["pending"] and ctl["executions"] == 1):
        return Result.inconclusive(a.name, ID, f"holding, approving and running an action in an "
                                   f"unchanged world did not execute it exactly once "
                                   f"({ctl['executions']} executions)", **common)
    control = "an approved action in an unchanged world ran exactly once"

    checks: List[Check] = []
    variants = a.world_variants()
    missing = getattr(a, "world_variants_missing", dict)()
    ev.write("variants.json", {"expressed": variants, "missing": missing})
    for v, why in missing.items():
        checks.append(Check(v, "not_expressible", None, why))
    for v in VARIANTS:
        if v not in variants:
            continue
        own = straight_run(f"p13-{v}-after-{run_tag}", change_first=v)
        ev.write(f"{v}-approved-after-change.json", own)
        if own["executions"] != 1:
            checks.append(Check(v, "changed world blocks the action even when approved", None,
                                f"approved after the change it ran {own['executions']} times, so "
                                f"a refusal under the earlier approval would not show a re-read"))
            continue
        aid = f"p13-{v}-{run_tag}"
        made = a.prepare_world(aid)
        a.hold(aid)
        if not a.is_pending(aid):
            checks.append(Check(v, "setup_failed", None, "action never became pending"))
            continue
        decided = a.decide(aid)
        if a.executions(aid):
            checks.append(Check(v, "ran_before_change", None,
                                "the approval alone ran the action, so the world could not be "
                                "changed between approval and execution"))
            continue
        how = a.change_world(v, aid)
        tries = [a.attempt(aid) for _ in range(ATTEMPTS)]
        n = a.executions(aid)
        again = a.is_pending(aid)
        ev.write(f"{v}.json", {"world": made, "decide_said": decided, "change": how,
                               "attempts": tries, "executions": n, "pending_again": again})
        if n:
            checks.append(Check(v, "ran_on_changed_world", False,
                                f"{how}; ran {n}x under the approval given before the change"))
        elif again:
            checks.append(Check(v, "asked_again", True,
                                f"{how}; the action went back to pending: {tries[-1][:200]}"))
        elif not all(reached(v, t) for t in tries):
            checks.append(Check(v, "stopped before the guarantee", None,
                                f"refused for an unrelated reason, so not evidence: {tries[-1][:200]}"))
        else:
            checks.append(Check(v, "refused", True, f"{how}; then: {tries[-1][:200]}"))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no change to the world could be exercised",
                                   checks=checks, control_held=True, control_detail=control,
                                   **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="no action ran in a world that changed after its approval",
                   fail_summary="an action ran in a world that changed after its approval",
                   **common)
