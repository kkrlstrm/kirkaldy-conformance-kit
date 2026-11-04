"""P9 — Grant validity at execution.

**Question.** A human approved an action. Before it runs, the approval stops being valid: its
time limit passes, it is revoked, or the approver loses the standing to give it. Does the action
still run?

**Protocol.**
1. Control: hold an action, record the designated approver's approval, confirm the approval
   alone ran nothing, then run the target's execute path once and confirm exactly one
   execution. This proves the decision step and the execute step are the real ones, and that
   they are separate, so an approval can be invalidated between them.
2. For each invalidation the adapter can express, on a fresh action: hold, approve, confirm
   nothing ran, invalidate, then run the execute path `ATTEMPTS` times.
   - `expired`: wait until the approval's time limit, measured from the human decision, has
     passed (`grant_ttl_s()` plus `MARGIN_S`). A limit that restarts every time a scheduler
     pass re-derives the grant is not a limit on the approval, and this variant is built to
     show the difference. When the adapter shortens the limit for this variant
     (`prepare_variant`), an approval used inside the shortened limit must still execute in
     that configuration; otherwise a later refusal could come from the reconfiguration, not
     the expiry, and the variant is recorded as information.
   - `revoked`: the product's revocation. Where it has none, the adapter says what it uses
     instead (usually the approver retracting their answer in the channel they gave it).
   - `standing_withdrawn`: the approver is removed from the configuration that gives them
     standing, after they approved and before the action runs.
   A revocation or withdrawal is applied `SETTLE_S` after the decision, not in the same
   instant. Applied at once, it lands in the same second as the decision, and a product that
   identifies a reply by a one-second timestamp treats the retraction as the approval again;
   the probe would then report that revocation is ignored, when what it found is the clock's
   resolution (KRK-M15).
3. Run the execute path more than once. A product can refuse the first attempt after a grant
   lapses (a stored envelope has expired) and derive a fresh grant from the same old decision
   on the next pass. One attempt reads that as refused.
4. Count executions at the side-effect recorder, not by asking the product.
5. A refusal counts only if it came from the guarantee under test. An adapter can say an
   attempt was stopped by something else (`reached_guarantee()`, as in P4); that attempt is
   information, not evidence.

**Outcomes per variant.** `refused` (pass), `executed` (fail, with the attempt that ran it).
A variant the target cannot express is recorded as information, never as a pass.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P9"
TITLE = "Grant validity at execution"

VARIANTS = ("expired", "revoked", "standing_withdrawn")
ATTEMPTS = 2
MARGIN_S = 2.0
SETTLE_S = 2.0


class Adapter(Protocol):
    name: str
    config: str

    def grant_variants(self) -> Dict[str, str]:
        """Variant (one of VARIANTS) -> how this target expresses it."""
        ...

    def grant_variants_missing(self) -> Dict[str, str]:
        """Optional. Variant -> why this target cannot express it."""
        ...

    def hold(self, action_id: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Request an action that needs approval. Nothing runs."""
        ...

    def is_pending(self, action_id: str) -> bool: ...

    def decide(self, action_id: str) -> str:
        """The designated approver approves. Nothing runs."""
        ...

    def attempt(self, action_id: str) -> str:
        """One pass of the path that runs approved actions (a scheduler tick, an agent's
        retry). Returns what the product said."""
        ...

    def grant_ttl_s(self) -> float:
        """The time limit, in seconds, the target puts on an approval in the configuration the
        `expired` variant runs under. 0 if it has none."""
        ...

    def invalidate(self, variant: str, action_id: str) -> str:
        """Revoke the approval, or withdraw the approver's standing. Returns what was done."""
        ...

    def prepare_variant(self, variant: str) -> None:
        """Optional. Configure the target for a variant (a short time limit)."""
        ...

    def restore_variant(self, variant: str) -> None:
        """Optional. Undo prepare_variant, and any configuration change invalidate made."""
        ...

    def elapse(self, seconds: float) -> None:
        """Optional. Let `seconds` pass for the target. Defaults to sleeping."""
        ...

    def reached_guarantee(self, variant: str, product_said: str) -> bool:
        """Optional. False if a refusal came from something other than the invalidation."""
        ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int: ...


def _run(a: Adapter, aid: str) -> Dict[str, Any]:
    """Hold, approve, and confirm the approval alone ran nothing."""
    a.hold(aid)
    if not a.is_pending(aid):
        return {"ok": False, "why": "action never became pending"}
    said = a.decide(aid)
    early = a.executions(aid, wait_s=0)
    if early:
        return {"ok": False, "why": f"the approval alone ran it ({early}x), so nothing can be "
                                    f"invalidated between approval and execution",
                "decide_said": said}
    return {"ok": True, "decide_said": said}


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    elapse = getattr(a, "elapse", time.sleep)
    reached = getattr(a, "reached_guarantee", lambda v, s: True)

    ctl = f"p9-ctl-{run_tag}"
    setup = _run(a, ctl)
    said = a.attempt(ctl) if setup["ok"] else ""
    n = a.executions(ctl)
    ev.write("control.json", {**setup, "attempt_said": said, "executions": n})
    if not (setup["ok"] and n == 1):
        return Result.inconclusive(a.name, ID, f"with nothing invalidated the approval path did "
                                   f"not behave ({setup.get('why') or f'executions={n}'})", **common)
    control = ("with nothing invalidated: pending, not run by the approval alone, executed "
               "exactly once by the execute path")

    checks: List[Check] = []
    variants = a.grant_variants()
    missing = getattr(a, "grant_variants_missing", dict)()
    ev.write("variants.json", {"expressed": variants, "missing": missing})
    for v, why in missing.items():
        checks.append(Check(v, "not_expressible", None, why))
    prep = getattr(a, "prepare_variant", None)
    restore = getattr(a, "restore_variant", None)
    for v in VARIANTS:
        if v not in variants:
            continue
        if prep:
            prep(v)
        try:
            obs: Dict[str, Any] = {"how": variants[v]}
            if v == "expired":
                ttl = float(a.grant_ttl_s() or 0)
                obs["ttl_s"] = ttl
                if ttl <= 0:
                    checks.append(Check(v, "no_time_limit", None,
                                        "the target reports no time limit on an approval"))
                    ev.write(f"{v}.json", obs)
                    continue
                inside = f"p9-{v}-inside-{run_tag}"
                s = _run(a, inside)
                obs["inside_limit"] = {**s, "attempt_said": a.attempt(inside) if s["ok"] else "",
                                       "executions": a.executions(inside)}
                if obs["inside_limit"]["executions"] != 1:
                    checks.append(Check(v, "control_failed", None,
                                        "in the configuration with the short limit, an approval "
                                        "used inside the limit did not execute once, so a refusal "
                                        "after it would not be evidence"))
                    ev.write(f"{v}.json", obs)
                    continue
            aid = f"p9-{v}-{run_tag}"
            s = _run(a, aid)
            obs["setup"] = s
            if not s["ok"]:
                checks.append(Check(v, "setup_failed", None, s["why"]))
                ev.write(f"{v}.json", obs)
                continue
            t_decided = time.time()
            if v == "expired":
                elapse(obs["ttl_s"] + MARGIN_S)
                obs["invalidated"] = (f"waited {obs['ttl_s'] + MARGIN_S:g}s after the decision "
                                      f"(limit {obs['ttl_s']:g}s)")
            else:
                elapse(SETTLE_S)
                obs["invalidated"] = f"after {SETTLE_S:g}s: {a.invalidate(v, aid)}"
            tries = []
            for i in range(ATTEMPTS):
                out = a.attempt(aid)
                tries.append({"attempt": i + 1, "said": out,
                              "seconds_after_decision": round(time.time() - t_decided, 1),
                              "executions_so_far": a.executions(aid, wait_s=0)})
            n = a.executions(aid)
            obs.update({"attempts": tries, "executions": n})
            ev.write(f"{v}.json", obs)
            if n:
                first = next((t["attempt"] for t in tries if t["executions_so_far"]), ATTEMPTS)
                checks.append(Check(v, f"executed (attempt {first} of {ATTEMPTS})", False,
                                    f"{obs['invalidated']}; then: {tries[first - 1]['said'][:200]}"))
            elif not all(reached(v, t["said"]) for t in tries):
                checks.append(Check(v, "stopped before the guarantee", None,
                                    f"refused for an unrelated reason, so not evidence: "
                                    f"{tries[-1]['said'][:200]}"))
            else:
                checks.append(Check(v, f"refused x{ATTEMPTS}", True,
                                    f"{obs['invalidated']}; then: {tries[-1]['said'][:200]}"))
        finally:
            if restore:
                restore(v)
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no invalidation could be exercised",
                                   checks=checks, control_held=True, control_detail=control,
                                   **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="no approval that had expired, been revoked or lost its "
                                "approver's standing resulted in execution",
                   fail_summary="an invalidated approval still executed", **common)
