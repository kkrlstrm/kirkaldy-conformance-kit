"""P11 — Concurrent executors.

**Question.** One action has been approved. Several executors (overlapping cron runs, two
workers on two hosts, an agent's parallel retries) each try to run it at the same moment. How
many times does the side effect happen?

**Protocol.**
1. For each executor kind the adapter offers (the product's plain execute call, the same call
   inside the product's claim primitive, an agent's retry): control first. Hold, approve, run a
   single executor of that kind, and confirm exactly one execution. Its execute step's
   duration is the yardstick for step 3. A kind that cannot run an approved action on its own
   is recorded as information; its silence under concurrency would mean nothing.
2. `ROUNDS` times per kind, on a fresh action: hold, approve, then start `N` executors of that
   kind on threads released together, each told to start its execute step at the same
   wall-clock moment (`start_at`), so executors that take time to launch still collide.
3. Concurrency has to be shown, not assumed. Each executor reports when its execute step
   began, measured where it runs (inside the executor process, after any launch cost), not when
   the probe's thread called it. A round counts only if every executor began within half the
   time one uncontended execution takes, so the last one began before the first could have
   finished. Thread start times cannot show this: an adapter that runs its executors one after
   another behind a lock still has threads that all start together, and a correct product's
   losing executors return at once, so "every thread still running" fails it. A round that
   does not count is recorded as information.
4. Count executions at the side-effect recorder. A race is probabilistic, so any overlapping
   round with a count other than one is a failure, and a kind passes only if every overlapping
   round produced exactly one.

**Outcomes per round.** `once` (pass), `none_ran` (fail: approved and never executed),
`ran_Nx` (fail).
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P11"
TITLE = "Concurrent executors"

N = 6
ROUNDS = 3
START_DELAY_S = 3.0
"""How far ahead of the threads' release the shared start moment is set. Long enough for a
process-per-executor adapter to start every process before it."""


class Adapter(Protocol):
    name: str
    config: str

    def executor_kinds(self) -> Dict[str, str]:
        """Kind -> one line on what an executor of this kind is in this product."""
        ...

    def hold(self, action_id: str, params=None) -> None: ...

    def is_pending(self, action_id: str) -> bool: ...

    def decide(self, action_id: str) -> str: ...

    def attempt_as(self, kind: str, action_id: str,
                   start_at: float = 0.0) -> Tuple[float, float, str]:
        """One executor of `kind` runs the approved action. Called from several threads at
        once. `start_at` is a wall-clock time the execute step should not begin before (0 =
        now). Returns (began, ended, said): when the execute step began and ended, as epoch
        seconds read inside the executor, and what the product said."""
        ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int: ...


def _concurrently(a: Adapter, kind: str, aid: str) -> Tuple[List[Tuple[float, float]], List[str]]:
    spans: List[Tuple[float, float]] = [(0.0, 0.0)] * N
    said: List[str] = [""] * N
    gate = threading.Barrier(N)
    start_at = time.time() + START_DELAY_S

    def one(i: int) -> None:
        gate.wait()
        try:
            began, ended, said[i] = a.attempt_as(kind, aid, start_at=start_at)
            spans[i] = (began, ended)
        except Exception as e:  # an executor that errors still took part, but has no times
            said[i] = f"raised {type(e).__name__}: {e}"

    threads = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(300)
    return spans, said


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    kinds = a.executor_kinds()
    ev.write("kinds.json", kinds)
    checks: List[Check] = []
    controls: Dict[str, str] = {}
    for kind in kinds:
        ctl = f"p11-{kind}-ctl-{run_tag}"
        a.hold(ctl)
        pending = a.is_pending(ctl)
        said, alone = "not pending", 0.0
        if pending:
            a.decide(ctl)
            began, ended, said = a.attempt_as(kind, ctl)
            alone = max(0.0, ended - began)
        n = a.executions(ctl)
        ev.write(f"{kind}-control.json", {"pending": pending, "said": said, "executions": n,
                                          "execute_step_s": round(alone, 3)})
        if not (pending and n == 1):
            checks.append(Check(kind, "control_failed", None,
                                f"a single executor of this kind ran it {n}x (pending={pending})"))
            continue
        controls[kind] = f"one executor ran it once, in a {alone:.2f}s execute step"
        rounds = []
        for r in range(1, ROUNDS + 1):
            aid = f"p11-{kind}-r{r}-{run_tag}"
            a.hold(aid)
            if not a.is_pending(aid):
                rounds.append({"round": r, "outcome": "setup_failed"})
                continue
            a.decide(aid)
            if a.executions(aid, wait_s=0):
                rounds.append({"round": r, "outcome": "ran_on_approval"})
                continue
            spans, said = _concurrently(a, kind, aid)
            began = [b for b, _ in spans if b]
            spread = (max(began) - min(began)) if len(began) == N else float("inf")
            overlapped = spread < alone / 2
            n = a.executions(aid)
            outcome = "once" if n == 1 else ("none_ran" if n == 0 else f"ran_{n}x")
            rounds.append({"round": r, "overlapped": overlapped, "executions": n,
                           "outcome": outcome, "said": said,
                           "began_spread_s": round(spread, 3), "alone_s": round(alone, 3),
                           "spans": [(round(b, 3), round(e, 3)) for b, e in spans]})
        ev.write(f"{kind}-rounds.json", rounds)
        real = [x for x in rounds if x.get("overlapped")]
        if not real:
            spreads = ", ".join(f"{x.get('began_spread_s')}s" for x in rounds)
            checks.append(Check(kind, "executors never overlapped", None,
                                f"in no round did every executor begin within {alone / 2:.2f}s "
                                f"of the first (spread per round: {spreads}), so no race was "
                                f"tested"))
            continue
        bad = [x for x in real if x["outcome"] != "once"]
        tally = ", ".join(f"r{x['round']}:{x['outcome']}" for x in real)
        if bad:
            checks.append(Check(kind, bad[0]["outcome"], False,
                                f"{N} concurrent executors, {len(real)} overlapping rounds: {tally}"))
        else:
            checks.append(Check(kind, "once", True,
                                f"{N} concurrent executors, {len(real)} overlapping rounds: {tally}"))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no executor kind could be raced against itself",
                                   checks=checks, control_held=bool(controls),
                                   control_detail="; ".join(f"{k}: {v}" for k, v in controls.items())
                                   or "no kind ran an approved action on its own", **common)
    control = "; ".join(f"{k}: {v}" for k, v in controls.items())
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary=f"{N} concurrent executors of one approved action produced exactly "
                                f"one side effect in every overlapping round",
                   fail_summary="concurrent executors did not produce exactly one side effect",
                   **common)
