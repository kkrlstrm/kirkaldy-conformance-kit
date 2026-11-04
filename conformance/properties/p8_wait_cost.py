"""P8 — Wait cost.

**Question.** While approvals are pending, what does each one hold? A wait that holds a process,
a thread or an open connection costs something for as long as the human takes, and long waits
are the whole point of an approval.

**Protocol.**
1. Churn control: ask `is_pending` about actions that do not exist `2 × WAITS` times to warm
   whatever the status path uses, sample, ask `2 × WAITS` more times, sample again. If the probe's own calls grow the counters (a client that opens a connection
   per call and never closes it, say), the measurement would be of the probe, and the result is
   inconclusive. Found the hard way (KRK-M6): an adapter that opened a client per call made an
   engine look like it held connections for every wait. Only the second round is judged: some
   engines open a fixed set of connections to the service on the first status calls and then
   stop, which one round read as a leak (KRK-M14). A real per-call leak grows in both rounds.
2. Baseline: that second sample, the median of `SAMPLES`. It sums every container and host
   process the adapter names: processes, threads, established TCP connections, resident memory.
3. Open `WAITS` approvals, confirm every one is pending, hold for `HOLD_S` seconds, sample. Then
   open a second batch of `WAITS`, hold, sample again.
4. Control: every approval is still pending after the holds, and approving one executes it
   exactly once. A wait that quietly died holds nothing and would look free.
5. Judge the second batch: its growth divided by `WAITS`. The first batch's is recorded as
   information. A pool that starts threads on demand and keeps them (Python's default executor,
   which some engines' async waits use for short calls) grows during the first batch and then stops;
   dividing that by the waits read a fixed cost as a per-wait one (KRK-M14). A cost that
   really is per wait grows in both batches.

The hold is longer than the suspension timers products use, so the sample is of the settled
wait a human leaves behind, not of the first minute. An engine may keep an invocation's stream to
the service open until an inactivity timeout, then suspend it.

**Pass.** Per pending approval: under half a process, half a thread and half a connection (so
none of them grows with the number of waits), and under `MB_PER_WAIT` of memory. Memory is the
noisy one; the raw samples are kept so a reader can judge the margin.
"""
from __future__ import annotations

import statistics
import time
from typing import Dict, List, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P8"
TITLE = "Wait cost"

WAITS = 10       # per batch; two batches
HOLD_S = 75.0    # per batch; longer than common suspension timers (often 60 s by default)
SAMPLES = 3
MB_PER_WAIT = 5.0
COUNTED = ("processes", "threads", "connections")


class Adapter(Protocol):
    name: str
    config: str

    def request(self, action_id: str) -> None: ...

    def is_pending(self, action_id: str) -> bool: ...

    def approve(self, action_id: str) -> str: ...

    def executions(self, action_id: str, wait_s: float = 20.0) -> int: ...

    def resource_sample(self) -> Dict[str, float]:
        """{"processes", "threads", "connections", "rss_mb"} summed over everything the target
        runs. A key the adapter cannot measure is omitted, never reported as 0."""
        ...


def _median(samples: List[Dict[str, float]]) -> Dict[str, float]:
    keys = set.intersection(*(set(s) for s in samples)) if samples else set()
    return {k: statistics.median(s[k] for s in samples) for k in keys}


def _sample(a: Adapter) -> Dict[str, float]:
    out = []
    for _ in range(SAMPLES):
        out.append(a.resource_sample())
        time.sleep(1 if HOLD_S else 0)
    return _median(out)


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    quiet = _sample(a)
    for i in range(2 * WAITS):  # round 1 warms whatever pool the status path uses
        a.is_pending(f"p8-churn-a{i}-{run_tag}")
    warmed = _sample(a)
    for i in range(2 * WAITS):  # round 2 is judged
        a.is_pending(f"p8-churn-b{i}-{run_tag}")
    before = _sample(a)
    churn = {k: before[k] - warmed[k] for k in COUNTED if k in before and k in warmed}
    ev.write("churn-control.json", {"quiet": quiet, "after_round_1": warmed, "after_round_2": before,
                                    "growth_round_1": {k: warmed[k] - quiet[k] for k in COUNTED
                                                       if k in warmed and k in quiet},
                                    "growth": churn})
    noisy = {k: v for k, v in churn.items() if v >= 0.5 * WAITS}
    if noisy:
        return Result.inconclusive(a.name, ID, f"the probe's own status calls grew {noisy}; the "
                                   "adapter leaks per call, so per-wait numbers would measure it",
                                   **common)
    def open_batch(b: int) -> List[str]:
        ids = [f"p8-{b}{i:02d}-{run_tag}" for i in range(WAITS)]
        for aid in ids:
            a.request(aid)
        return ids

    first = open_batch(0)
    if [x for x in first if not a.is_pending(x)]:
        return Result.inconclusive(a.name, ID, f"approvals in the first batch of {WAITS} never "
                                   "became pending", **common)
    time.sleep(HOLD_S)
    mid = _sample(a)
    second = open_batch(1)
    if [x for x in second if not a.is_pending(x)]:
        return Result.inconclusive(a.name, ID, f"approvals in the second batch of {WAITS} never "
                                   "became pending", **common)
    time.sleep(HOLD_S)
    after = _sample(a)
    ids = first + second
    still = [x for x in ids if a.is_pending(x)]
    said = a.approve(ids[0]) if still and still[0] == ids[0] else "not pending"
    ran = a.executions(ids[0])
    ev.write("samples.json", {"before": before, "after_first_batch": mid, "after_second_batch": after,
                              "waits_per_batch": WAITS, "hold_s_per_batch": HOLD_S,
                              "still_pending": len(still), "approve_said": said, "executions": ran})
    if len(still) != len(ids) or ran != 1:
        return Result.inconclusive(a.name, ID, f"after the holds {len(still)} of {len(ids)} were "
                                   f"pending and approving one executed it {ran} time(s)", **common)
    control = (f"all {len(ids)} approvals were still pending after the holds, and approving one "
               f"executed it exactly once")

    checks: List[Check] = []
    for k in COUNTED:
        if k not in before or k not in mid or k not in after:
            checks.append(Check(k, "not measured", None, "the adapter cannot sample this"))
            continue
        per = (after[k] - mid[k]) / WAITS
        first_per = (mid[k] - before[k]) / WAITS
        checks.append(Check(f"{k} per wait", f"{per:+.2f}", per < 0.5,
                            f"{mid[k]:.0f} -> {after[k]:.0f} over the second {WAITS} waits "
                            f"(first {WAITS}: {before[k]:.0f} -> {mid[k]:.0f})"))
        checks.append(Check(f"{k} per wait, first batch", f"{first_per:+.2f}", None,
                            "information: includes pools that warm up once and stop growing"))
    if "rss_mb" in before and "rss_mb" in mid and "rss_mb" in after:
        per = (after["rss_mb"] - mid["rss_mb"]) / WAITS
        checks.append(Check("memory per wait", f"{per:+.2f} MB", per < MB_PER_WAIT,
                            f"{mid['rss_mb']:.1f} -> {after['rss_mb']:.1f} MB over the second "
                            f"{WAITS} waits (first: {before['rss_mb']:.1f} -> {mid['rss_mb']:.1f})"))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no resource could be measured", checks=checks,
                                   control_held=True, control_detail=control, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="a pending approval holds no process, thread or connection, and "
                                "little memory",
                   fail_summary="each pending approval holds resources", **common)
