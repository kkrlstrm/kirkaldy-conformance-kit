"""P1 — Failure direction.

**Question.** When the component that decides whether a request is allowed cannot be reached,
does the product block the request (fail closed) or let it through (fail open)?

**Protocol.**
1. Control, with the decider healthy: a request the policy allows reaches the upstream, and a
   request the policy denies does not. If either is false, the probe never exercised the
   policy and the result is inconclusive.
2. For each failure mode the adapter can induce (decider stopped, decider slow past timeout,
   policy malformed): confirm the decider is actually unreachable, send every kind of denied
   request the adapter can express (an unknown key, a valid key asking for something it was
   not granted) `REPEATS` times each, then the allowed request, restore.
   Repeats matter: a product may refuse the first request while it notices the outage and
   fail open from the second on. A single attempt reads that as fail-closed.
3. The upstream mock is the ground truth. A denied request that reached it got through,
   whatever status code the client saw.
4. After every mode is restored, wait `LATE_S` and check every denied request again. A request
   held while the decider was paused can be released when it comes back; checking only at the
   moment the client gave up would read a late fail-open as fail-closed.

**Pass.** No denied request reached the upstream in any mode. Allowed requests failing during
an outage is availability, recorded but not judged.
"""
from __future__ import annotations

import time
from typing import List, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P1"
TITLE = "Failure direction"

REPEATS = 3
LATE_S = 8.0


class Adapter(Protocol):
    name: str
    config: str

    def failure_modes(self) -> List[str]:
        """Which ways of making the decider unreachable this adapter can induce."""
        ...

    def denied_kinds(self) -> List[str]:
        """Kinds of request the policy denies, e.g. ["denied:unknown-key",
        "denied:ungranted-model"]. Optional; defaults to ["denied"]."""
        ...

    def send(self, kind: str, marker: str) -> str:
        """Send a request of `kind` ("allowed" or one of denied_kinds()) tagged with `marker` so the upstream
        record can be matched to it. Returns a short description of what the client saw."""
        ...

    def upstream_received(self, marker: str) -> bool: ...

    def induce(self, mode: str) -> None: ...

    def restore(self, mode: str) -> None: ...

    def decider_reachable(self) -> bool:
        """Independent check, not via the product: is the decider up?"""
        ...


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    checks: List[Check] = []

    # 1 — control
    if not a.decider_reachable():
        return Result.inconclusive(a.name, ID, "decider not reachable before the probe began", **common)
    denied = list(getattr(a, "denied_kinds", lambda: ["denied"])())
    m_allow = f"p1-ctl-allow-{run_tag}"
    seen_allow = a.send("allowed", m_allow)
    allow_ok = a.upstream_received(m_allow)
    ctl = {"allowed": {"client_saw": seen_allow, "reached_upstream": allow_ok}}
    leaked = []
    for kind in denied:
        m = f"p1-ctl-{kind.replace(':', '-')}-{run_tag}"
        saw = a.send(kind, m)
        got = a.upstream_received(m)
        ctl[kind] = {"client_saw": saw, "reached_upstream": got}
        if got:
            leaked.append(kind)
    ev.write("control.json", ctl)
    if not allow_ok or leaked:
        why = ("allowed request never reached the upstream" if not allow_ok
               else f"denied requests {leaked} reached the upstream with the decider healthy, so "
                    f"the policy was never in force")
        return Result.inconclusive(a.name, ID, why, checks=checks, **common)
    control = (f"with the decider up, the allowed request reached the upstream and none of "
               f"{denied} did")

    # 2 — each failure mode
    denied_markers: List[tuple] = []
    modes = a.failure_modes()
    if not modes:
        return Result.inconclusive(a.name, ID, "adapter can induce no failure mode", **common)
    for mode in modes:
        a.induce(mode)
        try:
            if a.decider_reachable():
                checks.append(Check(f"{mode}: induce", "decider_still_reachable", None,
                                    "failure was not induced; mode skipped"))
                ev.write(f"{mode}.json", {"skipped": "decider still reachable after induce"})
                continue
            obs = {}
            for kind in denied:
                tried = []
                for i in range(REPEATS):
                    m = f"p1-{mode}-{kind.replace(':', '-')}-{i}-{run_tag}"
                    denied_markers.append((mode, kind, m))
                    saw = a.send(kind, m)
                    tried.append({"client_saw": saw, "reached_upstream": a.upstream_received(m)})
                obs[kind] = tried
                through = [i + 1 for i, t in enumerate(tried) if t["reached_upstream"]]
                checks.append(Check(f"{mode}: {kind}",
                                    f"reached upstream on attempt {through} (fail open)" if through
                                    else f"blocked x{REPEATS}",
                                    not through, "; ".join(t["client_saw"][:80] for t in tried)))
            ma = f"p1-{mode}-allow-{run_tag}"
            saw_a = a.send("allowed", ma)
            got_a = a.upstream_received(ma)
            obs["allowed"] = {"client_saw": saw_a, "reached_upstream": got_a}
            ev.write(f"{mode}.json", obs)
            checks.append(Check(f"{mode}: allowed request",
                                "served" if got_a else "refused (availability)", None, saw_a[:120]))
        finally:
            a.restore(mode)
    # 3 — late arrivals
    if denied_markers:
        time.sleep(LATE_S)
        flagged = {c.name for c in checks if c.ok is False}
        late = [(mode, kind, m) for mode, kind, m in denied_markers
                if f"{mode}: {kind}" not in flagged and a.upstream_received(m)]
        ev.write("late-arrivals.json", [m for _, _, m in late])
        for mode, kind, m in late:
            checks.append(Check(f"{mode}: {kind} (late)", "reached upstream after the outage",
                                False, f"{m} arrived after the probe had recorded it as blocked"))
    induced = [c for c in checks if c.ok is not None]
    if not induced:
        return Result.inconclusive(a.name, ID, "no failure mode could actually be induced",
                                   checks=checks, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="fails closed: no denied request reached the upstream while the "
                                "decider was unreachable",
                   fail_summary="fails open", **common)
