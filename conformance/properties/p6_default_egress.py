"""P6 — Default egress.

**Question.** A fresh sandbox with no network policy set: what can code inside it reach?

**Protocol.**
1. Control: the kit's listener (HTTP and raw TCP) is reachable from the host. If the host can't
   reach it, a blocked connection from the sandbox means nothing.
2. Baseline, per attempt: run the same attempt from an unsandboxed reference environment on
   the same host (a plain container). An attempt that fails there too says nothing about the
   sandbox: the network path does not exist on this machine. It is recorded as informational,
   never as "blocked". (Found the hard way: on the dev machine plain containers cannot resolve
   public names at all, so every sandbox looked like it blocked public egress.)
3. Create a sandbox with the product's defaults. From inside, run each attempt: HTTP to the
   listener, raw TCP to the listener, a DNS lookup of a public name, HTTPS to a public site.
4. The listener's own records decide the HTTP and TCP checks. What the command printed is
   kept as evidence only, because a sandbox can fake a client-side error.

**Pass.** Nothing got out: no connection reached the listener and public DNS/HTTPS failed.
The bar is deny-by-default. A vendor that intends open egress fails this bar on purpose; the
result records the vendor's stated default beside the measurement so a reader can tell
"documented and open" from "undocumented and open".
"""
from __future__ import annotations

from typing import Dict, List, Protocol, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P6"
TITLE = "Default egress"


class Adapter(Protocol):
    name: str
    config: str

    def listener_reachable_from_host(self) -> Tuple[bool, str]: ...

    def create_default_sandbox(self) -> None: ...

    def egress_attempts(self) -> Dict[str, str]:
        """Attempt name -> shell command (or code) the adapter runs inside the sandbox."""
        ...

    def baseline(self, attempt: str) -> Tuple[bool, str]:
        """Run `attempt` from an unsandboxed reference environment on the same host. Returns
        (got_out, detail). Optional: without it every attempt is judged as if its path exists."""
        ...

    def run_inside(self, attempt: str) -> Tuple[int, str]:
        """Run one attempt inside the sandbox. Returns (exit code, combined output)."""
        ...

    def listener_saw(self, attempt: str) -> bool:
        """Did the kit's listener record a connection tagged for `attempt`?
        Return False for attempts that do not target the listener."""
        ...

    def destroy_sandbox(self) -> None: ...


PUBLIC_ATTEMPTS = ("dns_public", "https_public")
"""Attempts judged by the command's own success, since the kit owns no public endpoint."""


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    reach, how = a.listener_reachable_from_host()
    ev.write("control.json", {"listener_reachable_from_host": reach, "detail": how})
    if not reach:
        return Result.inconclusive(a.name, ID, f"the listener is not reachable from the host: {how}",
                                   **common)
    control = "the listener was reachable from the host over HTTP and raw TCP"

    attempts = a.egress_attempts()
    baselines: Dict[str, Tuple[bool, str]] = {}
    if hasattr(a, "baseline"):
        for attempt in attempts:
            baselines[attempt] = a.baseline(attempt)
        ev.write("baseline.json", {k: {"got_out": v[0], "detail": v[1]} for k, v in baselines.items()})

    a.create_default_sandbox()
    sandbox_control = getattr(a, "sandbox_control", lambda: None)()
    if sandbox_control is not None:
        ev.write("sandbox-control.json", sandbox_control)
        if not sandbox_control.get("outside_write_blocked"):
            a.destroy_sandbox()
            return Result.inconclusive(a.name, ID, "the outside-workspace write was not blocked; "
                                       "the requested sandbox was not proven active", **common)
    # The listener must not already show an attempt before the sandbox has run anything. If the
    # baseline (or an earlier run) used the same tag and nothing cleared the listener, a record
    # cannot be attributed to the sandbox, and "egress allowed" would be the host's own request
    # (KRK-M16). Refuse a verdict rather than guess.
    stale = [x for x in attempts if x not in PUBLIC_ATTEMPTS and a.listener_saw(x)]
    if stale:
        ev.write("listener-precheck.json", {"already_seen_before_sandbox_ran": stale})
        a.destroy_sandbox()
        return Result.inconclusive(
            a.name, ID, "the listener already recorded " + ", ".join(stale) + " before the sandbox "
            "ran; a sandbox request cannot be told from the baseline's (tag sandbox and baseline "
            "probes differently, or reset the listener in create_default_sandbox)", **common)
    checks: List[Check] = []
    try:
        for attempt, cmd in attempts.items():
            code, out = a.run_inside(attempt)
            if attempt in PUBLIC_ATTEMPTS:
                got_out = code == 0
            else:
                got_out = a.listener_saw(attempt)
            ev.write(f"{attempt}.json", {"command": cmd, "exit": code, "output": out[-4000:],
                                         "got_out": got_out})
            base_ok = baselines.get(attempt, (True, ""))[0]
            if got_out and attempt in PUBLIC_ATTEMPTS and not base_ok:
                # The host itself has no path, so a "success" inside the sandbox is the adapter's
                # exit code, not egress (KRK-M17: an adapter returned 0 on a "still running" stub).
                checks.append(Check(attempt, "sandbox reported success where the host has no "
                                    "path; not counted (check the adapter's exit code)", None,
                                    out.strip()[-160:]))
            elif got_out:
                checks.append(Check(attempt, "egress allowed", False, out.strip()[-200:]))
            elif not base_ok:
                checks.append(Check(attempt, "no path on this host (baseline failed too)", None,
                                    baselines[attempt][1][-160:]))
            else:
                checks.append(Check(attempt, "blocked", True, out.strip()[-200:]))
    finally:
        a.destroy_sandbox()
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no egress attempt had a working baseline path",
                                   checks=checks, control_held=True, control_detail=control, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="default-deny: nothing left the fresh sandbox",
                   fail_summary="egress open by default", **common)
