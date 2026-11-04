"""P7 — Actor in audit.

**Question.** The same action is performed by a human and by an agent. Can the audit record
tell which one acted? And when the agent acts with the human's own session or credential,
can it still?

**Protocol.**
1. Perform the action twice as the human and twice as the agent, each run tagged. If the
   adapter supports it, twice more as the agent *using the human's session*.
2. Control: every action actually happened (its side effect is visible). Otherwise there is
   nothing to audit and the result is inconclusive.
3. Read the audit record for each run and flatten it into field -> value.
4. Fields that differ between two runs by the *same* actor are noise (timestamps, ids, the
   tag) and are discarded. What is left and differs between actors is attribution. The runs
   are interleaved across actors so that a monotonic field (a coarse timestamp) can never look
   stable within an actor and different between actors.

The adapter never says which field identifies the actor; the probe infers it. An adapter that
named its own attribution field could point at one that happens to differ and call it a pass.

**Agent in the human's session.** The agent acts with the human's credential *through the
product's own delegation mechanism if it has one* (token exchange with an actor claim, an
on-behalf-of mode). The adapter declares which case applies:

- `none` — the product offers no way for an agent to act for a human except by using the
  human's credential. That reuse is what is judged, because it is the only path there is.
- `exercised` — the adapter drives the product's delegation mechanism; that is judged.
- `exists-not-exercised: <why>` — a mechanism exists but could not be driven here (it needs a
  third-party identity provider, say). Bare reuse is still recorded, as information only, and
  the property cannot pass: the result is inconclusive unless something else failed.

**Pass.** Human and agent are distinguishable, and (where expressible) so are human and agent
in the human's session. An action that produced no audit record at all fails.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P7"
TITLE = "Actor in audit"

ACTORS = ("human", "agent", "agent_in_human_session")


class Adapter(Protocol):
    name: str
    config: str

    def actors(self) -> List[str]:
        """Subset of ACTORS this adapter can express. Must include "human" and "agent"."""
        ...

    def act(self, actor: str, marker: str) -> None: ...

    def happened(self, marker: str) -> bool: ...

    def audit_record(self, marker: str) -> Optional[Dict[str, Any]]:
        """The product's own audit record for the tagged action, or None if it wrote none."""
        ...

    def delegation_mechanism(self) -> str:
        """"none", "exercised", or "exists-not-exercised: <why>". Optional; default "none"."""
        ...


def flatten(obj: Any, prefix: str = "") -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = "" if obj is None else str(obj)
    return out


def _noise(a: Dict[str, str], b: Dict[str, str]) -> set:
    return {k for k in set(a) | set(b) if a.get(k) != b.get(k)}


def attribution_fields(x1: Dict[str, str], x2: Dict[str, str],
                       y1: Dict[str, str], y2: Dict[str, str]) -> List[str]:
    """Fields stable within actor X and within actor Y that differ between X and Y."""
    noise = _noise(x1, x2) | _noise(y1, y2)
    return sorted(k for k in set(x1) | set(y1) if k not in noise and x1.get(k) != y1.get(k))


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    actors = [x for x in ACTORS if x in a.actors()]
    if "human" not in actors or "agent" not in actors:
        return Result.inconclusive(a.name, ID, "adapter cannot express both a human and an agent "
                                   "performing the same action", **common)
    runs: Dict[str, List[str]] = {x: [f"p7-{x}-{i}-{run_tag}" for i in (1, 2)] for x in actors}
    # Interleaved, not grouped: human 1, agent 1, ..., then human 2, agent 2, .... For any field
    # that only moves forward (a timestamp at any resolution, a sequence number) this guarantees
    # that if it differs between human 1 and agent 1, it also differs between human 1 and
    # human 2, so it is discarded as noise. Grouped runs let a one-second timestamp that ticked
    # between the two actors pass as the field that identifies them (KRK-M8: the verdict then
    # depended on where the second boundary fell).
    for i in range(2):
        for x in actors:
            a.act(x, runs[x][i])
    missing = [m for ms in runs.values() for m in ms if not a.happened(m)]
    if missing:
        return Result.inconclusive(a.name, ID, f"actions did not happen: {missing}", **common)
    control = f"all {sum(len(v) for v in runs.values())} tagged actions happened"

    recs: Dict[str, Dict[str, str]] = {}
    checks: List[Check] = []
    for x, markers in runs.items():
        for m in markers:
            r = a.audit_record(m)
            ev.write(f"audit-{m}.json", r if r is not None else {"audit_record": None})
            if r is None:
                checks.append(Check(f"{m}: audit record", "none written", False,
                                    "the action left no audit record"))
            else:
                recs[m] = flatten(r)
    if any(c.ok is False for c in checks):
        return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                       pass_summary="", fail_summary="actions without an audit record", **common)

    def compare(x: str, y: str) -> Check:
        fields = attribution_fields(recs[runs[x][0]], recs[runs[x][1]],
                                    recs[runs[y][0]], recs[runs[y][1]])
        detail = ("distinguished by " + ", ".join(
            f"{f}: {recs[runs[x][0]].get(f, '∅')!r} vs {recs[runs[y][0]].get(f, '∅')!r}"
            for f in fields[:4])) if fields else "no stable field differs between them"
        return Check(f"{x} vs {y}", "distinguishable" if fields else "indistinguishable",
                     bool(fields), detail)

    checks.append(compare("human", "agent"))
    mech = str(getattr(a, "delegation_mechanism", lambda: "none")())
    unexercised = mech.startswith("exists-not-exercised")
    if "agent_in_human_session" in actors:
        c = compare("human", "agent_in_human_session")
        if unexercised:
            c = Check(c.name + " (bare credential reuse)", c.outcome, None,
                      f"information only: the product's delegation mechanism was not exercised "
                      f"({mech.split(':', 1)[-1].strip()}); {c.detail}")
        else:
            c.name += " (via delegation mechanism)" if mech == "exercised" else " (no delegation mechanism; credential reuse)"
        checks.append(c)
    ev.write("comparison.json", [c.__dict__ for c in checks])
    r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                pass_summary="the audit record distinguishes the agent from the human",
                fail_summary="the audit record cannot tell agent from human", **common)
    if unexercised and r.status.value == "pass":
        return Result.inconclusive(
            a.name, ID, "an agent with its own credential is distinguishable; the product's "
            f"delegation mechanism was not exercised ({mech.split(':', 1)[-1].strip()}), so the "
            "agent-in-the-human's-session case is unmeasured", checks=checks, control_held=True,
            control_detail=control, **common)
    return r
