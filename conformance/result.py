"""The result of one probe against one target, and the rule that makes it trustworthy.

A result is `pass` or `fail` only if the probe ran and its control held. The control is the run
that proves the probe exercised the real path: the upstream actually received the credential,
the policy engine was actually unreachable, the approval actually executed when nothing was
restarted. Without it, "nothing leaked" and "nothing was sent" look identical.

`Result` enforces that rule at construction, so no code path can record a verdict whose
control did not hold.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    """The target has no such mechanism (a sandbox has no approval primitive)."""
    INCONCLUSIVE = "inconclusive"
    """The control did not hold, or the target could not be driven. Never a verdict."""


class ControlNotHeld(ValueError):
    """Raised when code tries to record pass/fail without a held control."""


@dataclass
class Check:
    """One observation inside a probe: what was attempted and what was seen."""

    name: str
    outcome: str
    """Short machine-readable outcome, e.g. "blocked", "reached_upstream", "executed_once"."""
    ok: Optional[bool] = None
    """True if this observation is consistent with the property, False if it violates it,
    None if it is informational (an availability observation, say)."""
    detail: str = ""


@dataclass
class Result:
    target: str
    property_id: str
    status: Status
    summary: str
    control_held: Optional[bool]
    control_detail: str = ""
    checks: List[Check] = field(default_factory=list)
    target_version: str = ""
    config: str = ""
    """Name of the configuration the target ran under ("default", "known-bad: fail-open")."""
    vendor_claim: str = ""
    """What the vendor's documentation states about this property, quoted, or "not stated"."""
    evidence_dir: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    # When the verdict stops being valid (spec §3.5). The runner fills these
    # (`conformance.validity.stamp`); a result built directly by a probe carries none, and a
    # result without them reads as "validity unknown", never as valid.
    run_at: str = ""
    """UTC time the probe started, ISO 8601 with a Z."""
    valid_until: str = ""
    """`run_at` plus the maximum age (12 months). The verdict lapses then if nothing else
    changes first."""
    seed: Optional[int] = None
    """The run's seed. Re-running with it reproduces what the kit draws (see `unseeded`)."""
    probe_version: str = ""
    """Content hash of the property code (`conformance.versions`; files in `hashed`)."""
    fixture_version: str = ""
    """Content hash of the known-bad fixtures, vectors and their required outcomes."""
    adapter_version: str = ""
    """Content hash of the adapter that drove the target."""
    environment: Dict[str, str] = field(default_factory=dict)
    """The environment fields the property declares relevant, as measured."""
    hashed: Dict[str, Any] = field(default_factory=dict)
    """Which files each version hash covers, and the hashing scheme."""
    renewal: Dict[str, Any] = field(default_factory=dict)
    """The renewal condition as data: the fields whose change voids the verdict
    (`lapses_on_change`) and the age limit (`max_age_months`)."""
    unseeded: List[str] = field(default_factory=list)
    """What the probe draws that the seed does not reproduce, and why."""
    known_bad: Dict[str, Any] = field(default_factory=dict)
    """The known-bad run this verdict relied on (`conformance.knownbad.reference`): its record
    id and time, and the probe and fixture versions it checked. Empty when the runner found
    none; a `pass` or `fail` without one is no verdict (spec §3.5)."""

    def __post_init__(self) -> None:
        self.status = Status(self.status)
        if self.status in (Status.PASS, Status.FAIL) and self.control_held is not True:
            raise ControlNotHeld(
                f"{self.target}/{self.property_id}: refusing to record {self.status.value} "
                f"because the control did not hold ({self.control_detail or 'no control detail'}). "
                f"Record inconclusive instead.")

    @classmethod
    def inconclusive(cls, target: str, property_id: str, why: str, **kw: Any) -> "Result":
        return cls(target=target, property_id=property_id, status=Status.INCONCLUSIVE,
                   summary=why, control_held=kw.pop("control_held", False),
                   control_detail=kw.pop("control_detail", why), **kw)

    @classmethod
    def not_applicable(cls, target: str, property_id: str, why: str, **kw: Any) -> "Result":
        return cls(target=target, property_id=property_id, status=Status.NOT_APPLICABLE,
                   summary=why, control_held=None, **kw)

    def to_doc(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_doc(), indent=2, sort_keys=True)


def verdict(target: str, property_id: str, checks: List[Check], *, control_held: bool,
            control_detail: str, pass_summary: str, fail_summary: str, **kw: Any) -> Result:
    """Turn a probe's checks into a result. Any check with ok=False is a failure; a failed
    control makes the whole thing inconclusive regardless of what the checks say."""
    if not control_held:
        return Result.inconclusive(target, property_id, f"control did not hold: {control_detail}",
                                   checks=checks, control_detail=control_detail, **kw)
    violations = [c for c in checks if c.ok is False]
    if violations:
        names = ", ".join(f"{c.name} ({c.outcome})" for c in violations)
        return Result(target=target, property_id=property_id, status=Status.FAIL,
                      summary=f"{fail_summary}: {names}", control_held=True,
                      control_detail=control_detail, checks=checks, **kw)
    return Result(target=target, property_id=property_id, status=Status.PASS,
                  summary=pass_summary, control_held=True, control_detail=control_detail,
                  checks=checks, **kw)
