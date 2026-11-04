"""The adapters for KRK-22 (P22, cumulative ceiling across counterparties): the holder adapter
(role A, a new protocol) and the spender adapter (role B, X4's role-B adapter with
`role_b.RoleB`'s statements and P22's). `X9-CUMULATIVE-CEILING-DESIGN.md` §6.6.

An adapter translates the target's format and nothing more. A holder adapter never decides
whether a spend is allowed, never keeps an account of its own, and passes the holder's issuance
to the kit's stub spenders as bytes; the kit's profile reads it (KRK-M25, M99). The defaults
below never claim a capability.

P16 to P21 do not import this module.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol

from .role_b import RoleB

CLASSES = ("authorised", "refused", "rate-limited", "error")
"""What a holder's answer to a request for authority means (`Holder.classify`)."""


class Holder(Protocol):
    """Role A: the party that keeps the account for a root (design §6.6). Optional members are
    listed in `HOLDER_OPTIONAL`; a form that needs one the adapter lacks is not applicable."""

    name: str
    config: str
    clock: str
    """``real``; ``virtual`` only for the kit's own toys."""

    def role(self) -> str: ...                      # "A"
    def mechanism(self) -> str: ...                 # of ceiling.MECHANISMS
    def topology(self) -> str: ...                  # "bearer" | "forwarding"
    def ceiling_profile(self) -> Dict[str, Any]: ...
    def constraint_bindings(self) -> Dict[str, str]: ...
    def terms(self) -> Dict[str, Any]: ...
    def open_root(self, principal: str, limits: List[Dict[str, Any]], *, window: Any = None,
                  rule: Optional[str] = None) -> str: ...
    def bind_spender(self, name: str, url: str, key: Dict[str, bytes]) -> str: ...
    def holder_keys(self) -> Dict[str, bytes]: ...
    def request(self, root: str, spender: str, values: Dict[str, Any], *, request_id: str,
                agent: str) -> Dict[str, Any]: ...
    def classify(self, answer: Dict[str, Any]) -> str: ...
    def evidence_grade(self) -> str: ...            # "recorder"


HOLDER_OPTIONAL = ("overshoot", "delegate", "reissue", "regrant", "cancel", "claim_reversal",
                   "deliver", "account", "read_back", "restart", "replicas",
                   "partition_replicas", "max_in_flight", "documents_hard_limit",
                   "variants_not_applicable", "variant_notes", "exposes_times", "set_clock",
                   "issuance_of", "sessions")


class SpenderB(RoleB):
    """Role B: X4's role-B adapter (`withdrawal_bound`, `agreement`, `bind_requester`,
    `bind_recorder`, `present`, `classify`, `evidence_grade`) with P20's and P21's statements
    (`RoleB`) and these P22 defaults. One adapter class per target can then serve P19 to P22."""

    def mechanism(self) -> str:
        """How B takes part in the account (`ceiling.MECHANISMS`)."""
        return "allocation"

    def ceiling_profile(self) -> Dict[str, Any]:
        """What B reads of the ``cumulative`` member: ``{}`` reads none (a format gap)."""
        return {}

    def terms(self) -> Dict[str, Any]:
        """``tolerance_s``, ``commit_lag_s``, ``propagation_s``, each with its ``source``."""
        return {}

    def bind_holder(self, anchor: Dict[str, bytes], url: Optional[str]) -> str:
        """Pin the holder's key and, where B's mechanism asks the holder, its URL."""
        raise NotImplementedError("this B takes no holder")

    def reports(self) -> bool:
        """Whether B sends captures and releases to the holder."""
        return False

    def spender_identity(self) -> Dict[str, Any]:
        """``{"name", "keys": {kid: public bytes}}``: what the holder pins to read B's
        statements, and the party a share or reservation is addressed to."""
        return {}

    def endpoints(self) -> List[str]:
        return ["default"]

    def max_in_flight(self) -> int:
        return 1

    def documents_hard_limit(self) -> Optional[Dict[str, Any]]:
        """The documentation's statement of a hard cumulative limit, quoted."""
        return None


def opt(a: Any, name: str, default: Any = None) -> Any:
    """`a.name()` when the adapter has it, else `default`."""
    fn = getattr(a, name, None)
    if callable(fn):
        return fn()
    if isinstance(a, SpenderB) or hasattr(SpenderB, name):
        base = getattr(SpenderB(), name, None)
        if callable(base):
            try:
                return base()
            except NotImplementedError:
                return default
    return default
