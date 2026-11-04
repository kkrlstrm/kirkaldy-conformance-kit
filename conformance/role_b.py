"""The role-B adapter base for KRK-20 (P20) and KRK-21 (P21).

An adapter for P20 or P21 is X4's role-B adapter (`docs/KRK19-INTERFACE.md`, Module 5:
`withdrawal_bound`, `agreement`, `bind_requester`, `bind_recorder`, `present`, `classify`,
`evidence_grade`, and the optional members), so one adapter class per target can serve P19, P20
and P21. `RoleB` adds the statements X1 and X5 read before a run, with the defaults a B that says
nothing gets. A default never claims a capability: one issuer, no holder-signed hops, no staples,
``max_amount`` only. Every statement is recorded with the verdict's renewal condition.

The P19 property module does not import this file.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

STANDING_PROFILES = ("kirkaldy", "x4-status")
"""How B reads keys and standing. ``kirkaldy``: the kit's own formats (`standing.py`): a key
statement under a pinned anchor, standing assertions with an action class, grant 0.2.
``x4-status``: standing only as X4's status snapshot states it (per principal, no class), keys
pinned by configuration, grant 0.1 (`status.py`); a B like the reference implementation."""
GRANT_PROFILES = ("kirkaldy.grant/0.2", "kirkaldy.grant/0.1")
STANDING_CHANNELS = ("pull", "stapled", "push")
KEYS_FROM = ("statement", "bind", "adapter")
"""How B learns A's keys: ``statement`` (B reads A's key statement itself), ``bind`` (B's pins are
set once, at bind, from the statement), ``adapter`` (the adapter changes B's pins during a run:
a reading that rests on that translation is information, KRK-M71)."""


class RoleB:
    """Defaults for the P20 and P21 statements (module docstring). Subclass and override."""

    # X1 (P20) --------------------------------------------------------------------------------

    def standing_bound(self) -> Optional[Dict[str, Any]]:
        """A separate maximum evidence age B states, ``{"T_s", "source", "quote"}``; used only if
        smaller than the withdrawal bound T."""
        return None

    def standing_profile(self) -> Optional[str]:
        """One of `STANDING_PROFILES`; None is the kit's own."""
        return None

    def standing_channels(self) -> List[str]:
        """How B obtains standing evidence: any of `STANDING_CHANNELS`."""
        return ["pull"]

    def keys_from(self) -> str:
        return "statement"

    def issuers(self) -> int:
        """How many organisations B can pin at once (A, then A′, A2 and C)."""
        return 1

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        """Pin another organisation, as `bind_requester` pins A."""
        raise NotImplementedError("this B pins one organisation")

    def max_depth(self) -> Optional[int]:
        """The longest chain B accepts, in grants; None if B states none."""
        return None

    def accepts_holder_hops(self) -> bool:
        """Whether B accepts a hop signed by its parent's agent (grant 0.2) rather than by A."""
        return False

    # X5 (P21) --------------------------------------------------------------------------------

    def grant_profile(self) -> Optional[str]:
        """One of `GRANT_PROFILES`; None is the kit's own (0.2)."""
        return None

    def constraint_profile(self) -> List[str]:
        """The dimensions (`attenuation.DIMENSIONS`) B's format carries."""
        return ["max_amount"]

    def constraint_bindings(self) -> Dict[str, Dict[str, str]]:
        """Per operation, the request member each dimension reads; {} is the kit's default
        (``max_amount`` -> ``amount``, ``operations`` -> ``operation``, ``resources`` ->
        ``resources``)."""
        return {}

    def advisory_members(self) -> Dict[str, Dict[str, str]]:
        """Members B's documentation marks as not critical: ``{member: {quote, url}}``."""
        return {}

    def mappings(self) -> Dict[str, Any]:
        """Mappings between A's and B's operation names the agreement declares (X3's form,
        ``{"name": {"operations": {b_name: [a_name, ...]}}}``) for X5 ``translated_hop``."""
        return {}
