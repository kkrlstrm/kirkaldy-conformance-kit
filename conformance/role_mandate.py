"""The role-B adapter base for KRK-24 (P24, purpose and terms bound; design X2).

`X2-MANDATE-BOUND-DESIGN.md` §5 and §6.4. An adapter for P24 is X4's role-B adapter
(`docs/KRK19-INTERFACE.md`, Module 5) with X5's statements (`role_b.RoleB`), so one adapter class
can serve P19 to P24. `MandateB` adds the statements X2 reads before a run, with the defaults a B
that says nothing gets. A default never claims a capability: no term kinds (limits only), no
purpose map, no conditions, no selective disclosure. Every statement is recorded with the
verdict's renewal condition (design §5).

`role_b.py` is imported, never edited.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .role_b import RoleB

CONDITION_MODES = ("refuse", "hold", "none")
"""How B treats an action whose mandate requires a confirmation it was not given: refuses it,
holds it pending (and never performs it without the confirmation), or does not support
conditions (``none``)."""
DISCLOSURE_PROFILES = ("kirkaldy.sealed/0.1",)
"""Selective-disclosure formats the kit writes: its own (`terms` module docstring). A target
profile lives in that target's directory."""


class MandateB(RoleB):
    """Defaults for the P24 statements (module docstring). Subclass and override."""

    def term_profile(self) -> List[str]:
        """The term kinds B's format carries (`terms.PROFILE_KINDS`); [] is limits only."""
        return []

    def purpose_map(self) -> Optional[Dict[str, Any]]:
        """``{code: {"operations": [...], "resources": [...]}}``, quoted from B's documentation or
        configuration; None if B states no meaning for any purpose code (KRK-M150)."""
        return None

    def purpose_map_source(self) -> Optional[Dict[str, str]]:
        """Where the map is stated: ``{"quote", "location"}``. A purpose form is vulnerability
        class only where B states its coverage itself (design §1.8)."""
        return None

    def requires_terms(self) -> Dict[str, List[str]]:
        """Per operation, the term kinds B requires (``purpose``, ``serves``)."""
        return {}

    def term_bindings(self) -> Dict[str, Dict[str, str]]:
        """Per operation, the request member each ``fixed`` / ``floor`` member reads; {} reads each
        member by its own name (KRK-M163). The members listed beyond ``payee`` and ``amount`` are
        what ``fixed/unlisted_member`` draws from."""
        return {}

    def item_key(self) -> str:
        """How B identifies an item in an action's ``items`` (KRK-M163)."""
        return "id"

    def condition_mode(self) -> str:
        """One of `CONDITION_MODES`."""
        return "none"

    def hold_resolution_s(self) -> Optional[float]:
        """How long a held action can wait before B performs or drops it; None if unstated (the
        stability window is then 10 s)."""
        return None

    def disclosure_profile(self) -> Optional[str]:
        """B's selective-disclosure format (`DISCLOSURE_PROFILES`), or None."""
        return None

    def mandate_profile(self) -> Optional[str]:
        """B's mandate wire format; None is grant 0.4."""
        return None

    def advisory_terms(self) -> Dict[str, Dict[str, str]]:
        """Terms B's documentation marks as not enforced: ``{kind: {quote, location}}``. The
        runner's claim basis reads them; the probe records them."""
        return {}

    def documents_terms(self) -> bool:
        """Whether B's documentation says it checks the action against the mandate's terms (the
        disclosure class, design §1.8)."""
        return False

    def confirmation_binds_action(self) -> bool:
        """Whether B's confirmation format carries the action's digest; if not,
        ``condition/confirmed_sibling`` is a format gap (KRK-M160)."""
        return True
