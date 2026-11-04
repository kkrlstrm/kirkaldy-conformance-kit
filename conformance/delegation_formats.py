"""P21's delegation wire formats beyond the kit's own grants (`role_b.GRANT_PROFILES`).

A B that reads delegation chains in a format of its own cannot read the kit's grant 0.2 chains,
so every P21 form would read as a refusal for that reason alone. An adapter whose B reads another
format registers it here with `register_profile`, from the adapter's own directory, and names it
in `grant_profile()`. P21 then writes every chain in that format with the kit's own keys, once,
and changes nothing after signing (spec §3.9). The format's code is hashed with the adapter
(`conformance.versions`), because it is the adapter's reading of the product's format, not part
of the probe.

A format writes and signs only. It verifies no signature, compares no hop and filters no
presentation: B decides every answer (KRK-M25, M42). What it states about itself, P21 applies
before the run (`p21_no_widening.probe`):

- `delegation_forms`: ``("holder",)`` for a format whose only delegated grant is signed by the
  parent's subject; P21 then runs holder-only, and position ``a`` reads as a format gap.
- `cannot_carry`: format features the format cannot write, each with the reason, removed from
  what the adapter states (a form that needs one is a format gap, never a pass); the result lists
  the ones the adapter stated under ``not_carried_by_profile``.
- `carries`: format features the format states itself, added to the adapter's.
- `max_grants`: a depth limit the format states, as a count of grants with the root included.
  P21 uses the smaller of it and the adapter's `max_depth()`, and records `depth_source` and
  `depth_reading` beside it.
- `status_gap`: why A cannot narrow a parent in a status list B reads, for a format that carries
  no status reference. ``narrowed_parent`` is then a format gap.

A run calls `open` once, after P21 has made the stub organisations and before it binds B; the
members `anchor` returns are added to each organisation's trust anchor at bind; `write_chain`
writes each fixture chain; `close` ends the run. A grant `write_chain` returns has ``id`` (what
the request's authorisation names), ``token``, ``subject``, ``signer`` (``org:<issuer>`` or
``holder:<subject>``, KRK-M79) and ``holder`` (the stub organisation holding the subject's key).

`EXAMPLE` is a made-up format that exercises every hook; it is no product's format. Its toy
reader is `known_bad.attenuation_toys.ToyExampleFormat`, and the known-bad gate runs its
``example-good`` and ``example-bad:leaf_only`` toys.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


class DelegationFormat:
    """What P21 needs from a delegation format it does not write itself (module docstring).
    Subclass it and override `write_chain`; the other members default to a format that states
    nothing about itself."""

    name: str = ""
    delegation_forms: Tuple[str, ...] = ("a", "holder")
    cannot_carry: Dict[str, str] = {}
    carries: Tuple[str, ...] = ()
    max_grants: Optional[int] = None
    depth_source: str = ""
    depth_reading: str = ""
    status_gap: Optional[str] = None

    def open(self, clock: Any, orgs: Sequence[Any]) -> Any:
        """Per-run state (a key host the format's keys are fetched from, say), or None. `orgs`
        are the stub organisations, A first, then C where P21 makes one."""
        return None

    def anchor(self, state: Any, org: Any) -> Dict[str, Any]:
        """Members added to `org`'s trust anchor when B is bound to it."""
        return {}

    def write_chain(self, state: Any, hops: Sequence[Any], *, org: Any, holder_org: Any,
                    holder: bool, principal: str, now: float, utc_s: Callable[[float], str],
                    presented: Optional[int] = None) -> List[Any]:
        """Write and sign P21 fixture hops (`p21_no_widening.Hop`, root first); returned in
        fixture order. `org` is the stub A, whose grant key signs a root; with `holder`, every
        subject from the first delegated hop on is an agent of `holder_org` (C). `principal` is
        the chain's root principal, for a format that names one. `presented` is the index of the
        hop W presents (default: the last)."""
        raise NotImplementedError

    def close(self, state: Any) -> None:
        """End the run's state from `open`."""


PROFILES: Dict[str, DelegationFormat] = {}
"""Registered delegation formats by name (module docstring)."""


def register_profile(name: str, fmt: DelegationFormat) -> None:
    """Add the delegation format `name`, for an adapter's `grant_profile()`. Registering an
    instance of the same class again (a module imported twice) replaces it; any other format
    under a name already taken, or a name the kit's own grants use, raises ValueError."""
    from . import role_b
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"a delegation format needs a name, not {name!r}")
    if name in role_b.GRANT_PROFILES:
        raise ValueError(f"{name!r} is one of the kit's own grant profiles")
    if not isinstance(fmt, DelegationFormat):
        raise ValueError(f"delegation format {name!r}: {fmt!r} is not a DelegationFormat")
    have = PROFILES.get(name)
    if have is not None and have is not fmt and \
            (type(have).__module__, type(have).__qualname__) != \
            (type(fmt).__module__, type(fmt).__qualname__):
        raise ValueError(f"delegation format {name!r} is already registered by "
                         f"{type(have).__module__}")
    PROFILES[name] = fmt


def get(name: Optional[str]) -> Optional[DelegationFormat]:
    """The registered format `name`, or None (the kit's own grants, or an unknown name)."""
    return PROFILES.get(name) if name else None


# --------------------------------------------------------------------------- the example format


EXAMPLE_NAME = "example-delegation/1"
EXAMPLE_TYP = "example-delegation+jws"
EXAMPLE_PREFIX = "ex:"
"""A grant's id on the wire is ``ex:<grant id>``; the request's authorisation names that."""
EXAMPLE_MAX = 5
"""The example format's depth limit: five grants, the root included."""
EXAMPLE_MEMBERS = ("v", "id", "by", "to", "to_key", "for", "up", "allow", "at", "from", "until")
"""Every member a grant of the example format has (``from`` and ``until`` may be left out)."""


def example_id(grant_id: Any) -> Any:
    """A grant id as the example format writes it; anything else as given."""
    return f"{EXAMPLE_PREFIX}{grant_id}" if isinstance(grant_id, str) else grant_id


@dataclass(frozen=True)
class ExampleGrant:
    """One grant the example format wrote."""

    id: str
    """``ex:<grant id>``: what the request's authorisation names."""
    token: str
    subject: str
    signer: str
    """``org:<issuer>`` or ``holder:<subject>`` (KRK-M79)."""
    holder: Any = field(compare=False, repr=False)
    payload: Dict[str, Any] = field(compare=False, repr=False)


class ExampleFormat(DelegationFormat):
    """A compact JWS (``typ`` `EXAMPLE_TYP`) per grant over the canonical JSON of `EXAMPLE_MEMBERS`:
    ``by`` signs (A for a root, else the parent's subject), ``to`` is the subject and ``to_key``
    its key (``{kid, x}``, the raw Ed25519 key in hex), ``for`` the root principal, ``up`` the
    parent's id (null for a root, a list for two parents), ``allow`` the kit's constraints as given,
    ``at`` the signing time (RFC 3339, milliseconds), ``from`` / ``until`` the window. A delegated
    grant is always signed by its parent's subject; there is no crit list and one chain per
    request; the format carries its own depth limit and no status reference."""

    name = EXAMPLE_NAME
    delegation_forms = ("holder",)
    cannot_carry = {"crit": "the example format has no member that marks a constraint critical",
                    "second-chain": "the example format carries one chain per request"}
    carries = ("stated-depth",)
    max_grants = EXAMPLE_MAX
    depth_source = "the example format's own rule: a chain holds at most five grants"
    depth_reading = "five grants: the root and four delegated"
    status_gap = ("the example format writes no status reference, so A cannot narrow a parent "
                  "in a list B reads")

    def anchor(self, state: Any, org: Any) -> Dict[str, Any]:
        return {"example_delegation": {"version": EXAMPLE_NAME, "org": org.issuer}}

    def write_chain(self, state: Any, hops: Sequence[Any], *, org: Any, holder_org: Any,
                    holder: bool, principal: str, now: float, utc_s: Callable[[float], str],
                    presented: Optional[int] = None) -> List[Any]:
        from . import standing, status
        n = len(hops)
        gids = [h.grant_id or status.new_grant_id() for h in hops]
        by_gid = {g: i for i, g in enumerate(gids)}
        owners = [org if (not holder or i == 0) else holder_org for i in range(n)]
        subjects = [f"a{i}-{secrets.token_hex(3)}" for i in range(n)]
        pairs = [owners[i].agent(subjects[i]) for i in range(n)]
        out: List[ExampleGrant] = []
        for i, h in enumerate(hops):
            if h.crit is not None:
                raise ValueError("the example format carries no crit list (a format gap)")
            unknown_omit = set(h.omit) - {"not_before", "not_after"}
            if unknown_omit:
                raise ValueError(f"the example format has no rule for omitting "
                                 f"{sorted(unknown_omit)}")
            p = h.parent
            if p == "_":
                pidx, up = (i - 1 if i else None), (example_id(gids[i - 1]) if i else None)
            elif isinstance(p, list):
                idx = [by_gid.get(x) for x in p]
                pidx, up = next((j for j in idx if j is not None), None), [example_id(x)
                                                                         for x in p]
            elif p is None:
                pidx, up = None, None
            else:
                pidx, up = by_gid.get(p), example_id(p)
            if up is None:
                key, by, signer = org.key, org.issuer, f"org:{org.issuer}"
            else:                       # a parent outside the fixture: A's first agent signs
                j = pidx if pidx is not None else 0
                key, by, signer = pairs[j], subjects[j], f"holder:{subjects[j]}"
            payload: Dict[str, Any] = {
                "v": EXAMPLE_NAME, "id": example_id(gids[i]), "by": by, "to": subjects[i],
                "to_key": {"kid": pairs[i].kid, "x": pairs[i].public_bytes().hex()},
                "for": principal, "up": up, "allow": dict(h.c), "at": status.utc_ms(now),
                "from": utc_s(now + (h.nb if h.nb is not None else -3600)),
                "until": utc_s(now + (h.na if h.na is not None else 12 * 3600))}
            for member, name in (("from", "not_before"), ("until", "not_after")):
                if name in h.omit:
                    payload.pop(member)
            tok = standing.sign(payload, key, EXAMPLE_TYP, raw=h.raw)
            out.append(ExampleGrant(payload["id"], tok, subjects[i], signer, owners[i], payload))
        return out


EXAMPLE = ExampleFormat()
register_profile(EXAMPLE_NAME, EXAMPLE)
