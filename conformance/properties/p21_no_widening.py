"""P21 — No widening along a delegation chain (KRK-21, cross-organisation X5).

**Guarantee.** For every request B accepts under a delegation chain, every effect B commits lies
inside the allowed set of every grant in the chain, in every dimension the chain constrains
(`attenuation.DIMENSIONS`), and inside the root principal's standing where B holds evidence of it
with limits; a narrowing of a parent published by A applies to every child within B's T.

**Question.** Does the product commit an effect only inside the intersection of every grant in
the presented chain, in every dimension the chain constrains, including across a hop into a third
organisation, whatever form a hop takes and when a parent is narrowed after its child was issued?

**Who is graded.** B. The kit plays A, A's agents and a third organisation C with
`issuer.StubIssuer` (new modules only). Effects are counted at the kit's recorder.
The outcome is graded, not the mechanism: B may refuse a chain with a wider hop
whole (``chain_refused``) or enforce the intersection and act inside it (``clamped``); both pass,
and the result says which. Constraints are critical. Wider grants are genuinely
signed by their signers; nothing is altered after signing.

**The vocabulary** is `attenuation`'s six dimensions with written semantics, and the kit's
expectation for every fixture is computed there, from hand-written vectors, sharing no code with
any target (KRK-M83). A dimension B's format cannot carry (`constraint_profile`) is not tested and
is listed as a finding, never a pass (KRK-M84). Two grant profiles
(`role_b.GRANT_PROFILES`): the kit's 0.2, and 0.1 (X4's grants: one operation, an integer
``max_amount``, a window), the form the reference implementation reads; a fixture is written in B's profile where the
profile can say it.

**Within each trial** (design §4.1), three presentations, in a seeded order: **W** (the widened
chain, a request inside the leaf and outside the intersection, KRK-M81), **L** (the sibling: the
same shape, signers and members, differing only in the value under test, so the same request is
inside; KRK-M80, M85) and **W-in** (a request inside the intersection under W's own chain,
accepted ``clamped`` or refused ``chain_refused``; not presented where W's chain is malformed by
construction). Each variant changes one dimension at one hop. **Positions**: ``a`` (A signs every
hop) and ``holder`` (A signs the parent for its agent a1; a1's key signs the child for C's agent
c1), the latter only where B states it accepts holder-signed hops.

**Waiting for B's fetch** (KRK-M95). A B that obtains standing evidence only by
fetching it (`standing_channels`) is presented with ``root_exceeds_standing`` only once it has
fetched W's and L's root principals' assertions; where it reads standing limits
(``standing-limits``), with every static trial only once it has fetched for both root principals
(A's answer that it publishes none counts); and, where it reads A's key statements (`keys_from`
``statement``), with a holder-position chain through a hop C's agent signed only once it has
fetched C's key statement listing that agent. What was seen is in the
trial's ``fetched_before_present``; a fetch not seen within the limit is recorded and the trial
goes on. The limit is X4's, ``max(2 P, 5 s) + 1 s``; for a pull-only B that reads standing limits
the control measures P from B's fetches of its principal's standing (KRK-M95b).

**Before B's first fetch** (KRK-M95b). The wait hides a B that bounds a request by
the chain alone before it has fetched the root principal's standing.
``root_exceeds_standing/before_first_fetch`` presents to a pull-only B at once: A publishes W's
root principal's standing with a limit below the request, and W (inside the chain) is presented
before B has fetched anything for that principal (``presented_before_fetch``; a B that had already
fetched leaves the trial ``not_landed``). It is graded on W's effect alone: an effect is outside
the standing A publishes and fails; a refusal, for any reason, holds. L and W-in are not
presented. For a B that is not pull-only the form is not applicable.

**Incomplete chains** (KRK-M95c). P21 once presented only complete chains, so a B that
verifies the links it is given and never requires the chain to reach a root passed every form.
``incomplete_chain`` presents three, each a vulnerable form whose W must be refused: ``stops_before_root`` (root, middle and leaf are signed; the root is withheld, so the
middle names a parent nobody supplied), ``no_ancestors`` (a child presented with none of its
ancestors) and ``mutual_no_root`` (two grants, ids chosen before signing, each naming the other,
and no root). In the first two the withheld ancestor's bound excludes W's request, so a B that
acts lies outside a parent's stated bound. L is the same chain made complete and rooted, wide
enough for the same request. W-in is not presented. The form runs at position ``a`` (``holder``
for a holder-only B). ``mutual_no_root`` is built as ``cycle/id_cycle`` is; it is graded here as a
vulnerable form, there as cycle detection.

**Holder-only B.** A B whose only delegation form is holder-signed states it with
`delegation_forms()` returning ``["holder"]``: the control presents only the holder-signed chain,
every form runs at ``holder``, and position ``a`` reads as a format gap.

**Registered delegation formats** (`conformance.delegation_formats`). Besides 0.2 and 0.1, a B
may state a format an adapter registered with `delegation_formats.register_profile`. The
stand-in writes and signs every chain in that format with the kit's keys, once. What the format
states about itself is applied before the run: a holder-only format runs holder-only; a feature it
cannot carry is removed from B's statement (listed under ``not_carried_by_profile``) and a feature
it states is added; a depth limit it states bounds `max_depth()`; a format with no status
reference reads ``narrowed_parent`` as a format gap. The kit's own example is
`delegation_formats.EXAMPLE`.

**Depth.** `max_depth()` is a count of grants, the root included: the root plus N delegated.
Where a registered format states a depth limit, the smaller of the two is used. ``too_deep``
presents one more than the limit.

**Disclosure class.** A failing form of a vulnerable variant is vulnerability class
only where W's effect lies outside a bound some grant above the presented one states
(`outside_parent_bound`, computed from the fixture in the kit's vocabulary). Fail-safe: a member of
such a grant the vocabulary cannot read, or an amount it cannot compare exactly, counts as a bound
the effect may exceed, and a chain with no root rests on no bound A stated. Otherwise the form is
conformance. The result lists each failing form's class (``extra.disclosure_forms``).

**Grades.** P19's ladder, and ``library-decision`` below ``b-response``: the answer
of a verification library called directly, with no deployed B behind it. A result at that grade is
labelled a library-level reading in its summary and ``extra.level``.

**Control.** An honest two-hop chain, the child narrower than its parent in every dimension B
declares, and a fresh request inside every grant, accepted at every endpoint with one effect each;
with holder hops, the same with a holder-signed child. The control never requires a refusal, a
dimension beyond B's own, holder hops, chains deeper than two, or a mapping (KRK-M19).

**Outcomes.** Per trial: ``held`` (pass), ``outside_effect`` (fail, with the dimension and hop),
information ``collateral_refusal``, ``shape_refused``, ``not_landed``, ``hung`` (no answer and no
effect: an availability finding). ``narrowed_parent`` is timed with X4's harness
unchanged: ``within``, ``late``, ``not_within_W``, ``flapped``, ``inconclusive``;
a trial within T has a mode too, from the requests inside the narrowed ceiling: accepted is
``clamped``, refused is ``chain_refused`` (observed ``narrowed_as_withdrawn``: the narrowed parent
makes the child a wider hop, and a strict B refuses the whole chain; a pass).
Per variant: ``held`` (with the mode) or ``outside_effect``. **Result**: ``fail`` if any landed
variant fails; ``pass`` if the control held, every landed variant passed and no form in
`NA_FORBIDDEN` that B's format can carry is missing or inconclusive; else ``inconclusive``. The
dimensions covered and the format gaps are in ``extra``, and ``extra.must_land_missed`` lists the
forms in `NA_FORBIDDEN` that did not land (also when a variant failed), for the runner's claim
basis.
"""
from __future__ import annotations

import json
import os
import random
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict
from . import p19_withdrawal_within_t as p19

ID = "P21"
TITLE = "No widening along a delegation chain"
FIXTURES = ("known_bad/attenuation_toys.py", "tests/test_p21_no_widening.py",
            "tests/vectors/krk21/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("The stub organisations' keys, agents' keys, grant ids and each request's ref come "
            "from the operating system, never from the seed (KRK-M36).",
            "The seed draws the variant order, the presentation order and the drawn values.")

VARIANTS = ("wider_child", "middle_narrow", "dropped_constraint", "wildcard_default",
            "combined", "delegation_exceeded", "translated_hop", "cycle",
            "unknown_constraint", "numeric", "root_exceeds_standing", "narrowed_parent",
            "incomplete_chain")
FORMS = {"wider_child": ("amount", "operations", "resources", "audience", "time_after",
                         "time_before"),
         "middle_narrow": ("amount", "operations", "resources"),
         "dropped_constraint": ("omitted", "empty_list", "null_member"),
         "wildcard_default": ("wildcard_operation", "prefix_broader", "default_audience",
                              "default_window"),
         "combined": ("union_dimensions", "summed_amount", "two_parents"),
         "delegation_exceeded": ("not_delegable", "depth_exceeded"),
         "translated_hop": ("mapping_widens", "mapping_undeclared"),
         "cycle": ("id_cycle", "self_parent", "too_deep"),
         "unknown_constraint": ("in_parent", "in_child", "marked_critical", "near_name"),
         "numeric": ("precision", "large_integer", "units", "currency", "negative", "encoding"),
         "root_exceeds_standing": ("amount", "resources", "before_first_fetch"),
         "incomplete_chain": ("stops_before_root", "no_ancestors", "mutual_no_root")}
POSITIONS = ("a", "holder")
POSITIONED = ("wider_child", "dropped_constraint", "wildcard_default", "delegation_exceeded",
              "unknown_constraint", "numeric")
"""Variants whose every form runs at both hop positions (design §3.1)."""
TRIALS = {"*": 5, "narrowed_parent": 5}
DEV_TRIALS = {"*": 3, "narrowed_parent": 2}
PUBLISHED_TRIALS = TRIALS
NA_FORBIDDEN = ("control", ("wider_child", "amount"), ("middle_narrow", "amount"),
                ("dropped_constraint", "omitted"), ("unknown_constraint", "in_parent"),
                ("unknown_constraint", "in_child"), ("cycle", "id_cycle"),
                ("cycle", "self_parent"), ("numeric", "precision"), ("numeric", "negative"),
                ("incomplete_chain", "stops_before_root"), ("incomplete_chain", "no_ancestors"),
                ("incomplete_chain", "mutual_no_root"))
"""Forms (at position ``a``, or ``holder`` for a holder-only B) an adapter may not declare not
applicable (design §6.4); one B's format cannot carry is a format gap, a finding, not a missing
verdict."""
VULNERABLE_VARIANTS = ("wider_child", "middle_narrow", "dropped_constraint", "wildcard_default",
                       "combined", "delegation_exceeded", "unknown_constraint", "numeric",
                       "incomplete_chain")
"""Variants whose failing forms may be vulnerability class; each form's class is
`outside_parent_bound`'s."""
GRADES = p19.GRADES + ("library-decision",)
"""P19's ladder, then ``library-decision``: the lowest; read from B's answers."""
LIBRARY_GRADES = ("library-decision",)
POSITION_A_GAP = ("B's only delegation form is holder-signed, so a hop A signs below its own root "
                  "cannot be written")
PLAN_ENV = "ACK_P21_PLAN"
READY_S = 30.0
OP_A, OP_B = "crm.record.push", "crm.record.delete"
B_PRIME = "did:web:b-prime.example"
MAP_NAME = "kirkaldy.map/contacts-v1"
LAPSE_S = 60.0
"""``time_after``: the parent's window ends this long after its issue."""
MALFORMED = {("dropped_constraint", "null_member"), ("wildcard_default", "default_window"),
             ("wildcard_default", "wildcard_operation"), ("combined", "two_parents"),
             ("cycle", "id_cycle"), ("cycle", "self_parent"), ("cycle", "too_deep"),
             ("delegation_exceeded", "not_delegable"),
             ("delegation_exceeded", "depth_exceeded"),
             ("numeric", "precision"), ("numeric", "large_integer"), ("numeric", "encoding"),
             ("numeric", "negative")} | {("unknown_constraint", f) for f in
                                         FORMS["unknown_constraint"]} | \
    {("incomplete_chain", f) for f in FORMS["incomplete_chain"]}
"""Forms whose W chain (or W request) is outside every reading of the vocabulary: refusing it is
required, so W-in is not presented (design §4.1)."""
DIMS_OF = {("wider_child", "amount"): ["max_amount"],
           ("wider_child", "operations"): ["operations"],
           ("wider_child", "resources"): ["resources"],
           ("wider_child", "audience"): ["audience"],
           ("wider_child", "time_after"): ["window"], ("wider_child", "time_before"): ["window"],
           ("middle_narrow", "amount"): ["max_amount"],
           ("middle_narrow", "operations"): ["operations", "operation-lists"],
           ("middle_narrow", "resources"): ["resources"],
           ("dropped_constraint", "omitted"): ["resources"],
           ("dropped_constraint", "empty_list"): ["resources"],
           ("dropped_constraint", "null_member"): ["resources"],
           ("wildcard_default", "wildcard_operation"): ["operations", "operation-lists"],
           ("wildcard_default", "prefix_broader"): ["resources"],
           ("wildcard_default", "default_audience"): ["audience"],
           ("wildcard_default", "default_window"): ["window"],
           ("combined", "union_dimensions"): ["operations", "resources", "second-chain"],
           ("combined", "summed_amount"): ["max_amount", "second-chain"],
           ("combined", "two_parents"): ["max_amount"],
           ("delegation_exceeded", "not_delegable"): ["delegation"],
           ("delegation_exceeded", "depth_exceeded"): ["delegation"],
           ("translated_hop", "mapping_widens"): ["operations", "operation-lists", "mappings"],
           ("translated_hop", "mapping_undeclared"): ["operations", "operation-lists",
                                                       "mappings"],
           ("cycle", "id_cycle"): ["max_amount"], ("cycle", "self_parent"): ["max_amount"],
           ("cycle", "too_deep"): ["max_amount", "stated-depth"],
           ("unknown_constraint", "in_parent"): ["max_amount"],
           ("unknown_constraint", "in_child"): ["max_amount"],
           ("unknown_constraint", "marked_critical"): ["max_amount", "crit"],
           ("unknown_constraint", "near_name"): ["max_amount"],
           ("numeric", "precision"): ["max_amount"], ("numeric", "large_integer"): ["max_amount"],
           ("numeric", "units"): ["max_amount", "units"],
           ("numeric", "currency"): ["max_amount", "currency"],
           ("numeric", "negative"): ["max_amount"], ("numeric", "encoding"): ["max_amount"],
           ("root_exceeds_standing", "amount"): ["max_amount", "standing-limits"],
           ("root_exceeds_standing", "resources"): ["resources", "standing-limits"],
           ("root_exceeds_standing", "before_first_fetch"): ["max_amount", "standing-limits"],
           ("narrowed_parent", ""): ["max_amount"],
           ("incomplete_chain", "stops_before_root"): ["max_amount"],
           ("incomplete_chain", "no_ancestors"): ["max_amount"],
           ("incomplete_chain", "mutual_no_root"): ["max_amount"]}
"""What a form needs B's format to carry. Besides the dimensions: ``operation-lists`` (a grant
naming more than one operation), ``second-chain`` (a second chain on one request), ``mappings``
(a declared mapping between A's and B's operation names), ``stated-depth`` (B states a maximum
chain), ``crit``, ``units``, ``currency`` and ``standing-limits`` (B reads limits from a standing
assertion)."""
GAP_WORDS = {"operation-lists": "a grant names one operation, so a set of operations cannot be "
                                "written", "second-chain": "B reads one chain per request",
             "mappings": "no mapping between A's and B's operation names is declared for grants",
             "stated-depth": "B states no maximum chain", "crit": "the format has no crit list",
             "units": "amounts carry no minor units", "currency": "amounts carry no currency",
             "standing-limits": "B reads no limits from standing evidence"}


def _amt(v: Any, cur: str = "EUR", mu: int = 2) -> Dict[str, Any]:
    return {"value": v, "currency": cur, "minor_units": mu}


# --------------------------------------------------------------------------- fixtures


@dataclass
class Hop:
    """One grant in a fixture chain, root first, in the kit's vocabulary."""

    c: Dict[str, Any]
    nb: Optional[float] = None
    """not_before, seconds relative to now (default: an hour back)."""
    na: Optional[float] = None
    """not_after, seconds relative to now (default: twelve hours on)."""
    omit: Tuple[str, ...] = ()
    crit: Optional[List[str]] = None
    raw: bool = False
    parent: Any = "_"
    """``_``: the hop above; else a literal parent id or list (cycles, two parents)."""
    grant_id: Optional[str] = None


@dataclass
class Fixture:
    hops: List[Hop]
    request: Dict[str, Any]
    sib_hops: List[Hop]
    sib_request: Dict[str, Any]
    request_in: Optional[Dict[str, Any]] = None
    second: Optional[List[Hop]] = None
    sib_second: Optional[List[Hop]] = None
    standing: Optional[Dict[str, Any]] = None
    sib_standing: Optional[Dict[str, Any]] = None
    present_at: Optional[float] = None
    """Seconds after the build to present W and L (``time_after``)."""
    raw_request: bool = False
    cycle_tokens: Optional[str] = None
    hop_widened: Optional[Tuple[int, str]] = None
    """(index from the root of the hop that widens, dimension), for the evidence."""
    notes: Dict[str, Any] = field(default_factory=dict)
    present: Optional[List[int]] = None
    """W's hops (indexes from the root) that are presented; the rest are signed and withheld
    (``incomplete_chain``). None: every hop."""
    presented: Optional[int] = None
    """The index from the root of W's presented grant where it is not the last (cycles)."""


def _base(dims: List[str]) -> Dict[str, Any]:
    """An honest root's constraints in every dimension `dims` names."""
    c: Dict[str, Any] = {}
    if "max_amount" in dims:
        c["max_amount"] = _amt(500000)
    if "operations" in dims:
        c["operations"] = [OP_A, OP_B]
    if "resources" in dims:
        c["resources"] = ["acct-1/*", "acct-2/*"]
    if "audience" in dims:
        c["audience"] = ["did:web:b.example"]
    if "delegation" in dims:
        c["delegation"] = {"max_depth": 3}
    return c


def _req(op: str = OP_A, value: Any = 30000, *, res: Optional[List[str]] = None,
         cur: str = "EUR", mu: int = 2) -> Dict[str, Any]:
    return {"operation": op, "amount": _amt(value, cur, mu),
            "resources": res or [f"acct-1/r-{secrets.token_hex(3)}"]}


def _narrow(c: Dict[str, Any], dims: List[str]) -> Dict[str, Any]:
    """A child's constraints narrower than `c` in every dimension present."""
    out = dict(c)
    if "max_amount" in out:
        out["max_amount"] = _amt(400000)
    if "operations" in out and len(out["operations"]) > 1:
        out["operations"] = list(out["operations"])
    if "delegation" in out:
        out["delegation"] = {"max_depth": out["delegation"]["max_depth"] - 1}
    return out


def fixture(variant: str, form: str, rng: random.Random, *, party: str, dims: List[str],
            max_depth: Optional[int], mapping: Optional[Dict[str, Any]],
            tolerance: float = 0.0) -> Fixture:
    """W, L and W-in for one form, in the kit's vocabulary (design §3.1). Each changes one value
    at one hop, drawn from `rng` where a value is drawn (X3 §13 item 4: a toy cannot pass by
    guessing it). Delegation depth appears only in the forms about it: copied unchanged into a
    child it would itself be a wider hop."""
    base = {k: x for k, x in _base(dims).items() if k != "delegation"}
    hi = rng.randint(400, 600) * 1000      # the wide value (minor units)
    lo = rng.randint(50, 150) * 1000       # the narrow value
    mid = (lo + hi) // 2                   # inside the wide, outside the narrow
    small = lo // 2                        # inside both
    v = variant, form

    def two(pc: Dict[str, Any], cc: Dict[str, Any], **kw: Any) -> List[Hop]:
        return [Hop(pc, **kw.get("p", {})), Hop(cc, **kw.get("c", {}))]

    if v == ("wider_child", "amount"):
        return Fixture(two({**base, "max_amount": _amt(lo)}, {**base, "max_amount": _amt(hi)}),
                       _req(value=mid), two({**base, "max_amount": _amt(hi)},
                                            {**base, "max_amount": _amt(hi)}), _req(value=mid),
                       _req(value=small), hop_widened=(1, "max_amount"))
    if v == ("wider_child", "operations"):
        # One operation per grant, so a format with no operation lists can say it too.
        p, c = {**base, "operations": [OP_A]}, {**base, "operations": [OP_B]}
        return Fixture(two(p, c), _req(OP_B, small), two(c, c), _req(OP_B, small), None,
                       hop_widened=(1, "operations"))
    if v == ("wider_child", "resources"):
        p, c = {**base, "resources": ["acct-1/*"]}, {**base, "resources": ["acct-1/*", "acct-2/*"]}
        return Fixture(two(p, c), _req(res=["acct-2/x-" + secrets.token_hex(3)], value=small),
                       two(c, c), _req(res=["acct-2/x-" + secrets.token_hex(3)], value=small),
                       _req(value=small), hop_widened=(1, "resources"))
    if v == ("wider_child", "audience"):
        p, c = {**base, "audience": [B_PRIME]}, {**base, "audience": [B_PRIME, party]}
        return Fixture(two(p, c), _req(value=small), two(c, c), _req(value=small), None,
                       hop_widened=(1, "audience"))
    if v == ("wider_child", "time_after"):
        return Fixture(two(base, base, p={"na": LAPSE_S}), _req(value=small),
                       two(base, base), _req(value=small), None, present_at=LAPSE_S,
                       hop_widened=(1, "window"))
    if v == ("wider_child", "time_before"):
        # The parent starts beyond B's tolerance (KRK-M88), the child now.
        ahead = tolerance + LAPSE_S
        return Fixture(two(base, base, p={"nb": ahead}, c={"nb": -3600}), _req(value=small),
                       two(base, base, c={"nb": -3600}), _req(value=small), None,
                       hop_widened=(1, "window"))
    if variant == "middle_narrow":
        if form == "amount":
            w, n = {**base, "max_amount": _amt(hi)}, {**base, "max_amount": _amt(lo)}
            rw, rin = _req(value=mid), _req(value=small)
        elif form == "operations":
            w, n = {**base, "operations": [OP_A, OP_B]}, {**base, "operations": [OP_A]}
            rw, rin = _req(OP_B, small), _req(OP_A, small)
        else:
            w, n = {**base, "resources": ["acct-1/*", "acct-2/*"]}, \
                {**base, "resources": ["acct-1/*"]}
            rw, rin = _req(res=["acct-2/x-" + secrets.token_hex(3)], value=small), \
                _req(value=small)
        return Fixture([Hop(w), Hop(n), Hop(w)], rw, [Hop(w), Hop(w), Hop(w)], dict(rw), rin,
                       hop_widened=(2, form if form != "amount" else "max_amount"))
    if variant == "dropped_constraint":
        p = {**base, "resources": ["acct-1/*"]}
        if form == "omitted":
            c = {k: x for k, x in base.items() if k != "resources"}
            ps = {**base, "resources": ["acct-1/*", "acct-2/*"]}
            r = _req(res=["acct-2/x-" + secrets.token_hex(3)], value=small)
            return Fixture(two(p, c), r, two(ps, c), dict(r), _req(value=small))
        if form == "empty_list":
            return Fixture(two(p, {**base, "resources": []}), _req(value=small),
                           two(p, {**base, "resources": ["acct-1/*"]}), _req(value=small), None)
        return Fixture(two(p, {**base, "resources": None}), _req(value=small),
                       two(p, {**base, "resources": ["acct-1/*"]}), _req(value=small), None)
    if variant == "wildcard_default":
        if form == "wildcard_operation":
            return Fixture(two({**base, "operations": [OP_A]}, {**base, "operations": ["*"]}),
                           _req(OP_B, small),
                           two({**base, "operations": [OP_B]}, {**base, "operations": [OP_B]}),
                           _req(OP_B, small), None)
        if form == "prefix_broader":
            p, c = {**base, "resources": ["acct/1/*"]}, {**base, "resources": ["acct/*"]}
            return Fixture(two(p, c), _req(res=["acct/2/x-" + secrets.token_hex(3)],
                                           value=small),
                           two({**base, "resources": ["acct/*"]}, c),
                           _req(res=["acct/2/x-" + secrets.token_hex(3)], value=small),
                           _req(res=["acct/1/y-" + secrets.token_hex(3)], value=small),
                           hop_widened=(1, "resources"))
        if form == "default_audience":
            c = {k: x for k, x in base.items() if k != "audience"}
            return Fixture(two({**base, "audience": [B_PRIME]}, c), _req(value=small),
                           two({**base, "audience": [party]}, c), _req(value=small), None)
        # The child leaves out its window's end (malformed: no default); presented while the
        # parent is valid, so only a B that fills the end from a default of its own acts.
        return Fixture(two(base, base, c={"omit": ("not_after",)}), _req(value=small),
                       two(base, base), _req(value=small), None)
    if variant == "combined":
        root = {**base, "operations": [OP_A, OP_B], "resources": ["acct-1/*", "acct-2/*"]}
        if form == "union_dimensions":
            g1 = {**root, "operations": [OP_A], "resources": ["acct-1/*"]}
            g2 = {**root, "operations": [OP_B], "resources": ["acct-2/*"]}
            g1l = {**root, "operations": [OP_A, OP_B], "resources": ["acct-1/*"]}
            r = _req(OP_B, small)
            return Fixture([Hop(root), Hop(g1)], r, [Hop(root), Hop(g1l)], dict(r),
                           _req(OP_A, small), second=[Hop(root), Hop(g2)],
                           sib_second=[Hop(root), Hop(g2)])
        if form == "summed_amount":
            g = {**root, "max_amount": _amt(lo)}
            r = _req(value=lo + lo // 2)
            return Fixture([Hop(root), Hop(g)], r, [Hop(root), Hop({**root, "max_amount":
                                                                   _amt(2 * lo)})],
                           dict(r), _req(value=small), second=[Hop(root), Hop(g)],
                           sib_second=[Hop(root), Hop(g)])
        g1, g2 = status_ids()
        return Fixture([Hop(base, grant_id=g1), Hop(base, parent=[g1, g2])], _req(value=small),
                       [Hop(base), Hop(base)], _req(value=small), None,
                       notes={"second_parent": g2})
    if variant == "delegation_exceeded":
        if form == "not_delegable":
            return Fixture(two({**base, "delegation": {"max_depth": 0}},
                               {k: x for k, x in base.items() if k != "delegation"}),
                           _req(value=small),
                           two({**base, "delegation": {"max_depth": 1}},
                               {k: x for k, x in base.items() if k != "delegation"}),
                           _req(value=small), None)
        nd = {k: x for k, x in base.items() if k != "delegation"}
        return Fixture([Hop({**base, "delegation": {"max_depth": 1}}), Hop(nd), Hop(nd)],
                       _req(value=small),
                       [Hop({**base, "delegation": {"max_depth": 2}}), Hop(nd), Hop(nd)],
                       _req(value=small), None)
    if variant == "translated_hop":
        names = (mapping or {}).get("operations") or {}
        b_name = next(iter(names), "contacts:write")
        if form == "mapping_widens":
            return Fixture(two({**base, "operations": [OP_A]}, {**base, "operations": [b_name]}),
                           _req(OP_B, small),
                           two({**base, "operations": [OP_A, OP_B]},
                               {**base, "operations": [b_name]}),
                           _req(OP_B, small), _req(OP_A, small), hop_widened=(1, "operations"),
                           notes={"mapping": mapping})
        return Fixture(two({**base, "operations": [OP_A]}, {**base, "operations":
                                                            ["contacts:erase"]}),
                       _req(OP_A, small), two({**base, "operations": [OP_A]}, {**base,
                                              "operations": [OP_A]}), _req(OP_A, small), None)
    if variant == "cycle":
        if form == "self_parent":
            gid = status_ids()[0]
            return Fixture([Hop(base, grant_id=gid, parent=gid)], _req(value=small),
                           [Hop(base)], _req(value=small), None)
        if form == "id_cycle":
            g1, g2 = status_ids()
            return Fixture([Hop(base, grant_id=g2, parent=g1), Hop(base, grant_id=g1, parent=g2)],
                           _req(value=small), [Hop(base), Hop(base)], _req(value=small), None,
                           cycle_tokens="presented as the second grant, then the first",
                           presented=0)
        n = (max_depth or 2) + 1
        return Fixture([Hop(base) for _ in range(n)], _req(value=small),
                       [Hop(base) for _ in range(n - 1)], _req(value=small), None)
    if variant == "incomplete_chain":
        wide, narrow = {**base, "max_amount": _amt(hi)}, {**base, "max_amount": _amt(lo)}
        if form == "stops_before_root":
            # The root is signed and withheld; its bound excludes the request (KRK-M95c).
            return Fixture([Hop(narrow), Hop(wide), Hop(wide)], _req(value=mid),
                           [Hop(wide), Hop(wide), Hop(wide)], _req(value=mid), None,
                           present=[1, 2], notes={"withheld": "the root"})
        if form == "no_ancestors":
            return Fixture([Hop(narrow), Hop(wide)], _req(value=mid),
                           [Hop(wide), Hop(wide)], _req(value=mid), None, present=[1],
                           notes={"withheld": "every ancestor"})
        g1, g2 = status_ids()
        return Fixture([Hop(wide, grant_id=g2, parent=g1), Hop(wide, grant_id=g1, parent=g2)],
                       _req(value=mid), [Hop(wide), Hop(wide)], _req(value=mid), None,
                       presented=0, cycle_tokens="each names the other; no root")
    if variant == "unknown_constraint":
        member = f"x-krk-{secrets.token_hex(3)}"
        if form == "near_name":
            p = {**base, "max_amount": _amt(hi), "maxAmount": _amt(lo)}
            return Fixture(two(p, {**base, "max_amount": _amt(hi)}), _req(value=mid),
                           two({**base, "max_amount": _amt(hi)}, {**base, "max_amount":
                                                                  _amt(hi)}),
                           _req(value=mid), None)
        extra = {**base, member: {"limit": 1}}
        if form == "in_parent":
            return Fixture(two(extra, base), _req(value=small), two(base, base),
                           _req(value=small), None)
        if form == "in_child":
            return Fixture(two(base, extra), _req(value=small), two(base, base),
                           _req(value=small), None)
        return Fixture(two(base, extra, c={"crit": [member]}), _req(value=small),
                       two(base, base), _req(value=small), None)
    if variant == "numeric":
        if form == "precision":
            return Fixture(two({**base, "max_amount": _amt(lo)},
                               {**base, "max_amount": _amt(lo + 0.4)}, c={"raw": True}),
                           _req(value=lo + 0.4), two({**base, "max_amount": _amt(lo)},
                                                     {**base, "max_amount": _amt(lo)}),
                           _req(value=lo), None, raw_request=True)
        if form == "large_integer":
            return Fixture(two({**base, "max_amount": _amt(2 ** 53)},
                               {**base, "max_amount": _amt(2 ** 53 + 1)},
                               p={"raw": True}, c={"raw": True}),
                           _req(value=2 ** 53 + 1),
                           two({**base, "max_amount": _amt(2 ** 53 - 1)},
                               {**base, "max_amount": _amt(2 ** 53 - 1)}),
                           _req(value=2 ** 53 - 1), None, raw_request=True)
        if form == "units":
            return Fixture(two({**base, "max_amount": _amt(10000, mu=2)},
                               {**base, "max_amount": _amt(150, mu=0)}), _req(value=150, mu=0),
                           two({**base, "max_amount": _amt(15000, mu=2)},
                               {**base, "max_amount": _amt(150, mu=0)}), _req(value=150, mu=0),
                           _req(value=50, mu=0), hop_widened=(1, "max_amount"))
        if form == "currency":
            return Fixture(two({**base, "max_amount": _amt(hi)},
                               {**base, "max_amount": _amt(hi, "USD")}),
                           _req(value=small, cur="USD"),
                           two({**base, "max_amount": _amt(hi, "USD")},
                               {**base, "max_amount": _amt(hi, "USD")}),
                           _req(value=small, cur="USD"), None, hop_widened=(1, "max_amount"))
        if form == "negative":
            return Fixture(two(base, base), _req(value=-small), two(base, base),
                           _req(value=small), None)
        return Fixture(two({**base, "max_amount": _amt(str(hi))}, {**base, "max_amount":
                                                                    _amt(lo)},
                           p={"raw": True}), _req(value=small),
                       two({**base, "max_amount": _amt(hi)}, {**base, "max_amount": _amt(lo)}),
                       _req(value=small), None)
    if variant == "root_exceeds_standing":
        if form in ("amount", "before_first_fetch"):
            return Fixture(two({**base, "max_amount": _amt(hi)}, {**base, "max_amount":
                                                                  _amt(hi)}),
                           _req(value=mid), two({**base, "max_amount": _amt(hi)},
                                                {**base, "max_amount": _amt(hi)}),
                           _req(value=mid), _req(value=small),
                           standing={OP_A: {"max_amount": _amt(lo)}, OP_B: None},
                           sib_standing={OP_A: {"max_amount": _amt(hi)}, OP_B: None})
        r = _req(res=["acct-2/x-" + secrets.token_hex(3)], value=small)
        return Fixture(two({**base, "resources": ["acct-1/*", "acct-2/*"]},
                           {**base, "resources": ["acct-1/*", "acct-2/*"]}), r,
                       two({**base, "resources": ["acct-1/*", "acct-2/*"]},
                           {**base, "resources": ["acct-1/*", "acct-2/*"]}), dict(r),
                       _req(value=small), standing={OP_A: {"resources": ["acct-1/*"]},
                                                    OP_B: None},
                       sib_standing={OP_A: {"resources": ["acct-1/*", "acct-2/*"]},
                                     OP_B: None})
    raise ValueError(f"no fixture for {variant}/{form}")


def status_ids() -> Tuple[str, str]:
    from ..status import new_grant_id
    return new_grant_id(), new_grant_id()


# --------------------------------------------------------------------------- the guards
# One function each, so a test can show the reading each one prevents (KRK-M80 to KRK-M92).


def _mapped(c: Dict[str, Any], mapping: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """B-vocabulary operation names replaced by the A names a declared mapping gives them."""
    names = (mapping or {}).get("operations") or {}
    if "operations" not in c or not names:
        return c
    ops: List[str] = []
    for o in c["operations"]:
        for x in names.get(o, [o]):
            if x not in ops:
                ops.append(x)
    return {**c, "operations": ops}


def spec_claims(hops: List[Hop], *, now: float,
                mapping: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """KRK-M83: the kit's own claims for a fixture chain (presented grant first), for
    `attenuation`: what the fixture means, independent of B's profile and of any target."""
    from .. import status
    out = []
    ids = [h.grant_id or f"gr-{i:016x}" for i, h in enumerate(hops)]
    for i, h in enumerate(hops):
        par = (ids[i - 1] if i else None) if h.parent == "_" else h.parent
        c = {"schema": "kirkaldy.grant/0.2", "grant_id": ids[i], "issuer": "did:web:a.example",
             "subject": f"s{i}", "agent_key": {"kid": "k", "public_key": "0" * 64},
             "principal": "p", "constraints": _mapped(dict(h.c), mapping), "parent": par,
             "issued_at": status.utc_ms(now),
             "not_before": status.utc_s(now + (h.nb if h.nb is not None else -3600)),
             "not_after": status.utc_s(now + (h.na if h.na is not None else 12 * 3600)),
             "status": {"source": "s", "index": i}}
        for m in h.omit:
            c.pop(m, None)
        if h.crit is not None:
            c["crit"] = h.crit
        out.append(c)
    return out[::-1]


def truth(f: Fixture, *, now: float, at: float, tolerance_s: float, party: str
          ) -> Dict[str, Any]:
    """KRK-M81, M86: W's request lies inside the leaf alone and outside the intersection; L's and
    W-in's inside theirs. Read with the kit's own vocabulary (`attenuation`)."""
    from .. import attenuation as att
    m = f.notes.get("mapping")
    w = presented_claims(f, spec_claims(f.hops, now=now, mapping=m))
    s = spec_claims(f.sib_hops, now=now, mapping=m)
    aw = att.allowed(w, f.standing)
    as_ = att.allowed(s, f.sib_standing)
    leaf = att.allowed(w[:1] if w[0]["parent"] is None else [{**w[0], "parent": None}])
    out = {"w_outside": att.inside(f.request, aw, at=at, tolerance_s=tolerance_s,
                                   party=party),
           "l_inside": att.inside(f.sib_request, as_, at=at, tolerance_s=tolerance_s,
                                  party=party),
           "w_in_leaf": att.inside(f.request, leaf, at=at, tolerance_s=tolerance_s,
                                   party=party) if not isinstance(leaf, att.Refusal) else None,
           "w_in_inside": None}
    if f.request_in is not None:
        out["w_in_inside"] = att.inside(f.request_in, aw, at=at, tolerance_s=tolerance_s,
                                        party=party)
    return out


def presented_claims(f: Fixture, claims: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`claims` (presented first, as `spec_claims` returns them) less the hops `f` withholds
    (KRK-M95c)."""
    if f.present is None:
        return claims
    n = len(f.hops)
    keep = {n - 1 - i for i in f.present}
    return [c for j, c in enumerate(claims) if j in keep]


def _value(x: Any) -> Optional[Any]:
    """An amount's value in major units, exactly, or None if it cannot be read exactly."""
    from fractions import Fraction
    if not isinstance(x, dict) or not {"value", "currency"} <= set(x):
        return None
    v, mu = x.get("value"), x.get("minor_units", 0)
    if isinstance(v, bool) or not isinstance(mu, int) or isinstance(mu, bool):
        return None
    try:
        q = Fraction(v) if isinstance(v, int) else (Fraction(str(v)) if isinstance(v, float)
                                                     else None)
    except (ValueError, ZeroDivisionError):
        return None
    return None if q is None else q / (10 ** mu)


def outside_parent_bound(f: Fixture, *, now: float, at: float, tolerance_s: float, party: str
                         ) -> Optional[str]:
    """Which bound, stated by a grant above W's presented grant, W's request lies
    outside; None if it lies inside every such bound. Read from the fixture in the kit's
    vocabulary (withheld hops included), never from B. Fail-safe (a vulnerability is reported
    privately first): a member of such a grant the vocabulary cannot read, or an amount the kit
    cannot read exactly, counts as a bound the effect may exceed; and a chain in which no grant
    is a root rests on no bound A stated."""
    from .. import attenuation as att
    claims = spec_claims(f.hops, now=now, mapping=f.notes.get("mapping"))[::-1]   # root first
    if not any(c["parent"] is None for c in claims):
        return "no grant in the chain is a root, so the effect rests on no bound A stated"
    leaf = len(claims) - 1 if f.presented is None else f.presented
    if f.present is not None:
        leaf = max(f.present)
    req = f.request
    for i, c in enumerate(claims):
        if i == leaf:
            continue
        cons = c.get("constraints") or {}
        where = f"grant {i} from the root"
        unknown = sorted(set(cons) - set(att.CONSTRAINT_MEMBERS))
        if unknown:
            return f"{where} states {unknown}, which the kit's vocabulary cannot read"
        ops = cons.get("operations")
        if isinstance(ops, list) and req.get("operation") not in ops:
            return f"{where}: operation {req.get('operation')!r} is not in {ops}"
        res = cons.get("resources")
        if isinstance(res, list):
            for r in req.get("resources") or []:
                if not any(isinstance(p, str) and att.covers(p, r) for p in res):
                    return f"{where}: resource {r!r} is not covered by {res}"
        aud = cons.get("audience")
        if isinstance(aud, list) and party not in aud:
            return f"{where}: {party} is not in its audience {aud}"
        if "max_amount" in cons:
            lim, amt = cons["max_amount"], req.get("amount")
            lv, av = _value(lim), _value(amt)
            if lv is None or att.amount_problem(lim):
                return f"{where}: its max_amount {lim!r} cannot be read exactly"
            if not isinstance(amt, dict) or amt.get("currency") != lim.get("currency"):
                return f"{where}: the request's currency is not {lim.get('currency')!r}"
            if av is None or av > lv:
                return f"{where}: the request amount {amt!r} is above {lim!r}"
        d = cons.get("delegation")
        if isinstance(d, dict) and isinstance(d.get("max_depth"), int) and \
                leaf - i > d["max_depth"]:
            return f"{where} permits {d['max_depth']} hop(s) below it; the leaf is {leaf - i}"
        nb, na = att._epoch_s(c.get("not_before")), att._epoch_s(c.get("not_after"))
        if (nb is not None and at < nb - tolerance_s) or (na is not None and
                                                           at > na + tolerance_s):
            return f"{where}: {at:.0f} is outside its window"
    return None


def gaps_for(variant: str, form: str, carried: List[str], extras: List[str]) -> List[str]:
    """KRK-M84: the dimensions and format features a form needs that B's format cannot carry."""
    need = DIMS_OF.get((variant, form), [])
    have = set(carried) | set(extras)
    return [n for n in need if n not in have]


def shape_refused(control_two_hop: bool, hops: int, holder: bool, *,
                  control_holder: bool = False) -> bool:
    """KRK-M80: an L refusal on a chain longer than the control's, or with a holder hop the
    control did not have, is about the shape, not the width. In holder-only mode the control's
    own chain has a holder hop."""
    return (holder and not control_holder) or hops > 2


def mapping_from_agreement(a: Any) -> Optional[Dict[str, Any]]:
    """KRK-M92: the mapping is read from B's statement before the run, never assumed."""
    m = dict(getattr(a, "mappings", lambda: {})() or {})
    return m.get(MAP_NAME) or (next(iter(m.values())) if m else None)


def chain_digest(headers: Dict[str, str]) -> str:
    """KRK-M89: what left the kit, digested, for comparison with what B says it received."""
    import hashlib
    from .. import requester
    from ..issuer import CHAIN2_HEADER, GRANT2_HEADER
    h = hashlib.sha256()
    for k in (requester.GRANT_HEADER, requester.CHAIN_HEADER, GRANT2_HEADER, CHAIN2_HEADER):
        h.update(f"{k}\0{headers.get(k, '')}\n".encode())
    return "sha256:" + h.hexdigest()


# --------------------------------------------------------------------------- one run


class _Run(p19._Run):
    def __init__(self, *a: Any, profile: str, carried: List[str], extras: List[str],
                 holder_hops: bool, max_depth: Optional[int], bindings: Dict[str, Any],
                 mapping: Optional[Dict[str, Any]], tolerance: float,
                 std_channels: Optional[List[str]] = None, keys_from: str = "statement",
                 holder_only: bool = False, fmt: Any = None, fmt_state: Any = None,
                 **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.holder_only = holder_only
        """B's only delegation form is holder-signed: the control and every form
        run at ``holder``; position ``a`` is a format gap."""
        self.fmt = fmt
        """The registered delegation format B reads (`delegation_formats`), else None."""
        self.fmt_state = fmt_state
        self.std_channels = list(std_channels if std_channels is not None else ["pull"])
        self.keys_from = keys_from
        self.profile = profile
        self.v1 = profile == "kirkaldy.grant/0.1"
        self.carried = carried
        self.extras = extras
        self.holder_hops = holder_hops
        self.max_depth = max_depth
        self.bindings = bindings
        self.mapping = mapping
        self.tolerance = tolerance
        self.c: Any = None

    @property
    def pull_only(self) -> bool:
        """B obtains standing evidence only by fetching it (KRK-M95)."""
        return "pull" in self.std_channels and "stapled" not in self.std_channels

    # wire forms of the kit's values -----------------------------------------------------------

    def wire_values(self, req: Dict[str, Any]) -> Dict[str, Any]:
        from .. import requester
        v = requester.draw_values(self.rng)
        v["operation"] = req["operation"]
        if self.v1:
            v["amount"] = req["amount"]["value"]
        else:
            v.pop("items", None)
            v["amount"] = dict(req["amount"])
            v["resources"] = list(req["resources"])
        return v

    def build(self, hops: List[Hop], *, holder: bool, principal: str,
              presented: Optional[int] = None) -> Tuple[List[Any], Any]:
        """Sign `hops` (root first) in B's profile; returns (grants presented-first, leaf).
        A registered format writes them itself (`delegation_formats.DelegationFormat`)."""
        A = self.stub
        now = A.now()
        if self.fmt is not None:
            from .. import status
            made_f = self.fmt.write_chain(self.fmt_state, hops, org=A, holder_org=self.c,
                                          holder=holder, principal=principal, now=now,
                                          utc_s=status.utc_s, presented=presented)
            return made_f[::-1], made_f[-1]
        made: List[Any] = []
        for i, h in enumerate(hops):
            nb = now + (h.nb if h.nb is not None else -3600)
            na = now + (h.na if h.na is not None else 12 * 3600)
            par = (made[-1].id if made else None) if h.parent == "_" else h.parent
            subject = f"a{i}-{secrets.token_hex(3)}"
            if self.v1:
                c = h.c
                ops = c.get("operations") or [OP_A]
                ceiling: Dict[str, Any] = {}
                for k, x in c.items():
                    if k == "max_amount":
                        ceiling["max_amount"] = x["value"] if isinstance(x, dict) else x
                    elif k not in ("operations", "resources", "audience", "delegation"):
                        ceiling[k] = x["value"] if isinstance(x, dict) and "value" in x else x
                g = A.issue_v1(subject, ops[0], ceiling, principal=principal, parent_id=par,
                               grant_id=h.grant_id, not_before=nb, not_after=na, omit=h.omit,
                               raw=h.raw)
            elif i == 0 or not holder:
                g = A.issue_v2(subject, dict(h.c), principal=principal, parent=par,
                               not_before=nb, not_after=na, grant_id=h.grant_id, crit=h.crit,
                               raw=h.raw, omit=h.omit)
            else:
                g = A.delegate_holder(made[-1], subject, dict(h.c), org=self.c,
                                      principal=principal, not_before=nb, not_after=na,
                                      grant_id=h.grant_id, parent_id=par, crit=h.crit,
                                      raw=h.raw, omit=h.omit, check=False)
            made.append(g)
        return made[::-1], made[-1]

    def present_chain(self, grants: List[Any], req: Dict[str, Any], *, ep: str,
                      second: Optional[List[Any]] = None, staple: Any = None,
                      raw: bool = False, order: Optional[List[int]] = None) -> Any:
        from .. import standing
        from ..issuer import CHAIN2_HEADER, GRANT2_HEADER
        leaf = grants[0]
        toks = [g.token for g in grants]
        if order is not None:
            toks = [toks[i] for i in order]
        holder = getattr(leaf, "holder", None) or self.stub
        p = self.stub.under_raw(toks, self.wire_values(req), audience=self.audience(ep),
                                subject=leaf.subject, holder=holder, grant_id=leaf.id,
                                operation=req["operation"], loose=raw, window_s=self.req_window)
        if second:
            p.headers[GRANT2_HEADER] = second[0].token
            if len(second) > 1:
                p.headers[CHAIN2_HEADER] = ",".join(g.token for g in second[1:])
        if staple is not None:
            p.headers[standing.STANDING_HEADER] = staple.token
        return p


# --------------------------------------------------------------------------- control and trials


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    base = _base(run.carried)
    log: List[Any] = []
    obs: Dict[str, Any] = {}
    shapes = [("holder", True)] if run.holder_only else \
        [("a", False)] + ([("holder", True)] if run.holder_hops else [])
    deadline = run.clock.now() + READY_S
    pcs: List[str] = []
    for name, holder in shapes:
        pcs.append(f"pc-{secrets.token_hex(3)}@a.example")
        grants, _leaf = run.build([Hop(base), Hop(_narrow(base, run.carried))], holder=holder,
                                  principal=pcs[-1])
        for ep in run.endpoints:
            ok = False
            while not ok:
                p = run.send(run.present_chain(grants, _req(value=10000), ep=ep), "W",
                             tag=f"control:{name}")
                log.append(p)
                ok = p.accepted
                if not ok and run.clock.now() >= deadline:
                    return False, (f"an honest two-hop chain ({name}) was not accepted at "
                                   f"endpoint {ep!r} within {READY_S:g} s"), \
                        {"presentations": log}
                if not ok:
                    run.clock.sleep(1.0)
    run.settle(run.clock.now() + 0.5)
    for p in log:
        run.fill(p)
        if run.grade == "recorder":
            n = len(run.effect_times(p.ref))
            if p.accepted and n != 1:
                return False, f"an accepted presentation ({p.ref}) has {n} effects", \
                    {"presentations": log}
    obs["presentations"] = log
    if run.pull_only and "standing-limits" in run.extras:
        # KRK-M95b: P for the fetch waits, from B's fetches of the control principal's
        # standing, as P20's control measures it; otherwise the first waits run with P = 0.
        from ..timing import fetch_intervals
        path = _standing_path(pcs[0])
        end = run.clock.now() + max(10.0, 2.0 * (run.T or 30.0))
        while run.clock.now() < end and len(b_fetched(run.stub, path, float("-inf"))) < 3:
            run.clock.sleep(0.25)
        with run.stub._slock:
            starts = [e for e in run.stub._fetch_log if e.get("path") == path]
        iv = fetch_intervals(starts)
        if iv:
            run.max_interval = max(run.max_interval, max(iv))
        obs["fetch_intervals_s"] = [round(x, 3) for x in iv]
    return True, "", obs


@dataclass
class _T:
    variant: str
    form: str
    position: str
    k: int
    pres: List[Any] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    info: Optional[str] = None
    info_detail: str = ""


def _static_trial(run: _Run, variant: str, form: str, position: str, k: int) -> _T:
    from .. import attenuation as att
    A, clock = run.stub, run.clock
    tr = _T(variant, form, position, k)
    run.variant = variant
    run.disp.begin_trial()
    holder = position == "holder"
    f = fixture(variant, form, run.rng, party=run.counterparty, dims=run.carried,
                max_depth=run.max_depth, mapping=run.mapping, tolerance=run.tolerance)
    now_wall = A.now()
    at = now_wall + (f.present_at + run.tolerance + 1.0 if f.present_at else 0.0)
    t = truth(f, now=now_wall, at=at, tolerance_s=run.tolerance, party=run.counterparty)
    tr.extra["truth"] = t
    tr.extra["parent_bound"] = outside_parent_bound(f, now=now_wall, at=at,
                                                    tolerance_s=run.tolerance,
                                                    party=run.counterparty)
    outside_by_b = (variant, form) in (("cycle", "too_deep"),)
    if (not t["w_outside"] and not outside_by_b) or t["l_inside"] or \
            (f.request_in is not None and t["w_in_inside"]):
        raise AssertionError(f"the kit's own fixture for {variant}/{form} does not mean what it "
                             f"says (KRK-M81, M83): {t}")
    pw = f"pw-{secrets.token_hex(3)}@a.example"
    pl = f"pl-{secrets.token_hex(3)}@a.example"
    W, _ = run.build(f.hops, holder=holder, principal=pw, presented=f.presented)
    L, _ = run.build(f.sib_hops, holder=holder, principal=pl)
    W2 = run.build(f.second, holder=holder, principal=pw)[0] if f.second else None
    L2 = run.build(f.sib_second, holder=holder, principal=pl)[0] if f.sib_second else None
    if (variant, form) in (("cycle", "id_cycle"), ("incomplete_chain", "mutual_no_root")):
        # Each names the other; presented as the second grant, then the first: no root.
        W = W[::-1]
    if f.present is not None:
        # KRK-M95c: the withheld hops are signed and never sent.
        n = len(W)
        keep = {n - 1 - i for i in f.present}
        tr.extra["withheld"] = [g.id for j, g in enumerate(W) if j not in keep]
        W = [g for j, g in enumerate(W) if j in keep]
    sw = sl = None
    t_fix = clock.now()
    if f.standing is not None:
        sw = A.assert_standing(pw, f.standing)
        sl = A.assert_standing(pl, f.sib_standing or f.standing)
    if form == "before_first_fetch":
        _before_fetch(run, tr, W, f, pw, t_fix, sw)
        return tr
    if waits_for_fetch(run, variant, position, max(len(W), len(L))):
        waits: List[Tuple[str, Any, str, float, Tuple[str, ...]]] = []
        if f.standing is not None:
            waits += [(u, A, _standing_path(p), t_fix, ("ok",)) for u, p in (("W", pw),
                                                                              ("L", pl))]
        elif "standing-limits" in run.extras:
            # A B that reads standing limits learns that A publishes none for a principal
            # only from a fetch (A's 404 counts).
            waits += [(u, A, _standing_path(p), t_fix, ("ok", "stale", "not-found"))
                      for u, p in (("W", pw), ("L", pl))]
        if holder and max(len(W), len(L)) > 2:
            # A hop C's agent signed is C's only by C's key statement.
            waits.append(("C_keys", run.c, "/keys", run.c.keyset()["t_signed"], ("ok",)))
        tr.extra["fetched_before_present"] = await_fetches(run, waits)
    tr.extra["signers"] = [getattr(g, "signer", "org") for g in W]
    tr.extra["l_grants"] = len(L)
    tr.extra["hop_widened"] = f.hop_widened
    if f.present_at:
        clock.sleep_until(clock.now() + f.present_at + run.tolerance + 1.0)
    items: List[Tuple[str, Any]] = [
        ("W", run.present_chain(W, f.request, ep=run.endpoints[0], second=W2, staple=sw,
                                raw=f.raw_request)),
        ("L", run.present_chain(L, f.sib_request, ep=run.endpoints[-1], second=L2, staple=sl))]
    if f.request_in is not None and (variant, form) not in MALFORMED:
        items.append(("W-in", run.present_chain(W, f.request_in, ep=run.endpoints[0], second=W2,
                                                staple=sw)))
    run.rng.shuffle(items)
    for under, p in items:
        tr.extra.setdefault("chain_digests", {})[under] = chain_digest(p.headers)
        q = run.send(p, under, tag=f"static:{under}")
        tr.pres.append(q)
    run.settle(clock.now() + 2.0)
    for q in tr.pres:
        run.fill(q)
    return tr


def _before_fetch(run: _Run, tr: _T, W: List[Any], f: Fixture, pw: str, t_fix: float,
                  staple: Any) -> None:
    """KRK-M95b: present W once, at once, before B has fetched anything for its
    root principal `pw`; L and W-in are not presented. `staple` is never sent: the form is for
    a B that reads standing only by fetching."""
    A, clock = run.stub, run.clock
    path = _standing_path(pw)
    seen = b_fetched(A, path, t_fix)
    tr.extra["presented_before_fetch"] = not seen
    tr.extra["signers"] = [getattr(g, "signer", "org") for g in W]
    if seen:
        tr.info = "not_landed"
        tr.info_detail = ("B had already fetched the root principal's standing when the request "
                          "could be presented (KRK-M95b)")
        return
    p = run.present_chain(W, f.request, ep=run.endpoints[0])
    tr.extra.setdefault("chain_digests", {})["W"] = chain_digest(p.headers)
    tr.pres.append(run.send(p, "W", tag="static:W:before_fetch"))
    run.settle(clock.now() + 2.0)
    for q in tr.pres:
        run.fill(q)
    first = b_fetched(A, path, t_fix)
    tr.extra["first_fetch_after_s"] = round(first[0] - t_fix, 3) if first else None


def b_fetched(org: Any, path: str, after: float) -> List[float]:
    """The end times of B's fetches of `path` that started after kit time `after` and brought
    an answer from A (200 or 404). The stub logs B's fetches only (KRK-M95b)."""
    with org._slock:
        return sorted(e["t_end"] for e in org._fetch_log if e.get("path") == path
                      and e.get("t_end") is not None and e["t_start"] > after
                      and e.get("outcome") in ("ok", "stale", "not-found"))


def waits_for_fetch(run: _Run, variant: str, position: str, hops: int) -> bool:
    """KRK-M95: a B that obtains standing evidence only by fetching it is not
    presented with `root_exceeds_standing` until it has fetched the root principals' assertions;
    where it reads standing limits (`standing-limits`), with no static trial until it has fetched
    for both root principals, whose answer may be that A publishes none; and (where it reads A's
    key statements) with no chain through a hop C's agent signed until it has fetched C's key
    statement, which lists that agent. Presented at once, it holds none of these.
    A fetch not seen within the limit is recorded, and the trial goes on."""
    if not run.pull_only:
        return False
    if variant == "root_exceeds_standing" or "standing-limits" in run.extras:
        return True
    return position == "holder" and run.c is not None and run.keys_from == "statement" \
        and hops > 2


def _standing_path(principal: str) -> str:
    import urllib.parse
    from ..issuer import STANDING_PATH
    return STANDING_PATH + urllib.parse.quote(principal, safe="")


def await_fetches(run: _Run, waits: List[Tuple[str, Any, str, float, Tuple[str, ...]]]
                  ) -> Dict[str, bool]:
    """KRK-M95: wait, up to the fetch limit for each, for B's fetch of each `(label, org, path,
    after, outcomes)`; returns which were seen. The limit is X4's (`max(2 P, 5 s) + 1 s`), P the
    largest interval between B's fetches seen so far, measured here before each wait
    (KRK-M95b): P21 measured it only in `narrowed_parent`, so a static trial run before that
    variant waited 6 s whatever B's poll."""
    run.note_intervals()
    limit = max(2 * run.max_interval, 5.0) + 1
    return {label: org.wait_fetched(path, after, limit, outcomes=outcomes) is not None
            for label, org, path, after, outcomes in waits}


def _judge_static(run: _Run, tr: _T) -> Any:
    from ..timing import TrialOutcome
    if tr.form == "before_first_fetch":
        return _judge_before_fetch(tr)
    W = [p for p in tr.pres if p.under == "W"]
    L = [p for p in tr.pres if p.under == "L"]
    win = [p for p in tr.pres if p.under == "W-in"]
    hw = tr.extra.get("hop_widened")
    if any(p.accepted for p in W):
        where = f" (hop {hw[0]} from the root, {hw[1]})" if hw else ""
        return TrialOutcome("outside_effect", False, form=tr.form,
                            detail=f"an effect outside the chain's intersection{where}, at "
                                   f"position {tr.position}")
    if any(p.timed_out for p in W):
        return TrialOutcome("hung", None, form=tr.form, detail="no answer within the answer "
                            "timeout and no effect (an availability finding)")
    if not any(p.accepted for p in L):
        nh = max(len(tr.extra.get("signers") or []), int(tr.extra.get("l_grants") or 0))
        if shape_refused(True, nh, tr.position == "holder", control_holder=run.holder_only):
            return TrialOutcome("shape_refused", None, form=tr.form,
                                detail=f"the sibling of the same shape ({nh} grants, position "
                                       f"{tr.position}) was refused too (KRK-M80)")
        return TrialOutcome("collateral_refusal", None, form=tr.form,
                            detail="the sibling, inside the intersection, was refused too, so "
                                   "the refusal is not shown to be about the width (KRK-M85)")
    mode = "clamped" if any(p.accepted for p in win) else (
        "chain_refused" if win else "n/a")
    return TrialOutcome("held", True, form=tr.form,
                        detail=f"no effect for W; L accepted; mode {mode}")


def _judge_before_fetch(tr: _T) -> Any:
    """KRK-M95b: W's effect alone. An effect is above the standing limit A publishes; any
    refusal holds, whatever check gave it."""
    from ..timing import TrialOutcome
    if tr.info:
        return TrialOutcome(tr.info, None, form=tr.form, detail=tr.info_detail)
    W = [p for p in tr.pres if p.under == "W"]
    if any(p.accepted for p in W):
        return TrialOutcome("outside_effect", False, form=tr.form,
                            detail="an effect above the root principal's standing limit, "
                                   "presented before B had fetched anything for that principal "
                                   "(the chain alone allows it), at position a")
    if any(p.timed_out for p in W):
        return TrialOutcome("hung", None, form=tr.form, detail="no answer within the answer "
                            "timeout and no effect (an availability finding)")
    if W and all(p.refused for p in W):
        return TrialOutcome("held", True, form=tr.form,
                            detail="no effect for W, presented before B's first fetch for its "
                                   "root principal; graded on W alone; mode n/a")
    return TrialOutcome("not_landed", None, form=tr.form, detail="W had no readable answer")


def _narrowed_trial(run: _Run, k: int) -> Tuple[Any, Dict[str, Any]]:
    """``narrowed_parent``: parent P and child C each allow `hi`; after a request
    under C is accepted, A narrows P to `lo` in its status (X4's `narrow`); requests above `lo`
    under C follow on X4's schedule. Timed with X4's harness, unchanged."""
    from .. import timing
    from ..timing import TrialLog
    A, clock, T = run.stub, run.clock, run.T
    run.variant = "narrowed_parent"
    run.disp.begin_trial()
    ex: Dict[str, Any] = {}
    hi, lo = 500000, 100000
    base = {k: x for k, x in _base(run.carried).items() if k != "delegation"}
    pw = f"pw-{secrets.token_hex(3)}@a.example"
    W, _ = run.build([Hop({**base, "max_amount": _amt(hi)}), Hop({**base, "max_amount":
                                                                  _amt(hi)})],
                     holder=run.holder_only, principal=pw)
    L, _ = run.build([Hop({**base, "max_amount": _amt(hi)}), Hop({**base, "max_amount":
                                                                  _amt(hi)})],
                     holder=run.holder_only, principal=f"pl-{secrets.token_hex(3)}@a.example")
    parent_id = W[1].id
    pres: List[Any] = []
    deadline = clock.now() + READY_S
    for g, u in ((W, "W"), (L, "L")):
        ok = False
        while not ok:
            p = run.send(run.present_chain(g, _req(value=(lo + hi) // 2), ep=run.endpoints[0]),
                         u, tag="ready")
            pres.append(p)
            ok = p.accepted
            if not ok and clock.now() >= deadline:
                log = TrialLog("narrowed_parent", "", clock.now(), T, run.window, run.stability,
                               presentations=[], w_effects=[], info="not_ready",
                               info_detail="W or L was not accepted before the narrowing",
                               ended_at=clock.now())
                return log, ex
            if not ok:
                clock.sleep(1.0)
    clock.sleep(p19.SETTLE_S)
    if "pull-list" in run.channels:
        run.note_intervals()
    t0 = clock.now()
    wd = A.narrow(parent_id, {"max_amount": lo})
    got = A.read_back({parent_id: "narrowed"})
    t_n = wd.t_commit
    ex.update(narrowed=parent_id, read_back=got, t_n_kit=t_n)
    if not all(got.values()):
        log = TrialLog("narrowed_parent", "", t_n, T, run.window, run.stability,
                       presentations=[], w_effects=[], info="fixture_not_landed",
                       info_detail=f"the narrowing does not read back (KRK-M91): {got}",
                       ended_at=clock.now())
        return log, ex
    slots = timing.schedule(T, run.rng, window=run.window, resolution_s=run.resolution)
    disp = run.disp
    w_refs = [p.ref for p in pres if p.under == "W"]
    judged: List[Any] = []
    for i, slot in enumerate(slots):
        clock.sleep_until(t_n + slot.offset_s)
        disp.poll()
        ep = run.endpoints[i % len(run.endpoints)]
        q = disp.submit(run.present_chain(W, _req(value=(lo + hi) // 2), ep=ep), "W",
                        tag=slot.kind)
        if q is not None:
            judged.append(q)
            w_refs.append(q.ref)
        for g, u, val in ((W, "W-in", lo // 2), (L, "L", (lo + hi) // 2)):
            c = disp.submit(run.present_chain(g, _req(value=val), ep=ep), u, tag="regular",
                            companion=True)
            if c is not None:
                judged.append(c)
        streak = p19._streak(judged)
        if streak is not None and clock.now() - streak >= run.stability:
            break
    disp.drain()
    run.settle(clock.now() + 2.0)
    for q in judged:
        run.fill(q)
    w_eff = [t for r in set(w_refs) for t in run.effect_times(r)]
    log = TrialLog("narrowed_parent", "", t_n, T, run.window, run.stability,
                   presentations=judged, w_effects=w_eff, ended_at=clock.now(),
                   resolution_s=run.resolution)
    ex["t0_to_t_n_s"] = round(t_n - t0, 4)
    return log, ex


def _narrowed_mode(run: _Run, log: Any) -> Tuple[str, str]:
    """The mode of a ``narrowed_parent`` trial, from W-in's answers sent after ``t_n + T``, and
    what was observed: ``clamped`` (a request inside the narrowed ceiling was accepted),
    ``chain_refused`` (every one was refused; observed ``narrowed_as_withdrawn``), ``n/a`` (none
    was sent after the bound).

    Once the parent is narrowed, the child is a hop wider than its parent, so a B
    that refuses a chain with a wider hop also refuses the requests inside the narrowed ceiling.
    That is its ``chain_refused`` mode, and it passes, as the outcome rules pass both modes."""
    lim = log.t_w + (run.T or 0.0)
    inside = [p for p in log.presentations if p.under == "W-in" and p.t_sent > lim]
    if not inside:
        return "n/a", ""
    if any(p.accepted for p in inside):
        return "clamped", ""
    return "chain_refused", "narrowed_as_withdrawn"


def _judge_narrowed(run: _Run, log: Any) -> Any:
    from .. import timing
    o = timing.classify_trial(log)
    detail = o.detail.replace("the withdrawal", "the narrowing")
    if o.ok is True:
        mode, seen = _narrowed_mode(run, log)
        if seen:
            detail += ("; requests inside the narrowed ceiling were refused too (observed "
                       f"{seen}, read as mode {mode})")
        detail += f"; mode {mode}"
    return timing.TrialOutcome(o.outcome, o.ok, time_s=o.time_s, bracket=o.bracket,
                               last_effect_s=o.last_effect_s, onset_endpoint=o.onset_endpoint,
                               detail=detail, form=o.form)


# --------------------------------------------------------------------------- the probe


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    if raw.strip().startswith("{"):
        return json.loads(raw)
    with open(raw, encoding="utf-8") as fh:
        return json.load(fh)


def _trials(plan: Dict[str, Any], variant: str) -> int:
    t = plan.get("trials") or TRIALS
    if t == "dev":
        t = DEV_TRIALS
    elif t == "published":
        t = PUBLISHED_TRIALS
    return int(t.get(variant, t.get("*", 1)))


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import attenuation as att, delegation_formats, role_b
    from ..issuer import StubIssuer
    from ..mockserver import MockServer
    from ..requester import new_issuer
    from ..timing import make_clock, stability_s, window_s

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if getattr(a, "role", lambda: "B")() != "B":
        return Result.inconclusive(a.name, ID, "P21 grades B in version 1 (design §6.6)", **common)
    base = role_b.RoleB()

    def opt(name: str) -> Any:
        fn = getattr(a, name, None)
        return fn() if callable(fn) else getattr(base, name)()
    try:
        bound = dict(a.withdrawal_bound() or {})
        agreement = dict(a.agreement() or {})
        grade = a.evidence_grade()
        profile = opt("grant_profile") or "kirkaldy.grant/0.2"
        carried = [d for d in (opt("constraint_profile") or []) if d in att.DIMENSIONS]
        bindings = dict(opt("constraint_bindings") or {})
        holder_hops = bool(opt("accepts_holder_hops"))
        max_depth = opt("max_depth")
        advisory = dict(opt("advisory_members") or {})
        mapping = mapping_from_agreement(a)
        n_iss = int(opt("issuers") or 1)
        std_channels = list(opt("standing_channels") or [])
        keys_from = str(opt("keys_from") or "statement")
        channels = list(getattr(a, "channels", lambda: [])() or [])
        forms = list(getattr(a, "presentation_forms", lambda: ["agent"])() or ["agent"])
        extras = list(getattr(a, "format_features", lambda: [])() or [])
        dforms = getattr(a, "delegation_forms", None)
        dforms = list(dforms() or []) if callable(dforms) else None
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    fmt = delegation_formats.get(profile) if profile not in role_b.GRANT_PROFILES else None
    if profile not in role_b.GRANT_PROFILES and fmt is None:
        return Result.inconclusive(a.name, ID, f"unknown grant profile {profile!r}", **common)
    depth_reading: Dict[str, Any] = {"stated": max_depth, "unit": "grants, the root included"}
    not_carried: Dict[str, str] = {}
    if fmt is not None:
        # What the registered format cannot write, and what it states itself.
        not_carried = {k: v for k, v in dict(fmt.cannot_carry).items() if k in extras}
        extras = [x for x in extras if x not in fmt.cannot_carry]
        extras += [x for x in fmt.carries if x not in extras]
        if fmt.max_grants is not None:
            depth_reading.update(profile_limit=fmt.max_grants, profile_quote=fmt.depth_source,
                                 reading=fmt.depth_reading)
            max_depth = fmt.max_grants if max_depth is None else \
                min(int(max_depth), fmt.max_grants)
    depth_reading["used"] = max_depth
    holder_only = dforms == ["holder"] or (fmt is not None and
                                           tuple(fmt.delegation_forms) == ("holder",))
    T = bound.get("T_s")
    if T is not None and bound.get("source") == "carried":
        bound = {**bound, "carried_T_s": T, "T_s": None}
        T = None
    if not agreement.get("counterparty") or grade not in GRADES:
        return Result.inconclusive(a.name, ID, "no counterparty id, or an unknown evidence grade",
                                   **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not p19._is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock", **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    forbidden = {x if isinstance(x, str) else x[0] for x in NA_FORBIDDEN}
    if any(v in forbidden or v not in VARIANTS for v in na):
        return Result.inconclusive(a.name, ID, f"the adapter declares {sorted(na)} not "
                                   f"applicable; {sorted(forbidden)} may not be", **common)
    plan = dict(plan if plan is not None else ({} if p19._is_toy(a) else (_plan_from_env() or {})))
    published = plan == {"trials": "published"}
    development = bool(plan) and not published
    win = float(plan.get("window_s") or window_s(T))
    stab = float(plan.get("stability_s") or stability_s(T))
    only = list(plan.get("variants") or VARIANTS)
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = list(VARIANTS)
    rng.shuffle(order)
    clock = make_clock(kind)
    if kind == "virtual":
        a.set_clock(clock)
    recorder = MockServer(clock=clock.now)
    A = StubIssuer(new_issuer(), clock=clock, ttl_s=int(T) if T else 60,
                   audience=agreement["counterparty"])
    A.hang_s = (T or 30.0) + 5.0
    url = A.serve()
    progress = p19._Progress(ev)
    run = None
    fmt_state: Any = None
    fmt_open = False
    try:
        want_c = holder_hops and n_iss > 1
        if holder_only and not want_c:
            return Result.inconclusive(a.name, ID, "B's only delegation form is holder-signed, "
                                       "but it states no holder organisation (accepts_holder_"
                                       "hops and issuers > 1), so no chain can be written",
                                       **common)
        C = None
        peer_how = None
        if fmt is not None:
            # C exists before A is bound, so the format's state can name both organisations.
            C = A.peer() if want_c else None
            fmt_state = fmt.open(clock, [o for o in (A, C) if o is not None])
            fmt_open = True
            bind_how = a.bind_requester({**A.trust_anchor_x1(), **fmt.anchor(fmt_state, A)},
                                        url)
            if C is not None:
                peer_how = a.bind_peer({**C.trust_anchor_x1(), **fmt.anchor(fmt_state, C)},
                                       C.source_url)
        else:
            bind_how = a.bind_requester(A.trust_anchor_x1(), url)
            if want_c:
                C = A.peer()
                peer_how = a.bind_peer(C.trust_anchor_x1(), C.source_url)
        prefix = f"/p21/{run_tag}{secrets.token_hex(4)}"
        rec_how = a.bind_recorder(recorder.url + prefix)
        tol = float(bound.get("clock_tolerance_s") or agreement.get("clock_tolerance_s") or 0.0)
        run = _Run(a, ev, clock=clock, stub=A, recorder=recorder, prefix=prefix,
                   agreement=agreement, bound=bound, channels=channels, forms=forms,
                   grade=grade, rng=rng, window=win, stability=stab, profile=profile,
                   carried=carried, extras=extras, holder_hops=holder_hops and C is not None,
                   max_depth=max_depth, bindings=bindings, mapping=mapping, tolerance=tol,
                   std_channels=std_channels, keys_from=keys_from, holder_only=holder_only,
                   fmt=fmt, fmt_state=fmt_state)
        run.c = C
        run.progress = progress
        statements = {"grant_profile": profile, "constraint_profile": carried,
                      "format_features": extras, "constraint_bindings": bindings,
                      "accepts_holder_hops": holder_hops, "max_depth": max_depth,
                      "advisory_members": advisory, "mapping": mapping, "T_s": T,
                      "standing_channels": std_channels, "keys_from": keys_from,
                      "bound": bound, "clock_tolerance_s": tol,
                      "delegation_forms": dforms, "holder_only": holder_only,
                      "depth": depth_reading}
        if fmt is not None:
            statements["not_carried_by_profile"] = not_carried
        ev.write("run.json", {"seed": seed, "variant_order": ["control"] + order,
                              "statements": p19._jsonable(statements), "plan": plan,
                              "bind_requester": bind_how, "bind_peer": peer_how,
                              "bind_recorder": rec_how, "clock": kind})
        run.log("run", seed=seed, statements=statements, plan=plan)
        return _probe(run, a, ev, common, na, plan, development, only, order, seed, advisory)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        if run is not None:
            run.disp.close()
        if fmt_open:
            fmt.close(fmt_state)
        recorder.close()
        A.close()
        clock.close()


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], na: Dict[str, str],
           plan: Dict[str, Any], development: bool, only: List[str], order: List[str],
           seed: int, advisory: Dict[str, Any]) -> Result:
    from .. import timing
    held, why, obs = _control(run)
    ev.write("control.json", {"held": held, "why": why,
                              "fetch_intervals_s": obs.get("fetch_intervals_s"),
                              "presentations": [p19._pres_doc(p, None)
                                                for p in obs.get("presentations", [])]})
    run.log("control", held=held, why=why)
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    if run.holder_only:
        control = ("an honest two-hop chain with a holder-signed child (holder-only: B's only "
                   "delegation form), accepted at every endpoint with one effect each")
    else:
        control = ("an honest two-hop chain" + (", and one with a holder-signed child," if
                                               run.holder_hops else "") +
                   " accepted at every endpoint with one effect each")
    readings: Dict[str, Dict[str, Any]] = {}
    gaps: List[Dict[str, str]] = []
    if run.holder_only:
        gaps.append({"variant": "position", "form": "a", "missing": ["a-signed-delegation"],
                     "why": POSITION_A_GAP})
    classes: Dict[str, Dict[str, Any]] = {}
    docs: Dict[str, List[Dict[str, Any]]] = {}
    timed: List[Any] = []
    modes: Dict[str, set] = {}
    for variant in order:
        if variant in na or variant not in only:
            continue
        if variant == "narrowed_parent":
            if run.fmt is not None and run.fmt.status_gap:
                gaps.append({"variant": variant, "form": "-", "missing": ["status"],
                             "why": run.fmt.status_gap})
                readings[variant] = {"-": {"reading": "format_gap", "ok": None,
                                           "detail": run.fmt.status_gap}}
                continue
            if "max_amount" not in run.carried:
                readings[variant] = {"-": {"reading": "format_gap", "ok": None,
                                           "detail": "B carries no max_amount"}}
                continue
            if not run.T or not any(c in run.channels for c in ("pull-list", "pull-item",
                                                                 "push")):
                readings[variant] = {"-": {"reading": "not_applicable", "ok": None,
                                           "detail": "B states no status channel or no T"}}
                continue
            for k in range(_trials(plan, variant)):
                log, ex = _narrowed_trial(run, k)
                o = _judge_narrowed(run, log)
                timed.append(o)
                doc = {"k": k, "outcome": o.to_doc(), "extra": p19._jsonable(ex),
                       "presentations": [p19._pres_doc(p, log.t_w) for p in log.presentations]}
                if o.ok:
                    mode, seen = _narrowed_mode(run, log)
                    doc["mode"] = mode
                    if seen:
                        doc["observed"] = seen
                    if mode != "n/a":
                        modes.setdefault(variant, set()).add(mode)
                docs.setdefault(variant, []).append(doc)
                run.log("trial", variant=variant, **doc)
            lab, ok = timing.aggregate(timed, run.T, need=_trials(plan, variant))
            readings[variant] = {"-": {"reading": lab, "ok": ok, "detail": next(
                (o.detail for o in timed if o.ok is False), timed[0].detail if timed else "")}}
            ev.write(f"{variant}.json", {"variant": variant, "trials": docs.get(variant, [])})
            continue
        for form in FORMS[variant]:
            if form and variant in (plan.get("forms") or {}) and \
                    form not in plan["forms"][variant]:
                continue
            if variant in POSITIONED:
                positions: Tuple[str, ...] = POSITIONS
            else:
                positions = ("holder",) if run.holder_only else ("a",)
            first = positions[-1] if run.holder_only else positions[0]
            for pos in positions:
                key = form if (pos == "a" or variant not in POSITIONED) else f"{form}@holder"
                missing = gaps_for(variant, form, run.carried, run.extras)
                if missing:
                    why = "; ".join(GAP_WORDS.get(m, f"B's format carries no {m}")
                                    for m in missing)
                    if pos == first:
                        gaps.append({"variant": variant, "form": form, "missing": missing,
                                     "why": why})
                    readings.setdefault(variant, {})[key] = {"reading": "format_gap",
                                                             "ok": None, "detail": why}
                    continue
                if pos == "a" and run.holder_only:
                    readings.setdefault(variant, {})[key] = {"reading": "format_gap",
                                                             "ok": None,
                                                             "detail": POSITION_A_GAP}
                    continue
                if pos == "holder" and not run.holder_hops:
                    readings.setdefault(variant, {})[key] = {
                        "reading": "not_applicable", "ok": None,
                        "detail": "B accepts no hop signed by another organisation's agent "
                                  ""}
                    continue
                if form == "too_deep" and run.max_depth is None:
                    # Declaring `stated-depth` and stating no maximum is the
                    # same finding as not declaring it, never not applicable.
                    why = "B declares stated-depth but max_depth() states no maximum chain"
                    if pos == first:
                        gaps.append({"variant": variant, "form": form,
                                     "missing": ["stated-depth"], "why": why})
                    readings.setdefault(variant, {})[key] = {"reading": "format_gap",
                                                             "ok": None, "detail": why}
                    continue
                if form == "before_first_fetch" and not run.pull_only:
                    readings.setdefault(variant, {})[key] = {
                        "reading": "not_applicable", "ok": None,
                        "detail": "B does not obtain standing only by fetching it, so the other "
                                  "forms already present before its first fetch (KRK-M95b)"}
                    continue
                if variant == "translated_hop" and form == "mapping_widens" and \
                        not run.mapping:
                    readings.setdefault(variant, {})[key] = {
                        "reading": "format_gap", "ok": None, "detail": GAP_WORDS["mappings"]}
                    continue
                outs = []
                for k in range(_trials(plan, variant)):
                    tr = _static_trial(run, variant, form, pos, k)
                    o = _judge_static(run, tr)
                    outs.append(o)
                    if o.ok:
                        m = o.detail.rsplit("mode ", 1)[-1]
                        if m != "n/a":            # W-in not presented: no mode to read
                            modes.setdefault(variant, set()).add(m)
                    doc = {"form": form, "position": pos, "k": k, "outcome": o.to_doc(),
                           "extra": p19._jsonable(tr.extra),
                           "presentations": [p19._pres_doc(p, None) for p in tr.pres]}
                    docs.setdefault(variant, []).append(doc)
                    run.log("trial", variant=variant, **doc)
                fails = [o for o in outs if o.ok is False]
                counted = [o for o in outs if o.ok is not None]
                if fails and variant in VULNERABLE_VARIANTS:
                    # The class of a failing form, from its failing trials' W.
                    bound = next((d["extra"].get("parent_bound") for d, o in
                                  zip(docs[variant][-len(outs):], outs)
                                  if o.ok is False and d["extra"].get("parent_bound")), None)
                    classes[f"{variant}/{key}"] = {
                        "class": "vulnerability" if bound else "conformance",
                        "parent_bound": bound or "inside every bound a grant above the "
                                                 "presented one states"}
                if fails:
                    r = {"reading": "outside_effect", "ok": False, "detail": fails[0].detail}
                elif counted and all(o.ok for o in counted):
                    r = {"reading": "held", "ok": True, "detail": counted[0].detail}
                else:
                    infos = [o.outcome for o in outs]
                    r = {"reading": max(sorted(set(infos)), key=infos.count), "ok": None,
                         "detail": outs[0].detail if outs else ""}
                readings.setdefault(variant, {})[key] = r
        if variant in docs:
            ev.write(f"{variant}.json", {"variant": variant, "trials": docs[variant]})
    checks: List[Check] = []
    for variant in VARIANTS:
        if variant in na:
            checks.append(Check(variant, "not_applicable", None, na[variant]))
            continue
        fr = readings.get(variant)
        if not fr:
            continue
        parts = "; ".join(f"{k}: {d['reading']}" for k, d in fr.items())
        fails = [(k, d) for k, d in fr.items() if d["ok"] is False]
        passes = [(k, d) for k, d in fr.items() if d["ok"] is True]
        if fails:
            k, d = fails[0]
            c = Check(variant, d["reading"], False, f"{k}: {d['detail']}; {parts}")
        elif any(d["reading"] == timing.INCONCLUSIVE for d in fr.values()):
            c = Check(variant, timing.INCONCLUSIVE, None, parts)
        elif passes:
            labs = sorted({d["reading"] for _k, d in passes})
            m = sorted(modes.get(variant, set()) - {"n/a"})
            c = Check(variant, "+".join(labs), True, parts + (f"; mode {'/'.join(m)}" if m
                                                              else ""))
        else:
            c = Check(variant, next(iter(fr.values()))["reading"], None, parts)
        checks.append(c)
    must = []
    for x in NA_FORBIDDEN:
        if isinstance(x, str):
            continue
        v, f = x
        if v not in only or v in na:
            continue
        if run.holder_only and v in POSITIONED:
            f = f"{f}@holder"               # the forms that must land, at holder
        d = readings.get(v, {}).get(f)
        if d is None:
            continue
        if d["ok"] is None and d["reading"] not in ("format_gap", "not_applicable"):
            must.append(f"{v}/{f}")
    fails = [c for c in checks if c.ok is False]
    documents = bool(getattr(a, "documents_attenuation", lambda: False)())
    vuln = documents and any(c["class"] == "vulnerability" for c in classes.values())
    covered = sorted({d for (v, f), ds in DIMS_OF.items() for d in ds
                      if d in run.carried and readings.get(v, {}).get(
                          f"{f}@holder" if run.holder_only and v in POSITIONED else f,
                          {}).get("ok") is True})
    extra: Dict[str, Any] = {
        "seed": seed, "grant_profile": run.profile, "constraint_profile": run.carried,
        "dimensions_covered": covered,
        "dimensions_not_expressible": sorted(set(("max_amount", "operations", "resources",
                                                  "audience", "window", "delegation"))
                                             - set(run.carried)),
        "format_gaps": gaps, "forms": readings, "must_land_missed": must,
        "modes": {k: sorted(v) for k, v in modes.items()},
        "accepts_holder_hops": run.holder_hops, "max_depth": run.max_depth,
        "mapping": run.mapping, "advisory_members": advisory,
        "disclosure": "vulnerability" if vuln else "conformance",
        "disclosure_forms": classes, "documents_attenuation": documents,
        "grant_profile_holder_only": run.holder_only,
        "level": "library" if run.grade in LIBRARY_GRADES else "deployed",
        "evidence_grade": run.grade, "clock": getattr(a, "clock", "real"),
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if timed:
        st = timing.statistics(timed, run.T)
        st.pop("trials", None)
        extra["statistics"] = {"narrowed_parent": st}
    if plan:
        extra["plan"] = plan
    dev = "Development plan (smaller counts; not a published run). " if development else ""
    if run.grade in LIBRARY_GRADES:
        dev = (f"Library-level reading (grade {run.grade}: a verification library's answers, "
               f"no deployed B). ") + dev
    gap_txt = (f" Not expressible in B's format (findings, never a pass): "
               f"{', '.join(g['variant'] + '/' + g['form'] for g in gaps)}." if gaps else "")
    if not fails and must:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant failed, but forms that must land "
                                f"did not: {must}.{gap_txt}", checks=checks, control_held=True,
                                control_detail=control, extra=extra, **common)
    elif not [c for c in checks if c.ok is not None]:
        r = Result.inconclusive(a.name, ID, f"{dev}no variant landed with a verdict.{gap_txt}",
                                checks=checks, control_held=True, control_detail=control,
                                extra=extra, **common)
    else:
        r = verdict(a.name, ID, checks, control_held=True, control_detail=control,
                    pass_summary=f"{dev}no effect outside the intersection of the presented "
                                 f"chain, in {', '.join(covered) or 'no dimension'}.{gap_txt}",
                    fail_summary=f"{dev}an effect lay outside a grant in the presented chain"
                                 f"{'.' + gap_txt if gap_txt else ''}",
                    extra=extra, **common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r
