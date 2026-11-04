"""P24 — Purpose and terms bound (KRK-24, cross-organisation X2, "mandate bound" in the design).

**Guarantee.** For every request B accepts under a mandate, every effect B commits meets every
term of the mandate that B's format carries, under the meaning B declared for it before the run:
the purpose's coverage, the exact fill of every slot, every fixed value byte for byte, every floor
and ceiling, the link to the goal the action is authorised under, and every condition, with
evidence of the condition presented. A term B cannot read is not met.

**Question.** Does the product commit an effect only when it meets every term of the mandate it
acts under (purpose, required items, fixed values, floors, goal link and conditions, as well as
its limits), never reading a term it cannot evaluate as met?

**Who is graded.** B. The kit plays the principal, the principal's trusted surface
(which signs confirmations) and the agent, with `mandator.StubMandator` (new modules only). Effects are counted at the kit's recorder. The outcome is graded, not the mechanism: refusing W, holding it (``pending``, never performed within the stability
window S), and performing only the part inside the terms (``clamped``, for ``extra_item`` and
``over_quantity``, at the ``recorder`` and ``b-signed`` grades only) all pass, and the result says
which. Terms are critical: an unknown term, a sealed member without its disclosure
and a purpose code B's map does not list are never met.

**The vocabulary** is `terms`'s, with written semantics, evaluated by the kit from hand-written
vectors and sharing no code with any target (KRK-M152). Purpose has only the meaning B states
(`purpose_map`); with none, purpose forms do not land and the gap is a finding (KRK-M150). A term
kind B's format cannot carry (`term_profile`) is not tested and is listed as a finding, never a
pass (KRK-M21). Limits are X5's (`attenuation`), at depth one (``outside_ceiling``).

**Within each trial** (design §4.2), up to four presentations: for ``cross_goal``, the prior
completion of the principal's other goal G1 (KRK-M159); then **W** (inside every limit and
outside exactly one term, or for ``outside_ceiling`` the reverse; KRK-M151) and **L** (a sibling
mandate of the same shape, differing only in the value under test, so the same action meets every
term; KRK-M155) in a seeded order; then **W-in** (an action meeting every term of W's own mandate,
always after W, KRK-M169; not presented where W's mandate cannot be met by construction). The kit
checks every fixture with `terms.meets` and `attenuation.inside` before sending (`truth`; a
fixture that does not mean what it says raises). After the trial's last answer the recorder is
watched for S (B's stated hold resolution, else 10 s) when any answer was pending, and in a
published run after every ``condition`` and ``hidden_terms`` trial whatever B answered (a B that
answers *refused* and performs the action between 2 s and S later is otherwise missed); else for 2 s. A W effect inside it is an effect, whatever B answered (KRK-M158).

**Control.** On fresh mandates carrying every term kind B declares (sealed members disclosed): one
action meeting every term at every endpoint; where B declares ``confirm``, one conditioned action
with the principal's genuine confirmation; where B declares ``serves``, one action with a linked
authorisation issued for its goal; where B accepts holder hops, one through a restated hop whose
terms equal its parent's. Each accepted with exactly one effect, whose body meets every term. The
first is required (else no verdict). If the conditioned action does not complete, ``condition``
reads ``shape_refused`` (KRK-M157); likewise ``cross_goal`` and ``restated_terms`` for their
shapes. The control never requires a refusal or a term check (KRK-M19).

**Outcomes.** Per trial: ``held`` (pass; mode ``refused``, ``pending`` or ``clamped``),
``outside_effect`` (fail, with the term and direction: ``less``, ``more``, ``other``,
``unconfirmed``, ``other_goal``, ``unreadable``, ``over_limit``), and information
``inside_refused``, ``collateral_refusal``, ``shape_refused``, ``not_landed``, ``hung``, and for
``free_text/text_narrower`` ``text_applied`` or ``text_ignored``. Per variant: ``held`` or
``outside_effect``. **Result**: ``fail`` if any landed variant fails; ``pass`` if the control
held, every landed variant held and no form `must_land` lists is missing or inconclusive; else
``inconclusive``. ``extra.forms`` carries each form's reading for the runner's claim basis,
``extra.must_land_missed`` the forms `must_land` lists that did not land (also when a variant
failed), and ``extra.disclosure_forms`` each failing form's class (design
§1.8).
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..evidence import Evidence
from ..result import Check, Result, verdict
from . import p19_withdrawal_within_t as p19

ID = "P24"
TITLE = "Purpose and terms bound"
FIXTURES = ("known_bad/mandate_toys.py", "tests/test_p24_mandate_bound.py",
            "tests/vectors/krk24/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("The principal's, agents' and C's keys, grant ids, goal ids, confirmation ids, seal "
            "salts and each request's ref come from the operating system, never from the seed "
            "(KRK-M36).",
            "The seed draws the variant order, the presentation order and the drawn values: "
            "slots, items, quantities, amounts, payees, purpose codes and members.")

VARIANTS = ("outside_ceiling", "purpose", "goal_items", "fixed", "cross_goal", "condition",
            "hidden_terms", "free_text", "unknown_term", "restated_terms")
FORMS = {"outside_ceiling": ("amount", "operation", "counterparty", "window", "currency",
                             "negative", "precision"),
         "purpose": ("mismatch", "asserted_by_agent", "absent", "unknown_code", "lookalike"),
         "goal_items": ("partial", "extra_item", "not_acceptable", "over_quantity",
                        "under_quantity", "item_reused", "empty_slot"),
         "fixed": ("differs", "lower_amount", "below_floor", "missing_in_action",
                   "normalised", "unlisted_member"),
         "cross_goal": ("other_goal", "presenter_named", "unbound"),
         "condition": ("unconfirmed", "agent_confirmed", "confirmed_sibling"),
         "hidden_terms": ("slot_hidden", "fixed_hidden", "purpose_hidden", "all_hidden"),
         "free_text": ("text_wider", "text_narrower"),
         "unknown_term": ("in_terms", "in_member", "near_name"),
         "restated_terms": ("purpose_changed", "slot_dropped", "fixed_changed")}
INFORMATION_ONLY = {("free_text", "text_narrower")}
TRIALS = {"*": 5}
DEV_TRIALS = {"*": 3}
PUBLISHED_TRIALS = TRIALS
NO_W_IN = {("outside_ceiling", "counterparty"), ("outside_ceiling", "window"),
           ("purpose", "absent"), ("purpose", "unknown_code"), ("purpose", "lookalike"),
           ("goal_items", "empty_slot"), ("cross_goal", "unbound"),
           ("restated_terms", "slot_dropped"), ("restated_terms", "fixed_changed"),
           ("free_text", "text_narrower")} | \
    {("hidden_terms", f) for f in FORMS["hidden_terms"]} | \
    {("unknown_term", f) for f in FORMS["unknown_term"]}
"""Forms whose W mandate cannot be met by construction, or must be refused whole, so W-in is not
presented (design §4.2). ``restated_terms/fixed_changed`` is added to the design's list: its root
and child fix two different payees, so no action meets both. ``outside_ceiling/counterparty`` and
``window`` are added too: W's grant admits nothing at B (another audience, or expired)."""
CLAMPABLE = {("goal_items", "extra_item"), ("goal_items", "over_quantity")}
"""Forms where performing only the goal's items is a pass (``clamped``)."""
CLAMP_GRADES = ("recorder", "b-signed")
GRADES = p19.GRADES + ("library-decision",)
LIBRARY_GRADES = ("library-decision",)
ALWAYS_MUST_LAND = (("outside_ceiling", "amount"), ("outside_ceiling", "operation"),
                    ("unknown_term", "in_terms"))
CORE_FORMS = {"purpose": (("purpose", "mismatch"), ("purpose", "asserted_by_agent")),
              "slots": (("goal_items", "partial"), ("goal_items", "extra_item"),
                        ("goal_items", "not_acceptable")),
              "fixed": (("fixed", "differs"), ("fixed", "missing_in_action")),
              "floor": (("fixed", "below_floor"),),
              "serves": (("cross_goal", "other_goal"), ("cross_goal", "presenter_named")),
              "confirm": (("condition", "unconfirmed"), ("condition", "agent_confirmed"))}
"""Design §6.5: the core forms of each term kind B declares; a B that declares the kind and
cannot land them reads inconclusive. ``sealed`` adds ``slot_hidden`` or ``fixed_hidden``,
whichever the format can seal (`must_land`)."""
NA_FORBIDDEN = ("control",) + ALWAYS_MUST_LAND
VULNERABLE_FORMS = {("outside_ceiling", f) for f in FORMS["outside_ceiling"]} | \
    {("goal_items", f) for f in FORMS["goal_items"]} | \
    {("fixed", f) for f in FORMS["fixed"]} | {("cross_goal", f) for f in FORMS["cross_goal"]} | \
    {("condition", "unconfirmed"), ("condition", "agent_confirmed")} | \
    {("hidden_terms", f) for f in FORMS["hidden_terms"]} | \
    {("unknown_term", f) for f in FORMS["unknown_term"]}
"""Design §1.8: a failing form here is vulnerability class where B documents that it checks the
action against the terms. ``purpose`` forms are too, only where B states its purpose coverage
itself (`purpose_map_source`)."""
PLAN_ENV = "ACK_P24_PLAN"
READY_S = 30.0
SETTLE_S = 2.0
DEFAULT_S = 10.0
LAPSE_S = 60.0
STABLE_VARIANTS = ("condition", "hidden_terms")
"""Variants whose every trial is watched for S in a published run, whatever B answered (a probe
change under spec §3.10): a held or sealed action is the one a B may perform late."""
OP_BUY, OP_COMMIT, OP_PAY = "shop.checkout.complete", "shop.order.commit", "shop.payment.execute"
OP_READ, OP_DELETE, OP_PURGE = "data.record.read", "data.record.delete", "data.record.purge"
KIT_OPS = (OP_BUY, OP_COMMIT, OP_PAY, OP_READ, OP_DELETE, OP_PURGE)
B_PRIME = "did:web:b-prime.example"
USUAL_MEMBERS = ("payee", "amount")
NOT_TERM_MEMBERS = ("operation", "ref", "items", "resources")
DIMS_OF = {"amount": "max_amount", "operation": "operations", "counterparty": "audience",
           "window": "window", "currency": "max_amount", "negative": "max_amount",
           "precision": "max_amount"}


def _amt(v: Any, cur: str = "EUR", mu: int = 2) -> Dict[str, Any]:
    return {"value": v, "currency": cur, "minor_units": mu}


def _hex(rng: random.Random, n: int = 8) -> str:
    return f"{rng.getrandbits(4 * n):0{n}x}"


def fold(code: str) -> str:
    """How ``fuzzy_purpose`` reads a code (case, spaces and punctuation folded). The kit never
    reads codes this way; it is here so the fixture can build a code that folds onto another."""
    return "".join(ch for ch in code.casefold() if ch.isalnum())


# --------------------------------------------------------------------------- B's statements


@dataclass
class Ctx:
    """B's statements, as read before the run (design §5)."""

    party: str
    dims: List[str]
    kinds: List[str]
    pmap: Optional[Dict[str, Any]]
    requires: Dict[str, List[str]]
    bindings: Dict[str, Dict[str, str]]
    item_key: str
    condition_mode: str
    disclosure: Optional[str]
    holder_hops: bool
    confirm_binds: bool
    tolerance: float

    def binding(self, op: str) -> Dict[str, str]:
        return dict(self.bindings.get(op) or {})

    def member(self, op: str, m: str) -> str:
        return self.binding(op).get(m, m)

    def needs(self, op: str) -> List[str]:
        return list(self.requires.get(op) or [])


def _needs(variant: str, form: str, ctx: Ctx) -> Optional[str]:
    """Why the form cannot land for B, or None (KRK-M21: a term B's format cannot carry is a
    format gap, never a pass)."""
    kinds = set(ctx.kinds)

    def kind(*ks: str) -> Optional[str]:
        miss = [k for k in ks if k not in kinds]
        return f"B's format carries no {', '.join(miss)} term" if miss else None
    if variant == "outside_ceiling":
        d = DIMS_OF[form]
        return None if d in ctx.dims else f"B's format carries no {d} limit"
    if variant in ("purpose", "free_text") or (variant, form) in (
            ("hidden_terms", "purpose_hidden"), ("hidden_terms", "all_hidden"),
            ("restated_terms", "purpose_changed")):
        w = kind("purpose") or (kind("text") if variant == "free_text" else None)
        if w:
            return w
        if not ctx.pmap:
            return "B states no meaning for any purpose code (KRK-M150)"
    if variant == "goal_items" or (variant, form) in (("hidden_terms", "slot_hidden"),
                                                     ("hidden_terms", "all_hidden"),
                                                     ("unknown_term", "in_member"),
                                                     ("restated_terms", "slot_dropped")):
        w = kind("slots")
        if w:
            return w
    if (variant == "fixed" and form != "below_floor") or (variant, form) in (
            ("hidden_terms", "fixed_hidden"), ("hidden_terms", "all_hidden"),
            ("unknown_term", "near_name"), ("restated_terms", "fixed_changed")):
        w = kind("fixed")
        if w:
            return w
    if (variant, form) == ("fixed", "below_floor"):
        return kind("floor")
    if variant == "cross_goal":
        return kind("serves")
    if variant == "condition":
        w = kind("confirm")
        if w:
            return w
        if ctx.condition_mode not in ("refuse", "hold"):
            return "B states it supports no conditions (condition_mode none)"
        if form == "confirmed_sibling" and not ctx.confirm_binds:
            return "B's confirmation format carries no action digest (KRK-M160)"
    if variant == "hidden_terms":
        w = kind("sealed")
        if w:
            return w
        if not ctx.disclosure:
            return "B states no selective-disclosure format"
    if variant == "restated_terms" and not ctx.holder_hops:
        return "B accepts no hop signed by the holder of its parent"
    return None


# --------------------------------------------------------------------------- fixtures


@dataclass
class MSpec:
    """One mandate chain: (constraints, terms) per hop, root first; hops after the first are
    restated by the holder of their parent (design §3.1 ``restated_terms``)."""

    hops: List[Tuple[Dict[str, Any], Dict[str, Any]]]
    na: Optional[float] = None
    """The root's not_after, seconds from now (default: twelve hours)."""


@dataclass
class ASpec:
    """One presentation: an action under a mandate, and what the agent presents with it."""

    mandate: str
    values: Dict[str, Any]
    linked: Optional[str] = None
    confirm: Optional[str] = None
    """``principal`` or ``agent``: who signs a confirmation presented with the action."""
    confirm_of: Optional[Dict[str, Any]] = None
    """The values the confirmation binds (a sibling's); default the action's own."""
    withhold: Tuple[str, ...] = ()
    """Sealed paths whose disclosure the agent does not present (``"*"``: none presented)."""
    purpose_header: Optional[str] = None
    goal_header: Optional[str] = None
    """A mandate key; the agent names that mandate's goal in `mandator.GOAL_HEADER`."""
    raw: bool = False


@dataclass
class Fx:
    mandates: Dict[str, MSpec]
    W: ASpec
    L: ASpec
    W_in: Optional[ASpec] = None
    links: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = field(default_factory=dict)
    """name -> (constraints, the mandate key whose goal it serves, or None)."""
    prior: Optional[ASpec] = None
    present_at: Optional[float] = None
    term: str = ""
    hidden: Tuple[str, ...] = ()
    notes: Dict[str, Any] = field(default_factory=dict)


class NotLanded(Exception):
    """B's statements give the form nothing to draw from (a finding, never a pass)."""


def _res(rng: random.Random, pats: Optional[List[str]] = None) -> str:
    """A resource covered by every pattern list in `pats` (exact ids are used as given)."""
    if pats:
        p = pats[0]
        return p[:-1] + f"r-{_hex(rng, 6)}" if p.endswith("/*") else p
    return f"ds-1/r-{_hex(rng, 6)}"


def _items(rng: random.Random, n: int) -> List[str]:
    out: List[str] = []
    while len(out) < n:
        x = f"sku-{_hex(rng)}"
        if x not in out:
            out.append(x)
    return out


def _it(ctx: Ctx, pairs: Sequence[Tuple[str, int]]) -> List[Dict[str, Any]]:
    return [{ctx.item_key: i, "quantity": q} for i, q in pairs]


def _slots(rng: random.Random, k: int) -> Tuple[List[Dict[str, Any]], List[Tuple[str, int]]]:
    """`k` slots with disjoint acceptable lists, and an exact fill of them."""
    ids = _items(rng, 3 * k)
    slots, fill = [], []
    for i in range(k):
        n = rng.randint(1, 3)
        acc = ids[3 * i:3 * i + n]
        q = rng.randint(1, 3)
        slots.append({"slot": f"s{i + 1}", "acceptable": acc, "quantity": q})
        fill.append((rng.choice(acc), q))
    return slots, fill


def _act(ctx: Ctx, rng: random.Random, op: str, *, res: str, amount: Any = None,
         items: Optional[List[Tuple[str, int]]] = None, payee: Optional[str] = None,
         cur: str = "EUR", mu: int = 2, omit: Sequence[str] = (), **members: Any
         ) -> Dict[str, Any]:
    v: Dict[str, Any] = {
        "operation": op, "ref": f"r-{secrets.token_hex(8)}",
        "amount": amount if isinstance(amount, dict) else
        _amt(rng.randint(1000, 9000) if amount is None else amount, cur, mu),
        "resources": [res],
        "items": _it(ctx, items if items is not None else [(f"sku-{_hex(rng)}", 1)])}
    v[ctx.member(op, "payee")] = payee or f"m-{_hex(rng, 6)}"
    v[ctx.member(op, "instrument")] = f"card-{_hex(rng, 6)}"
    v[ctx.member(op, "execution_date")] = f"2026-11-{rng.randint(10, 28)}"
    for k, x in members.items():
        v[ctx.member(op, k)] = x
    for k in omit:
        v.pop(ctx.member(op, k), None)
    return v


def _lim(ctx: Ctx, res: str, *, ops: Optional[List[str]] = None, max_amount: Any = None,
         audience: Optional[List[str]] = None) -> Dict[str, Any]:
    """Constraints in every dimension B carries, wide enough for the trial's actions."""
    c: Dict[str, Any] = {}
    if "max_amount" in ctx.dims:
        c["max_amount"] = max_amount or _amt(500000)
    if "operations" in ctx.dims:
        allops = set(KIT_OPS) | {o for e in (ctx.pmap or {}).values()
                                 for o in (e.get("operations") or [])}
        c["operations"] = sorted(ops if ops is not None else allops)
    if "resources" in ctx.dims:
        c["resources"] = [res]
    if "audience" in ctx.dims:
        c["audience"] = list(audience or [ctx.party])
    return c


def _purpose_pick(ctx: Ctx, rng: random.Random, *, avoid_required: bool = False,
                  need_in_both: bool = False) -> Tuple[str, str, str, Optional[str], str]:
    """``(code_n, code_y, op_w, op_in, res)`` from B's map: `code_n` does not cover `op_w`,
    `code_y` does, `op_in` is covered by `code_n` (and by `code_y` with `need_in_both`), and `res`
    is covered by both entries (KRK-M150: only B's meaning)."""
    pm = ctx.pmap or {}
    cands = []
    for cn in sorted(pm):
        for cy in sorted(pm):
            if cn == cy:
                continue
            on = set(pm[cn].get("operations") or [])
            oy = set(pm[cy].get("operations") or [])
            for op in sorted(oy - on):
                if (avoid_required and "purpose" in ctx.needs(op)) or "serves" in ctx.needs(op):
                    continue
                ins = sorted(on & oy) if need_in_both else sorted(on)
                cands.append((cn, cy, op, ins))
    if not cands:
        raise NotLanded("B's purpose map has no two codes that differ on an operation")
    rng.shuffle(cands)
    for cn, cy, op, ins in cands:
        res = _res(rng, pm[cy].get("resources"))
        from .. import terms as tm
        if not tm.purpose_covers(pm, cy, op, [res]) or (
                "resources" in pm[cn] and not any(
                    tm.purpose_covers(pm, cn, o, [res]) for o in pm[cn]["operations"])):
            continue
        op_in = next((o for o in ins if tm.purpose_covers(pm, cn, o, [res])
                      and (not need_in_both or tm.purpose_covers(pm, cy, o, [res]))
                      and not ctx.needs(o)), None)
        return cn, cy, op, op_in, res
    raise NotLanded("B's purpose map has no pair of codes whose resources overlap")


def fixture(variant: str, form: str, rng: random.Random, ctx: Ctx) -> Fx:
    """W, L and W-in for one form (design §3.1), each a genuine statement of the principal or
    the agent. Values that change are drawn from `rng` (X3 §13 item 4)."""
    res = _res(rng)
    lo = rng.randint(50, 150) * 1000
    hi = rng.randint(400, 600) * 1000
    mid = (lo + hi) // 2
    small = rng.randint(1000, 9000)
    act = lambda op=OP_BUY, **kw: _act(ctx, rng, op, res=kw.pop("res", res), **kw)  # noqa: E731
    one = lambda c, t, **kw: MSpec([(c, t)], **kw)                                   # noqa: E731

    if variant == "outside_ceiling":
        L_ = _lim(ctx, res)
        if form == "amount":
            W_ = _lim(ctx, res, max_amount=_amt(lo))
            L_ = _lim(ctx, res, max_amount=_amt(hi))
            return Fx({"W": one(W_, {}), "L": one(L_, {})}, ASpec("W", act(amount=mid)),
                      ASpec("L", act(amount=mid)), ASpec("W", act(amount=small)),
                      term="max_amount")
        if form == "operation":
            W_ = _lim(ctx, res, ops=[OP_BUY])
            L_ = _lim(ctx, res, ops=[OP_BUY, OP_DELETE])
            return Fx({"W": one(W_, {}), "L": one(L_, {})}, ASpec("W", act(OP_DELETE)),
                      ASpec("L", act(OP_DELETE)), ASpec("W", act(OP_BUY)), term="operations")
        if form == "counterparty":
            W_ = _lim(ctx, res, audience=[B_PRIME])
            return Fx({"W": one(W_, {}), "L": one(L_, {})}, ASpec("W", act()),
                      ASpec("L", act()), term="audience")
        if form == "window":
            return Fx({"W": one(L_, {}, na=LAPSE_S), "L": one(L_, {})}, ASpec("W", act()),
                      ASpec("L", act()), present_at=LAPSE_S, term="window")
        if form == "currency":
            W_ = _lim(ctx, res, max_amount=_amt(hi))
            L_ = _lim(ctx, res, max_amount=_amt(hi, "USD"))
            return Fx({"W": one(W_, {}), "L": one(L_, {})},
                      ASpec("W", act(amount=small, cur="USD")),
                      ASpec("L", act(amount=small, cur="USD")),
                      ASpec("W", act(amount=small)), term="max_amount (currency)")
        if form == "negative":
            return Fx({"W": one(L_, {}), "L": one(L_, {})}, ASpec("W", act(amount=-small)),
                      ASpec("L", act(amount=small)), ASpec("W", act(amount=small)),
                      term="max_amount (negative)")
        W_ = _lim(ctx, res, max_amount=_amt(lo))
        return Fx({"W": one(W_, {}), "L": one(W_, {})},
                  ASpec("W", act(amount=_amt(lo + 0.4)), raw=True),
                  ASpec("L", act(amount=lo)), ASpec("W", act(amount=small)),
                  term="max_amount (precision)")

    if variant in ("purpose", "free_text"):
        if form == "absent":
            ops = [o for o in sorted(ctx.requires) if "purpose" in ctx.needs(o)]
            pm = ctx.pmap or {}
            pairs = [(o, c) for o in ops for c in sorted(pm)
                     if o in (pm[c].get("operations") or []) and "serves" not in ctx.needs(o)]
            if not pairs:
                raise NotLanded("B states no operation that requires a purpose, with a code "
                                "that covers it")
            op, cy = rng.choice(pairs)
            r = _res(rng, pm[cy].get("resources"))
            c = _lim(ctx, r)
            return Fx({"W": one(c, {}), "L": one(c, {"purpose": {"code": cy}})},
                      ASpec("W", act(op, res=r)), ASpec("L", act(op, res=r)),
                      term="purpose (required, absent)")
        if form in ("unknown_code", "lookalike"):
            pm = ctx.pmap or {}
            cands = [(c, o) for c in sorted(pm) for o in (pm[c].get("operations") or [])
                     if not ctx.needs(o)]
            if form == "lookalike":
                cands = [(c, o) for c, o in cands if any(ch.isalpha() for ch in c)]
            if not cands:
                raise NotLanded("B's purpose map lists no code to draw from")
            cy, op = rng.choice(cands)
            r = _res(rng, pm[cy].get("resources"))
            if form == "unknown_code":
                code = f"x-krk-{secrets.token_hex(4)}"
            else:
                code = next((cy.replace(s, " ") for s in "-_." if s in cy), None) or \
                    cy.swapcase()
                if code in pm or fold(code) != fold(cy):
                    raise NotLanded("no lookalike of a code in B's map folds onto it")
            c = _lim(ctx, r)
            return Fx({"W": one(c, {"purpose": {"code": code}}),
                       "L": one(c, {"purpose": {"code": cy}})},
                      ASpec("W", act(op, res=r)), ASpec("L", act(op, res=r)),
                      term=f"purpose ({form})", notes={"code": code, "near": cy})
        cn, cy, op, op_in, r = _purpose_pick(ctx, rng)
        c = _lim(ctx, r)
        if variant == "free_text":
            if form == "text_wider":
                text = f"{cn}: work through the records and {op} anything obsolete"
                return Fx({"W": one(c, {"purpose": {"code": cn}, "text": text}),
                           "L": one(c, {"purpose": {"code": cy}, "text": text})},
                          ASpec("W", act(op, res=r)), ASpec("L", act(op, res=r)),
                          ASpec("W", act(op_in, res=r)) if op_in else None,
                          term="purpose (the text names the operation)")
            text = f"{cy}: only {op_in or 'read'} the records; never {op} anything"
            return Fx({"W": one(c, {"purpose": {"code": cy}, "text": text}),
                       "L": one(c, {"purpose": {"code": cy}})},
                      ASpec("W", act(op, res=r)), ASpec("L", act(op, res=r)),
                      term="text (narrower than the structured terms)")
        hdr = cy if form == "asserted_by_agent" else None
        return Fx({"W": one(c, {"purpose": {"code": cn}}), "L": one(c, {"purpose": {"code": cy}})},
                  ASpec("W", act(op, res=r), purpose_header=hdr),
                  ASpec("L", act(op, res=r), purpose_header=hdr),
                  ASpec("W", act(op_in, res=r), purpose_header=hdr) if op_in else None,
                  term="purpose", notes={"code": cn, "covering": cy, "operation": op})

    if variant == "goal_items":
        c = _lim(ctx, res)
        k = rng.randint(2, 3)
        slots, exact = _slots(rng, k)
        j = rng.randrange(k)
        G = lambda s: {"slots": s}                                                  # noqa: E731
        if form == "partial":
            W_items = [p for i, p in enumerate(exact) if i != j]
            Ls = [s for i, s in enumerate(slots) if i != j]
            return Fx({"W": one(c, G(slots)), "L": one(c, G(Ls))},
                      ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                      ASpec("W", act(items=exact)), term="slots (less)",
                      notes={"empty_slot": slots[j]["slot"]})
        if form in ("extra_item", "empty_slot"):
            z = f"sku-{_hex(rng)}-x"
            W_items = exact + [(z, 1)]
            if form == "extra_item":
                Ls = slots + [{"slot": "s-extra", "acceptable": [z], "quantity": 1}]
                return Fx({"W": one(c, G(slots)), "L": one(c, G(Ls))},
                          ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                          ASpec("W", act(items=exact)), term="slots (more)")
            Ws = slots + [{"slot": "s-empty", "acceptable": [], "quantity": 1}]
            Ls = slots + [{"slot": "s-empty", "acceptable": [z], "quantity": 1}]
            return Fx({"W": one(c, G(Ws)), "L": one(c, G(Ls))},
                      ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                      term="slots (an empty list admits nothing)")
        if form == "not_acceptable":
            j2 = (j + 1 + rng.randrange(k - 1)) % k
            x2 = exact[j2][0]
            W_items = [((x2, exact[i][1]) if i == j else exact[i]) for i in range(k)]
            Ls = [dict(s, acceptable=s["acceptable"] + [x2]) if i == j else s
                  for i, s in enumerate(slots)]
            return Fx({"W": one(c, G(slots)), "L": one(c, G(Ls))},
                      ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                      ASpec("W", act(items=exact)), term="slots (other: substituted)",
                      notes={"slot": slots[j]["slot"], "filled_from": slots[j2]["slot"]})
        if form in ("over_quantity", "under_quantity"):
            if form == "under_quantity" and slots[j]["quantity"] < 2:
                slots[j] = dict(slots[j], quantity=rng.randint(2, 3))
                exact[j] = (exact[j][0], slots[j]["quantity"])
            d = 1 if form == "over_quantity" else -1
            W_items = [((p, q + d) if i == j else (p, q)) for i, (p, q) in enumerate(exact)]
            Ls = [dict(s, quantity=s["quantity"] + d) if i == j else s
                  for i, s in enumerate(slots)]
            return Fx({"W": one(c, G(slots)), "L": one(c, G(Ls))},
                      ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                      ASpec("W", act(items=exact)),
                      term=f"slots ({'more' if d > 0 else 'less'}: quantity)")
        # item_reused: two slots share an item; the action carries it once, at one slot's count.
        x, a1, b1 = _items(rng, 3)
        q = rng.randint(1, 3)
        others, ofill = _slots(rng, rng.randint(0, 1))
        others = [dict(s, slot=f"o{i + 1}") for i, s in enumerate(others)]
        Ws = [{"slot": "sa", "acceptable": [x, a1], "quantity": q},
              {"slot": "sb", "acceptable": [x, b1], "quantity": q}] + others
        Ls = [Ws[0]] + others
        W_items = [(x, q)] + ofill
        return Fx({"W": one(c, G(Ws)), "L": one(c, G(Ls))},
                  ASpec("W", act(items=W_items)), ASpec("L", act(items=W_items)),
                  ASpec("W", act(items=[(x, q), (b1, q)] + ofill)),
                  term="slots (one unit counted for two slots)")

    if variant == "fixed":
        c = _lim(ctx, res)
        p1, p2 = f"m-{_hex(rng, 6)}", f"m-{_hex(rng, 6)}"
        if form == "differs":
            return Fx({"W": one(c, {"fixed": {"payee": p1}}), "L": one(c, {"fixed": {"payee": p2}})},
                      ASpec("W", act(payee=p2)), ASpec("L", act(payee=p2)),
                      ASpec("W", act(payee=p1)), term="fixed payee (other)")
        if form == "lower_amount":
            f = rng.randint(10, 30) * 1000
            got = f - rng.randint(1, 999)
            return Fx({"W": one(c, {"fixed": {"amount": _amt(f)}}),
                       "L": one(c, {"fixed": {"amount": _amt(got)}})},
                      ASpec("W", act(amount=got)), ASpec("L", act(amount=got)),
                      ASpec("W", act(amount=f)), term="fixed amount (less)")
        if form == "below_floor":
            f = rng.randint(1000, 9000)
            return Fx({"W": one(c, {"floor": {"amount": _amt(f)}}),
                       "L": one(c, {"floor": {"amount": _amt(f - 1)}})},
                      ASpec("W", act(amount=f - 1)), ASpec("L", act(amount=f - 1)),
                      ASpec("W", act(amount=f)), term="floor (less)")
        if form == "missing_in_action":
            return Fx({"W": one(c, {"fixed": {"payee": p1}}), "L": one(c, {"fixed": {"payee": p1}})},
                      ASpec("W", act(omit=("payee",))), ASpec("L", act(payee=p1)),
                      ASpec("W", act(payee=p1)), term="fixed payee (absent)")
        if form == "normalised":
            base = unicodedata.normalize("NFC", f"Café {_hex(rng, 4)}")
            alt = rng.choice([unicodedata.normalize("NFD", base), base.upper()])
            return Fx({"W": one(c, {"fixed": {"payee": base}}),
                       "L": one(c, {"fixed": {"payee": alt}})},
                      ASpec("W", act(payee=alt)), ASpec("L", act(payee=alt)),
                      ASpec("W", act(payee=base)), term="fixed payee (normalised)",
                      notes={"fixed": base, "presented": alt})
        extra = sorted(set(ctx.binding(OP_BUY)) - set(USUAL_MEMBERS) - set(NOT_TERM_MEMBERS))
        if not extra:
            raise NotLanded("B's bindings declare no member beyond payee and amount")
        m = rng.choice(extra)
        a, b = (f"2026-12-{rng.randint(10, 19)}", f"2026-12-{rng.randint(20, 28)}") \
            if "date" in m else (f"{m}-{_hex(rng, 6)}", f"{m}-{_hex(rng, 6)}")
        return Fx({"W": one(c, {"fixed": {m: a}}), "L": one(c, {"fixed": {m: b}})},
                  ASpec("W", act(**{m: b})), ASpec("L", act(**{m: b})),
                  ASpec("W", act(**{m: a})), term=f"fixed {m} (a member beyond payee and amount)",
                  notes={"member": m})

    if variant == "cross_goal":
        ops = [o for o in sorted(ctx.requires) if "serves" in ctx.needs(o)]
        if form == "unbound" and not ops:
            raise NotLanded("B states no operation that requires a goal link")
        op = ops[0] if ops else OP_PAY
        c = _lim(ctx, res)
        pc = _lim(ctx, res, ops=[op], max_amount=_amt(hi))
        mands = {"G1": one(c, {}), "W": one(c, {}), "L": one(c, {})}
        links = {"P1": (pc, "G1"), "P2": (pc, "W"), "PL": (pc, "L"), "PU": (pc, None)}
        prior = ASpec("G1", act(op, amount=small), linked="P1")
        named = form == "presenter_named"
        if form in ("other_goal", "presenter_named"):
            return Fx(mands, ASpec("W", act(op, amount=small), linked="P1",
                                   goal_header="G1" if named else None),
                      ASpec("L", act(op, amount=small), linked="PL",
                            goal_header="L" if named else None),
                      ASpec("W", act(op, amount=small), linked="P2",
                            goal_header="W" if named else None),
                      links=links, prior=prior, term="serves (another goal)")
        return Fx(mands, ASpec("W", act(op, amount=small), linked="PU"),
                  ASpec("L", act(op, amount=small), linked="PL"), links=links, prior=prior,
                  term="serves (no goal named)")

    if variant == "condition":
        c = _lim(ctx, res)
        t = {"confirm": {"operations": [OP_COMMIT], "by": "principal"}}
        items = [(f"sku-{_hex(rng)}", 1)]
        w = act(OP_COMMIT, items=items)
        mands = {"W": one(c, t), "L": one(c, t)}
        L = ASpec("L", act(OP_COMMIT, items=items), confirm="principal")
        W_in = ASpec("W", act(OP_COMMIT, items=items), confirm="principal")
        if form == "unconfirmed":
            return Fx(mands, ASpec("W", w), L, W_in, term="confirm (none presented)")
        if form == "agent_confirmed":
            return Fx(mands, ASpec("W", w, confirm="agent"), L, W_in,
                      term="confirm (signed by the agent)")
        sib = act(OP_COMMIT, items=[(f"sku-{_hex(rng)}", 1)])
        return Fx(mands, ASpec("W", w, confirm="principal", confirm_of=sib), L, W_in,
                  term="confirm (a sibling action's)")

    if variant == "hidden_terms":
        from ..mandator import Seal
        c = _lim(ctx, res)
        if form == "slot_hidden":
            k = rng.randint(2, 3)
            slots, exact = _slots(rng, k)
            j = rng.randrange(k)
            z = f"sku-{_hex(rng)}-x"
            q = slots[j]["quantity"]
            Wt = [dict(s, acceptable=Seal(s["acceptable"])) if i == j else s
                  for i, s in enumerate(slots)]
            Lt = [dict(s, acceptable=Seal([z])) if i == j else s for i, s in enumerate(slots)]
            items = [((z, q) if i == j else p) for i, p in enumerate(exact)]
            path = f"slots/{j}/acceptable"
            return Fx({"W": one(c, {"slots": Wt}), "L": one(c, {"slots": Lt})},
                      ASpec("W", act(items=items), withhold=(path,)),
                      ASpec("L", act(items=items)), term="slots (sealed, not disclosed)",
                      hidden=(path,))
        if form == "fixed_hidden":
            p1, p2 = f"m-{_hex(rng, 6)}", f"m-{_hex(rng, 6)}"
            return Fx({"W": one(c, {"fixed": {"payee": Seal(p1)}}),
                       "L": one(c, {"fixed": {"payee": Seal(p2)}})},
                      ASpec("W", act(payee=p2), withhold=("fixed/payee",)),
                      ASpec("L", act(payee=p2)), term="fixed (sealed, not disclosed)",
                      hidden=("fixed/payee",))
        cn, cy, op, _op_in, r = _purpose_pick(ctx, rng, avoid_required=True)
        c = _lim(ctx, r)
        if form == "purpose_hidden":
            return Fx({"W": one(c, {"purpose": Seal({"code": cn})}),
                       "L": one(c, {"purpose": Seal({"code": cy})})},
                      ASpec("W", act(op, res=r), withhold=("purpose",)),
                      ASpec("L", act(op, res=r)), term="purpose (sealed, not disclosed)",
                      hidden=("purpose",))
        slots, exact = _slots(rng, rng.randint(1, 2))
        p1 = f"m-{_hex(rng, 6)}"
        Wt = {"purpose": Seal({"code": cn}), "slots": Seal(slots),
              "fixed": Seal({"payee": p1})}
        Lt = {"purpose": Seal({"code": cy}), "slots": Seal(slots), "fixed": Seal({"payee": p1})}
        hid = ("fixed", "purpose", "slots")
        return Fx({"W": one(c, Wt), "L": one(c, Lt)},
                  ASpec("W", act(op, res=r, items=exact, payee=p1), withhold=hid),
                  ASpec("L", act(op, res=r, items=exact, payee=p1)),
                  term="every term sealed, none disclosed", hidden=hid)

    if variant == "unknown_term":
        c = _lim(ctx, res)
        if form == "in_terms":
            name = f"x-krk-{secrets.token_hex(3)}"
            return Fx({"W": one(c, {name: {"limit": 0}}), "L": one(c, {})}, ASpec("W", act()),
                      ASpec("L", act()), term=f"unknown term {name}")
        if form == "in_member":
            slots, exact = _slots(rng, 2)
            Ws = [dict(slots[0], **{"x-krk-colour": "red"})] + slots[1:]
            return Fx({"W": one(c, {"slots": Ws}), "L": one(c, {"slots": slots})},
                      ASpec("W", act(items=exact)), ASpec("L", act(items=exact)),
                      term="unknown member in slots")
        p1, p2 = f"m-{_hex(rng, 6)}", f"m-{_hex(rng, 6)}"
        return Fx({"W": one(c, {"fixed": {"payee": p2}, "Fixed": {"payee": p1}}),
                   "L": one(c, {"fixed": {"payee": p2}})},
                  ASpec("W", act(payee=p2)), ASpec("L", act(payee=p2)),
                  term="unknown term Fixed (near fixed)")

    if variant == "restated_terms":
        if form == "purpose_changed":
            cn, cy, op, op_in, r = _purpose_pick(ctx, rng, need_in_both=True)
            c = _lim(ctx, r)
            return Fx({"W": MSpec([(c, {"purpose": {"code": cn}}), (c, {"purpose": {"code": cy}})]),
                       "L": MSpec([(c, {"purpose": {"code": cy}}), (c, {"purpose": {"code": cy}})])},
                      ASpec("W", act(op, res=r)), ASpec("L", act(op, res=r)),
                      ASpec("W", act(op_in, res=r)) if op_in else None,
                      term="purpose (restated at the hop)")
        c = _lim(ctx, res)
        if form == "slot_dropped":
            slots, exact = _slots(rng, 3)
            j = rng.randrange(3)
            child = [s for i, s in enumerate(slots) if i != j]
            items = [p for i, p in enumerate(exact) if i != j]
            return Fx({"W": MSpec([(c, {"slots": slots}), (c, {"slots": child})]),
                       "L": MSpec([(c, {"slots": child}), (c, {"slots": child})])},
                      ASpec("W", act(items=items)), ASpec("L", act(items=items)),
                      term="slots (one dropped at the hop)")
        p1, p2 = f"m-{_hex(rng, 6)}", f"m-{_hex(rng, 6)}"
        return Fx({"W": MSpec([(c, {"fixed": {"payee": p1}}), (c, {"fixed": {"payee": p2}})]),
                   "L": MSpec([(c, {"fixed": {"payee": p2}}), (c, {"fixed": {"payee": p2}})])},
                  ASpec("W", act(payee=p2)), ASpec("L", act(payee=p2)),
                  term="fixed payee (restated at the hop)")
    raise ValueError(f"no fixture for {variant}/{form}")


# --------------------------------------------------------------------------- the guards
# One function each, so a test can show the reading each one prevents (KRK-M150 to KRK-M169).


def is_wildcard_reading(slot: Dict[str, Any]) -> bool:
    """KRK-M152: the kit never reads ``acceptable: []`` as any item."""
    return False


def landed_disclosures(headers: Dict[str, str], hidden: Sequence[str]) -> Optional[str]:
    """KRK-M154: None if no disclosure for a hidden path was presented, else the path."""
    from .. import mandator
    try:
        got = json.loads(headers.get(mandator.DISCLOSURES_HEADER) or "[]")
    except ValueError:
        return None
    paths = {d[1] for d in got if isinstance(d, list) and len(d) == 3}
    for h in hidden:
        if h in paths:
            return h
    return None


def headers_digest(headers: Dict[str, str], request: bytes) -> str:
    """KRK-M156, M162: `mandator.headers_digest`, what left the kit."""
    from .. import mandator
    return mandator.headers_digest(headers, request)


def statements_digest(ctx: Ctx) -> str:
    """KRK-M167: B's term profile and purpose map, digested before and after the run."""
    from ..receipts import canonical_json
    return "sha256:" + hashlib.sha256(canonical_json(
        {"kinds": sorted(ctx.kinds), "pmap": ctx.pmap or {}})).hexdigest()


def stability_window(stated: Optional[float]) -> float:
    """S: B's stated hold resolution, else 10 s."""
    return float(stated) if isinstance(stated, (int, float)) and stated > 0 else DEFAULT_S


def clamp_credited(grade: str) -> bool:
    """KRK-M164: ``clamped`` is credited only where the grade shows what was performed."""
    return grade in CLAMP_GRADES


def direction(why: Optional[str]) -> str:
    from .. import terms as tm
    return tm.DIRECTION.get(tm.reason_of(why) or "", "other")


# --------------------------------------------------------------------------- one run


class _Run(p19._Run):
    def __init__(self, *a: Any, ctx: Ctx, S: float, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.ctx = ctx
        self.S = S
        self.published = False
        self.c: Any = None
        self.bodies: Dict[str, List[Any]] = {}
        self.received = getattr(self.a, "received", None)

    def refresh_effects(self) -> None:
        new, self._eff_idx = self.recorder.effects_after(self._eff_idx, self.prefix)
        for e in new:
            body = e.get("effect")
            if body is None:
                try:
                    body = json.loads(e.get("raw") or b"null")
                except ValueError:
                    body = None
            ref = str((body or {}).get("ref") if isinstance(body, dict) else None)
            self._effects.setdefault(ref, []).append(e["t_kit"])
            self.bodies.setdefault(ref, []).append(body)

    # building ---------------------------------------------------------------------------------

    def build(self, fx: Fx) -> Tuple[Dict[str, List[Any]], Dict[str, Any], Dict[str, str]]:
        """Sign every mandate (presented chains, presented grant first), every linked
        authorisation, and draw each mandate's goal id."""
        A = self.stub
        now = A.now()
        chains: Dict[str, List[Any]] = {}
        goals: Dict[str, str] = {}
        from .. import terms as tm
        for key, ms in fx.mandates.items():
            goal = tm.new_goal_id()
            goals[key] = goal
            pk = f"p{key.lower()}-{secrets.token_hex(3)}@a.example"
            c0, t0 = ms.hops[0]
            na = now + ms.na if ms.na is not None else None
            made = [A.issue_v4(f"a1-{secrets.token_hex(3)}", dict(c0), {**t0, "goal_id": goal},
                               principal=pk, not_after=na)]
            for c, t in ms.hops[1:]:
                made.append(A.restate(made[-1], f"c1-{secrets.token_hex(3)}",
                                      {**t, "goal_id": goal}, constraints=dict(c), org=self.c))
            chains[key] = made[::-1]
        links: Dict[str, Any] = {}
        for name, (c, serves) in fx.links.items():
            links[name] = A.linked(goals[serves] if serves else None, dict(c),
                                   principal=f"pay-{secrets.token_hex(3)}@a.example")
        return chains, links, goals

    def present_spec(self, s: ASpec, chains: Dict[str, List[Any]], links: Dict[str, Any],
                     goals: Dict[str, str], ep: str) -> Tuple[Any, Dict[str, Any]]:
        """The presentation for `s`, and what the kit knows about it (for `truth`)."""
        from .. import authz, standing
        A = self.stub
        chain = chains[s.mandate]
        disc: List[Any] = []
        for m in chain:
            for d in m.disclosures:
                if "*" in s.withhold or d[1] in s.withhold:
                    continue
                disc.append(list(d))
        conf_tok = None
        conf: Optional[Tuple[str, Dict[str, Any]]] = None
        if s.confirm:
            conf_tok = A.confirm(chain[0], s.confirm_of or s.values, by=s.confirm, loose=s.raw)
            conf = (s.confirm, standing.peek(conf_tok))
        linked = links.get(s.linked) if s.linked else None
        p = A.present(chain, s.values, audience=self.audience(ep), linked=linked,
                      confirmation=conf_tok, disclosures=disc or None,
                      asserted_purpose=s.purpose_header,
                      named_goal=goals.get(s.goal_header) if s.goal_header else None,
                      loose=s.raw, window_s=self.req_window)
        basis = authz.RAW if s.raw else authz.CANONICAL
        know = {"chain": chain, "linked": linked, "confirmation": conf, "disclosures": disc,
                "digest": authz.binding_digest(p.request, basis)}
        return p, know

    def kit_reading(self, s: ASpec, know: Dict[str, Any], *, view: str = "kit",
                    values: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """`terms.meets` for `s`: ``kit`` reads every term as the principal approved it (sealed
        members open); ``b`` reads the terms as B was given them, with the disclosures B was
        given."""
        from .. import terms as tm
        chain = know["chain"]
        vals = s.values if values is None else values
        op = vals.get("operation") if isinstance(vals, dict) else None
        if view == "kit":
            tchain = [m.terms for m in chain]
            disc = None
        else:
            tchain = [m.grant.claims["terms"] for m in chain]
            disc = know["disclosures"]
        linked: Any = "_none"
        if know["linked"] is not None:
            linked = know["linked"].terms if view == "kit" else know["linked"].grant.claims["terms"]
        return tm.meets(vals, tchain, purpose_map=self.ctx.pmap,
                        bindings=self.ctx.binding(op or ""), item_key=self.ctx.item_key,
                        linked=linked, confirmation=know["confirmation"], disclosures=disc,
                        request_digest=know["digest"], grant_id=chain[0].id,
                        requires=self.ctx.needs(op or ""))

    def limits(self, know: Dict[str, Any], values: Dict[str, Any], at: float) -> Optional[str]:
        """`attenuation.inside` over the presented chain and the linked authorisation."""
        from .. import attenuation as att, terms as tm
        chain = [tm.without_terms(m.grant.claims) for m in know["chain"]]
        al = att.allowed(chain)
        why = att.inside(values, al, at=at, tolerance_s=self.ctx.tolerance, party=self.counterparty)
        if why or know["linked"] is None:
            return why
        al2 = att.allowed([tm.without_terms(know["linked"].grant.claims)])
        return att.inside(values, al2, at=at, tolerance_s=self.ctx.tolerance,
                          party=self.counterparty)


def truth(run: _Run, variant: str, form: str, items: Dict[str, Tuple[ASpec, Dict[str, Any]]],
          at: float) -> Dict[str, Any]:
    """KRK-M151, M165, M152: W inside every limit and outside a term (for ``outside_ceiling`` the
    reverse); L, W-in and the prior completion inside every limit and meeting every term. Read
    with the kit's own vocabulary."""
    out: Dict[str, Any] = {}
    for under, (s, know) in items.items():
        out[under] = {"limits": run.limits(know, s.values, at),
                      "terms_kit": run.kit_reading(s, know, view="kit"),
                      "terms_b": run.kit_reading(s, know, view="b")}
    w = out["W"]
    bad = []
    if variant == "outside_ceiling":
        if w["limits"] is None or w["terms_kit"] is not None:
            bad.append("W must be outside a limit and meet every term")
    elif (variant, form) in INFORMATION_ONLY:
        if w["limits"] is not None or w["terms_kit"] is not None:
            bad.append("W must meet every structured term and every limit")
    else:
        if w["limits"] is not None:
            bad.append(f"W must be inside every limit (KRK-M151): {w['limits']}")
        if w["terms_kit"] is None:
            bad.append("W must be outside a term")
        if variant == "hidden_terms" and w["terms_b"] is None:
            bad.append("W must be unreadable to B (KRK-M154)")
    for under in ("L", "W-in", "prior"):
        if under in out and (out[under]["limits"] is not None or out[under]["terms_kit"] is not None
                             or out[under]["terms_b"] is not None):
            bad.append(f"{under} must meet every term and limit: {out[under]}")
    if bad:
        raise AssertionError(f"the kit's own fixture for {variant}/{form} does not mean what it "
                             f"says (KRK-M151, M152): {bad}; {out}")
    return out


@dataclass
class _T:
    variant: str
    form: str
    k: int
    pres: List[Any] = field(default_factory=list)
    specs: Dict[str, Tuple[ASpec, Dict[str, Any]]] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)
    info: Optional[str] = None
    info_detail: str = ""


def _send(run: _Run, p: Any, under: str, tag: str) -> Any:
    return run.send(p, under, tag=tag)


def _settle(run: _Run, pres: List[Any], variant: str = "") -> float:
    """Watch the recorder for S after the last answer when any answer was pending (KRK-M158), or
    in a published run after any trial of a `STABLE_VARIANTS` variant; else for
    `SETTLE_S`. Returns the wait."""
    wait = run.S if (any(q.cls == "in-progress" for q in pres)
                     or (run.published and variant in STABLE_VARIANTS)) else SETTLE_S
    run.settle(run.clock.now() + wait)
    for q in pres:
        run.fill(q)
    return wait


def _received_ok(run: _Run, p: Any) -> Optional[bool]:
    """KRK-M156, M162: whether what B says it received equals what left the kit; None where the
    adapter gives no account of what B received."""
    if not callable(run.received):
        return None
    try:
        ref = str(json.loads(p.request.decode("utf-8")).get("ref"))
        got = run.received(ref)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(got, dict):
        return None
    return got.get("digest") == headers_digest(p.headers, p.request)


def _trial(run: _Run, variant: str, form: str, k: int) -> _T:
    from .. import mandator
    A, clock = run.stub, run.clock
    tr = _T(variant, form, k)
    run.variant = variant
    run.disp.begin_trial()
    fx = fixture(variant, form, run.rng, run.ctx)
    chains, links, goals = run.build(fx)
    if fx.present_at:
        clock.sleep_until(clock.now() + fx.present_at + run.ctx.tolerance + 1.0)
    at = A.now()
    ep0, ep1 = run.endpoints[0], run.endpoints[-1]
    specs: Dict[str, Tuple[ASpec, Any, Dict[str, Any]]] = {}
    for under, s, ep in (("prior", fx.prior, ep0), ("W", fx.W, ep0), ("L", fx.L, ep1),
                         ("W-in", fx.W_in, ep0)):
        if s is None or (under == "W-in" and (variant, form) in NO_W_IN):
            continue
        p, know = run.present_spec(s, chains, links, goals, ep)
        specs[under] = (s, p, know)
    tr.specs = {u: (s, know) for u, (s, _p, know) in specs.items()}
    tr.extra["truth"] = truth(run, variant, form, tr.specs, at)
    tr.extra["term"] = fx.term
    tr.extra["notes"] = fx.notes
    tr.extra["goals"] = goals
    tr.extra["sent"] = {u: headers_digest(p.headers, p.request) for u, (_s, p, _k) in specs.items()}
    # KRK-M154, M156: the fixture lands only if what the form needs reached B.
    pw = specs["W"][1]
    leaked = landed_disclosures(pw.headers, fx.hidden)
    if leaked:
        tr.info, tr.info_detail = "not_landed", f"W carried the disclosure of {leaked} (KRK-M154)"
        return tr
    if fx.W.purpose_header and mandator.PURPOSE_HEADER not in pw.headers or \
            fx.W.goal_header and mandator.GOAL_HEADER not in pw.headers:
        tr.info, tr.info_detail = "not_landed", "the agent's claim was not sent (KRK-M156)"
        return tr
    if "prior" in specs:
        q = _send(run, specs["prior"][1], "prior", "static:prior")
        tr.pres.append(q)
        run.settle(clock.now() + 0.5)
        run.fill(q)
    order = [u for u in ("W", "L") if u in specs]
    run.rng.shuffle(order)
    if "W-in" in specs:
        order.append("W-in")                 # always after W (KRK-M169)
    for under in order:
        tr.pres.append(_send(run, specs[under][1], under, f"static:{under}"))
    tr.extra["order"] = order
    tr.extra["settle_s"] = _settle(run, tr.pres, variant)
    tr.extra["received"] = {q.under: _received_ok(run, specs[q.under][1]) for q in tr.pres}
    tr.extra["w_effects"] = run.bodies.get(str(json.loads(pw.request.decode("utf-8"))
                                               .get("ref")), [])
    return tr


def _judge(run: _Run, tr: _T) -> Any:
    from ..timing import TrialOutcome
    if tr.info:
        return TrialOutcome(tr.info, None, form=tr.form, detail=tr.info_detail)
    by = {}
    for q in tr.pres:
        by.setdefault(q.under, []).append(q)
    W, L, Win, prior = by.get("W", []), by.get("L", []), by.get("W-in", []), by.get("prior", [])
    if any(v is False for v in tr.extra.get("received", {}).values()):
        return TrialOutcome("not_landed", None, form=tr.form,
                            detail="what B received differs from what left the kit "
                                   "(KRK-M156, KRK-M162)")
    v_f = (tr.variant, tr.form)
    s_w, know_w = tr.specs["W"]
    if any(p.accepted for p in W):
        if v_f in INFORMATION_ONLY:
            return TrialOutcome("text_ignored", None, form=tr.form,
                                detail="W, inside the structured terms, was accepted; the "
                                       "narrower text was not applied (information)")
        bodies = [b for b in tr.extra.get("w_effects") or [] if isinstance(b, dict)]
        if v_f in CLAMPABLE and clamp_credited(run.grade) and bodies and all(
                run.kit_reading(s_w, know_w, values=b) is None and
                run.limits(know_w, b, run.stub.now()) is None for b in bodies):
            if not any(p.accepted for p in L):
                return TrialOutcome("collateral_refusal", None, form=tr.form,
                                    detail="W was clamped but the sibling, which meets every "
                                           "term, was refused (KRK-M155)")
            return TrialOutcome("held", True, form=tr.form,
                                detail="B performed only the goal's items; mode clamped")
        if tr.variant == "outside_ceiling":
            d, why = "over_limit", tr.extra["truth"]["W"]["limits"]
        else:
            body = bodies[0] if bodies else s_w.values
            why = run.kit_reading(s_w, know_w, view="b", values=body) or \
                run.kit_reading(s_w, know_w, view="kit", values=body)
            d = direction(why)
        late = [q for q in W if q.cls in ("in-progress", "refused") and q.accepted]
        tail = f"; B answered {late[0].cls} and the effect landed within S" if late else ""
        return TrialOutcome("outside_effect", False, form=tr.form,
                            detail=f"an effect outside the mandate's {tr.extra.get('term')} "
                                   f"(direction {d}): {why}{tail}")
    if v_f in INFORMATION_ONLY:
        return TrialOutcome("text_applied", None, form=tr.form,
                            detail="W, inside the structured terms, was refused (information)")
    if any(p.timed_out for p in W):
        return TrialOutcome("hung", None, form=tr.form, detail="no answer within the answer "
                            "timeout and no effect (an availability finding)")
    if prior and not any(p.accepted for p in prior):
        return TrialOutcome("collateral_refusal", None, form=tr.form,
                            detail="the principal's other goal G1 was refused, so B never knew "
                                   "the goal W's payment authority names (KRK-M159)")
    if not any(p.accepted for p in L):
        if tr.variant == "restated_terms" and not run.shape_ok.get("holder", True):
            return TrialOutcome("shape_refused", None, form=tr.form,
                                detail="B refuses every restated hop (the control's holder "
                                       "chain was refused)")
        return TrialOutcome("collateral_refusal", None, form=tr.form,
                            detail="the sibling, which meets every term, was refused too, so the "
                                   "refusal is not shown to be about the term (KRK-M155)")
    repeat = getattr(run.a, "is_repeat_refusal", None)
    if callable(repeat) and any(p.cls == "refused" and repeat(getattr(p, "answer", {}))
                                for p in W):
        return TrialOutcome("not_landed", None, form=tr.form,
                            detail="W was refused as a repeat of an earlier use (KRK-M169)")
    if Win and not any(p.accepted for p in Win):
        return TrialOutcome("inside_refused", None, form=tr.form,
                            detail="W-in, which meets every term of W's own mandate, was refused "
                                   "(information: over-refusal is safe)")
    mode = "pending" if any(p.cls == "in-progress" for p in W) else "refused"
    return TrialOutcome("held", True, form=tr.form,
                        detail=f"no W effect within {tr.extra.get('settle_s')} s; L accepted; "
                               f"mode {mode}")


# --------------------------------------------------------------------------- control


def _control_terms(ctx: Ctx, rng: random.Random, op: str, res: str, *, seal: bool
                   ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Terms carrying every kind B declares that apply to one action, and the action."""
    from ..mandator import Seal
    items = [(f"sku-{_hex(rng)}", rng.randint(1, 2))]
    payee = f"m-{_hex(rng, 6)}"
    amount = rng.randint(1000, 9000)
    t: Dict[str, Any] = {}
    kinds = set(ctx.kinds)
    if "purpose" in kinds and ctx.pmap:
        from .. import terms as tm
        code = next((c for c in sorted(ctx.pmap) if tm.purpose_covers(ctx.pmap, c, op, [res])),
                    None)
        if code is not None:
            t["purpose"] = {"code": code}
    if "slots" in kinds:
        t["slots"] = [{"slot": "s1", "acceptable": [items[0][0]], "quantity": items[0][1]}]
    if "fixed" in kinds:
        t["fixed"] = {"payee": Seal(payee) if seal and "sealed" in kinds else payee}
    if "floor" in kinds:
        t["floor"] = {"amount": _amt(amount)}
    if "text" in kinds:
        t["text"] = "the control's goal, which this action meets"
    return t, _act(ctx, rng, op, res=res, amount=amount, items=items, payee=payee)


def _control_res(ctx: Ctx, rng: random.Random, op: str) -> str:
    from .. import terms as tm
    for c in sorted(ctx.pmap or {}):
        e = (ctx.pmap or {})[c]
        if op in (e.get("operations") or []):
            r = _res(rng, e.get("resources"))
            if tm.purpose_covers(ctx.pmap, c, op, [r]):
                return r
    return _res(rng)


def _control(run: _Run) -> Tuple[bool, str, Dict[str, Any]]:
    ctx, rng = run.ctx, run.rng
    kinds = set(ctx.kinds)
    shapes = [("plain", OP_BUY)]
    if "confirm" in kinds and ctx.condition_mode in ("refuse", "hold"):
        shapes.append(("conditioned", OP_COMMIT))
    if "serves" in kinds:
        ops = [o for o in sorted(ctx.requires) if "serves" in ctx.needs(o)]
        shapes.append(("linked", ops[0] if ops else OP_PAY))
    if ctx.holder_hops and run.c is not None:
        shapes.append(("holder", OP_BUY))
    log: List[Any] = []
    obs: Dict[str, Any] = {"shapes": {}}
    deadline = run.clock.now() + READY_S
    for name, op in shapes:
        ok_all = True
        for ep in run.endpoints:
            while True:
                res = _control_res(ctx, rng, op)
                t, values = _control_terms(ctx, rng, op, res, seal=name == "plain")
                c = _lim(ctx, res)
                if name == "conditioned":
                    t["confirm"] = {"operations": [op], "by": "principal"}
                hops = [(c, t)] + ([(c, t)] if name == "holder" else [])
                fx = Fx({"M": MSpec(hops)}, ASpec("M", values), ASpec("M", values))
                links_ = {}
                spec = ASpec("M", values, confirm="principal" if name == "conditioned" else None)
                if name == "linked":
                    fx.links = {"P": (_lim(ctx, res, ops=[op]), "M")}
                    spec.linked = "P"
                chains, links_, goals = run.build(fx)
                p, know = run.present_spec(spec, chains, links_, goals, ep)
                why = run.kit_reading(spec, know) or run.kit_reading(spec, know, view="b") or \
                    run.limits(know, values, run.stub.now())
                if why:
                    raise AssertionError(f"the control's {name} action does not meet its own "
                                         f"terms: {why}")
                q = run.send(p, name, tag=f"control:{name}")
                log.append(q)
                wait = run.S if q.cls == "in-progress" else 0.5
                run.settle(run.clock.now() + wait)
                run.fill(q)
                ok = q.accepted
                if ok and run.grade == "recorder":
                    n = len(run.effect_times(q.ref))
                    bodies = run.bodies.get(q.ref) or []
                    if n != 1:
                        return False, f"an accepted control presentation ({q.ref}) has {n} " \
                                      f"effects", {"presentations": log}
                    if any(run.kit_reading(spec, know, values=b) for b in bodies
                           if isinstance(b, dict)):
                        return False, (f"the control's {name} effect does not meet its terms "
                                       f"(the recorder's body differs from the action)"), \
                            {"presentations": log}
                rec = _received_ok(run, p)
                if rec is False:
                    return False, "what B received differs from what left the kit (KRK-M89)", \
                        {"presentations": log}
                if ok or name != "plain":
                    break
                if run.clock.now() >= deadline:
                    return False, (f"an action meeting every term was not accepted at endpoint "
                                   f"{ep!r} within {READY_S:g} s"), {"presentations": log}
                run.clock.sleep(1.0)
            ok_all = ok_all and ok
        obs["shapes"][name] = ok_all
    obs["presentations"] = log
    return True, "", obs


# --------------------------------------------------------------------------- the probe


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    try:
        p = json.loads(raw)
    except ValueError:
        return None
    return p if isinstance(p, dict) else None


def _trials(plan: Dict[str, Any], variant: str) -> int:
    t = plan.get("trials")
    if isinstance(t, int) and t > 0:
        return t
    table = DEV_TRIALS if t == "dev" else TRIALS
    return table.get(variant, table["*"])


def must_land(kinds: Sequence[str], forms: Dict[str, Dict[str, Any]]) -> List[str]:
    """Design §6.5: the forms that must read held or fail for this B: the always-required ones
    (a format gap excused), and the core forms of every term kind B declares."""
    need: List[Tuple[str, str, bool]] = [(v, f, True) for v, f in ALWAYS_MUST_LAND]
    for k in kinds:
        need += [(v, f, False) for v, f in CORE_FORMS.get(k, ())]
    if "sealed" in kinds:
        a = forms.get("hidden_terms", {}).get("slot_hidden", {})
        b = forms.get("hidden_terms", {}).get("fixed_hidden", {})
        if a.get("ok") is None and b.get("ok") is None:
            need.append(("hidden_terms", "slot_hidden" if "slots" in kinds else "fixed_hidden",
                         False))
    out = []
    for v, f, gap_ok in need:
        d = forms.get(v, {}).get(f)
        if d is None:
            continue
        if d["ok"] is None and not (gap_ok and d["reading"] in ("format_gap", "not_applicable")):
            out.append(f"{v}/{f}")
    return out


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from .. import attenuation as att, role_mandate
    from ..mandator import StubMandator
    from ..mockserver import MockServer
    from ..requester import new_issuer
    from ..timing import make_clock

    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if getattr(a, "role", lambda: "B")() != "B":
        return Result.inconclusive(a.name, ID, "P24 grades B in version 1",
                                   **common)
    base = role_mandate.MandateB()

    def opt(name: str) -> Any:
        fn = getattr(a, name, None)
        return fn() if callable(fn) else getattr(base, name)()

    def read_ctx() -> Ctx:
        agreement = dict(a.agreement() or {})
        bound = dict(getattr(a, "withdrawal_bound", lambda: {})() or {})
        tol = float(bound.get("clock_tolerance_s") or agreement.get("clock_tolerance_s") or 0.0)
        return Ctx(party=agreement.get("counterparty") or "",
                   dims=[d for d in (opt("constraint_profile") or []) if d in att.DIMENSIONS],
                   kinds=[k for k in (opt("term_profile") or [])],
                   pmap=opt("purpose_map"), requires=dict(opt("requires_terms") or {}),
                   bindings=dict(opt("term_bindings") or {}), item_key=str(opt("item_key")),
                   condition_mode=str(opt("condition_mode")),
                   disclosure=opt("disclosure_profile"),
                   holder_hops=bool(opt("accepts_holder_hops")) and int(opt("issuers") or 1) > 1,
                   confirm_binds=bool(opt("confirmation_binds_action")), tolerance=tol)
    try:
        ctx = read_ctx()
        grade = a.evidence_grade()
        profile = opt("mandate_profile")
        hold_s = opt("hold_resolution_s")
        advisory = dict(opt("advisory_terms") or {})
        pmap_source = opt("purpose_map_source")
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    from .. import terms as tm
    unknown_kinds = sorted(set(ctx.kinds) - set(tm.PROFILE_KINDS))
    if unknown_kinds:
        return Result.inconclusive(a.name, ID, f"unknown term kinds {unknown_kinds}", **common)
    if profile is not None:
        return Result.inconclusive(a.name, ID, f"mandate profile {profile!r} has no writer in "
                                   f"the kit yet (grant 0.4 only)", **common)
    if not ctx.party or grade not in GRADES:
        return Result.inconclusive(a.name, ID, "no counterparty id, or an unknown evidence grade",
                                   **common)
    kind = getattr(a, "clock", "real")
    if kind == "virtual" and not p19._is_toy(a):
        return Result.inconclusive(a.name, ID, "only a toy may declare a virtual clock", **common)
    na: Dict[str, str] = dict(getattr(a, "variants_not_applicable", lambda: {})() or {})
    forbidden = {"outside_ceiling", "unknown_term"}
    if any(v in forbidden or v not in VARIANTS for v in na):
        return Result.inconclusive(a.name, ID, f"the adapter declares {sorted(na)} not "
                                   f"applicable; {sorted(forbidden)} may not be", **common)
    plan = dict(plan if plan is not None else ({} if p19._is_toy(a) else (_plan_from_env() or {})))
    published = plan == {} or plan.get("trials") == "published"
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
    A = StubMandator(new_issuer(), clock=clock, ttl_s=60, audience=ctx.party)
    url = A.serve()
    progress = p19._Progress(ev)
    run = None
    S = stability_window(hold_s)
    try:
        C = None
        peer_how = None
        bind_how = a.bind_requester(A.trust_anchor_x1(), url)
        if ctx.holder_hops:
            C = A.peer()
            peer_how = a.bind_peer(C.trust_anchor_x1(), C.source_url)
        prefix = f"/p24/{run_tag}{secrets.token_hex(4)}"
        rec_how = a.bind_recorder(recorder.url + prefix)
        bound = dict(getattr(a, "withdrawal_bound", lambda: {})() or {})
        agreement = dict(a.agreement() or {})
        channels = list(getattr(a, "channels", lambda: [])() or [])
        run = _Run(a, ev, clock=clock, stub=A, recorder=recorder, prefix=prefix,
                   agreement=agreement, bound={**bound, "T_s": None}, channels=channels,
                   forms=["agent"], grade=grade, rng=rng, window=0.0, stability=S, ctx=ctx, S=S)
        run.c = C
        run.published = published
        run.progress = progress
        run.shape_ok = {}
        statements = {"term_profile": ctx.kinds, "purpose_map": ctx.pmap,
                      "purpose_map_source": pmap_source, "requires_terms": ctx.requires,
                      "term_bindings": ctx.bindings, "item_key": ctx.item_key,
                      "condition_mode": ctx.condition_mode, "hold_resolution_s": hold_s,
                      "stability_s": S, "disclosure_profile": ctx.disclosure,
                      "accepts_holder_hops": ctx.holder_hops, "advisory_terms": advisory,
                      "constraint_profile": ctx.dims, "clock_tolerance_s": ctx.tolerance,
                      "confirmation_binds_action": ctx.confirm_binds,
                      "documents_terms": bool(opt("documents_terms")),
                      "digest": statements_digest(ctx)}
        ev.write("run.json", {"seed": seed, "variant_order": ["control"] + order,
                              "statements": p19._jsonable(statements), "plan": plan,
                              "bind_requester": bind_how, "bind_peer": peer_how,
                              "bind_recorder": rec_how, "clock": kind})
        run.log("run", seed=seed, statements=statements, plan=plan)
        r = _probe(run, a, ev, common, na, plan, published, only, order, seed, statements,
                   pmap_source)
        try:
            after = statements_digest(read_ctx())
        except Exception:  # noqa: BLE001
            after = None
        if after != statements["digest"] and r.status.value in ("pass", "fail"):
            return Result.inconclusive(a.name, ID, "B's term profile or purpose map changed "
                                       "during the run (KRK-M167)", checks=r.checks,
                                       control_held=True, control_detail=r.control_detail,
                                       extra=r.extra, **common)
        return r
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
        recorder.close()
        A.close()
        clock.close()


def _probe(run: _Run, a: Any, ev: Evidence, common: Dict[str, Any], na: Dict[str, str],
           plan: Dict[str, Any], published: bool, only: List[str], order: List[str], seed: int,
           statements: Dict[str, Any], pmap_source: Any) -> Result:
    held, why, obs = _control(run)
    run.shape_ok = dict(obs.get("shapes") or {})
    ev.write("control.json", {"held": held, "why": why, "shapes": run.shape_ok,
                              "presentations": [p19._pres_doc(p, None)
                                                for p in obs.get("presentations", [])]})
    run.log("control", held=held, why=why, shapes=run.shape_ok)
    if not held:
        return Result.inconclusive(a.name, ID, f"control did not hold: {why}", **common)
    ctx = run.ctx
    control = ("fresh mandates carrying every term kind B declares, each met by an action "
               f"accepted at every endpoint with one effect each ({', '.join(run.shape_ok)})")
    readings: Dict[str, Dict[str, Any]] = {}
    gaps: List[Dict[str, str]] = []
    docs: Dict[str, List[Dict[str, Any]]] = {}
    modes: Dict[str, set] = {}
    classes: Dict[str, Dict[str, Any]] = {}
    documents = bool(statements.get("documents_terms"))
    shape_of = {"condition": "conditioned", "cross_goal": "linked", "restated_terms": "holder"}
    for variant in order:
        if variant in na or variant not in only:
            continue
        for form in FORMS[variant]:
            if variant in (plan.get("forms") or {}) and form not in plan["forms"][variant]:
                continue
            gap = _needs(variant, form, ctx)
            if gap:
                gaps.append({"variant": variant, "form": form, "why": gap})
                readings.setdefault(variant, {})[form] = {"reading": "format_gap", "ok": None,
                                                          "detail": gap}
                continue
            sh = shape_of.get(variant)
            if sh and run.shape_ok.get(sh) is False:
                why = (f"the control's {sh} action meeting every term was not completed, so a "
                       f"refusal here is not shown to be about the term "
                       f"({'KRK-M157' if sh == 'conditioned' else 'KRK-M155'})")
                readings.setdefault(variant, {})[form] = {"reading": "shape_refused", "ok": None,
                                                          "detail": why}
                continue
            outs = []
            try:
                for k in range(_trials(plan, variant)):
                    tr = _trial(run, variant, form, k)
                    o = _judge(run, tr)
                    outs.append(o)
                    if o.ok:
                        m = o.detail.rsplit("mode ", 1)[-1]
                        modes.setdefault(variant, set()).add(m)
                    doc = {"form": form, "k": k, "outcome": o.to_doc(),
                           "extra": p19._jsonable({x: y for x, y in tr.extra.items()
                                                   if x != "w_effects"}),
                           "w_effects": p19._jsonable(tr.extra.get("w_effects")),
                           "presentations": [p19._pres_doc(p, None) for p in tr.pres]}
                    docs.setdefault(variant, []).append(doc)
                    run.log("trial", variant=variant, **doc)
            except NotLanded as e:
                gaps.append({"variant": variant, "form": form, "why": str(e)})
                readings.setdefault(variant, {})[form] = {"reading": "format_gap", "ok": None,
                                                          "detail": str(e)}
                continue
            fails = [o for o in outs if o.ok is False]
            counted = [o for o in outs if o.ok is not None]
            if fails:
                r = {"reading": "outside_effect", "ok": False, "detail": fails[0].detail}
                vuln = documents and ((variant, form) in VULNERABLE_FORMS or
                                      (variant == "purpose" and bool(pmap_source)))
                classes[f"{variant}/{form}"] = {
                    "class": "vulnerability" if vuln else "conformance",
                    "why": ("B documents that it checks the action against the mandate's terms, "
                            "and this form's failure lets an agent spend an open mandate on "
                            "something the principal did not approve" if vuln else
                            "outside design §1.8's vulnerable forms, or B documents no term "
                            "check")}
            elif counted and all(o.ok for o in counted):
                r = {"reading": "held", "ok": True, "detail": counted[0].detail}
            else:
                infos = [o.outcome for o in outs]
                r = {"reading": max(sorted(set(infos)), key=infos.count) if infos else
                     "not_landed", "ok": None, "detail": outs[0].detail if outs else ""}
            readings.setdefault(variant, {})[form] = r
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
        elif passes:
            m = sorted(modes.get(variant, set()))
            c = Check(variant, "held", True, parts + (f"; mode {'/'.join(m)}" if m else ""))
        elif all(d["reading"] == "format_gap" for d in fr.values()):
            c = Check(variant, "not_applicable", None, f"no form can be written in B's format: "
                      f"{parts}")
        else:
            c = Check(variant, next(iter(fr.values()))["reading"], None, parts)
        checks.append(c)
    must = [m for m in must_land(ctx.kinds, readings)
            if m.split("/")[0] in only and m.split("/")[0] not in na]
    fails = [c for c in checks if c.ok is False]
    vuln = any(c["class"] == "vulnerability" for c in classes.values())
    covered = sorted(k for k, fs in CORE_FORMS.items() if k in ctx.kinds and any(
        readings.get(v, {}).get(f, {}).get("ok") is True for v, f in fs))
    extra: Dict[str, Any] = {
        "seed": seed, "term_profile": ctx.kinds, "term_kinds_covered": covered,
        "term_kinds_not_expressible": sorted(set(tm_kinds()) - set(ctx.kinds)),
        "format_gaps": gaps, "forms": readings, "must_land_missed": must,
        "modes": {k: sorted(v) for k, v in modes.items()},
        "disclosure": "vulnerability" if vuln else "conformance",
        "disclosure_forms": classes, "documents_terms": documents,
        "purpose_map": ctx.pmap, "stability_s": run.S, "control_shapes": run.shape_ok,
        "stability_every_trial": list(STABLE_VARIANTS) if published else [],
        "level": "library" if run.grade in LIBRARY_GRADES else "deployed",
        "evidence_grade": run.grade, "clock": getattr(a, "clock", "real"),
        "progress": os.path.relpath(run.progress.path, ev.dir) if run.progress else None}
    if plan:
        extra["plan"] = plan
    dev = "" if published else "Development plan (smaller counts; not a published run). "
    if run.grade in LIBRARY_GRADES:
        dev = (f"Library-level reading (grade {run.grade}: a verification library's answers, "
               f"no deployed B). ") + dev
    gap_txt = (f" Cannot express in B's format (findings, never a pass): "
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
                    pass_summary=f"{dev}no effect outside the mandate's terms, in "
                                 f"{', '.join(covered) or 'no term kind'}.{gap_txt}",
                    fail_summary=f"{dev}an effect lay outside the mandate's terms"
                                 f"{'.' + gap_txt if gap_txt else ''}",
                    extra=extra, **common)
    run.log("end", status=r.status.value, summary=r.summary,
            checks={c.name: [c.outcome, c.ok] for c in checks})
    return r


def tm_kinds() -> Tuple[str, ...]:
    from .. import terms as tm
    return tm.PROFILE_KINDS
