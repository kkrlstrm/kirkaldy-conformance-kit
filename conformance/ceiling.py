"""Grant 0.3, reservations, spend statements and the kit's own account for KRK-22 (P22,
cumulative ceiling across counterparties, cross-organisation X9).

`X9-CUMULATIVE-CEILING-DESIGN.md` §2.5, §2.6 and §6.2. This module states what the total was,
from the recorder alone, and what each format means. It imports no target, keeps no state, and
shares no code with any target (spec §5.1 rule 7); its answers are checked against hand-written
vectors (`tests/vectors/krk22/`). Every format is a compact JWS (EdDSA) over the canonical JSON of
its claims (`standing.sign`, `standing.verify` with this module's shape checks).

**Grant 0.3** (`GRANT_V3_SCHEMA`, typ ``krk-grant+jws`` as 0.2): grant 0.2 with one more member of
``constraints``, ``cumulative``:

    {"ceiling_id": "cl-<16 hex>", "limits": [limit, ...], "window": null | window,
     "reversals": "gross" | "net-recorded", "holder": null | {"source", "kid"},
     "share": null | {"spender", "share_id", "limits": [limit, ...]}}

A limit is ``{"kind": "amount", "value", "currency", "minor_units"}`` (X5's amount, exact) or
``{"kind": "count", "value", "unit"}``. A window is ``{"kind": "fixed", "period_s",
"anchor_ms"}`` (an absolute anchor on the holder's clock, epoch milliseconds) or ``{"kind":
"rolling", "period_s"}``. Every limit holds; a child inherits its parent's ``ceiling_id``s and may
add its own. Grant 0.2 is unchanged: to a 0.2 reader ``cumulative`` is an unknown
constraint and the grant is refused, which is safe and a format gap for P22.

**Reservation** (`RESERVATION_SCHEMA`, typ `RESERVATION_TYP`), signed by the holder:
``reservation_id``, ``kind`` (``reservation`` or ``online``), ``ceiling_ids``, ``spender``,
``quantity`` (limits' shape, one entry per limit), ``request_id``, ``request_digest`` (or null),
``issued_at`` (epoch ms, holder's clock), ``not_after`` (epoch ms, or null: never expires),
``holder``.

**Spend statement** (`SPEND_SCHEMA`, typ `SPEND_TYP`), signed by a spender: ``kind``
(``captured``, ``released``, ``reversed``), ``ref`` (a reservation id or share id), ``spender``,
``ceiling_ids``, ``quantity``, ``effect_ref`` (the recorder's reference, or null), ``at`` (epoch
ms, the spender's clock).

**The kit's account** (§2.6). Quantities are exact integers. Amounts are carried in units of
10^-`SCALE` of the currency, so amounts stated with different ``minor_units`` add exactly; counts
are whole effects. Nothing is ever converted between currencies or count units: a spend in a unit
the limit does not state is *uncountable* (`quantity` returns None), and an uncountable effect
committed under a ceiling is itself outside it (KRK-M105). A negative spend frees
nothing: only a reversal the spender recorded can, and only under ``net-recorded`` (KRK-M104).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import attenuation

GRANT_V3_SCHEMA = "kirkaldy.grant/0.3"
GRANT_TYP = attenuation.GRANT_TYP
RESERVATION_SCHEMA, RESERVATION_TYP = "kirkaldy.reservation/0.1", "krk-reservation+jws"
SPEND_SCHEMA, SPEND_TYP = "kirkaldy.spend/0.1", "krk-spend+jws"
FORWARD_SCHEMA, FORWARD_TYP = "kirkaldy.forward/0.1", "krk-forward+jws"
LIMIT_KINDS = ("amount", "count")
WINDOW_KINDS = ("fixed", "rolling")
REVERSAL_RULES = ("gross", "net-recorded")
MECHANISMS = ("allocation", "reservation", "online", "forwarding", "metering")
TOPOLOGIES = ("bearer", "forwarding")
SPEND_KINDS = ("captured", "released", "reversed")
RESERVATION_KINDS = ("reservation", "online")
CUMULATIVE_MEMBERS = ("ceiling_id", "limits", "window", "reversals", "holder", "share")
SCALE = attenuation.MAX_MINOR_UNITS
"""Amounts are summed in units of 10^-18 of the currency: exact for every ``minor_units`` the
vocabulary admits (0 to 18)."""
MAX_SAFE = attenuation.MAX_SAFE

MALFORMED = attenuation.MALFORMED
UNKNOWN = attenuation.UNKNOWN

_CL_ID = re.compile(r"cl-[0-9a-f]{16,64}")
_ID = re.compile(r"[a-z]{2,3}-[0-9a-f]{16,64}")
_CURRENCY = re.compile(r"[A-Z]{3}")
_UNIT = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


def _is_int(v: Any, lo: int = 0, hi: int = MAX_SAFE) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


# --------------------------------------------------------------------------- shape


def limit_problem(lim: Any) -> Optional[str]:
    """Why `lim` is not a limit the kit can count exactly."""
    if not isinstance(lim, dict) or lim.get("kind") not in LIMIT_KINDS:
        return "a limit is {kind: amount | count, ...}"
    if lim["kind"] == "amount":
        if set(lim) != {"kind", "value", "currency", "minor_units"}:
            return "an amount limit is {kind, value, currency, minor_units}"
        return attenuation.amount_problem({k: lim[k] for k in ("value", "currency",
                                                               "minor_units")})
    if set(lim) != {"kind", "value", "unit"}:
        return "a count limit is {kind, value, unit}"
    if not _is_int(lim["value"]):
        return f"count value {lim['value']!r} is not an integer from 0 to 2^53 - 1"
    if not isinstance(lim["unit"], str) or not _UNIT.fullmatch(lim["unit"]):
        return f"count unit {lim['unit']!r} is not a unit name"
    return None


def limits_problem(limits: Any) -> Optional[str]:
    if not isinstance(limits, list) or not limits:
        return "limits is a non-empty list"
    seen = set()
    for lim in limits:
        p = limit_problem(lim)
        if p:
            return p
        k = limit_key(lim)
        if k in seen:
            return f"two limits of the same kind and unit: {k}"
        seen.add(k)
    return None


def window_problem(w: Any) -> Optional[str]:
    if w is None:
        return None
    if not isinstance(w, dict) or w.get("kind") not in WINDOW_KINDS:
        return "a window is null or {kind: fixed | rolling, ...}"
    if w["kind"] == "fixed":
        if set(w) != {"kind", "period_s", "anchor_ms"}:
            return "a fixed window is {kind, period_s, anchor_ms}"
        if not _is_int(w["anchor_ms"]):
            return "anchor_ms is epoch milliseconds"
    elif set(w) != {"kind", "period_s"}:
        return "a rolling window is {kind, period_s}"
    if not _is_int(w["period_s"], 1, 366 * 86400):
        return "period_s is a whole number of seconds"
    return None


def cumulative_problem(c: Any) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `c` is not a well-formed ``cumulative`` member, else None. A
    member the vocabulary does not have is `UNKNOWN` (critical)."""
    if not isinstance(c, dict):
        return MALFORMED, "cumulative is an object"
    extra = sorted(set(c) - set(CUMULATIVE_MEMBERS))
    if extra:
        return UNKNOWN, f"unknown cumulative member(s) {extra}: refused"
    missing = [m for m in CUMULATIVE_MEMBERS if m not in c]
    if missing:
        return MALFORMED, f"cumulative is missing {missing}"
    if not isinstance(c["ceiling_id"], str) or not _CL_ID.fullmatch(c["ceiling_id"]):
        return MALFORMED, "ceiling_id is 'cl-' and 16 to 64 hex digits"
    p = limits_problem(c["limits"])
    if p:
        return MALFORMED, f"limits: {p}"
    p = window_problem(c["window"])
    if p:
        return MALFORMED, f"window: {p}"
    if c["reversals"] not in REVERSAL_RULES:
        return MALFORMED, f"reversals is one of {REVERSAL_RULES}"
    h = c["holder"]
    if h is not None and (not isinstance(h, dict) or set(h) != {"source", "kid"}
                          or not all(isinstance(h[k], str) and h[k] for k in h)):
        return MALFORMED, "holder is null or {source, kid}"
    s = c["share"]
    if s is not None:
        if not isinstance(s, dict) or set(s) != {"spender", "share_id", "limits"}:
            return MALFORMED, "share is null or {spender, share_id, limits}"
        if not isinstance(s["spender"], str) or not s["spender"]:
            return MALFORMED, "share.spender is a party"
        if not isinstance(s["share_id"], str) or not _ID.fullmatch(s["share_id"]):
            return MALFORMED, "share.share_id is an id"
        p = limits_problem(s["limits"])
        if p:
            return MALFORMED, f"share.limits: {p}"
        keys = {limit_key(x) for x in c["limits"]}
        if any(limit_key(x) not in keys for x in s["limits"]):
            return MALFORMED, "a share limits only what the ceiling limits"
    return None


def grant_v3_problem(claims: Any) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `claims` are not a well-formed 0.3 grant: grant 0.2's rules
    (`attenuation.grant_v2_problem`) for everything but ``cumulative``, which is checked here.
    ``cumulative`` is optional in 0.3 (a 0.3 grant without it states no ceiling)."""
    if not isinstance(claims, dict):
        return MALFORMED, "claims are not a JSON object"
    if claims.get("schema") != GRANT_V3_SCHEMA:
        return MALFORMED, f"schema must be {GRANT_V3_SCHEMA!r}"
    cons = claims.get("constraints")
    if not isinstance(cons, dict):
        return MALFORMED, "constraints is an object"
    v2 = {**claims, "schema": attenuation.GRANT_V2_SCHEMA,
          "constraints": {k: v for k, v in cons.items() if k != "cumulative"}}
    if "crit" in claims and isinstance(claims["crit"], list):
        v2["crit"] = [x for x in claims["crit"] if x != "cumulative"]
    p = attenuation.grant_v2_problem(v2)
    if p:
        return p
    if "cumulative" in cons:
        return cumulative_problem(cons["cumulative"])
    return None


def problem_text(p: Optional[Tuple[str, str]]) -> Optional[str]:
    return None if p is None else f"{p[0]}: {p[1]}"


def _ms(v: Any, nullable: bool = False) -> bool:
    return (nullable and v is None) or _is_int(v)


def reservation_problem(c: Any) -> Optional[str]:
    keys = {"schema", "reservation_id", "kind", "ceiling_ids", "spender", "quantity",
            "request_id", "request_digest", "issued_at", "not_after", "holder"}
    if not isinstance(c, dict) or set(c) != keys:
        return f"a reservation has exactly {sorted(keys)}"
    if c["schema"] != RESERVATION_SCHEMA:
        return f"schema must be {RESERVATION_SCHEMA!r}"
    if c["kind"] not in RESERVATION_KINDS:
        return f"kind is one of {RESERVATION_KINDS}"
    if not isinstance(c["reservation_id"], str) or not _ID.fullmatch(c["reservation_id"]):
        return "reservation_id is an id"
    if not isinstance(c["ceiling_ids"], list) or not c["ceiling_ids"] or not all(
            isinstance(x, str) and _CL_ID.fullmatch(x) for x in c["ceiling_ids"]):
        return "ceiling_ids is a non-empty list of ceiling ids"
    for k in ("spender", "request_id", "holder"):
        if not isinstance(c[k], str) or not c[k]:
            return f"{k} is a non-empty string"
    if c["request_digest"] is not None and not isinstance(c["request_digest"], str):
        return "request_digest is a string or null"
    p = limits_problem(c["quantity"])
    if p:
        return f"quantity: {p}"
    if not _ms(c["issued_at"]) or not _ms(c["not_after"], nullable=True):
        return "issued_at and not_after are epoch milliseconds (not_after may be null)"
    return None


def spend_problem(c: Any) -> Optional[str]:
    keys = {"schema", "kind", "ref", "spender", "ceiling_ids", "quantity", "effect_ref", "at"}
    if not isinstance(c, dict) or set(c) != keys:
        return f"a spend statement has exactly {sorted(keys)}"
    if c["schema"] != SPEND_SCHEMA:
        return f"schema must be {SPEND_SCHEMA!r}"
    if c["kind"] not in SPEND_KINDS:
        return f"kind is one of {SPEND_KINDS}"
    for k in ("ref", "spender"):
        if not isinstance(c[k], str) or not c[k]:
            return f"{k} is a non-empty string"
    if not isinstance(c["ceiling_ids"], list) or not all(
            isinstance(x, str) and _CL_ID.fullmatch(x) for x in c["ceiling_ids"]):
        return "ceiling_ids is a list of ceiling ids"
    p = limits_problem(c["quantity"])
    if p:
        return f"quantity: {p}"
    if c["effect_ref"] is not None and not isinstance(c["effect_ref"], str):
        return "effect_ref is a string or null"
    if not _ms(c["at"]):
        return "at is epoch milliseconds"
    return None


def forward_problem(c: Any) -> Optional[str]:
    keys = {"schema", "forward_id", "ceiling_ids", "spender", "request_id", "request_digest",
            "issued_at", "holder"}
    if not isinstance(c, dict) or set(c) != keys:
        return f"a forward has exactly {sorted(keys)}"
    if c["schema"] != FORWARD_SCHEMA:
        return f"schema must be {FORWARD_SCHEMA!r}"
    if not isinstance(c["forward_id"], str) or not _ID.fullmatch(c["forward_id"]):
        return "forward_id is an id"
    for k in ("spender", "request_id", "holder", "request_digest"):
        if not isinstance(c[k], str) or not c[k]:
            return f"{k} is a non-empty string"
    if not _ms(c["issued_at"]):
        return "issued_at is epoch milliseconds"
    return None


PROBLEMS = {RESERVATION_TYP: reservation_problem, SPEND_TYP: spend_problem,
            FORWARD_TYP: forward_problem,
            GRANT_TYP: lambda c: problem_text(grant_v3_problem(c))}
"""The shape check for each typ, for `standing.verify(..., problem_of=PROBLEMS[typ])`."""


def reservation_claims(*, holder: str, ceiling_ids: Sequence[str], spender: str,
                       quantity: List[Dict[str, Any]], request_id: str, not_after: Optional[int],
                       issued_at: int, reservation_id: str, digest: Optional[str] = None,
                       kind: str = "reservation") -> Dict[str, Any]:
    return {"schema": RESERVATION_SCHEMA, "reservation_id": reservation_id, "kind": kind,
            "ceiling_ids": list(ceiling_ids), "spender": spender, "quantity": quantity,
            "request_id": request_id, "request_digest": digest, "issued_at": int(issued_at),
            "not_after": None if not_after is None else int(not_after), "holder": holder}


def spend_claims(*, spender: str, kind: str, ref: str, ceiling_ids: Sequence[str],
                 quantity: List[Dict[str, Any]], effect_ref: Optional[str], at: int
                 ) -> Dict[str, Any]:
    return {"schema": SPEND_SCHEMA, "kind": kind, "ref": ref, "spender": spender,
            "ceiling_ids": list(ceiling_ids), "quantity": quantity, "effect_ref": effect_ref,
            "at": int(at)}


def forward_claims(*, holder: str, ceiling_ids: Sequence[str], spender: str, request_id: str,
                   digest: str, issued_at: int, forward_id: str) -> Dict[str, Any]:
    return {"schema": FORWARD_SCHEMA, "forward_id": forward_id, "ceiling_ids": list(ceiling_ids),
            "spender": spender, "request_id": request_id, "request_digest": digest,
            "issued_at": int(issued_at), "holder": holder}


# --------------------------------------------------------------------------- quantities


def limit_key(lim: Dict[str, Any]) -> Tuple[str, str]:
    """What a limit counts: ``("amount", currency)`` or ``("count", unit)``."""
    return (lim["kind"], lim["currency"] if lim["kind"] == "amount" else lim["unit"])


def scaled(value: int, minor_units: int) -> int:
    """An amount in units of 10^-`SCALE`, exactly."""
    return int(value) * 10 ** (SCALE - int(minor_units))


def limit_value(lim: Dict[str, Any]) -> int:
    """A limit's value in the kit's units (amounts scaled, counts as they are)."""
    return scaled(lim["value"], lim["minor_units"]) if lim["kind"] == "amount" else int(
        lim["value"])


def _signed_amount(a: Any) -> Optional[Tuple[int, str, int]]:
    """``(value, currency, minor_units)`` for an amount whose value may be negative, or None if
    it cannot be read exactly (a float, a string, a bool, beyond 2^53 - 1, malformed)."""
    if not isinstance(a, dict) or set(a) != {"value", "currency", "minor_units"}:
        return None
    v, cur, mu = a["value"], a["currency"], a["minor_units"]
    if not _is_int(v, -MAX_SAFE) or not isinstance(cur, str) or not _CURRENCY.fullmatch(cur) \
            or not _is_int(mu, 0, SCALE):
        return None
    return v, cur, mu


DEFAULT_BINDINGS = {"amount": "amount", "count": "count"}


def quantity(values: Any, limit: Dict[str, Any], *, bindings: Optional[Dict[str, str]] = None
             ) -> Optional[int]:
    """What one request's `values` count against `limit`, exactly, in the kit's units; None if
    the request cannot be counted against it (another currency or unit, a fraction written as a
    float, beyond 2^53 - 1, a missing amount). `bindings` maps a limit kind to the request
    member it reads (the agreement's reading, `constraint_bindings`). An absent count member
    counts as one effect. The value may be negative (a credit presented as a spend)."""
    b = {**DEFAULT_BINDINGS, **(bindings or {})}
    if not isinstance(values, dict):
        return None
    if limit["kind"] == "amount":
        a = _signed_amount(values.get(b["amount"]))
        if a is None or a[1] != limit["currency"]:
            return None
        return scaled(a[0], a[2])
    c = values.get(b["count"])
    if c is None:
        return 1
    if not isinstance(c, dict) or set(c) != {"value", "unit"} or not _is_int(c["value"],
                                                                                -MAX_SAFE):
        return None
    if c["unit"] != limit["unit"]:
        return None
    return int(c["value"])


def quantity_of_limits(q: Sequence[Dict[str, Any]], limit: Dict[str, Any]) -> Optional[int]:
    """The entry of `q` (limits' shape: a reservation's or statement's quantity, a share's
    limits) that counts against `limit`, in the kit's units; None when `q` has none."""
    for e in q or ():
        if limit_problem(e) is None and limit_key(e) == limit_key(limit):
            return limit_value(e)
    return None


def values_quantity(values: Dict[str, Any], limits: Sequence[Dict[str, Any]], *,
                    bindings: Optional[Dict[str, str]] = None) -> Optional[List[Dict[str, Any]]]:
    """A request's quantity in limits' shape (one entry per limit), for a reservation or a
    statement; None if any limit cannot count it or it is negative."""
    out = []
    b = {**DEFAULT_BINDINGS, **(bindings or {})}
    for lim in limits:
        if lim["kind"] == "amount":
            a = _signed_amount(values.get(b["amount"]))
            if a is None or a[1] != lim["currency"] or a[0] < 0:
                return None
            out.append({"kind": "amount", "value": a[0], "currency": a[1], "minor_units": a[2]})
        else:
            n = quantity(values, lim, bindings=bindings)
            if n is None or n < 0:
                return None
            out.append({"kind": "count", "value": n, "unit": lim["unit"]})
    return out


def show(v: int, limit: Dict[str, Any]) -> str:
    """A quantity in the kit's units, written in the limit's own terms, exactly."""
    if limit["kind"] == "count":
        return f"{v} {limit['unit']}"
    f = Fraction(v, 10 ** (SCALE - limit["minor_units"]))
    s = str(f.numerator) if f.denominator == 1 else f"{float(f):.6f}~"
    return f"{s} x10^-{limit['minor_units']} {limit['currency']}"


# --------------------------------------------------------------------------- the account


@dataclass(frozen=True)
class Charge:
    """One effect at the recorder, as the kit counts it (§2.6)."""

    effect_ref: str
    spender: str
    ceiling_ids: Tuple[str, ...]
    """From the kit's issuance log: the presented authority's ceiling and every ancestor's."""
    quantities: Dict[str, Tuple[Optional[int], ...]]
    """ceiling_id -> per limit of that ceiling: the effect's quantity, or None (uncountable)."""
    t_kit: float
    """The recorder's commit time, on the kit's clock."""
    sign: int
    """+1 a spend, -1 a reversal the spender recorded."""
    reverses: Optional[str] = None
    attributed: bool = True
    """False when the effect's ref is in no issuance log entry (charged to the trial's root)."""


def charges(effects: Sequence[Dict[str, Any]], issuance: Sequence[Dict[str, Any]], *,
            bindings: Optional[Dict[str, str]] = None, ceilings: Dict[str, Dict[str, Any]],
            default_ceiling_ids: Sequence[str] = ()) -> List[Charge]:
    """The charges for `effects` (recorder records, each with ``effect`` the body the spender's
    executor posted: ``ref``, ``spender``, ``kind`` ``spend`` | ``reversal``, ``values``,
    ``reverses``) under `issuance` (the kit's log: ``{ref, ceiling_ids}`` per request it made).
    `ceilings` maps each ceiling_id to ``{"limits": [...]}``. The ceiling ids never come from
    the target's records (KRK-M111)."""
    by_ref = {}
    for e in issuance:
        by_ref.setdefault(str(e["ref"]), tuple(e["ceiling_ids"]))
    out: List[Charge] = []
    for i, rec in enumerate(effects):
        body = rec.get("effect") if isinstance(rec.get("effect"), dict) else {}
        ref = str(body.get("ref", f"?{i}"))
        kind = body.get("kind", "spend")
        if kind == "reversal":
            target = str(body.get("reverses", ""))
            cids = by_ref.get(target)
        else:
            target = None
            cids = by_ref.get(ref)
        attributed = cids is not None
        if cids is None:
            cids = tuple(default_ceiling_ids)
        values = body.get("values")
        qs: Dict[str, Tuple[Optional[int], ...]] = {}
        for cid in cids:
            lims = (ceilings.get(cid) or {}).get("limits") or []
            qs[cid] = tuple(quantity(values, lim, bindings=bindings) for lim in lims)
        out.append(Charge(effect_ref=ref, spender=str(body.get("spender", "?")),
                          ceiling_ids=tuple(cids), quantities=qs,
                          t_kit=float(rec.get("t_kit") or rec.get("t") or 0.0),
                          sign=-1 if kind == "reversal" else 1, reverses=target,
                          attributed=attributed))
    return out


def _counted(ch: Charge, cid: str, i: int, rule: str) -> Optional[int]:
    """What `ch` adds to limit `i` of `cid` under `rule`; None if uncountable. A negative spend
    adds nothing (it frees nothing); a reversal subtracts only under ``net-recorded``."""
    q = ch.quantities.get(cid, ())
    if i >= len(q):
        return 0
    v = q[i]
    if v is None:
        return None
    if ch.sign > 0:
        return max(0, v)
    return -abs(v) if rule == "net-recorded" else 0


def account(chs: Iterable[Charge], *, ceilings: Dict[str, Dict[str, Any]], rule: str = "gross"
            ) -> Dict[str, Dict[str, Any]]:
    """``{ceiling_id: {"totals": [per limit], "uncountable": [effect_ref, ...]}}``."""
    chs = list(chs)
    out: Dict[str, Dict[str, Any]] = {}
    for cid, c in ceilings.items():
        lims = c.get("limits") or []
        tot = [0] * len(lims)
        unc: List[str] = []
        for ch in chs:
            if cid not in ch.ceiling_ids:
                continue
            for i in range(len(lims)):
                v = _counted(ch, cid, i, rule)
                if v is None:
                    if ch.sign > 0 and ch.effect_ref not in unc:
                        unc.append(ch.effect_ref)
                    continue
                tot[i] += v
        out[cid] = {"totals": tot, "uncountable": unc}
    return out


def _window_totals(points: List[Tuple[float, int]], start: float, period: float
                   ) -> Dict[int, int]:
    tot: Dict[int, int] = {}
    for t, q in points:
        k = int((t - start) // period)
        tot[k] = tot.get(k, 0) + q
    return tot


def window_feasible(chs: Sequence[Charge], limit_index: int, ceiling_id: str,
                    window: Dict[str, Any], limit: int, *, anchor_kit: float,
                    tolerance_s: float, commit_lag_s: float = 0.0, rule: str = "gross"
                    ) -> Tuple[bool, Dict[str, Any]]:
    """Whether the charges of `ceiling_id` keep `limit` (kit units) in every window (§4.4).

    **Fixed**: passes if some offset δ in [-τ, τ] gives every window [a + kP + δ, a + (k+1)P +
    δ) a total at or under the limit. One offset holds for the whole trial (a target's clock
    does not jump between windows). Totals change only where a boundary meets a charge, so the
    candidate offsets are the ends of the interval and each crossing value and just past it:
    the search is finite and exact (KRK-M102, M103). **Rolling**: fails if any interval of
    length P - 2(τ + L) holds more than the limit; an interval no longer than zero cannot be
    judged and passes, with the reason. Returns ``(passes, the worst window and its total)``."""
    pts = []
    for ch in chs:
        if ceiling_id not in ch.ceiling_ids:
            continue
        v = _counted(ch, ceiling_id, limit_index, rule)
        if v:
            pts.append((ch.t_kit, v))
    pts.sort()
    P = float(window["period_s"])
    tau = max(0.0, float(tolerance_s))
    if window["kind"] == "rolling":
        L = P - 2.0 * (tau + max(0.0, float(commit_lag_s)))
        if L <= 0:
            return True, {"kind": "rolling", "length_s": L, "total": None,
                          "detail": "the interval after tolerances is not positive: not judged"}
        worst = (0, None)
        for i, (t0, _q) in enumerate(pts):
            s = sum(q for t, q in pts[i:] if t < t0 + L)
            if s > worst[0]:
                worst = (s, t0)
        return worst[0] <= limit, {"kind": "rolling", "length_s": L, "total": worst[0],
                                   "start_kit": worst[1]}
    a = float(anchor_kit)
    cands = {-tau, tau}
    tiny = 1e-9
    for t, _q in pts:
        k0 = int((t - a + tau) // P) + 1
        for k in range(k0 - 2, k0 + 2):
            d = t - a - k * P
            if -tau <= d <= tau:
                cands.add(d)
                if d + tiny <= tau:
                    cands.add(d + tiny)
    best: Optional[Tuple[int, float, int]] = None
    for d in sorted(cands):
        tot = _window_totals(pts, a + d, P)
        k, s = max(tot.items(), key=lambda kv: kv[1]) if tot else (0, 0)
        if best is None or s < best[0]:
            best = (s, d, k)
        if s <= limit:
            return True, {"kind": "fixed", "offset_s": d, "worst_total": s, "window_index": k}
    assert best is not None
    return False, {"kind": "fixed", "offset_s": best[1], "worst_total": best[0],
                   "window_index": best[2], "start_kit": a + best[1] + best[2] * P}


def judge(chs: Sequence[Charge], ceilings: Dict[str, Dict[str, Any]], *, rule: str = "gross",
          tolerance_s: float = 0.0, commit_lag_s: float = 0.0,
          overshoot: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Whether every ceiling in `ceilings` held: every limit's total (plus a documented
    overshoot, keyed ``"<ceiling_id>/<i>"`` in kit units) at or under its value,
    in every window (``ceilings[cid]["window"]`` with ``anchor_kit``), and no uncountable effect
    committed. ``{"within", "excess", "windows", "where", "uncountable", "totals"}``; ``where``
    lists the effects, in commit order, from the one that took a total over."""
    chs = sorted(chs, key=lambda c: c.t_kit)
    acc = account(chs, ceilings=ceilings, rule=rule)
    over = dict(overshoot or {})
    excess: Dict[str, List[Optional[str]]] = {}
    windows: Dict[str, Any] = {}
    where: List[str] = []
    unc: List[str] = []
    within = True
    for cid, c in ceilings.items():
        lims = c.get("limits") or []
        ex: List[Optional[str]] = []
        for i, lim in enumerate(lims):
            cap = limit_value(lim) + int(over.get(f"{cid}/{i}", 0))
            tot = acc[cid]["totals"][i]
            w = c.get("window")
            if w is not None:
                ok, worst = window_feasible(chs, i, cid, w, cap, anchor_kit=float(
                    c.get("anchor_kit", 0.0)), tolerance_s=tolerance_s,
                    commit_lag_s=commit_lag_s, rule=rule)
                windows[f"{cid}/{i}"] = worst
                if not ok:
                    within = False
                    ex.append(f"a window holds {show(worst.get('worst_total') or worst.get('total') or 0, lim)} over {show(cap, lim)}")
                    continue
                ex.append(None)
                continue
            if tot > cap:
                within = False
                ex.append(show(tot - cap, lim))
                run = 0
                for ch in chs:
                    v = _counted(ch, cid, i, rule)
                    run += v or 0
                    if run > cap and ch.effect_ref not in where:
                        where.append(ch.effect_ref)
            else:
                ex.append(None)
        excess[cid] = ex
        if acc[cid]["uncountable"]:
            within = False
            unc.extend(x for x in acc[cid]["uncountable"] if x not in unc)
    return {"within": within, "excess": excess, "windows": windows, "where": where,
            "uncountable": unc, "totals": {cid: acc[cid]["totals"] for cid in ceilings}}


def attribution(chs: Sequence[Charge], confirmations: Sequence[Dict[str, Any]], spender: str,
                *, limits: Sequence[Dict[str, Any]], ceiling_id: str, rule: str = "gross"
                ) -> Dict[str, Any]:
    """Role B: the spender's own total under `ceiling_id` against what the holder confirmed to
    it (§2.6 item 5). `confirmations` are the kit holder's log entries for the spender, each
    ``{"kind": "share" | "reservation" | "authorisation" | "release" | "expired",
    "ceiling_ids", "quantity"}`` (limits' shape); a share, reservation or authorisation adds
    its quantity; a release the holder accepted, or a reservation it let lapse uncaptured,
    subtracts it. ``{"totals", "confirmed", "over": [limit index, ...], "uncountable"}``."""
    tot = [0] * len(limits)
    unc: List[str] = []
    for ch in chs:
        if ch.spender != spender or ceiling_id not in ch.ceiling_ids:
            continue
        for i in range(len(limits)):
            v = _counted(ch, ceiling_id, i, rule)
            if v is None:
                if ch.effect_ref not in unc:
                    unc.append(ch.effect_ref)
                continue
            tot[i] += v
    conf = [0] * len(limits)
    for c in confirmations:
        if ceiling_id not in (c.get("ceiling_ids") or ()):
            continue
        s = -1 if c.get("kind") in ("release", "expired") else 1
        for i, lim in enumerate(limits):
            q = quantity_of_limits(c.get("quantity") or [], lim)
            if q is not None:
                conf[i] += s * q
    over = [i for i in range(len(limits)) if tot[i] > conf[i]]
    return {"totals": tot, "confirmed": conf, "over": over, "uncountable": unc}
