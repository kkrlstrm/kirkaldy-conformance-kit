"""The translation profile and the faithful image, for KRK-26 (P26, the ceiling survives
translation).

`X11-TRANSLATION-DESIGN.md` §2. The kit's own statement of what a translated authority may admit,
written from the design's rules and checked against hand-written vectors
(`tests/vectors/krk26/vectors.json`). It imports nothing from the kit and no target or policy
library (spec §5.1 rule 7, KRK-M193): only the standard library. Arithmetic is
`fractions.Fraction` over integers. No floating point is used anywhere in this module.

**The profile** (`PROFILE_SCHEMA`) is declared by the target's side and pinned by `profile_digest`
before a run (KRK-M190). This module never supplies or completes one:

- ``fields``: target member -> the source member it carries.
- ``values``: source field -> {target value: [source values it can realise]}. Enumerated, never
  computed (Mih conformance draft §7.2). A target value absent from the map is unmapped.
- ``amounts``: currency pairs ``{source: {currency, minor_units}, target: {currency,
  minor_units}, rate: {num, den}}``; the rate is exact, target major units per source major unit
  (KRK-M206: the direction is a fact of the profile).
- ``counts``: unit pairs ``{source, target, rate}``, target units per source unit.
- ``time``: ``{target_unit: "s" | "ms", basis: "absolute"}``.
- ``unmapped``: ``"refuse"`` (the only value in version 1).

Minor units come from the profile and the original only, never from a currency table (KRK-M195).

**The original** is the claims of a ``kirkaldy.authority/0.1`` authority
(`translation_formats`): ``constraints`` (``max_amount``, ``min_amount``, ``max_count``,
``operations``, ``resources``, ``audience``, ``payee``, ``categories``, ``regions``,
``channels``), ``not_before`` (optional) and ``not_after`` in ``time_unit`` (``s`` or ``ms``),
and ``crit``. Every constraint member is critical (as grant 0.2).

**The translated form** is read as decoded members in the target's vocabulary, each with the
semantics the target documents (`semantics`: member -> ``{"semantics": "enforced" |
"informational" | "ignorable_extension", "absent": "unbounded" | "nothing"}``). Only an enforced
member constrains anything (KRK-M197, M203).

**Rounding** (§2.4) is toward the original's bound: a maximum is floored, a minimum ceiled, an
end floored to the target's resolution, a start ceiled. `back` never rounds: it states the widest
source set exactly.

- `image`: the widest translated members whose every admitted request, mapped back, lies inside
  the original; a `Refusal` when there is none.
- `back`: the widest set of source requests the translated members admit, exactly.
- `no_wider`: the dimensions where `back` exceeds the original.
- `effect_outside`: the dimensions where one committed effect, in target terms, lies outside the
  original read in its own terms (the probe's judgement of every effect; KRK-M200).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, FrozenSet, List, Optional, Sequence

PROFILE_SCHEMA = "kirkaldy.translation-profile/0.1"
TOPOLOGIES = ("T", "R", "TR")
SOURCE_MEMBERS = ("max_amount", "min_amount", "max_count", "operations", "resources", "audience",
                  "payee", "categories", "regions", "channels")
WINDOW_MEMBERS = ("not_before", "not_after")
CARRIABLE = SOURCE_MEMBERS + WINDOW_MEMBERS
SET_MEMBERS = ("operations", "audience", "categories", "regions", "channels")
AMOUNT_MEMBERS = ("max_amount", "min_amount")
TIME_UNITS = {"s": 1, "ms": 1000}
SEMANTICS = ("enforced", "informational", "ignorable_extension")
ABSENT = ("unbounded", "nothing")
MAX_MINOR_UNITS = 30

# Refusal reasons
UNDECLARED = "rate-undeclared"
INCOMPARABLE = "incomparable"
CANNOT_CARRY = "cannot-carry"
UNMAPPED = "unmapped-value"
UNIT_UNDECLARED = "unit-undeclared"
MALFORMED = "malformed"
AMBIGUOUS = "ambiguous-pair"

_CURRENCY = re.compile(r"[A-Z][A-Z0-9]{2,7}")
_DIGITS = re.compile(r"0|[1-9][0-9]*")


@dataclass(frozen=True)
class Refusal:
    """Why there is no faithful image: one of the reasons above, with words for the evidence."""

    reason: str
    detail: str = ""

    def __bool__(self) -> bool:          # a Refusal is never a translated form
        return False


# --------------------------------------------------------------------------- numbers


def _is_int(v: Any, lo: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo


def int_value(v: Any) -> Optional[int]:
    """An amount's value: a non-negative JSON integer or a string of decimal digits, else None."""
    if _is_int(v):
        return v
    if isinstance(v, str) and _DIGITS.fullmatch(v):
        return int(v)
    return None


def _rate(r: Any) -> Optional[Fraction]:
    if not isinstance(r, dict) or set(r) != {"num", "den"}:
        return None
    if not (_is_int(r["num"], 1) and _is_int(r["den"], 1)):
        return None
    return Fraction(r["num"], r["den"])


def amount_problem(a: Any) -> Optional[str]:
    if not isinstance(a, dict) or set(a) != {"value", "currency", "minor_units"}:
        return "an amount is {value, currency, minor_units}"
    if int_value(a["value"]) is None:
        return f"amount value {a['value']!r} is not a non-negative integer"
    if not isinstance(a["currency"], str) or not _CURRENCY.fullmatch(a["currency"]):
        return f"currency {a['currency']!r} is not a currency or asset code"
    if not _is_int(a["minor_units"]) or a["minor_units"] > MAX_MINOR_UNITS:
        return f"minor_units {a['minor_units']!r} is not an integer from 0 to {MAX_MINOR_UNITS}"
    return None


# --------------------------------------------------------------------------- the profile


def _jcs(obj: Any) -> bytes:
    """JCS (RFC 8785) for the values a profile may hold: objects, arrays, strings, integers within
    2^53 - 1, booleans, null. A float is refused, never serialised."""
    def check(x: Any) -> None:
        if isinstance(x, float):
            raise TypeError("a profile holds no floating-point number")
        if isinstance(x, int) and not isinstance(x, bool) and abs(x) > 2 ** 53 - 1:
            raise TypeError("integer beyond 2^53 - 1")
        if isinstance(x, dict):
            for k, v in x.items():
                if not isinstance(k, str):
                    raise TypeError("object keys are strings")
                check(v)
        elif isinstance(x, list):
            for v in x:
                check(v)
    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def profile_digest(p: Dict[str, Any]) -> str:
    """SHA-256 over the profile's JCS form (KRK-M190: the profile is pinned before the run)."""
    return "sha256:" + hashlib.sha256(_jcs(p)).hexdigest()


def profile_problem(p: Any) -> Optional[str]:
    """Why `p` is not a well-formed translation profile, or None."""
    if not isinstance(p, dict):
        return "a profile is an object"
    if p.get("schema") != PROFILE_SCHEMA:
        return f"schema is not {PROFILE_SCHEMA}"
    for k in ("source", "target"):
        if not isinstance(p.get(k), str) or not p[k]:
            return f"{k} names a format"
    fields = p.get("fields")
    if not isinstance(fields, dict) or not fields:
        return "fields maps each target member to a source member"
    for t, s in fields.items():
        if not isinstance(t, str) or s not in CARRIABLE:
            return f"field {t!r} -> {s!r}: the source member is not one the source format has"
    vals = p.get("values", {})
    if not isinstance(vals, dict):
        return "values is an object"
    for field, table in vals.items():
        if field not in SET_MEMBERS or not isinstance(table, dict):
            return f"values.{field} is not a value map of a set member"
        for tv, svs in table.items():
            if not isinstance(tv, str) or not isinstance(svs, list) or not svs or \
                    any(not isinstance(x, str) or not x for x in svs) or len(set(svs)) != len(svs):
                return f"values.{field}.{tv} is a non-empty list of distinct source values"
    for i, pair in enumerate(p.get("amounts", [])):
        if not isinstance(pair, dict) or _rate(pair.get("rate")) is None:
            return f"amounts[{i}] needs an exact rate {{num, den}} of positive integers"
        for side in ("source", "target"):
            s = pair.get(side)
            if not isinstance(s, dict) or not isinstance(s.get("currency"), str) or \
                    not _CURRENCY.fullmatch(s["currency"]) or not _is_int(s.get("minor_units")) \
                    or s["minor_units"] > MAX_MINOR_UNITS:
                return f"amounts[{i}].{side} is {{currency, minor_units}}"
    seen = set()
    for pair in p.get("amounts", []):
        key = (pair["source"]["currency"], pair["target"]["currency"])
        if key in seen:
            return f"the pair {key} is declared twice"
        seen.add(key)
    for i, pair in enumerate(p.get("counts", [])):
        if not isinstance(pair, dict) or _rate(pair.get("rate")) is None or \
                not isinstance(pair.get("source"), str) or not isinstance(pair.get("target"), str):
            return f"counts[{i}] is {{source, target, rate}}"
    t = p.get("time", {"target_unit": "s", "basis": "absolute"})
    if not isinstance(t, dict) or t.get("target_unit") not in TIME_UNITS or \
            t.get("basis") != "absolute":
        return "time is {target_unit: s | ms, basis: absolute}"
    if p.get("unmapped", "refuse") != "refuse":
        return "unmapped is \"refuse\" in version 1"
    return None


def semantics_problem(sem: Any, profile: Dict[str, Any]) -> Optional[str]:
    """Why the target's member semantics cannot be read (KRK-M197, M203): every member the kit's
    receiver reads needs a documented semantics and a documented meaning of absence."""
    if not isinstance(sem, dict) or not sem:
        return "the target states no member semantics"
    for m, d in sem.items():
        if not isinstance(d, dict) or d.get("semantics") not in SEMANTICS:
            return f"member {m!r} has no documented semantics"
        if d["semantics"] == "enforced" and d.get("absent") not in ABSENT:
            return f"member {m!r}: the target does not say what its absence means"
        if not d.get("quote"):
            return f"member {m!r}: the semantics is not quoted from the target"
    return None


def time_unit(profile: Dict[str, Any]) -> str:
    return (profile.get("time") or {}).get("target_unit", "s")


def pair_for(profile: Dict[str, Any], currency: str, target: Optional[str] = None
             ) -> Optional[Dict[str, Any]]:
    """The declared pair from `currency`, to `target` when given. None when there is none, or
    when there are several and no target is named."""
    hits = [p for p in profile.get("amounts", []) if p["source"]["currency"] == currency
            and (target is None or p["target"]["currency"] == target)]
    return hits[0] if len(hits) == 1 else None


def count_pair(profile: Dict[str, Any], unit: str, target: Optional[str] = None
               ) -> Optional[Dict[str, Any]]:
    hits = [p for p in profile.get("counts", []) if p["source"] == unit
            and (target is None or p["target"] == target)]
    return hits[0] if len(hits) == 1 else None


def realised(target_value: str, profile: Dict[str, Any], field: str) -> Optional[FrozenSet[str]]:
    """The source values a target value can realise, or None if it is unmapped. A set member
    without a value map is the identity."""
    table = (profile.get("values") or {}).get(field)
    if table is None:
        return frozenset([target_value])
    got = table.get(target_value)
    return frozenset(got) if got is not None else None


# --------------------------------------------------------------------------- conversion


def convert(amount: Dict[str, Any], pair: Optional[Dict[str, Any]], *, bound: str
            ) -> Any:
    """`amount` in the pair's target units, exactly, rounded toward the original's bound:
    ``bound="max"`` floors, ``"min"`` ceils. A `Refusal` when there is no pair, or the amount is
    not in the pair's source currency and minor units (never rescaled from a table, KRK-M195)."""
    if amount_problem(amount):
        return Refusal(MALFORMED, amount_problem(amount) or "")
    if pair is None:
        return Refusal(UNDECLARED, f"no declared rate from {amount['currency']}")
    src, tgt = pair["source"], pair["target"]
    if amount["currency"] != src["currency"] or amount["minor_units"] != src["minor_units"]:
        return Refusal(INCOMPARABLE, f"{amount['currency']}/{amount['minor_units']} is not the "
                                     f"pair's source {src['currency']}/{src['minor_units']}")
    exact = (Fraction(int_value(amount["value"])) * _rate(pair["rate"])
             * Fraction(10) ** (tgt["minor_units"] - src["minor_units"]))
    value = math.floor(exact) if bound == "max" else math.ceil(exact)
    return {"value": value, "currency": tgt["currency"], "minor_units": tgt["minor_units"]}


def back_value(amount: Dict[str, Any], pair: Dict[str, Any]) -> Fraction:
    """A target amount in the pair's source minor units, exactly (never rounded)."""
    src, tgt = pair["source"], pair["target"]
    return (Fraction(int_value(amount["value"])) / _rate(pair["rate"])
            * Fraction(10) ** (src["minor_units"] - tgt["minor_units"]))


def convert_back(amount: Dict[str, Any], pair: Dict[str, Any], *, bound: str) -> Dict[str, Any]:
    """A target amount in the pair's source currency, rounded toward the bound (the reverse leg
    of a round trip)."""
    v = back_value(amount, pair)
    return {"value": math.floor(v) if bound == "max" else math.ceil(v),
            "currency": pair["source"]["currency"],
            "minor_units": pair["source"]["minor_units"]}


def convert_time(n: int, src_unit: str, tgt_unit: str, *, bound: str) -> int:
    """A time in `src_unit` in `tgt_unit`: an end is floored, a start ceiled (KRK-M205)."""
    exact = Fraction(n) * TIME_UNITS[tgt_unit] / TIME_UNITS[src_unit]
    return math.floor(exact) if bound == "end" else math.ceil(exact)


def convert_count(c: Dict[str, Any], pair: Optional[Dict[str, Any]]) -> Any:
    if pair is None:
        return Refusal(UNIT_UNDECLARED, f"no declared relation from unit {c.get('unit')!r}")
    return {"value": math.floor(Fraction(c["value"]) * _rate(pair["rate"])),
            "unit": pair["target"]}


# --------------------------------------------------------------------------- image


def _targets_of(profile: Dict[str, Any], source_member: str) -> List[str]:
    return sorted(t for t, s in profile["fields"].items() if s == source_member)


def _enforced(sem: Dict[str, Any], member: str) -> bool:
    return (sem.get(member) or {}).get("semantics") == "enforced"


def covers(parent: str, child: str) -> bool:
    """Resource pattern `parent` covers `child` (an id or a prefix ending in ``/*``)."""
    if parent.endswith("/*"):
        stem = parent[:-1]
        return child.startswith(stem) and child != stem
    return parent == child


def image(original: Dict[str, Any], profile: Dict[str, Any], sem: Dict[str, Any], *,
          currency: Optional[str] = None, count_unit: Optional[str] = None) -> Any:
    """The widest faithful translated members of `original`, or a `Refusal`. `currency` and
    `count_unit` name the target currency and unit where the profile declares several pairs from
    the original's."""
    prob = profile_problem(profile)
    if prob:
        return Refusal(MALFORMED, f"profile: {prob}")
    c = original.get("constraints") or {}
    unknown = sorted(set(c) - set(SOURCE_MEMBERS))
    if unknown:
        return Refusal(CANNOT_CARRY, f"unknown constraint member(s) {unknown}")
    out: Dict[str, Any] = {}
    present = [m for m in SOURCE_MEMBERS if m in c] + \
        [m for m in WINDOW_MEMBERS if original.get(m) is not None]
    for m in present:
        carriers = [t for t in _targets_of(profile, m) if _enforced(sem, t)]
        if not carriers:
            return Refusal(CANNOT_CARRY, f"{m}: the target format has no enforced member for it")
    pair = None
    for m in AMOUNT_MEMBERS:
        if m not in c:
            continue
        a = c[m]
        if amount_problem(a):
            return Refusal(MALFORMED, f"{m}: {amount_problem(a)}")
        pair = pair_for(profile, a["currency"], currency)
        got = convert(a, pair, bound="max" if m == "max_amount" else "min")
        if isinstance(got, Refusal):
            return got
        for t in _targets_of(profile, m):
            if _enforced(sem, t):
                out[t] = got
    if "max_count" in c:
        got = convert_count(c["max_count"], count_pair(profile, c["max_count"].get("unit"),
                                                       count_unit))
        if isinstance(got, Refusal):
            return got
        for t in _targets_of(profile, "max_count"):
            if _enforced(sem, t):
                out[t] = got
    for m in SET_MEMBERS:
        if m not in c:
            continue
        allowed = set(c[m])
        table = (profile.get("values") or {}).get(m)
        if table is None:
            chosen = sorted(allowed)
        else:
            chosen = sorted(tv for tv, svs in table.items() if set(svs) <= allowed)
            covered = set().union(*[set(table[tv]) for tv in chosen]) if chosen else set()
            missing = sorted(allowed - covered)
            if missing:
                return Refusal(UNMAPPED, f"{m}: no target value realises {missing} within "
                                         f"the original")
        for t in _targets_of(profile, m):
            if _enforced(sem, t):
                out[t] = chosen
    for m in ("resources", "payee"):
        if m in c:
            for t in _targets_of(profile, m):
                if _enforced(sem, t):
                    out[t] = list(c[m]) if m == "resources" else c[m]
    src_unit = original.get("time_unit", "s")
    tu = time_unit(profile)
    for m, bound in (("not_after", "end"), ("not_before", "start")):
        if original.get(m) is not None:
            v = convert_time(original[m], src_unit, tu, bound=bound)
            for t in _targets_of(profile, m):
                if _enforced(sem, t):
                    out[t] = v
    return out


# --------------------------------------------------------------------------- back


def back(translated: Dict[str, Any], profile: Dict[str, Any], sem: Dict[str, Any], *,
         source_currency: Optional[str] = None, source_unit: Optional[str] = None,
         source_time_unit: str = "s") -> Dict[str, Any]:
    """The widest source set the translated members admit, exactly. Each dimension is
    ``None`` (unbounded), or its limit in source terms. An amount whose currency has no declared
    pair from `source_currency` is ``"incomparable"``, which is wider than any bound."""
    out: Dict[str, Any] = {}
    by_source: Dict[str, List[str]] = {}
    for t, s in profile["fields"].items():
        if _enforced(sem, t):
            by_source.setdefault(s, []).append(t)
    for s in CARRIABLE:
        vals = [translated[t] for t in by_source.get(s, []) if t in translated]
        absent_nothing = any((sem.get(t) or {}).get("absent") == "nothing"
                             for t in by_source.get(s, []) if t not in translated)
        if absent_nothing and not vals:
            out[s] = "nothing"
            continue
        if not vals:
            out[s] = None
            continue
        v = vals[0]
        if s in AMOUNT_MEMBERS:
            if amount_problem(v) or source_currency is None:
                out[s] = "incomparable"
                continue
            pair = pair_for(profile, source_currency, v["currency"])
            if pair is None or pair["target"]["minor_units"] != v["minor_units"]:
                out[s] = "incomparable"
            else:
                out[s] = back_value(v, pair)
        elif s == "max_count":
            pair = count_pair(profile, source_unit, v.get("unit")) if source_unit else None
            out[s] = "incomparable" if pair is None else Fraction(v["value"]) / _rate(pair["rate"])
        elif s in SET_MEMBERS:
            sets = [realised(x, profile, s) for x in v]
            out[s] = "incomparable" if any(x is None for x in sets) else \
                frozenset().union(*sets) if sets else frozenset()
        elif s in ("resources", "payee"):
            out[s] = v
        else:
            out[s] = Fraction(v) * TIME_UNITS[source_time_unit] / TIME_UNITS[time_unit(profile)]
    return out


def no_wider(translated: Dict[str, Any], original: Dict[str, Any], profile: Dict[str, Any],
             sem: Dict[str, Any]) -> List[str]:
    """The dimensions where the translated members admit more than the original."""
    c = original.get("constraints") or {}
    cur = next((c[m]["currency"] for m in AMOUNT_MEMBERS if m in c), None)
    unit = (c.get("max_count") or {}).get("unit")
    b = back(translated, profile, sem, source_currency=cur, source_unit=unit,
             source_time_unit=original.get("time_unit", "s"))
    wide: List[str] = []
    for m in SOURCE_MEMBERS:
        if m not in c:
            continue
        got = b.get(m)
        if got == "nothing":
            continue
        if got is None or got == "incomparable":
            wide.append(m)
        elif m == "max_amount" and got > int_value(c[m]["value"]):
            wide.append(m)
        elif m == "min_amount" and got < int_value(c[m]["value"]):
            wide.append(m)
        elif m == "max_count" and got > c[m]["value"]:
            wide.append(m)
        elif m in SET_MEMBERS and not got <= frozenset(c[m]):
            wide.append(m)
        elif m == "resources" and not all(any(covers_pattern(p, q) for p in c[m])
                                          for q in got):
            wide.append(m)
        elif m == "payee" and got != c[m]:
            wide.append(m)
    for m, cmp in (("not_after", lambda x, o: x > o), ("not_before", lambda x, o: x < o)):
        if original.get(m) is None:
            continue
        got = b.get(m)
        if got == "nothing":
            continue
        if got is None or cmp(got, original[m]):
            wide.append(m)
    return wide


def covers_pattern(parent: str, child: str) -> bool:
    """Pattern `parent` covers every id pattern `child` admits."""
    if not child.endswith("/*"):
        return covers(parent, child)
    if not parent.endswith("/*"):
        return False
    return child[:-1].startswith(parent[:-1])


# --------------------------------------------------------------------------- effects


def effect_outside(effect: Dict[str, Any], original: Dict[str, Any], profile: Dict[str, Any], *,
                   tolerance: int = 0) -> List[str]:
    """The dimensions where one committed effect, in target terms, lies outside the original,
    read in the original's own terms. The effect carries what the recorder stored with it
    (KRK-M200): ``operation`` (a target value), ``amount`` ``{value, currency, minor_units}``,
    ``count`` ``{value, unit}``, ``resource``, ``audience``, ``payee``, ``at`` (target time unit),
    ``category``, ``region``, ``channel``. Nothing is rounded. `tolerance` is the receiver's
    stated clock tolerance in the target's time unit: a time inside it is not outside."""
    c = original.get("constraints") or {}
    out: List[str] = []
    amt = effect.get("amount")
    for m in AMOUNT_MEMBERS:
        if m not in c:
            continue
        if amt is None:
            continue
        pair = pair_for(profile, c[m]["currency"], amt.get("currency"))
        if pair is None or amount_problem(amt) or \
                pair["source"]["minor_units"] != c[m]["minor_units"] or \
                pair["target"]["minor_units"] != amt["minor_units"]:
            if "currency" not in out:
                out.append("currency")
            continue
        v = back_value(amt, pair)
        bound = int_value(c[m]["value"])
        if (m == "max_amount" and v > bound) or (m == "min_amount" and v < bound):
            out.append(m)
    if "max_count" in c and effect.get("count") is not None:
        cnt = effect["count"]
        pair = count_pair(profile, c["max_count"].get("unit"), cnt.get("unit"))
        if pair is None or Fraction(cnt["value"]) / _rate(pair["rate"]) > c["max_count"]["value"]:
            out.append("max_count")
    if "operations" in c:
        r = realised(str(effect.get("operation")), profile, "operations")
        if r is None or not r <= frozenset(c["operations"]):
            out.append("operations")
    for m, k in (("audience", "audience"), ("categories", "category"), ("regions", "region"),
                 ("channels", "channel")):
        if m in c:
            r = realised(str(effect.get(k)), profile, m)
            if r is None or not r <= frozenset(c[m]):
                out.append(m)
    if "resources" in c:
        if not any(covers(p, str(effect.get("resource"))) for p in c["resources"]):
            out.append("resources")
    if "payee" in c and effect.get("payee") != c["payee"]:
        out.append("payee")
    at = effect.get("at")
    if at is not None:
        scale = Fraction(TIME_UNITS[original.get("time_unit", "s")], TIME_UNITS[time_unit(profile)])
        if original.get("not_after") is not None and \
                (Fraction(at) - tolerance) * scale > original["not_after"]:
            out.append("not_after")
        if original.get("not_before") is not None and \
                (Fraction(at) + tolerance) * scale < original["not_before"]:
            out.append("not_before")
    return out


def source_effect_outside(effect: Dict[str, Any], original: Dict[str, Any]) -> List[str]:
    """An effect committed in the source format's own terms (a round trip's O′ enacted by the
    kit's source receiver), against the original (KRK-M204: O′'s effect is compared with O, never
    with the intermediate form)."""
    c = original.get("constraints") or {}
    out: List[str] = []
    amt = effect.get("amount")
    if "max_amount" in c and amt is not None:
        if amt.get("currency") != c["max_amount"]["currency"] or \
                amt.get("minor_units") != c["max_amount"]["minor_units"]:
            out.append("currency")
        elif int_value(amt["value"]) > int_value(c["max_amount"]["value"]):
            out.append("max_amount")
    if "operations" in c and effect.get("operation") not in c["operations"]:
        out.append("operations")
    at = effect.get("at")
    if at is not None and original.get("not_after") is not None:
        if Fraction(at) * TIME_UNITS[original.get("time_unit", "s")] > original["not_after"]:
            out.append("not_after")
    return out


def exact_rational(x: Any) -> str:
    """A Fraction as ``n/d`` (or an int) for evidence; never a float."""
    if isinstance(x, Fraction):
        return str(x.numerator) if x.denominator == 1 else f"{x.numerator}/{x.denominator}"
    return str(x)


def dimension_words(dims: Sequence[str]) -> str:
    return ", ".join(dims) if dims else "none"
