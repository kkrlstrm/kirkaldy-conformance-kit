"""Grant 0.2 and the constraint vocabulary for KRK-21 (P21, no widening), shared with KRK-20 (P20).

`X5-NO-WIDENING-DESIGN.md` §2. The kit's statement of what a delegation chain allows, written from
the design's table and checked against hand-written vectors (`tests/vectors/krk21/`). It imports
no target or policy library and shares no code with any target (spec §5.1 rule 7, KRK-M83). Toys
call it as a correct B would; the probe calls it to say what each fixture means (W outside the
intersection, its sibling L and W-in inside).

**Grant 0.2** (`GRANT_V2_SCHEMA`, typ ``krk-grant+jws`` as 0.1): ``grant_id``, ``issuer``,
``subject`` (the agent), ``agent_key`` (``{kid, public_key}``), ``principal`` (who authorised this
hop at the signer's organisation), ``constraints`` (below), ``parent`` (a grant id or null),
``issued_at`` (RFC 3339 UTC, milliseconds), ``not_before`` / ``not_after`` (RFC 3339 UTC, whole
seconds; both required, no default), ``status`` (``{source, index}``), and optionally ``audience``
(a single relying party, as 0.1 had; ``constraints.audience`` is the list form) and ``crit`` (a list
of ``constraints`` members the issuer marks critical; in the kit's format every member is critical
whether listed or not). A **holder-signed hop** has as ``issuer`` its parent's
``subject`` and is signed by the parent's ``agent_key`` (`standing.verify_holder_chain` checks
signatures; this module checks meaning). 0.1 is unchanged and P19 keeps reading it.

**The dimensions** (`DIMENSIONS`), each a member of ``constraints`` except the window:

| Member | A child is within its parent when | A request is inside when |
|---|---|---|
| ``max_amount`` ``{value, currency, minor_units}`` | same currency; value no greater, compared exactly after scaling both to the larger ``minor_units`` | same currency, an exact non-negative integer no greater after the same scaling |
| ``operations`` ``[name, ...]`` | a subset of the parent's | its operation is in the set |
| ``resources`` ``[pattern, ...]`` | each child pattern is covered by a parent pattern | every resource it names is covered |
| ``audience`` ``[party, ...]`` | a subset | B is in the set |
| window (``not_before`` / ``not_after``) | inside the parent's | the commit time is inside every window, with B's tolerance |
| ``delegation`` ``{max_depth}`` | at most the parent's less one; a parent with 0 admits no child | the hops below each grant are at most its ``max_depth`` |

A resource pattern is an exact id (no ``*``) or a prefix ending in ``/*`` with no other ``*``.
**Absent** adds no constraint (the intersection keeps the parent's). **Empty** (``[]``) allows
nothing. **``null``**, a ``"*"`` in ``operations`` or ``audience``, and any other pattern are
malformed. **Any other member** is an unknown constraint and is refused (critical).
Amounts that cannot be compared exactly (not an integer, a bool, negative, beyond 2^53 - 1, a
string, another currency) are refused.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

GRANT_V2_SCHEMA = "kirkaldy.grant/0.2"
GRANT_TYP = "krk-grant+jws"
DIMENSIONS = ("max_amount", "operations", "resources", "audience", "window", "delegation")
CONSTRAINT_MEMBERS = ("max_amount", "operations", "resources", "audience", "delegation")
GRANT_V2_CLAIMS = ("schema", "grant_id", "issuer", "subject", "agent_key", "principal",
                   "constraints", "parent", "issued_at", "not_before", "not_after", "status")
GRANT_V2_OPTIONAL = ("audience", "crit")
MAX_SAFE = 2 ** 53 - 1
MAX_MINOR_UNITS = 18

_GR_ID = re.compile(r"gr-[0-9a-f]{16,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC_S = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_UTC_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_CURRENCY = re.compile(r"[A-Z]{3}")

# Refusal reasons `allowed` and `constraints_problem` give, so a reading can say which.
MALFORMED = "malformed"
UNKNOWN = "unknown-constraint"
CYCLE = "cycle"
SELF_PARENT = "self-parent"
TWO_PARENTS = "two-parents"
NOT_ROOTED = "not-rooted"
DEPTH = "depth-exceeded"
WIDER = "wider-than-parent"
INCOMPARABLE = "incomparable"


@dataclass(frozen=True)
class Refusal:
    """Why a chain allows nothing: one of the reasons above, with words for the evidence."""

    reason: str
    detail: str = ""

    def __bool__(self) -> bool:      # a Refusal is never an allowed set
        return False


def _is_int(v: Any, lo: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= MAX_SAFE


# --------------------------------------------------------------------------- shape


def amount_problem(a: Any) -> Optional[str]:
    """Why `a` is not an amount ``{value, currency, minor_units}`` the kit can compare exactly."""
    if not isinstance(a, dict) or set(a) != {"value", "currency", "minor_units"}:
        return "an amount is {value, currency, minor_units}"
    if not _is_int(a["value"]):
        return f"amount value {a['value']!r} is not an integer from 0 to 2^53 - 1"
    if not isinstance(a["currency"], str) or not _CURRENCY.fullmatch(a["currency"]):
        return f"currency {a['currency']!r} is not an ISO 4217 code"
    if not _is_int(a["minor_units"]) or a["minor_units"] > MAX_MINOR_UNITS:
        return f"minor_units {a['minor_units']!r} is not an integer from 0 to {MAX_MINOR_UNITS}"
    return None


def pattern_problem(p: Any) -> Optional[str]:
    """An exact id (no ``*``), or a prefix ending in ``/*`` and no other ``*``."""
    if not isinstance(p, str) or not p:
        return "a resource pattern is a non-empty string"
    if "*" not in p:
        return None
    if p.endswith("/*") and "*" not in p[:-2] and len(p) > 2:
        return None
    return f"resource pattern {p!r} is neither an exact id nor a prefix ending in '/*'"


def constraints_problem(c: Any) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `c` is not a well-formed ``constraints`` object, else None. The
    reason is `UNKNOWN` for a member the vocabulary does not have (critical), else `MALFORMED`."""
    if not isinstance(c, dict):
        return MALFORMED, "constraints is an object"
    extra = sorted(set(c) - set(CONSTRAINT_MEMBERS))
    if extra:
        return UNKNOWN, f"unknown constraint member(s) {extra}: refused"
    for k, v in c.items():
        if v is None:
            return MALFORMED, f"constraints.{k} is null"
    if "max_amount" in c:
        p = amount_problem(c["max_amount"])
        if p:
            return MALFORMED, f"max_amount: {p}"
    for k in ("operations", "audience"):
        if k in c:
            v = c[k]
            if not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v):
                return MALFORMED, f"constraints.{k} is a list of non-empty strings"
            if "*" in v:
                return MALFORMED, f"constraints.{k} lists the wildcard '*'"
            if len(set(v)) != len(v):
                return MALFORMED, f"constraints.{k} lists a name twice"
    if "resources" in c:
        v = c["resources"]
        if not isinstance(v, list):
            return MALFORMED, "constraints.resources is a list of patterns"
        for p in v:
            prob = pattern_problem(p)
            if prob:
                return MALFORMED, prob
    if "delegation" in c:
        d = c["delegation"]
        if not isinstance(d, dict) or set(d) != {"max_depth"} or not _is_int(d["max_depth"]) \
                or d["max_depth"] > 64:
            return MALFORMED, "constraints.delegation is {max_depth: 0..64}"
    return None


def _epoch_s(s: Any) -> Optional[float]:
    from datetime import datetime, timezone
    if isinstance(s, str) and _UTC_S.fullmatch(s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    if isinstance(s, str) and _UTC_MS.fullmatch(s):
        base, frac = s[:-1].split(".")
        return datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc).timestamp() + int(frac) / 1000.0
    return None


def grant_v2_problem(claims: Any) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `claims` are not a well-formed 0.2 grant, else None. Shape only:
    signatures are `standing.verify_holder_chain`'s."""
    if not isinstance(claims, dict):
        return MALFORMED, "claims are not a JSON object"
    missing = [c for c in GRANT_V2_CLAIMS if c not in claims]
    if missing:
        return MALFORMED, f"missing claims: {', '.join(missing)} (the window has no default)"
    extra = sorted(set(claims) - set(GRANT_V2_CLAIMS) - set(GRANT_V2_OPTIONAL))
    if extra:
        return MALFORMED, f"unknown claims: {', '.join(extra)}"
    if claims["schema"] != GRANT_V2_SCHEMA:
        return MALFORMED, f"schema must be {GRANT_V2_SCHEMA!r}"
    if not isinstance(claims["grant_id"], str) or not _GR_ID.fullmatch(claims["grant_id"]):
        return MALFORMED, "grant_id must be 'gr-' and 16 to 64 hex digits"
    for c in ("issuer", "subject", "principal"):
        if not isinstance(claims[c], str) or not claims[c]:
            return MALFORMED, f"{c} must be a non-empty string"
    ak = claims["agent_key"]
    if (not isinstance(ak, dict) or set(ak) != {"kid", "public_key"}
            or not isinstance(ak["kid"], str) or not ak["kid"]
            or not isinstance(ak["public_key"], str) or not _HEX64.fullmatch(ak["public_key"])):
        return MALFORMED, "agent_key must be {kid, public_key: 64 hex}"
    par = claims["parent"]
    if isinstance(par, list):
        return TWO_PARENTS, "a grant names one parent; this names a list"
    if par is not None and (not isinstance(par, str) or not _GR_ID.fullmatch(par)):
        return MALFORMED, "parent must be a grant id or null"
    if not isinstance(claims["issued_at"], str) or not _UTC_MS.fullmatch(claims["issued_at"]):
        return MALFORMED, "issued_at must be RFC 3339 UTC with milliseconds"
    nb, na = _epoch_s(claims["not_before"]), _epoch_s(claims["not_after"])
    if nb is None or na is None or not _UTC_S.fullmatch(str(claims["not_before"])) \
            or not _UTC_S.fullmatch(str(claims["not_after"])):
        return MALFORMED, "not_before and not_after must be RFC 3339 UTC, whole seconds"
    if na <= nb:
        return MALFORMED, "not_after must be later than not_before"
    st = claims["status"]
    if (not isinstance(st, dict) or set(st) != {"source", "index"}
            or not isinstance(st["source"], str) or not st["source"] or not _is_int(st["index"])):
        return MALFORMED, "status must be {source, index}"
    if "audience" in claims and (not isinstance(claims["audience"], str) or not claims["audience"]):
        return MALFORMED, "audience, when present, is one relying party"
    if "crit" in claims:
        cr = claims["crit"]
        if not isinstance(cr, list) or any(not isinstance(x, str) for x in cr):
            return MALFORMED, "crit is a list of constraint member names"
        unknown = sorted(set(cr) - set(CONSTRAINT_MEMBERS))
        if unknown:
            return UNKNOWN, f"crit names member(s) the vocabulary does not have: {unknown}"
    return constraints_problem(claims["constraints"])


# --------------------------------------------------------------------------- comparisons


def normalise_amount(a: Any) -> Optional[Tuple[int, str, int]]:
    """``(value, currency, minor_units)``, exact, or None if `a` cannot be compared exactly."""
    if amount_problem(a):
        return None
    return a["value"], a["currency"], a["minor_units"]


def amount_le(a: Any, b: Any) -> Optional[bool]:
    """Whether amount `a` is no greater than amount `b`, exactly; None if they cannot be compared
    (either malformed, or another currency: no conversion in version 1)."""
    na, nb = normalise_amount(a), normalise_amount(b)
    if na is None or nb is None or na[1] != nb[1]:
        return None
    m = max(na[2], nb[2])
    return na[0] * 10 ** (m - na[2]) <= nb[0] * 10 ** (m - nb[2])


def covers(parent_pattern: str, child_pattern: str) -> bool:
    """Whether every resource `child_pattern` names is named by `parent_pattern`. An exact id
    covers only itself; ``x/*`` covers ``x/...`` exactly and every prefix ``x/.../*`` under it.
    A malformed pattern covers nothing and is covered by nothing."""
    if pattern_problem(parent_pattern) or pattern_problem(child_pattern):
        return False
    if not parent_pattern.endswith("/*"):
        return child_pattern == parent_pattern
    base = parent_pattern[:-1]                          # "x/"
    if child_pattern.endswith("/*"):
        return child_pattern[:-1].startswith(base)
    return child_pattern.startswith(base) and len(child_pattern) > len(base)


def _window(g: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    return _epoch_s(g.get("not_before")), _epoch_s(g.get("not_after"))


def wider(child: Dict[str, Any], parent: Dict[str, Any]) -> List[str]:
    """The dimensions in which `child`'s own constraints exceed `parent`'s (an absent member adds
    no constraint, so it is never wider: the intersection keeps the parent's). Incomparable
    amounts read as wider: B cannot show they are within."""
    out: List[str] = []
    cc, pc = child.get("constraints") or {}, parent.get("constraints") or {}
    if "max_amount" in pc and "max_amount" in cc:
        le = amount_le(cc["max_amount"], pc["max_amount"])
        if le is not True:
            out.append("max_amount")
    for k in ("operations", "audience"):
        if k in pc and k in cc and not set(cc[k]) <= set(pc[k]):
            out.append(k)
    if "resources" in pc and "resources" in cc:
        if any(not any(covers(pp, cp) for pp in pc["resources"]) for cp in cc["resources"]):
            out.append("resources")
    cnb, cna = _window(child)
    pnb, pna = _window(parent)
    if cnb is None or cna is None or pnb is None or pna is None or cnb < pnb or cna > pna:
        out.append("window")
    if "delegation" in pc:
        pd = pc["delegation"]["max_depth"] if isinstance(pc["delegation"], dict) else None
        cd = (cc.get("delegation") or {}).get("max_depth") if isinstance(cc.get("delegation"),
                                                                          dict) else None
        if not isinstance(pd, int) or pd <= 0 or (isinstance(cd, int) and cd > pd - 1):
            out.append("delegation")
    return out


# --------------------------------------------------------------------------- a chain


@dataclass
class Allowed:
    """What a chain allows: the conjunction of every grant's own constraints and window (the
    presented grant first), and the root principal's standing limit for each operation where
    one was given. `inside` reads a request against every part."""

    chain: List[Dict[str, Any]]
    standing: Optional[Dict[str, Any]] = None
    hops_wider: List[Tuple[int, List[str]]] = field(default_factory=list)
    """(index of the child, dimensions) for each hop wider than its parent: a B that refuses
    such chains whole (``chain_refused``) refuses here; a B that enforces the intersection
    (``clamped``) need not."""


def allowed(chain: Sequence[Dict[str, Any]], standing: Optional[Dict[str, Any]] = None
            ) -> Any:
    """The intersection over `chain` (claims, the presented grant first, then each parent), or a
    `Refusal` when there is none: a malformed or unknown member, a cycle, a self-parent, two
    parents, a chain that does not end at a root, or a depth some grant does not permit.
    `standing` is a standing assertion's ``classes`` (``{operation: limit or None}``); a limit
    is ``constraints`` in this vocabulary (``max_amount``, ``resources``)."""
    chain = list(chain)
    if not chain:
        return Refusal(MALFORMED, "no grant was presented")
    seen: Dict[str, int] = {}
    for i, g in enumerate(chain):
        p = grant_v2_problem(g)
        if p:
            return Refusal(p[0], f"grant {i}: {p[1]}")
        gid = g["grant_id"]
        if g["parent"] == gid:
            return Refusal(SELF_PARENT, f"grant {gid} names itself as its parent")
        if gid in seen:
            return Refusal(CYCLE, f"grant {gid} appears twice in the chain")
        seen[gid] = i
        if i + 1 < len(chain) and g["parent"] != chain[i + 1]["grant_id"]:
            return Refusal(NOT_ROOTED, f"grant {gid} names parent {g['parent']}, not "
                                       f"{chain[i + 1]['grant_id']}")
    if chain[-1]["parent"] is not None:
        return Refusal(NOT_ROOTED, f"the chain ends at {chain[-1]['grant_id']}, which names "
                                   f"parent {chain[-1]['parent']}")
    for i, g in enumerate(chain):
        d = (g["constraints"] or {}).get("delegation")
        if d is not None and i > d["max_depth"]:
            return Refusal(DEPTH, f"grant {g['grant_id']} permits {d['max_depth']} hop(s) "
                                  f"below it; the chain has {i}")
    if standing is not None:
        if not isinstance(standing, dict):
            return Refusal(MALFORMED, "standing classes are an object")
        for op, lim in standing.items():
            if lim is not None:
                p = constraints_problem(lim)
                if p:
                    return Refusal(p[0], f"standing limit for {op}: {p[1]}")
    hops = []
    for i in range(len(chain) - 1):
        w = wider(chain[i], chain[i + 1])
        if w:
            hops.append((i, w))
    return Allowed(chain, dict(standing) if standing is not None else None, hops)


def _inside_one(request: Dict[str, Any], c: Dict[str, Any], bindings: Dict[str, str],
                *, party: Optional[str], where: str) -> Optional[str]:
    if "operations" in c:
        op = request.get(bindings.get("operations", "operation"))
        if op not in c["operations"]:
            return f"{where}: operation {op!r} is not in {c['operations']}"
    if "resources" in c:
        rs = request.get(bindings.get("resources", "resources"))
        if not isinstance(rs, list) or not rs:
            return f"{where}: the request names no resources"
        for r in rs:
            if not isinstance(r, str) or "*" in r:
                return f"{where}: resource {r!r} is not an exact id"
            if not any(covers(p, r) for p in c["resources"]):
                return f"{where}: resource {r!r} is not covered by {c['resources']}"
    if "max_amount" in c:
        amt = request.get(bindings.get("max_amount", "amount"))
        if normalise_amount(amt) is None:
            return f"{where}: the request amount {amt!r} cannot be compared exactly"
        le = amount_le(amt, c["max_amount"])
        if le is None:
            return f"{where}: the request amount {amt!r} is in another currency than " \
                   f"{c['max_amount']}"
        if not le:
            return f"{where}: the request amount {amt!r} is above {c['max_amount']}"
    if "audience" in c and party is not None and party not in c["audience"]:
        return f"{where}: {party} is not in the audience {c['audience']}"
    return None


def inside(request: Dict[str, Any], a: Any, *, bindings: Optional[Dict[str, str]] = None,
           at: Optional[float] = None, tolerance_s: float = 0.0,
           party: Optional[str] = None) -> Optional[str]:
    """Why `request` (its values) lies outside `a` (an `Allowed`), or None when inside every
    grant, every window at wall time `at` (with `tolerance_s` either side), and the root's
    standing limit for its operation. A `Refusal` is outside everything."""
    if isinstance(a, Refusal):
        return f"no intersection: {a.reason}: {a.detail}"
    b = dict(bindings or {})
    for i, g in enumerate(a.chain):
        where = f"grant {i} ({g['grant_id']})"
        why = _inside_one(request, g["constraints"] or {}, b, party=party, where=where)
        if why:
            return why
        if at is not None:
            nb, na = _window(g)
            if nb is None or na is None or at < nb - tolerance_s or at > na + tolerance_s:
                return f"{where}: {at:.0f} is outside its window"
        if g.get("audience") is not None and party is not None and g["audience"] != party:
            return f"{where}: addressed to {g['audience']}, not {party}"
    if a.standing is not None:
        op = request.get(b.get("operations", "operation"))
        if op not in a.standing:
            return f"the root principal's standing does not cover {op!r}"
        lim = a.standing[op]
        if lim:
            why = _inside_one(request, lim, b, party=party, where="the root's standing")
            if why:
                return why
    return None
