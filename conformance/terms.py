"""Grant 0.4 and the term vocabulary for KRK-24 (P24, purpose and terms bound; design X2).

`X2-MANDATE-BOUND-DESIGN.md` §2.4 to §2.6. The kit's statement of what each term of a mandate
means, written from the design's table and checked against hand-written vectors
(`tests/vectors/krk24/`). It imports `attenuation` for amounts and patterns and nothing from any
target or policy library (spec §5.1 rule 7, KRK-M152). Toys call it as a correct B would; the
probe calls it to say what each fixture means.

**Grant 0.4** (`GRANT_V4_SCHEMA`, typ ``krk-grant+jws`` as 0.2): grant 0.2's members and one
more, ``terms`` (required, an object). Under 0.2's rules ``terms`` is an unknown claim, so a B
that reads only 0.2 refuses a 0.4 grant. `grant_v4_problem` checks the terms, then the rest under
`attenuation.grant_v2_problem` with the schema read as 0.2.

**The terms** (`TERM_KINDS`), each a member of ``terms``:

| Member | Shape | An effect meets it when |
|---|---|---|
| ``goal_id`` | ``"gl-"`` and 16 to 64 hex digits | identity only (read by ``serves``) |
| ``purpose`` | ``{code}`` | B's declared map has an entry for ``code`` exactly (no folding) whose ``operations`` hold the effect's operation and whose ``resources`` (if the entry states any) cover every resource it names |
| ``slots`` | ``[{slot, acceptable: [id, ...], quantity}, ...]`` | the effect's units, by B's item key, can be assigned so that each slot gets exactly ``quantity`` units of items in its ``acceptable`` list, every unit is assigned, and no unit counts twice (an integer flow equal to both totals) |
| ``fixed`` | ``{member: value, ...}`` | each named request member is present and its canonical JSON equals the value's, byte for byte |
| ``floor`` | ``{member: amount, ...}`` | the member is an amount in the same currency, not less after scaling both to the larger ``minor_units`` |
| ``serves`` | a goal id | on a linked authorisation: the grant that authorises the effect has this ``goal_id`` |
| ``confirm`` | ``{operations: [op, ...], by}`` | if the effect's operation is listed, a confirmation signed by the party ``by`` names binds the effect's request digest |
| ``text`` | a string | never consulted to allow anything |

**Empty means nothing**: an ``acceptable`` of ``[]`` admits no item. **Absent means no term of
that kind.** **Any other member**, at the top or inside one above, is unknown and is refused. **Sealed members**: a term member's value, an element of ``slots``, a slot's
``acceptable`` or one of its elements, and a value inside ``fixed`` or ``floor`` may be
``{"_sealed": d}``, where ``d`` is the unpadded base64url SHA-256 of the canonical JSON of
``[salt, value]``. A disclosure ``[salt, path, value]`` opens the sealed member at ``path``
(members and list indexes joined by ``/``, from the top of ``terms``). A sealed member without a
matching disclosure is a term B cannot read: never met.

Every comparison is in integers; nothing here uses floating point.
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import attenuation as att
from .receipts import canonical_json

GRANT_V4_SCHEMA = "kirkaldy.grant/0.4"
GRANT_TYP = att.GRANT_TYP
CONFIRMATION_SCHEMA = "kirkaldy.confirmation/0.1"
CONFIRMATION_TYP = "krk-confirmation+jws"
TERM_KINDS = ("goal_id", "purpose", "slots", "fixed", "floor", "serves", "confirm", "text")
PROFILE_KINDS = ("purpose", "slots", "fixed", "floor", "serves", "confirm", "sealed", "text")
"""What an adapter's `term_profile()` may list: the term kinds, and ``sealed`` (B reads the kit's
selective disclosure)."""
SLOT_MEMBERS = ("slot", "acceptable", "quantity")
CONFIRM_MEMBERS = ("operations", "by")
CONFIRMATION_CLAIMS = ("schema", "confirmation_id", "goal_id", "grant_id", "request_digest",
                       "issued_at", "not_after")
MAX_QUANTITY = 10_000
SEALED = "_sealed"

# Reasons. `meets` returns "<reason>: <detail>"; `reason_of` reads the reason back.
UNREADABLE = "unreadable"
"""A term B cannot read: unknown, malformed, sealed without its disclosure, or no declared
meaning."""
NOT_COVERED = "not-covered"
"""The purpose's declared coverage does not hold the operation or a resource."""
LESS = "less"
MORE = "more"
OTHER = "other"
UNCONFIRMED = "unconfirmed"
OTHER_GOAL = "other-goal"
REASONS = (UNREADABLE, NOT_COVERED, LESS, MORE, OTHER, UNCONFIRMED, OTHER_GOAL)
DIRECTION = {UNREADABLE: "unreadable", NOT_COVERED: "other", LESS: "less", MORE: "more",
             OTHER: "other", UNCONFIRMED: "unconfirmed", OTHER_GOAL: "other_goal"}
"""The direction a result reports for each reason (design §4.4)."""
UNKNOWN = "unknown-term"
MALFORMED = "malformed-term"
"""`terms_problem`'s reasons (shape)."""

_GOAL = re.compile(r"gl-[0-9a-f]{16,64}")
_CF_ID = re.compile(r"cf-[0-9a-f]{16,64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SEAL = re.compile(r"[A-Za-z0-9_-]{43}")


def new_goal_id() -> str:
    """A fresh goal id from the operating system, never from the seed (KRK-M36)."""
    import secrets
    return "gl-" + secrets.token_hex(8)


def reason_of(why: Optional[str]) -> Optional[str]:
    """The reason at the front of a `meets` answer, or None for None."""
    if why is None:
        return None
    head = why.split(":", 1)[0]
    return head if head in REASONS else UNREADABLE


def _why(reason: str, detail: str) -> str:
    return f"{reason}: {detail}"


# --------------------------------------------------------------------------- sealing


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def seal(value: Any, salt: str) -> Dict[str, str]:
    """The sealed form of `value` under `salt` (module docstring)."""
    if not isinstance(salt, str) or not salt:
        raise ValueError("a salt is a non-empty string")
    return {SEALED: _b64(hashlib.sha256(canonical_json([salt, value])).digest())}


def is_sealed(x: Any) -> bool:
    return isinstance(x, dict) and set(x) == {SEALED}


def sealed_paths(t: Any) -> List[str]:
    """Every path in `t` (a terms object) that holds a sealed member, in document order."""
    out: List[str] = []

    def walk(x: Any, path: str) -> None:
        if is_sealed(x):
            out.append(path)
            return
        if isinstance(x, dict):
            for k in sorted(x):
                walk(x[k], f"{path}/{k}" if path else str(k))
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}/{i}" if path else str(i))
    walk(t, "")
    return out


@dataclass(frozen=True)
class Unreadable:
    """What `open_sealed` returns when a sealed member has no matching disclosure."""

    paths: Tuple[str, ...]

    def __bool__(self) -> bool:
        return False


def open_sealed(t: Any, disclosures: Optional[Sequence[Any]]) -> Any:
    """`t` with every sealed member replaced by the value a disclosure opens it with, or an
    `Unreadable` naming the sealed members no disclosure opens. A disclosure that opens nothing
    is ignored; one whose value does not match the seal opens nothing."""
    by_path: Dict[str, List[Tuple[str, Any]]] = {}
    for d in disclosures or []:
        if isinstance(d, (list, tuple)) and len(d) == 3 and isinstance(d[0], str) \
                and isinstance(d[1], str):
            by_path.setdefault(d[1], []).append((d[0], d[2]))
    missing: List[str] = []

    def walk(x: Any, path: str) -> Any:
        if is_sealed(x):
            for salt, value in by_path.get(path, []):
                try:
                    if seal(value, salt) == x:
                        return value
                except (ValueError, TypeError):
                    continue
            missing.append(path)
            return x
        if isinstance(x, dict):
            return {k: walk(v, f"{path}/{k}" if path else str(k)) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v, f"{path}/{i}" if path else str(i)) for i, v in enumerate(x)]
        return x
    out = walk(t, "")
    return Unreadable(tuple(missing)) if missing else out


# --------------------------------------------------------------------------- shape


def _seal_ok(x: Any) -> bool:
    return is_sealed(x) and isinstance(x[SEALED], str) and bool(_SEAL.fullmatch(x[SEALED]))


def _int(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def terms_problem(t: Any, *, sealed_ok: bool = True) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `t` is not a well-formed ``terms`` object, else None. `UNKNOWN` for
    a member the vocabulary does not have, at any level; `MALFORMED` otherwise.
    With ``sealed_ok`` false (after `open_sealed`), a sealed member is malformed."""
    if not isinstance(t, dict):
        return MALFORMED, "terms is an object"
    extra = sorted(set(t) - set(TERM_KINDS))
    if extra:
        return UNKNOWN, f"unknown term(s) {extra}: refused"

    def sealed(x: Any, where: str) -> Optional[Tuple[str, str]]:
        if not is_sealed(x):
            return None
        if not sealed_ok:
            return MALFORMED, f"{where} is still sealed"
        return None if _seal_ok(x) else (MALFORMED, f"{where}: a seal is 43 base64url characters")

    for k, v in t.items():
        if v is None:
            return MALFORMED, f"terms.{k} is null"
        if is_sealed(v):
            if k == "goal_id":
                return MALFORMED, "goal_id is never sealed"
            p = sealed(v, f"terms.{k}")
            if p:
                return p
            continue
        if k in ("goal_id", "serves"):
            if not isinstance(v, str) or not _GOAL.fullmatch(v):
                return MALFORMED, f"terms.{k} is 'gl-' and 16 to 64 hex digits"
        elif k == "purpose":
            if not isinstance(v, dict):
                return MALFORMED, "terms.purpose is {code}"
            ex = sorted(set(v) - {"code"})
            if ex:
                return UNKNOWN, f"unknown member(s) {ex} in terms.purpose"
            if not isinstance(v.get("code"), str) or not v["code"]:
                return MALFORMED, "terms.purpose.code is a non-empty string"
        elif k == "slots":
            if not isinstance(v, list):
                return MALFORMED, "terms.slots is a list"
            names = []
            for i, s in enumerate(v):
                where = f"terms.slots[{i}]"
                if is_sealed(s):
                    p = sealed(s, where)
                    if p:
                        return p
                    continue
                if not isinstance(s, dict):
                    return MALFORMED, f"{where} is an object"
                ex = sorted(set(s) - set(SLOT_MEMBERS))
                if ex:
                    return UNKNOWN, f"unknown member(s) {ex} in {where}"
                miss = [m for m in SLOT_MEMBERS if m not in s]
                if miss:
                    return MALFORMED, f"{where} lacks {miss}"
                if not isinstance(s["slot"], str) or not s["slot"]:
                    return MALFORMED, f"{where}.slot is a non-empty string"
                names.append(s["slot"])
                if not _int(s["quantity"], 1, MAX_QUANTITY):
                    return MALFORMED, f"{where}.quantity is an integer from 1 to {MAX_QUANTITY}"
                acc = s["acceptable"]
                if is_sealed(acc):
                    p = sealed(acc, f"{where}.acceptable")
                    if p:
                        return p
                    continue
                if not isinstance(acc, list):
                    return MALFORMED, f"{where}.acceptable is a list"
                ids = []
                for j, a in enumerate(acc):
                    if is_sealed(a):
                        p = sealed(a, f"{where}.acceptable[{j}]")
                        if p:
                            return p
                        continue
                    if not isinstance(a, str) or not a:
                        return MALFORMED, f"{where}.acceptable lists non-empty strings"
                    ids.append(a)
                if len(set(ids)) != len(ids):
                    return MALFORMED, f"{where}.acceptable lists an item twice"
            if len(set(names)) != len(names):
                return MALFORMED, "terms.slots names a slot twice"
        elif k in ("fixed", "floor"):
            if not isinstance(v, dict) or not v:
                return MALFORMED, f"terms.{k} is a non-empty object"
            for m, x in v.items():
                if not isinstance(m, str) or not m:
                    return MALFORMED, f"terms.{k} names members by non-empty strings"
                if is_sealed(x):
                    p = sealed(x, f"terms.{k}.{m}")
                    if p:
                        return p
                    continue
                if x is None:
                    return MALFORMED, f"terms.{k}.{m} is null"
                if k == "floor":
                    prob = att.amount_problem(x)
                    if prob:
                        return MALFORMED, f"terms.floor.{m}: {prob}"
                else:
                    try:
                        canonical_json(x)
                    except (TypeError, ValueError) as e:
                        return MALFORMED, f"terms.fixed.{m} has no canonical form: {e}"
        elif k == "confirm":
            if not isinstance(v, dict):
                return MALFORMED, "terms.confirm is {operations, by}"
            ex = sorted(set(v) - set(CONFIRM_MEMBERS))
            if ex:
                return UNKNOWN, f"unknown member(s) {ex} in terms.confirm"
            ops = v.get("operations")
            if not isinstance(ops, list) or not ops or \
                    any(not isinstance(o, str) or not o for o in ops) or len(set(ops)) != len(ops):
                return MALFORMED, "terms.confirm.operations is a list of distinct operation names"
            if not isinstance(v.get("by"), str) or not v["by"]:
                return MALFORMED, "terms.confirm.by is 'principal' or a party id"
        elif k == "text":
            if not isinstance(v, str):
                return MALFORMED, "terms.text is a string"
    return None


def without_terms(claims: Dict[str, Any]) -> Dict[str, Any]:
    """A 0.4 grant read as 0.2 (`terms` left out, the schema 0.2's), for `attenuation`."""
    out = {k: v for k, v in claims.items() if k != "terms"}
    out["schema"] = att.GRANT_V2_SCHEMA
    return out


def grant_v4_problem(claims: Any) -> Optional[Tuple[str, str]]:
    """``(reason, detail)`` if `claims` are not a well-formed 0.4 grant, else None. Shape only:
    signatures are `standing.verify_holder_chain`'s."""
    if not isinstance(claims, dict):
        return att.MALFORMED, "claims are not a JSON object"
    if claims.get("schema") != GRANT_V4_SCHEMA:
        return att.MALFORMED, f"schema must be {GRANT_V4_SCHEMA!r}"
    if "terms" not in claims:
        return att.MALFORMED, "a 0.4 grant carries terms"
    p = terms_problem(claims["terms"])
    if p:
        return p
    return att.grant_v2_problem(without_terms(claims))


def confirmation_problem(c: Any) -> Optional[str]:
    """Why `c` is not a well-formed confirmation, or None."""
    if not isinstance(c, dict):
        return "a confirmation is a JSON object"
    if set(c) != set(CONFIRMATION_CLAIMS):
        return f"a confirmation has exactly {list(CONFIRMATION_CLAIMS)}"
    if c["schema"] != CONFIRMATION_SCHEMA:
        return f"schema must be {CONFIRMATION_SCHEMA!r}"
    if not isinstance(c["confirmation_id"], str) or not _CF_ID.fullmatch(c["confirmation_id"]):
        return "confirmation_id is 'cf-' and 16 to 64 hex digits"
    if not isinstance(c["goal_id"], str) or not _GOAL.fullmatch(c["goal_id"]):
        return "goal_id is a goal id"
    if not isinstance(c["grant_id"], str) or not c["grant_id"].startswith("gr-"):
        return "grant_id is a grant id"
    if not isinstance(c["request_digest"], str) or not _DIGEST.fullmatch(c["request_digest"]):
        return "request_digest is 'sha256:' and 64 hex digits"
    for k in ("issued_at", "not_after"):
        if not _int(c[k], 0, att.MAX_SAFE):
            return f"{k} is a time in milliseconds"
    if c["not_after"] <= c["issued_at"]:
        return "not_after is after issued_at"
    return None


# --------------------------------------------------------------------------- the terms


def purpose_covers(purpose_map: Optional[Mapping[str, Any]], code: Any, operation: Any,
                   resources: Any) -> bool:
    """Whether B's declared entry for `code` (exact key, no folding) holds `operation` and covers
    every one of `resources`. An entry that states no ``resources`` constrains none. No map, no
    entry, or a malformed entry: False (KRK-M150: the kit never supplies a meaning)."""
    if not isinstance(purpose_map, Mapping) or not isinstance(code, str) or code not in purpose_map:
        return False
    e = purpose_map[code]
    if not isinstance(e, Mapping) or not isinstance(e.get("operations"), list):
        return False
    if operation not in e["operations"]:
        return False
    if "resources" in e:
        pats = e["resources"]
        if not isinstance(pats, list):
            return False
        for r in (resources if isinstance(resources, list) else []):
            if not isinstance(r, str) or not any(isinstance(p, str) and att.covers(p, r)
                                                 for p in pats):
                return False
    return True


def units(items: Any, item_key: str = "id") -> Optional[Dict[str, int]]:
    """An action's items as ``{item: units}``, or None if they cannot be read: a list of objects
    each with the item key (a non-empty string) and a ``quantity`` from 1."""
    if not isinstance(items, list):
        return None
    out: Dict[str, int] = {}
    for it in items:
        if not isinstance(it, dict):
            return None
        k, q = it.get(item_key), it.get("quantity")
        if not isinstance(k, str) or not k or not _int(q, 1, MAX_QUANTITY):
            return None
        out[k] = out.get(k, 0) + q
    return out


def assignment(have: Dict[str, int], slots: Sequence[Dict[str, Any]]
               ) -> Tuple[int, Dict[Tuple[str, str], int]]:
    """A maximum assignment of `have`'s units to `slots` (each unit to one slot whose acceptable
    list holds it, each slot at most its quantity): ``(units assigned, {(item, slot): units})``.
    A small integer max flow (Edmonds-Karp) over source, items, slots, sink."""
    items = sorted(have)
    names = [s["slot"] for s in slots]
    n_i, n_s = len(items), len(names)
    S, T = 0, 1 + n_i + n_s
    N = T + 1
    cap = [[0] * N for _ in range(N)]
    for i, it in enumerate(items):
        cap[S][1 + i] = have[it]
        for j, s in enumerate(slots):
            if it in s["acceptable"]:
                cap[1 + i][1 + n_i + j] = have[it]
    for j, s in enumerate(slots):
        cap[1 + n_i + j][T] = s["quantity"]
    flow = [[0] * N for _ in range(N)]
    total = 0
    while True:
        prev = [-1] * N
        prev[S] = S
        q = deque([S])
        while q and prev[T] < 0:
            u = q.popleft()
            for v in range(N):
                if prev[v] < 0 and cap[u][v] - flow[u][v] > 0:
                    prev[v] = u
                    q.append(v)
        if prev[T] < 0:
            break
        b, v = None, T
        while v != S:
            u = prev[v]
            r = cap[u][v] - flow[u][v]
            b = r if b is None else min(b, r)
            v = u
        v = T
        while v != S:
            u = prev[v]
            flow[u][v] += b
            flow[v][u] -= b
            v = u
        total += b
    out = {}
    for i, it in enumerate(items):
        for j in range(n_s):
            f = flow[1 + i][1 + n_i + j]
            if f > 0:
                out[(it, names[j])] = f
    return total, out


def fill(items: Any, slots: Sequence[Dict[str, Any]], *, item_key: str = "id") -> Optional[str]:
    """None if `items` fill `slots` exactly (every slot its quantity, every unit assigned, no unit
    twice); else a reason: `LESS` (every unit assigned, some slot short), `MORE` (every slot
    filled, units left over), `OTHER` (otherwise: a substitution), `UNREADABLE` (the items cannot
    be read)."""
    have = units(items, item_key)
    if have is None:
        return _why(UNREADABLE, f"the action's items cannot be read by {item_key!r}")
    supply, demand = sum(have.values()), sum(s["quantity"] for s in slots)
    got, _ = assignment(have, slots)
    if got == supply == demand:
        return None
    if got == supply < demand:
        return _why(LESS, f"{demand - got} unit(s) of the goal are missing")
    if got == demand < supply:
        return _why(MORE, f"{supply - got} unit(s) beyond the goal")
    return _why(OTHER, f"{supply - got} unit(s) fill no slot and {demand - got} unit(s) of the "
                       f"goal are missing")


def clamp_items(items: Any, slots: Sequence[Dict[str, Any]], *, item_key: str = "id"
                ) -> Optional[List[Dict[str, Any]]]:
    """The part of `items` that fills `slots` exactly, where every slot can be filled from them
    (an action that does more than the goal), else None. Item order follows `items`."""
    have = units(items, item_key)
    if have is None:
        return None
    got, asg = assignment(have, slots)
    if got != sum(s["quantity"] for s in slots):
        return None
    used: Dict[str, int] = {}
    for (it, _s), n in asg.items():
        used[it] = used.get(it, 0) + n
    out = []
    for it in items:
        k = it[item_key]
        n = min(it["quantity"], used.get(k, 0))
        if n > 0:
            out.append({**it, "quantity": n})
            used[k] -= n
    return out


def _member(request: Dict[str, Any], m: str, bindings: Optional[Mapping[str, str]]) -> str:
    return (bindings or {}).get(m, m)


def fixed_ok(request: Any, fixed: Mapping[str, Any],
             bindings: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """None if every member `fixed` names is present in `request` with the same canonical JSON,
    byte for byte; else why. An amount that is lower or higher in the same currency reads
    `LESS` or `MORE`; anything else that differs, or is absent, reads `OTHER`."""
    if not isinstance(request, dict):
        return _why(UNREADABLE, "the action is not an object")
    for m, want in fixed.items():
        name = _member(request, m, bindings)
        if name not in request:
            return _why(OTHER, f"fixed member {m!r} ({name!r}) is absent from the action")
        got = request[name]
        try:
            same = canonical_json(got) == canonical_json(want)
        except (TypeError, ValueError):
            return _why(UNREADABLE, f"the action's {name!r} has no canonical form")
        if same:
            continue
        le, ge = att.amount_le(got, want), att.amount_le(want, got)
        if le is True and ge is True:
            return _why(OTHER, f"{name!r} is {got!r}: the same value as the fixed {want!r}, "
                               f"written differently, so not byte for byte")
        if le is True:
            return _why(LESS, f"{name!r} is {got!r}; the mandate fixes {want!r}")
        if le is False:
            return _why(MORE, f"{name!r} is {got!r}; the mandate fixes {want!r}")
        return _why(OTHER, f"{name!r} is {got!r}; the mandate fixes {want!r}")
    return None


def floor_ok(request: Any, floor: Mapping[str, Any],
             bindings: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """None if every member `floor` names is an amount in the floor's currency and not less;
    else why (`LESS`, or `UNREADABLE` where it cannot be compared exactly)."""
    if not isinstance(request, dict):
        return _why(UNREADABLE, "the action is not an object")
    for m, lo in floor.items():
        name = _member(request, m, bindings)
        got = request.get(name)
        le = att.amount_le(lo, got)
        if le is None:
            return _why(UNREADABLE, f"{name!r} ({got!r}) cannot be compared with the floor "
                                    f"{lo!r}")
        if not le:
            return _why(LESS, f"{name!r} is {got!r}, below the floor {lo!r}")
    return None


def goal_of(terms_chain: Sequence[Dict[str, Any]]) -> Optional[str]:
    """The goal of the grant that authorises the action: the presented grant's ``goal_id``, else
    the nearest parent's."""
    for t in terms_chain:
        if isinstance(t, dict) and isinstance(t.get("goal_id"), str):
            return t["goal_id"]
    return None


def meets(effect: Any, terms_chain: Sequence[Any], *,
          purpose_map: Optional[Mapping[str, Any]] = None,
          bindings: Optional[Mapping[str, str]] = None, item_key: str = "id",
          linked: Any = "_none", confirmation: Optional[Tuple[str, Dict[str, Any]]] = None,
          disclosures: Optional[Sequence[Any]] = None, request_digest: Optional[str] = None,
          grant_id: Optional[str] = None, requires: Iterable[str] = ()) -> Optional[str]:
    """Why `effect` (an action's values) does not meet every term of every hop in `terms_chain`
    (the presented grant's terms first), or None when it meets them all (design §2.3).

    - `purpose_map`: B's declared coverage (`purpose_covers`).
    - `bindings`: term member to request member, for ``fixed`` and ``floor``.
    - `linked`: the terms of a linked authorisation presented with the action (``"_none"`` when
      none was presented). Its ``serves`` must be the action's goal (`goal_of`).
    - `confirmation`: ``(party that signed it, its claims)``, signature already checked.
    - `disclosures`: what was presented to open sealed members.
    - `request_digest`, `grant_id`: the action's digest and the presented grant's id, which a
      confirmation must bind.
    - `requires`: term kinds B requires for this operation (``purpose``, ``serves``).
    """
    if not isinstance(effect, dict):
        return _why(UNREADABLE, "the action is not an object")
    op = effect.get("operation")
    opened: List[Dict[str, Any]] = []
    for i, t in enumerate(terms_chain):
        where = "the presented grant" if i == 0 else f"grant {i} above the presented one"
        o = open_sealed(t, disclosures)
        if isinstance(o, Unreadable):
            return _why(UNREADABLE, f"{where}: sealed term(s) {list(o.paths)} with no disclosure")
        p = terms_problem(o, sealed_ok=False)
        if p:
            return _why(UNREADABLE, f"{where}: {p[0]}: {p[1]}")
        opened.append(o)
    req = set(requires or ())
    if "purpose" in req and not any("purpose" in t for t in opened):
        return _why(NOT_COVERED, f"operation {op!r} requires a purpose and the mandate states none")
    for i, t in enumerate(opened):
        where = "the presented grant" if i == 0 else f"grant {i} above the presented one"
        if "purpose" in t:
            if purpose_map is None:
                return _why(UNREADABLE, f"{where}: B states no meaning for any purpose code")
            code = t["purpose"]["code"]
            if not purpose_covers(purpose_map, code, op, effect.get("resources")):
                return _why(NOT_COVERED, f"{where}: purpose {code!r} does not cover {op!r} on "
                                         f"{effect.get('resources')!r}")
        if "slots" in t:
            why = fill(effect.get("items"), t["slots"], item_key=item_key)
            if why:
                return f"{why} ({where})"
        if "fixed" in t:
            why = fixed_ok(effect, t["fixed"], bindings)
            if why:
                return f"{why} ({where})"
        if "floor" in t:
            why = floor_ok(effect, t["floor"], bindings)
            if why:
                return f"{why} ({where})"
        if "confirm" in t and op in t["confirm"]["operations"]:
            need = t["confirm"]["by"]
            if confirmation is None:
                return _why(UNCONFIRMED, f"{where}: {op!r} needs a confirmation by {need!r}")
            by, c = confirmation
            if by != need:
                return _why(UNCONFIRMED, f"{where}: confirmed by {by!r}, not {need!r}")
            if confirmation_problem(c) or c.get("request_digest") != request_digest or \
                    c.get("goal_id") != goal_of(opened) or \
                    (grant_id is not None and c.get("grant_id") != grant_id):
                return _why(UNCONFIRMED, f"{where}: the confirmation does not bind this action")
    goal = goal_of(opened)
    if linked != "_none":
        lt = linked if isinstance(linked, dict) else {}
        serves = lt.get("serves")
        if serves is None:
            if "serves" in req:
                return _why(OTHER_GOAL, "the linked authorisation names no goal")
        elif serves != goal:
            return _why(OTHER_GOAL, f"the linked authorisation serves {serves!r}; the action's "
                                    f"goal is {goal!r}")
    elif "serves" in req:
        return _why(OTHER_GOAL, f"operation {op!r} requires a linked authorisation for its goal")
    return None


@dataclass
class Goal:
    """A goal the stub principal approved: its id and its terms as approved (before sealing)."""

    goal_id: str
    terms: Dict[str, Any]
    disclosures: List[List[Any]] = field(default_factory=list)
