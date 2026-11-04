"""The class vocabulary for KRK-23 (P23): claims, the class of one request, the ceiling, the
window, and the judge of restoration (`X10-REVERSIBILITY-DESIGN.md` §2.2, §2.5, §6.2).

This module imports no target code and no policy library (KRK-M83's rule, spec §5.1 rule 7). Its
expected answers are pinned by hand-written vectors in ``tests/vectors/krk23/``.

**A claim** is B's statement about one operation, in the kit's terms, read before the run with
its source and a quote (KRK-M122):

```json
{"operation": "crm.contact.create", "class": "reversible",
 "means": {"operation": "krk.reverse", "by": ["requester", "operator"]},
 "window": {"seconds": 600, "until": []}, "completion_bound_s": 10,
 "restores": ["object", "fields", "links"], "residues": [{"kind": "history_entry"}],
 "counter_effect": null, "conditions": [], "source": "documented", "quote": "...", "url": "..."}
```

**Classes**, ordered for the ceiling: ``reversible`` < ``compensable`` < ``irreversible``. An
operation with no claim, or with a malformed claim, is ``irreversible`` (§2.2).

**Aspects** a claim may restore, each read at the world: ``object`` (exists, not deleted),
``fields``, ``links`` (live edges to and from the object), ``balance`` (the balances of the
accounts the action moved; under ``reversible`` the ledger entries too, KRK-M118), ``delivery``
(a message not recalled, an item not retracted) and ``history`` (read from the world's history,
never from the current state, KRK-M126). An aspect not listed is not judged.

**Residues** a claim may declare: ``history_entry``, ``notice`` (mail to a named party), ``fee``
(a transfer of at most ``max_amount`` to a named account), ``copy_at_subscriber`` and
``read_receipt``. A residue matches only if it is of a declared kind, to a declared party (where
the residue names one), within its limits. The reader adds no residue of its own (KRK-M125).

**Authorisation 0.2** (`AUTHZ_V2_SCHEMA`): X3's 0.1 claims (`authz.REQUIRED_CLAIMS`) with the
schema changed, plus ``max_class`` (required), ``agent`` (``{"id", "grants"}``: the operations A
granted the agent, as A signs them) and ``reverses`` (``{"authorisation_id", "request_digest"}``
of the original, or null). Built here, in a new module, so X3's format code is unchanged.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import authz, receipts
from .receipts import Keypair, Verified

CLASSES = ("reversible", "compensable", "irreversible")
ASPECTS = ("object", "fields", "links", "balance", "delivery", "history")
RESIDUES = ("history_entry", "notice", "fee", "copy_at_subscriber", "read_receipt")
UNTIL = ("message_read", "fanout_delivered", "funds_moved")
MODES = ("immediate", "deferred", "compensating", "conservative")
COUNTER_EFFECTS = ("transfer", "retract", "recall", "void", "restore")
AUTHZ_V2_SCHEMA = "kirkaldy.request-authorisation/0.2"
PREDICATES = ("equals", "in", "domain_in", "domain_not_in")
HOLDINGS = ("copy_at_subscriber", "read_receipt", "funds_moved")
"""Kinds of downstream holding the kit reads at a party D after a reversal."""


# --------------------------------------------------------------------------- claims


def claim_problem(claim: Any) -> Optional[str]:
    """Why `claim` is not a well-formed claim, or None. Shape only (§2.2)."""
    if not isinstance(claim, dict):
        return "a claim is a JSON object"
    op = claim.get("operation")
    if not isinstance(op, str) or not op:
        return "operation must be a non-empty string"
    cls = claim.get("class")
    if cls not in CLASSES:
        return f"unknown class {cls!r}"
    for c in claim.get("conditions") or []:
        if not isinstance(c, dict) or c.get("class") not in CLASSES:
            return "each condition names a class"
        w = c.get("when")
        if not isinstance(w, dict) or not isinstance(w.get("member"), str):
            return "each condition's when names a request member"
        preds = [p for p in PREDICATES if p in w]
        if len(preds) != 1 or set(w) - {"member", *PREDICATES}:
            return f"each condition has exactly one predicate of {PREDICATES}"
    if cls == "irreversible":
        return None
    means = claim.get("means")
    if not isinstance(means, dict) or not isinstance(means.get("operation"), str) \
            or not means["operation"]:
        return "a reversible or compensable claim names its means (means.operation)"
    win = claim.get("window")
    if not isinstance(win, dict):
        return "a reversible or compensable claim states a window"
    secs, until = win.get("seconds"), list(win.get("until") or [])
    unbounded = win.get("unbounded") is True
    if secs is not None and (isinstance(secs, bool) or not isinstance(secs, (int, float))
                             or secs <= 0):
        return "window.seconds must be a positive number or null"
    if any(u not in UNTIL for u in until):
        return f"window.until may name only {UNTIL}"
    if secs is None and not until and not unbounded:
        return "a window with neither seconds nor until is malformed (§2.2)"
    if unbounded and secs is not None:
        return "an unbounded window has no seconds"
    r = claim.get("completion_bound_s")
    if r is not None and (isinstance(r, bool) or not isinstance(r, (int, float)) or r <= 0):
        return "completion_bound_s must be a positive number or null"
    restores = claim.get("restores")
    if not isinstance(restores, list) or not restores or any(a not in ASPECTS for a in restores):
        return f"restores must be a non-empty list of {ASPECTS}"
    residues = claim.get("residues") or []
    if not isinstance(residues, list) or any(not isinstance(x, dict) or x.get("kind")
                                             not in RESIDUES for x in residues):
        return f"residues must be a list of objects whose kind is one of {RESIDUES}"
    if "history" in restores and any(x["kind"] == "history_entry" for x in residues):
        return "a claim cannot restore history and declare a history entry as a residue"
    ce = claim.get("counter_effect")
    if cls == "compensable":
        if not isinstance(ce, dict) or ce.get("kind") not in COUNTER_EFFECTS:
            return f"a compensable claim declares its counter_effect, one of {COUNTER_EFFECTS}"
    elif ce is not None:
        return "a reversible claim has no counter_effect"
    return None


def claim_for(claims: Iterable[Dict[str, Any]], operation: str) -> Optional[Dict[str, Any]]:
    """B's claim for `operation`, or None when B declares nothing for it."""
    for c in claims or []:
        if isinstance(c, dict) and c.get("operation") == operation:
            return c
    return None


def _domain(v: Any) -> str:
    s = str(v)
    return s.rsplit("@", 1)[-1].lower() if "@" in s else s.lower()


def condition_holds(when: Dict[str, Any], request: Dict[str, Any]) -> bool:
    """Whether one condition's predicate holds for the request the kit sent."""
    v = request.get(when["member"])
    vs = v if isinstance(v, list) else [v]
    if "equals" in when:
        return v == when["equals"]
    if "in" in when:
        return v in list(when["in"])
    if "domain_in" in when:
        return any(_domain(x) in [d.lower() for d in when["domain_in"]] for x in vs)
    if "domain_not_in" in when:
        return any(_domain(x) not in [d.lower() for d in when["domain_not_in"]] for x in vs)
    return False


def class_for(claims: Iterable[Dict[str, Any]], operation: str, request: Dict[str, Any]) -> str:
    """The class of this request: B's claim for the operation, its conditions evaluated by the
    kit from the request it sent (§2.2). An absent or malformed claim reads ``irreversible``. A
    class stated in the request itself is never read (decision 3)."""
    c = claim_for(claims, operation)
    if c is None or claim_problem(c):
        return "irreversible"
    for cond in c.get("conditions") or []:
        if condition_holds(cond["when"], request):
            return cond["class"]
    return c["class"]


def class_le(a: str, b: str) -> bool:
    """`a` is admitted under a ceiling of `b`. An unknown class is above every ceiling."""
    if a not in CLASSES or b not in CLASSES:
        return False
    return CLASSES.index(a) <= CLASSES.index(b)


def window_open(claim: Dict[str, Any], *, t_e: float, t_q: float,
                events: Iterable[Dict[str, Any]] = (), tol_s: float = 0.0,
                eps_s: float = 0.05) -> str:
    """Where a reversal sent at `t_q` falls against the claim's window, which starts at `t_e`,
    the world's commit of the action (KRK-M119): ``condition_held`` if a world event the claim
    names in ``until`` was committed at or before `t_q`; else ``inside`` (at most
    ``W - 2ε - tol`` after `t_e`), ``outside`` (at least ``W + 2ε + tol``) or ``crossing``.
    An unbounded window is always ``inside`` (tested to H)."""
    win = claim.get("window") or {}
    until = set(win.get("until") or [])
    for e in events or []:
        if e.get("event") in until and e.get("t") is not None and e["t"] <= t_q:
            return "condition_held"
    secs = win.get("seconds")
    if secs is None:
        return "inside"
    margin = 2 * eps_s + tol_s
    dt = t_q - t_e
    if dt <= secs - margin:
        return "inside"
    if dt >= secs + margin:
        return "outside"
    return "crossing"


def mapped(claim: Dict[str, Any], *, quote: Optional[str], mapping: str) -> Dict[str, Any]:
    """A claim the adapter mapped from B's own vocabulary before the run, with the quote that
    justifies the mapping recorded beside it (KRK-M122)."""
    return {**claim, "mapping": mapping, "quote": quote, "source": claim.get("source") or
            "documented"}


# --------------------------------------------------------------------------- authorisation 0.2


def authorise_v2_claims(*, issuer: str, audience: Dict[str, Any], operation: str,
                        request: bytes, max_class: str, agent: Optional[Dict[str, Any]],
                        not_before: str, not_after: str,
                        reverses: Optional[Dict[str, str]] = None,
                        authorisation_id: Optional[str] = None) -> Dict[str, Any]:
    """The claims of one authorisation 0.2: an exact 0.1 binding over `request`, plus the
    ceiling, the agent and, for a reversal, the original it reverses."""
    if max_class not in CLASSES:
        raise ValueError(f"max_class must be one of {CLASSES}")
    base = authz.authorisation_claims(
        issuer=issuer, audience=audience, operation=operation,
        binding=authz.exact_binding(request), max_uses=1, not_before=not_before,
        not_after=not_after, decision_digest=None, authorisation_id=authorisation_id)
    base["schema"] = AUTHZ_V2_SCHEMA
    base["max_class"] = max_class
    base["agent"] = dict(agent) if agent else None
    base["reverses"] = dict(reverses) if reverses else None
    return base


def claims_problem_v2(claims: Any) -> Optional[str]:
    """Why these are not well-formed 0.2 claims, or None. Shape only."""
    if not isinstance(claims, dict):
        return "claims are not a JSON object"
    if claims.get("schema") != AUTHZ_V2_SCHEMA:
        return f"schema must be {AUTHZ_V2_SCHEMA!r}"
    p = authz.claims_problem({**claims, "schema": authz.SCHEMA})
    if p:
        return p
    if claims.get("max_class") not in CLASSES:
        return f"max_class must be one of {CLASSES}"
    ag = claims.get("agent")
    if ag is not None and (not isinstance(ag, dict) or not isinstance(ag.get("id"), str)
                           or not isinstance(ag.get("grants"), list)):
        return "agent must be null or {id, grants}"
    rv = claims.get("reverses")
    if rv is not None and (not isinstance(rv, dict) or set(rv) != {"authorisation_id",
                                                                    "request_digest"}):
        return "reverses must be null or {authorisation_id, request_digest}"
    return None


def sign_v2(claims: Dict[str, Any], key: Keypair) -> str:
    return authz.sign_authorisation(claims, key)


def verify_v2(token: Any, pinned: Dict[str, bytes]) -> Verified:
    """A reader of authorisation 0.2: compact JWS, EdDSA, a pinned kid, canonical payload, then
    the signature (the order and reasons of `authz.verify_authorisation`)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def bad(reason: str, detail: str, kid: Optional[str] = None) -> Verified:
        return Verified(ok=False, reason=reason, claims=None, kid=kid, detail=detail)

    if not isinstance(token, str) or token.count(".") != 2:
        return bad("malformed", "not a compact JWS")
    h_seg, p_seg, s_seg = token.split(".")
    try:
        hdr = receipts._strict_json(receipts._b64d(h_seg))
        payload = receipts._b64d(p_seg)
        claims = receipts._strict_json(payload)
        sig = receipts._b64d(s_seg)
    except (ValueError, UnicodeDecodeError) as e:
        return bad("malformed", str(e))
    kid = hdr.get("kid") if isinstance(hdr, dict) else None
    if not isinstance(hdr, dict) or hdr.get("typ") != authz.TYP:
        return bad("malformed", "header is not a krk-authz+jws header", kid)
    if str(hdr.get("alg", "")).lower() == "none" or not sig:
        return bad("unsigned", "no signature", kid)
    if hdr.get("alg") != authz.ALG:
        return bad("malformed", f"alg {hdr.get('alg')!r} is not {authz.ALG}", kid)
    try:
        if receipts.canonical_json(claims) != payload:
            return bad("malformed", "payload is not canonical", kid)
    except (ValueError, TypeError) as e:
        return bad("malformed", str(e), kid)
    problem = claims_problem_v2(claims)
    if problem:
        return bad("malformed", problem, kid)
    if kid not in pinned:
        return bad("unpinned-key", f"kid {kid!r} is not pinned", kid)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pinned[kid])).verify(
            sig, f"{h_seg}.{p_seg}".encode("ascii"))
    except InvalidSignature:
        return bad("bad-signature", "signature does not verify", kid)
    return Verified(ok=True, reason=None, claims=claims, kid=kid, detail="verified")


def reversal_values(original_claims: Dict[str, Any], original_request: bytes, *,
                    means_operation: str, request_id: str, agent: str) -> Dict[str, Any]:
    """The body of a reversal request in the kit's format: what it reverses, by request digest
    and authorisation id, and a request id of its own."""
    return {"operation": means_operation, "request_id": request_id, "agent": agent,
            "reverses": {"authorisation_id": original_claims["authorisation_id"],
                         "request_digest": authz.binding_digest(original_request)}}


# --------------------------------------------------------------------------- the judge


def _live(kind: str, s: Optional[Dict[str, Any]]) -> bool:
    """Whether an entity is present in the aspect sense: an object not deleted, an edge live, a
    message not recalled, an item not retracted, a transfer not voided."""
    if s is None:
        return False
    if kind == "object":
        return not s.get("deleted")
    if kind == "edge":
        return bool(s.get("live"))
    if kind == "mail":
        return not s.get("recalled")
    if kind == "item":
        return not s.get("retracted")
    if kind == "transfer":
        return not s.get("voided")
    return True


ASPECT_OF = {"object": ("object", "fields"), "edge": ("links",), "mail": ("delivery",),
             "item": ("delivery",), "transfer": ("balance",), "account": ("balance",)}


def aspect_problems(cls: str, restores: List[str], key: Tuple[str, str],
                    s0: Optional[Dict[str, Any]], s: Optional[Dict[str, Any]]) -> List[str]:
    """The restored aspects of one footprint entity that state `s` does not restore against its
    state `s0` before the action, under class `cls`."""
    kind, eid = key[0], key[1]
    out: List[str] = []
    if kind == "object":
        if "object" in restores and _live(kind, s) != _live(kind, s0):
            out.append(f"object:{eid}")
        if "fields" in restores and _live(kind, s0) and (s or {}).get("fields") != s0.get("fields"):
            out.append(f"fields:{eid}")
    elif kind == "edge":
        if "links" in restores and _live(kind, s) != _live(kind, s0):
            out.append(f"links:{eid}")
    elif kind in ("mail", "item"):
        if "delivery" in restores and _live(kind, s) != _live(kind, s0):
            out.append(f"delivery:{eid}")
    elif kind == "transfer":
        # Under reversible the ledger entries are compared, never totals (KRK-M118). Under
        # compensable the entry may stay in the history; only balances are judged.
        if "balance" in restores and cls == "reversible" and _live(kind, s) != _live(kind, s0):
            out.append(f"entry:{eid}")
    elif kind == "account":
        if "balance" in restores and (s or {}).get("balance") != (s0 or {}).get("balance"):
            out.append(f"balance:{eid}")
    return out


def _residue_for(change: Dict[str, Any], residues: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The declared residue a new entity matches, or None."""
    kind = change["key"][0]
    after = change.get("after") or {}
    for r in residues:
        if r["kind"] == "notice" and kind == "mail" and \
                (r.get("party") is None or r.get("party") == after.get("party")):
            return r
        if r["kind"] == "fee" and kind == "transfer" and \
                r.get("account") == after.get("to") and \
                isinstance(after.get("amount"), int) and after["amount"] <= int(r.get(
                    "max_amount") or 0):
            return r
    return None


def _holding_residue(h: Dict[str, Any], residues: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for r in residues:
        if r["kind"] == h["kind"] and (r.get("party") is None or r.get("party") == h.get("party")):
            return r
    return None


def _is_counter(ce: Dict[str, Any], change: Dict[str, Any], x_transfer: Optional[Dict[str, Any]]
                ) -> bool:
    """Whether a new entity is the declared counter-effect of a transfer: a transfer back from
    the payee to the payer of the same amount (``direction: back``, ``amount: same``)."""
    if ce.get("kind") != "transfer" or change["key"][0] != "transfer" or not x_transfer:
        return False
    a = change.get("after") or {}
    amount_ok = (a.get("amount") == x_transfer.get("amount") if ce.get("amount", "same") == "same"
                 else a.get("amount") == ce.get("amount"))
    return a.get("from") == x_transfer.get("to") and a.get("to") == x_transfer.get("from") \
        and amount_ok and not a.get("voided")


@dataclass
class Judgement:
    """What the world shows at one moment against the claim (§4.4)."""

    restored: bool
    aspects_not_restored: List[str] = field(default_factory=list)
    aspects_restored: List[str] = field(default_factory=list)
    residues_declared: List[Dict[str, Any]] = field(default_factory=list)
    residues_undeclared: List[Dict[str, Any]] = field(default_factory=list)
    new_effects: List[Dict[str, Any]] = field(default_factory=list)
    other_touched: List[str] = field(default_factory=list)
    counter_effects: int = 0
    x_relanded: List[str] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        return bool(self.aspects_not_restored) and bool(self.aspects_restored)

    @property
    def clean(self) -> bool:
        """Restored, with nothing undeclared, nothing new and no other effect touched."""
        return (self.restored and not self.residues_undeclared and not self.new_effects
                and not self.other_touched and not self.x_relanded)

    def to_doc(self) -> Dict[str, Any]:
        d = asdict(self)
        d["partial"] = self.partial
        d["clean"] = self.clean
        return d


def judge(claim: Dict[str, Any], footprint: Dict[Tuple[str, str], Tuple[Any, Any]], *,
          others: List[Dict[str, Any]], siblings: Dict[Tuple[str, str], Tuple[Any, Any]],
          holdings: List[Dict[str, Any]], counter_ops: int = 0,
          x_transfer: Optional[Dict[str, Any]] = None, x_tokens: Iterable[str] = (),
          history_trace: Optional[List[str]] = None) -> Judgement:
    """Judge the world against `claim` at one moment (§2.2, §4.4).

    - `footprint`: every entity the action changed or created by S1, ``{key: (s0, s)}``, its
      state before the action and at the moment judged;
    - `others`: every other change B made in the partition since S0, net, ``{"key", "before",
      "after"}`` (untagged ones included, KRK-M114);
    - `siblings`: L's, K's (and X′'s) footprints, ``{key: (s1, s)}``, which must not change;
    - `holdings`: what downstream parties hold from X (``{"kind", "party"}``, `HOLDINGS`);
    - `counter_ops`: B's changes to footprint entities that are the declared counter-effect
      (a retraction or recall, counted by the caller from the history);
    - `x_transfer`: X's transfer as committed, for a transfer counter-effect;
    - `x_tokens`: X's drawn values: a new entity carrying one is X landing again;
    - `history_trace`: for the ``history`` aspect, the history entries that show X, read from
      the world's history interface (KRK-M126)."""
    cls = claim.get("class")
    restores = list(claim.get("restores") or [])
    residues = list(claim.get("residues") or [])
    ce = claim.get("counter_effect") or {}
    j = Judgement(restored=False)
    for key, (s0, s) in sorted(footprint.items()):
        probs = aspect_problems(cls, restores, key, s0, s)
        j.aspects_not_restored.extend(probs)
        for asp in ASPECT_OF.get(key[0], ()):
            label = f"{'entry' if key[0] == 'transfer' else asp}:{key[1]}"
            if asp in restores and label not in probs and not (key[0] == "object" and asp ==
                                                               "fields" and not _live(key[0], s0)):
                j.aspects_restored.append(label)
    if "history" in restores and history_trace:
        j.aspects_not_restored.extend(f"history:{h}" for h in history_trace)
    toks = [t for t in x_tokens if t]
    explained_accounts: set = set()
    j.counter_effects = int(counter_ops)
    for ch in others:
        blob = json.dumps(ch.get("after"), sort_keys=True, default=str)
        if ch.get("before") is None and toks and any(t in blob for t in toks):
            if _live(ch["key"][0], ch.get("after")):
                j.x_relanded.append(f"{ch['key'][0]}:{ch['key'][1]}")
            continue
        if cls == "compensable" and _is_counter(ce, ch, x_transfer):
            j.counter_effects += 1
            explained_accounts.update({(ch.get("after") or {}).get("from"),
                                       (ch.get("after") or {}).get("to")})
            continue
        if ch["key"][0] == "account":
            continue                                    # explained below, by the transfers
        r = _residue_for(ch, residues) if ch.get("before") is None else None
        if r is not None:
            j.residues_declared.append({"change": ch["key"], "residue": r})
            if ch["key"][0] == "transfer":
                explained_accounts.update({(ch.get("after") or {}).get("from"),
                                           (ch.get("after") or {}).get("to")})
            continue
        j.new_effects.append({"key": ch["key"], "after": ch.get("after"),
                              "before": ch.get("before")})
        if ch["key"][0] == "transfer":
            explained_accounts.update({(ch.get("after") or {}).get("from"),
                                       (ch.get("after") or {}).get("to")})
    for ch in others:
        if ch["key"][0] == "account" and ch["key"][1] not in explained_accounts \
                and (ch["key"][0], ch["key"][1]) not in footprint:
            j.new_effects.append({"key": ch["key"], "after": ch.get("after"),
                                  "before": ch.get("before")})
    for h in holdings:
        r = _holding_residue(h, residues)
        if r is None:
            j.residues_undeclared.append(h)
        else:
            j.residues_declared.append({"holding": h, "residue": r})
    for key, (s1, s) in sorted(siblings.items()):
        if s1 != s:
            j.other_touched.append(f"{key[0]}:{key[1]}")
    j.restored = not j.aspects_not_restored and bool(footprint or toks)
    return j
