"""Known-bad and known-good toy B's for P24 (KRK-24, purpose and terms bound; design X2).

One toy B with a real recorder path (`X2-MANDATE-BOUND-DESIGN.md` §4.7): it verifies grant 0.4
chains, A-signed and holder-signed (`standing.verify_holder_chain`), a linked authorisation
(`mandator.LINKED_HEADER`), a confirmation (`mandator.CONFIRMATION_HEADER`) and disclosures
(`mandator.DISCLOSURES_HEADER`), verifies the agent's per-request authorisation, checks X5's
limits for every grant (`attenuation`), evaluates the terms with the kit's vocabulary (`terms`),
and acts by POSTing the action's values to the kit's recorder. It declares every term kind, a
fixed purpose map (`PURPOSE_MAP`), the item key ``id`` and bindings that name two members beyond
payee and amount.

**Correct toys** (each MUST pass): ``good`` refuses every action outside a term or a limit,
anything it cannot read, and never reads the text or the agent's headers. ``good-hold`` answers
``queued`` for a conditioned action without its confirmation and for an action with a sealed term
it cannot open, and never performs either (mode ``pending``). ``good-clamp`` performs only the
goal's items for an action that does more than the goal (mode ``clamped``).

**Flaws** read the terms wrongly; none removes members from what it was sent (KRK-M47). Each is
``good`` with one reading changed:

| Flaw | What it does | Forms it fails (`FAILS`) |
|---|---|---|
| `limits_only` (also ``bad``) | checks signatures and X5's limits; reads ``terms`` as known and evaluates none of it | every term form |
| `no_ceiling` | checks the terms, never the limits | every `outside_ceiling` form |
| `float_amounts` | reads amounts as floating point, rounded to minor units | `outside_ceiling/precision` |
| `ignores_currency` | compares amounts without their currency | `outside_ceiling/currency` |
| `accepts_negative` | reads a negative amount as zero | `outside_ceiling/negative` |
| `capability_only` | checks the operation against the grant, never the purpose | every `purpose` form, `text_wider`, `purpose_changed` |
| `presence_only` | checks that a purpose is present and non-empty | `purpose` but `absent`, `text_wider`, `purpose_changed` |
| `request_purpose` | reads the purpose from the agent's header when there is one | `asserted_by_agent` |
| `fuzzy_purpose` | folds case, spaces and punctuation before the lookup | `lookalike` |
| `subset_only` | each item acceptable for some slot; never checks every slot is filled | `partial`, `not_acceptable`, `over_quantity`, `under_quantity`, `item_reused`, `slot_dropped` |
| `fill_only` | every slot filled; extra units ignored | `extra_item`, `over_quantity` |
| `count_only` | compares total quantities | `not_acceptable`, `empty_slot` |
| `reuses_item` | counts a unit for every slot that accepts it | `item_reused` (and refuses `not_acceptable`'s sibling: `COLLATERAL`) |
| `empty_means_any` | reads ``acceptable: []`` as any item | `empty_slot` |
| `fixed_as_ceiling` | reads a fixed amount as a maximum | `lower_amount` |
| `upper_only` | checks no floor | `below_floor` |
| `missing_as_match` | reads a fixed member the action leaves out as equal | `missing_in_action` |
| `normalises` | compares fixed strings after NFC and case folding | `normalised` |
| `fixed_subset` | compares only payee and amount | `unlisted_member` |
| `goal_unchecked` | checks the linked authorisation's signature and limits, never its goal | every `cross_goal` form |
| `trusts_presented_goal` | compares ``serves`` with the agent's goal header when there is one | `presenter_named` |
| `unbound_any` | accepts a linked authorisation that names no goal | `unbound` |
| `ignores_condition` | never asks for a confirmation | every `condition` form |
| `any_signer_confirms` | accepts a confirmation signed by the agent too | `agent_confirmed` |
| `confirmation_unbound` | accepts the principal's confirmation for the goal, whatever action it binds | `confirmed_sibling` |
| `hidden_as_absent` | reads a sealed member with no disclosure as no term | every `hidden_terms` form |
| `reads_text` | allows an operation the free text names | `text_wider` |
| `ignores_unknown_term` | drops terms and members it does not know | every `unknown_term` form |
| `leaf_terms_only` | evaluates the presented grant's terms only | every `restated_terms` form |
| `late_executor` | holds a conditioned action it cannot confirm, answers ``queued``, and performs it 2 s later (KRK-M158) | every `condition` form |

``hold_forever`` holds every conditioned action, the confirmed one included, and never performs
it: its control's conditioned action does not complete, so `condition` reads ``shape_refused``
and the result is inconclusive, never a pass (KRK-M157). ``no-control``: the executor posts
elsewhere, so the control cannot hold.
"""
from __future__ import annotations

import json
import secrets
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from known_bad.withdrawal_toys import _KEEP, _answer

OP_BUY, OP_COMMIT, OP_PAY = "shop.checkout.complete", "shop.order.commit", "shop.payment.execute"
OP_READ, OP_DELETE, OP_PURGE = "data.record.read", "data.record.delete", "data.record.purge"
OPS = (OP_BUY, OP_COMMIT, OP_PAY, OP_READ, OP_DELETE, OP_PURGE)
PARTY = "did:web:b.example"
TOLERANCE_S = 5.0
PURPOSE_MAP = {"research": {"operations": [OP_READ], "resources": ["ds-1/*"]},
               "research-admin": {"operations": [OP_READ, OP_DELETE], "resources": ["ds-1/*"]},
               "maintenance": {"operations": [OP_READ, OP_DELETE, OP_PURGE],
                               "resources": ["ds-1/*"]},
               "purchase": {"operations": [OP_BUY, OP_COMMIT, OP_PAY], "resources": ["ds-1/*"]}}
REQUIRES = {OP_PURGE: ["purpose"], OP_PAY: ["serves"]}
BINDINGS = {op: {"payee": "payee", "amount": "amount", "instrument": "instrument",
                 "execution_date": "execution_date"} for op in OPS}
LATE_S = 2.0

FLAWS = ("limits_only", "no_ceiling", "float_amounts", "ignores_currency", "accepts_negative",
         "capability_only", "presence_only", "request_purpose", "fuzzy_purpose", "subset_only",
         "fill_only", "count_only", "reuses_item", "empty_means_any", "fixed_as_ceiling",
         "upper_only", "missing_as_match", "normalises", "fixed_subset", "goal_unchecked",
         "trusts_presented_goal", "unbound_any", "ignores_condition", "any_signer_confirms",
         "confirmation_unbound", "hidden_as_absent", "reads_text", "ignores_unknown_term",
         "leaf_terms_only", "late_executor")
INFO = ("hold_forever",)
GOOD = ("good", "good-hold", "good-clamp")
HOLDS = ("good-hold", "late_executor", "hold_forever")
"""Configurations whose condition mode is ``hold``."""

_OC = "outside_ceiling"
_TERM_FORMS = {
    "purpose": ("mismatch", "asserted_by_agent", "absent", "unknown_code", "lookalike"),
    "goal_items": ("partial", "extra_item", "not_acceptable", "over_quantity", "under_quantity",
                   "item_reused", "empty_slot"),
    "fixed": ("differs", "lower_amount", "below_floor", "missing_in_action", "normalised",
              "unlisted_member"),
    "cross_goal": ("other_goal", "presenter_named", "unbound"),
    "condition": ("unconfirmed", "agent_confirmed", "confirmed_sibling"),
    "hidden_terms": ("slot_hidden", "fixed_hidden", "purpose_hidden", "all_hidden"),
    "free_text": ("text_wider",),
    "unknown_term": ("in_terms", "in_member", "near_name"),
    "restated_terms": ("purpose_changed", "slot_dropped", "fixed_changed")}


def _all(v: str) -> set:
    return {f"{v}/{f}" for f in _TERM_FORMS[v]}


FAILS: Dict[str, set] = {
    "limits_only": set().union(*(_all(v) for v in _TERM_FORMS)),
    "no_ceiling": {f"{_OC}/{f}" for f in ("amount", "operation", "counterparty", "window",
                                          "currency", "negative", "precision")},
    "float_amounts": {f"{_OC}/precision"}, "ignores_currency": {f"{_OC}/currency"},
    "accepts_negative": {f"{_OC}/negative"},
    "capability_only": _all("purpose") | {"free_text/text_wider",
                                          "restated_terms/purpose_changed"},
    "presence_only": (_all("purpose") - {"purpose/absent"}) |
    {"free_text/text_wider", "restated_terms/purpose_changed"},
    "request_purpose": {"purpose/asserted_by_agent"}, "fuzzy_purpose": {"purpose/lookalike"},
    "subset_only": {"goal_items/partial", "goal_items/not_acceptable",
                    "goal_items/over_quantity", "goal_items/under_quantity",
                    "goal_items/item_reused", "restated_terms/slot_dropped"},
    "fill_only": {"goal_items/extra_item", "goal_items/over_quantity"},
    "count_only": {"goal_items/not_acceptable", "goal_items/empty_slot"},
    "reuses_item": {"goal_items/item_reused"}, "empty_means_any": {"goal_items/empty_slot"},
    "fixed_as_ceiling": {"fixed/lower_amount"}, "upper_only": {"fixed/below_floor"},
    "missing_as_match": {"fixed/missing_in_action"}, "normalises": {"fixed/normalised"},
    "fixed_subset": {"fixed/unlisted_member"}, "goal_unchecked": _all("cross_goal"),
    "trusts_presented_goal": {"cross_goal/presenter_named"},
    "unbound_any": {"cross_goal/unbound"}, "ignores_condition": _all("condition"),
    "any_signer_confirms": {"condition/agent_confirmed"},
    "confirmation_unbound": {"condition/confirmed_sibling"},
    "hidden_as_absent": _all("hidden_terms"), "reads_text": {"free_text/text_wider"},
    "ignores_unknown_term": _all("unknown_term"), "leaf_terms_only": _all("restated_terms"),
    "late_executor": _all("condition")}
"""Each flaw's failing forms, written from the table above (design §3.3), not read off a run:
the test checks the run against it (X3 §13 item 7, KRK-M47)."""
COLLATERAL: Dict[str, set] = {"reuses_item": {"goal_items/not_acceptable"}}
"""Forms where a flaw's reading also refuses the sibling L, so the form reads
``collateral_refusal`` (information, no reading) rather than held. `reuses_item` counts a unit for
every slot that accepts it, and any mandate that admits ``not_acceptable``'s action accepts one
item in two slots, so it over-counts L as well (over-refusal, never a pass or a fail)."""


def _fold(code: str) -> str:
    return "".join(ch for ch in code.casefold() if ch.isalnum())


def _nfc_fold(x: Any) -> Any:
    return unicodedata.normalize("NFC", x).casefold() if isinstance(x, str) else x


class ToyMandate:
    """A B that acts under mandates (P24's role-B adapter, in process)."""

    name = "toy-mandate"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *,
                 clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "limits_only"
        if config in INFO:
            flaw, config = config, "info"
        if flaw is not None and flaw not in FLAWS + INFO:
            raise ValueError(f"unknown flaw {flaw!r}")
        if config not in GOOD + ("bad", "no-control", "info"):
            raise ValueError(f"unknown configuration {config!r}")
        self.flaw = flaw
        self.config = config if flaw is None else (f"info:{flaw}" if flaw in INFO
                                                   else f"bad:{flaw}")
        self.mode = config if flaw is None else flaw
        self.no_control = config == "no-control"
        self.clock = clock
        self._clock: Any = None
        self.recorder = ""
        self.orgs: Dict[str, Dict[str, Any]] = {}
        self.seen: Dict[str, Dict[str, Any]] = {}

    # kit plumbing ---------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-mandate {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P24": "toy: 'an action is performed only when it meets every term of its "
                       "mandate'"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def role(self) -> str:
        return "B"

    def set_clock(self, clock: Any) -> None:
        self._clock = clock

    def _c(self) -> Any:
        if self._clock is None:
            from conformance.timing import RealClock
            self._clock = RealClock()
        return self._clock

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": PARTY, "endpoints": ["e1", "e2"], "tenants": [],
                "max_validity_s": 3600, "clock_tolerance_s": TOLERANCE_S}

    def evidence_grade(self) -> str:
        return "recorder"

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "accepted", "queued": "in-progress",
                "refused": "refused"}.get(code, "error")

    # statements (`role_mandate.MandateB`) ---------------------------------------------------------

    def constraint_profile(self) -> List[str]:
        return ["max_amount", "operations", "resources", "audience", "window"]

    def term_profile(self) -> List[str]:
        return ["purpose", "slots", "fixed", "floor", "serves", "confirm", "sealed", "text"]

    def purpose_map(self) -> Dict[str, Any]:
        return json.loads(json.dumps(PURPOSE_MAP))

    def purpose_map_source(self) -> Dict[str, str]:
        return {"quote": "toy: 'each purpose code covers the operations listed for it'",
                "location": "known_bad/mandate_toys.py PURPOSE_MAP"}

    def requires_terms(self) -> Dict[str, List[str]]:
        return json.loads(json.dumps(REQUIRES))

    def term_bindings(self) -> Dict[str, Dict[str, str]]:
        return json.loads(json.dumps(BINDINGS))

    def item_key(self) -> str:
        return "id"

    def condition_mode(self) -> str:
        return "hold" if self.mode in HOLDS else "refuse"

    def hold_resolution_s(self) -> Optional[float]:
        return None

    def disclosure_profile(self) -> str:
        return "kirkaldy.sealed/0.1"

    def accepts_holder_hops(self) -> bool:
        return True

    def issuers(self) -> int:
        return 2

    def documents_terms(self) -> bool:
        return True

    def received(self, ref: str) -> Optional[Dict[str, Any]]:
        """What this B received for the request `ref` (KRK-M156, M162)."""
        return self.seen.get(ref)

    # binding --------------------------------------------------------------------------------

    def _bind(self, anchor: Dict[str, Any]) -> str:
        from conformance import standing as st
        iss = anchor["issuer"]
        v = st.verify(anchor["keyset"], {k: bytes(x) for k, x in anchor["anchor"].items()},
                      st.KEYSET_TYP)
        self.orgs[iss] = {"keyset": v.claims if v.ok else None}
        return iss

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        return f"pinned {self._bind(anchor)}"

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        return f"pinned {self._bind(anchor)}"

    def bind_recorder(self, recorder_url: str) -> str:
        self.recorder = recorder_url.rstrip("/")
        return f"effects to {self.recorder}/effect/<id>"

    # reading --------------------------------------------------------------------------------

    def _shape(self, c: Any) -> Optional[str]:
        from conformance import attenuation as att, terms as tm
        if self.mode == "limits_only":
            if not isinstance(c, dict) or c.get("schema") != tm.GRANT_V4_SCHEMA or \
                    not isinstance(c.get("terms"), dict):
                return "not a 0.4 grant"
            p = att.grant_v2_problem(tm.without_terms(c))
            return f"{p[0]}: {p[1]}" if p else None
        p = tm.grant_v4_problem(c)
        if p is None:
            return None
        if self.mode == "ignores_unknown_term" and p[0] == tm.UNKNOWN:
            p2 = att.grant_v2_problem(tm.without_terms(c))
            return f"{p2[0]}: {p2[1]}" if p2 else None
        return f"{p[0]}: {p[1]}"

    def _chain(self, toks: List[str]) -> Tuple[Optional[str], Any]:
        from conformance import standing as st
        anchors = {iss: o["keyset"] for iss, o in self.orgs.items() if o["keyset"]}
        hops, problem = st.verify_holder_chain(toks, anchors, problem_of=self._shape,
                                               lenient=False)
        if problem:
            return problem, None
        return None, [h.claims for h in hops]

    def _normalise(self, x: Any) -> Any:
        """The lenient flaws' reading of amounts (limits only)."""
        if isinstance(x, dict):
            if set(x) == {"value", "currency", "minor_units"}:
                v, cur, mu = x["value"], x["currency"], x["minor_units"]
                if self.mode == "float_amounts" and isinstance(v, (int, float)) \
                        and not isinstance(v, bool):
                    v = int(round(float(v)))
                if self.mode == "ignores_currency":
                    cur = "EUR"
                if self.mode == "accepts_negative" and isinstance(v, int) and v < 0:
                    v = 0
                return {"value": v, "currency": cur, "minor_units": mu}
            return {k: self._normalise(v) for k, v in x.items()}
        if isinstance(x, list):
            return [self._normalise(v) for v in x]
        return x

    def _limits(self, chain: List[Dict[str, Any]], values: Dict[str, Any]) -> Optional[str]:
        from conformance import attenuation as att, terms as tm
        if self.mode == "no_ceiling":
            return None
        c02 = [tm.without_terms(g) for g in chain]
        vals = values
        if self.mode in ("float_amounts", "ignores_currency", "accepts_negative"):
            c02 = [self._normalise(g) for g in c02]
            vals = self._normalise(values)
        al = att.allowed(c02)
        return att.inside(vals, al, at=self._c().wall(), tolerance_s=TOLERANCE_S, party=PARTY)

    def _strip_unknown(self, t: Dict[str, Any]) -> Dict[str, Any]:
        from conformance import terms as tm
        out = {k: v for k, v in t.items() if k in tm.TERM_KINDS}
        if isinstance(out.get("slots"), list):
            out["slots"] = [{k: v for k, v in s.items() if k in tm.SLOT_MEMBERS}
                            if isinstance(s, dict) else s for s in out["slots"]]
        if isinstance(out.get("purpose"), dict):
            out["purpose"] = {k: v for k, v in out["purpose"].items() if k == "code"}
        if isinstance(out.get("confirm"), dict):
            out["confirm"] = {k: v for k, v in out["confirm"].items() if k in tm.CONFIRM_MEMBERS}
        return out

    def _drop_unopened(self, t: Any, disclosures: List[Any]) -> Any:
        """`hidden_as_absent`: every sealed member no disclosure opens is left out, as if the
        mandate had no such term; a slot whose ``acceptable`` is left out admits any item."""
        from conformance import terms as tm
        by: Dict[str, List[Any]] = {}
        for d in disclosures:
            if isinstance(d, list) and len(d) == 3:
                by.setdefault(str(d[1]), []).append(d)

        def walk(x: Any, path: str) -> Any:
            if tm.is_sealed(x):
                for salt, _p, value in by.get(path, []):
                    try:
                        if tm.seal(value, salt) == x:
                            return value
                    except (TypeError, ValueError):
                        continue
                return _GONE
            if isinstance(x, dict):
                out = {}
                for k, v in x.items():
                    w = walk(v, f"{path}/{k}" if path else str(k))
                    if w is not _GONE:
                        out[k] = w
                return out
            if isinstance(x, list):
                return [w for w in (walk(v, f"{path}/{i}" if path else str(i))
                                    for i, v in enumerate(x)) if w is not _GONE]
            return x
        out = walk(t, "")
        for k in ("fixed", "floor"):
            if out.get(k) == {}:
                out.pop(k)                    # every member hidden: no such term
        return out

    def _slots_ok(self, items: Any, slots: List[Dict[str, Any]], key: str
                  ) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]]]:
        """(why not, clamped items) for one hop's slots, with this toy's reading."""
        from conformance import terms as tm
        any_slot = [s for s in slots if "acceptable" not in s]      # hidden_as_absent only
        if any_slot or (self.mode == "empty_means_any" and any(s["acceptable"] == []
                                                               for s in slots)):
            have = tm.units(items, key) or {}
            pool = sorted(have)
            slots = [dict(s, acceptable=pool) if ("acceptable" not in s or
                                                  (self.mode == "empty_means_any"
                                                   and s["acceptable"] == [])) else s
                     for s in slots]
        have = tm.units(items, key)
        if have is None:
            return "the action's items cannot be read", None
        if self.mode == "subset_only":
            ok = all(any(i in s["acceptable"] for s in slots) for i in have)
            return (None if ok else "an item is in no slot's list"), None
        if self.mode == "count_only":
            ok = sum(have.values()) == sum(s["quantity"] for s in slots)
            return (None if ok else "the total quantity differs"), None
        if self.mode == "reuses_item":
            for s in slots:
                n = sum(q for i, q in have.items() if i in s["acceptable"])
                if n != s["quantity"]:
                    return f"slot {s['slot']} has {n} units", None
            ok = all(any(i in s["acceptable"] for s in slots) for i in have)
            return (None if ok else "an item is in no slot's list"), None
        if self.mode == "fill_only":
            got, _ = tm.assignment(have, slots)
            ok = got == sum(s["quantity"] for s in slots)
            return (None if ok else "a slot is not filled"), None
        why = tm.fill(items, slots, item_key=key)
        if why and self.mode == "good-clamp" and tm.reason_of(why) == tm.MORE:
            clamped = tm.clamp_items(items, slots, item_key=key)
            if clamped is not None:
                return None, clamped
        return why, None

    def _fixed_ok(self, values: Dict[str, Any], fixed: Dict[str, Any], op: str) -> Optional[str]:
        from conformance import attenuation as att, terms as tm
        b = BINDINGS.get(op, {})
        if self.mode == "fixed_subset":
            fixed = {m: v for m, v in fixed.items() if m in ("payee", "amount")}
        for m, want in fixed.items():
            name = b.get(m, m)
            if name not in values:
                if self.mode == "missing_as_match":
                    continue
                return f"fixed {m} absent"
            got = values[name]
            if self.mode == "fixed_as_ceiling" and att.amount_problem(want) is None:
                if att.amount_le(got, want) is not True:
                    return f"{m} above the fixed amount"
                continue
            if self.mode == "normalises" and isinstance(got, str) and isinstance(want, str):
                if _nfc_fold(got) != _nfc_fold(want):
                    return f"{m} differs"
                continue
            why = tm.fixed_ok(values, {m: want}, b)
            if why:
                return why
        return None

    def _confirmed(self, p: Any, chain: List[Dict[str, Any]], goal: Optional[str],
                   basis: str) -> bool:
        from conformance import authz, mandator, standing as st, terms as tm
        tok = p.headers.get(mandator.CONFIRMATION_HEADER)
        if not tok:
            return False
        ks = self.orgs.get(chain[-1]["issuer"], {}).get("keyset") or {}
        keys = mandator.principal_keys(ks)
        if self.mode == "any_signer_confirms":
            ak = chain[0]["agent_key"]
            keys = {**keys, ak["kid"]: bytes.fromhex(ak["public_key"])}
        v = st.verify(tok, keys, tm.CONFIRMATION_TYP, problem_of=tm.confirmation_problem)
        if not v.ok:
            return False
        c = v.claims
        if c["goal_id"] != goal or c["grant_id"] != chain[0]["grant_id"]:
            return False
        if c["not_after"] < int(self._c().wall() * 1000):
            return False
        if self.mode == "confirmation_unbound":
            return True
        return c["request_digest"] == authz.binding_digest(p.request, basis)

    def _terms(self, p: Any, chain: List[Dict[str, Any]], values: Dict[str, Any],
               linked: Optional[Dict[str, Any]], basis: str) -> Tuple[str, str, Any]:
        """``("ok", "", clamped items or None)``, ``("refuse", why, None)`` or
        ``("hold", why, None)``."""
        from conformance import mandator, terms as tm
        op = values.get("operation")
        if self.mode == "limits_only":
            return "ok", "", None
        tlist = [g["terms"] for g in chain]
        if self.mode == "leaf_terms_only":
            tlist = tlist[:1]
        try:
            disc = json.loads(p.headers.get(mandator.DISCLOSURES_HEADER) or "[]")
        except ValueError:
            return "refuse", "disclosures cannot be read", None
        hold = self.condition_mode() == "hold"
        opened: List[Dict[str, Any]] = []
        for t in tlist:
            o = tm.open_sealed(t, disc)
            if isinstance(o, tm.Unreadable):
                if self.mode == "hidden_as_absent":
                    o = self._drop_unopened(t, disc)
                elif self.mode == "good-hold":
                    return "hold", f"sealed terms {list(o.paths)} not disclosed", None
                else:
                    return "refuse", f"sealed terms {list(o.paths)} not disclosed", None
            if self.mode == "ignores_unknown_term":
                o = self._strip_unknown(o)
            shape = o
            if self.mode == "hidden_as_absent" and isinstance(o.get("slots"), list):
                shape = {**o, "slots": [dict(s, acceptable=[]) if isinstance(s, dict) and
                                        "acceptable" not in s else s for s in o["slots"]]}
            prob = tm.terms_problem(shape, sealed_ok=False)
            if prob:
                return "refuse", f"{prob[0]}: {prob[1]}", None
            opened.append(o)
        need = REQUIRES.get(op, [])
        texts = " ".join(t.get("text", "") for t in opened if isinstance(t.get("text"), str))
        skip_purpose = self.mode == "capability_only" or \
            (self.mode == "reads_text" and isinstance(op, str) and op.rsplit(".", 1)[-1] in texts)
        if "purpose" in need and not skip_purpose and not any("purpose" in t for t in opened):
            return "refuse", "a purpose is required", None
        clamped = None
        for t in opened:
            if "purpose" in t and not skip_purpose:
                code = t["purpose"].get("code")
                if self.mode == "presence_only":
                    if not isinstance(code, str) or not code:
                        return "refuse", "no purpose code", None
                else:
                    if self.mode == "request_purpose" and p.headers.get(mandator.PURPOSE_HEADER):
                        code = p.headers[mandator.PURPOSE_HEADER]
                    pmap = PURPOSE_MAP
                    if self.mode == "fuzzy_purpose":
                        pmap = {_fold(k): v for k, v in PURPOSE_MAP.items()}
                        code = _fold(code) if isinstance(code, str) else code
                    if not tm.purpose_covers(pmap, code, op, values.get("resources")):
                        return "refuse", f"purpose {code!r} does not cover {op!r}", None
            if "slots" in t:
                why, cl = self._slots_ok(values.get("items"), t["slots"], self.item_key())
                if why:
                    return "refuse", why, None
                if cl is not None:
                    clamped = cl
            if "fixed" in t:
                why = self._fixed_ok(values, t["fixed"], op)
                if why:
                    return "refuse", why, None
            if "floor" in t and self.mode != "upper_only":
                why = tm.floor_ok(values, t["floor"], BINDINGS.get(op, {}))
                if why:
                    return "refuse", why, None
        goal = tm.goal_of(opened) if opened else tm.goal_of([g["terms"] for g in chain])
        conditioned = any("confirm" in t and op in (t["confirm"].get("operations") or [])
                          for t in opened)
        if conditioned and self.mode != "ignores_condition":
            if self.mode == "hold_forever":
                return "hold", "every conditioned action is held", None
            if not self._confirmed(p, chain, goal, basis):
                return ("hold" if hold else "refuse"), "no confirmation of this action", None
        if linked is not None:
            serves = linked["terms"].get("serves")
            if self.mode != "goal_unchecked":
                want = goal
                if self.mode == "trusts_presented_goal" and p.headers.get(mandator.GOAL_HEADER):
                    want = p.headers[mandator.GOAL_HEADER]
                if serves is None:
                    if "serves" in need and self.mode != "unbound_any":
                        return "refuse", "the linked authorisation names no goal", None
                elif serves != want:
                    return "refuse", "the linked authorisation serves another goal", None
        elif "serves" in need:
            return "refuse", "a linked authorisation is required", None
        return "ok", "", clamped

    # the entry point ------------------------------------------------------------------------

    def _decide(self, p: Any) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], bool]:
        """(answer, values to perform or None, perform later)."""
        from conformance import authz, mandator, requester
        toks = [p.headers.get(requester.GRANT_HEADER) or ""] + [
            t for t in (p.headers.get(requester.CHAIN_HEADER) or "").split(",") if t]
        if not toks[0]:
            return _answer("refused", "no grant"), None, False
        why, chain = self._chain(toks)
        if why:
            return _answer("refused", f"grant chain: {why}"), None, False
        leaf = chain[0]
        ak = leaf["agent_key"]
        v = authz.verify_authorisation(p.authorisation, {ak["kid"]: bytes.fromhex(ak["public_key"])})
        if not v.ok or v.claims["issuer"] != leaf["subject"] or \
                v.claims.get("grant_id") != leaf["grant_id"] or \
                v.claims["audience"]["counterparty"] != PARTY:
            return _answer("refused", f"authorisation: {v.reason or 'not under this grant'}"), \
                None, False
        if v.claims["binding"]["request_digest"] != authz.binding_digest(
                p.request, v.claims["binding"]["basis"]):
            return _answer("refused", "payload-mismatch"), None, False
        values = json.loads(p.request.decode("utf-8"))
        linked = None
        ltok = p.headers.get(mandator.LINKED_HEADER)
        if ltok:
            why, lchain = self._chain([ltok])
            if why:
                return _answer("refused", f"linked authorisation: {why}"), None, False
            linked = lchain[0]
        why = self._limits(chain, values)
        if why is None and linked is not None:
            why = self._limits([linked], values)
        if why:
            return _answer("refused", f"limit: {why}"), None, False
        verdict, why, clamped = self._terms(p, chain, values, linked,
                                            v.claims["binding"]["basis"])
        if verdict == "refuse":
            return _answer("refused", f"terms: {why}"), None, False
        if verdict == "hold":
            later = self.mode == "late_executor"
            return _answer("queued", f"held: {why}"), (values if later else None), later
        if clamped is not None:
            values = {**values, "items": clamped}
        return _answer("executed", "performed"), values, False

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        from conformance.mandator import headers_digest
        try:
            ref = str(json.loads(p.request.decode("utf-8")).get("ref"))
        except ValueError:
            ref = ""
        self.seen[ref] = {"digest": headers_digest(p.headers, p.request)}
        ans, values, later = self._decide(p)
        if values is None:
            return ans
        if later:
            c = self._c()
            c.call_at(c.now() + LATE_S, lambda: self._effect(values))
            return ans
        res = self._effect(values)
        return res if res is not None else ans

    def _effect(self, values: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = (f"{self.recorder}/effect/{secrets.token_hex(6)}" if not self.no_control
               else f"{self.recorder.rsplit('/p24/', 1)[0]}/elsewhere/{secrets.token_hex(4)}")
        body = json.dumps(values, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        try:
            code, _h = _KEEP.post(url, body)
        except Exception as e:  # noqa: BLE001
            return _answer("refused", f"effect failed: {type(e).__name__}")
        return None if code == 200 else _answer("refused", f"effect failed {code}")


_GONE = object()


def make(flaw: Optional[str] = None, **kw: Any) -> ToyMandate:
    return ToyMandate("bad" if flaw else "good", flaw, **kw)


def toy(config: str) -> ToyMandate:
    if config.startswith("bad:"):
        return make(config[4:])
    if config.startswith("info:"):
        return ToyMandate(config[5:])
    return ToyMandate(config)


def cases() -> List[Tuple[str, str]]:
    """Each P24 toy configuration and the outcome the known-bad gate requires of it."""
    out = [("good", "pass"), ("good-hold", "pass"), ("good-clamp", "pass"), ("bad", "fail")]
    out += [(f"bad:{f}", "fail") for f in FLAWS if f != "limits_only"]
    out += [("info:hold_forever", "inconclusive"), ("no-control", "inconclusive")]
    return out
