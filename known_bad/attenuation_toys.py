"""Known-bad and known-good toy B's for P21 (KRK-21, no widening).

One toy B with a real recorder path (`X5-NO-WIDENING-DESIGN.md` §4.5): it verifies grant 0.2
chains, A-signed and holder-signed (`standing.verify_holder_chain`), reads a stapled standing
assertion for the root principal's limits, maps operation names through the mapping it declares,
applies A's status to every hop (polling each organisation's X4 status list every T/4), verifies
the agent's per-request authorisation, and acts by POSTing the request's values to the kit's
recorder.

``good`` computes `attenuation.allowed` over the whole chain and the standing, refuses unknown,
null and wildcard members and anything it cannot compare exactly, refuses cycles, self-parents,
two parents and chains beyond its stated depth, and acts only inside the intersection
(``clamped``: a request inside every grant of a chain with a wider hop is accepted).
``good-strict`` also refuses any chain with a hop wider than its parent (``chain_refused``). Both
must pass.

Flaws read the chain wrongly; none removes members from what it was sent (KRK-M47). Several
model a B that checks every hop against its parent and the request against the leaf: correct
when the hop check is, and wrong in exactly the reading each flaw names.

| Flaw | What it does | Variant it fails |
|---|---|---|
| `leaf_only` | compares the request with the presented grant only (also ``bad``) | `wider_child` |
| `ends_only` | checks the presented grant and the root | `middle_narrow` |
| `absent_means_any` | checks hops, and reads a member the leaf leaves out as any | `dropped_constraint` (``omitted``) |
| `empty_means_any` | checks hops, and reads ``[]`` at the leaf as any | `dropped_constraint` (``empty_list``) |
| `glob_operations` | reads ``"*"`` as matching every operation | `wildcard_default` (``wildcard_operation``) |
| `compares_backwards` | tests the parent's pattern against the child's | `wildcard_default` (``prefix_broader``) |
| `defaults_fill` | fills a member the leaf leaves out from its own settings | `wildcard_default` (``default_audience``, ``default_window``) |
| `unions_grants` | takes each dimension from whichever presented grant allows it, sums amounts, takes two parents | `combined` |
| `ignores_depth` | checks no delegation depth | `delegation_exceeded` |
| `maps_child_only` | maps the child into its own terms and checks the request against it alone | `translated_hop` |
| `stops_at_seen` | stops at a repeated parent and reads the chain as rooted | `cycle` (``id_cycle``) |
| `follows_unbounded` | follows parents to a cap and ignores its stated depth | `cycle` (``too_deep``) |
| `ignores_unknown` | drops members it does not know | `unknown_constraint` |
| `float_compare` | reads amounts as floating point, rounded to minor units | `numeric` (``precision``, ``large_integer``) |
| `ignores_units` | compares amounts without their minor units | `numeric` (``units``) |
| `ignores_currency` | compares amounts without their currency | `numeric` (``currency``) |
| `accepts_negative` | takes a negative amount as inside | `numeric` (``negative``) |
| `lenient_numbers` | reads amounts written as strings or with exponents | `numeric` (``encoding``) |
| `ignores_standing_limit` | reads no limit from the standing assertion | `root_exceeds_standing` |
| `static_parent` | applies A's status to the presented grant only | `narrowed_parent` |
| `chain_before_fetch` | reads standing only by fetching (as ``pull-good``), and bounds a request by the chain alone for a principal A has not yet answered for | `root_exceeds_standing` (``before_first_fetch``) |
| `walks_supplied_only` | checks the links it is given and reads the last grant supplied as the root, whether or not it names a parent (KRK-M95c) | `incomplete_chain` (every form) |

``hangs_on_cycle`` never answers on a cyclic chain and commits nothing (information only,
``hung``). ``no-control``: the executor posts elsewhere.

**Pull only** (KRK-M95, M95b). ``pull-good`` is ``good`` reading the root principal's standing as
the reference implementation's ``limits`` channel does: only by fetching, on its poll, for the
principals A's status list names, never a staple. An assertion it holds bounds the request; after
A has answered 404 the chain alone bounds it; before A has answered at all it refuses. It must
pass. ``bad:chain_before_fetch`` reads the same way but bounds the request by the chain alone
before A has answered; only ``before_first_fetch`` presents that early.

**A registered delegation format** (`conformance.delegation_formats`). ``example-good`` reads
the made-up example format (`delegation_formats.EXAMPLE`) and nothing else, holder-only. Its
reader is written here and shares no code with the writer: the presented grant first, then each
parent, as the kit's own reader takes 0.2 chains; the last grant must be a root signed under a
grant key of an organisation it pinned whose anchor named the format; every other grant is signed
under its parent's ``to_key``, by its parent's subject; the canonical form and ``typ`` are
checked. Each grant is then read into grant 0.2 claims (``allow`` as the constraints, ``ex:``
stripped from the ids) and judged as ``good``, at most five grants deep. It must pass.
``example-bad:leaf_only`` reads the same way and compares the request with the presented grant
only. It must fail.
"""
from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from known_bad.withdrawal_toys import _KEEP, _answer

FLAWS = ("leaf_only", "ends_only", "absent_means_any", "empty_means_any", "glob_operations",
         "compares_backwards", "defaults_fill", "unions_grants", "ignores_depth",
         "maps_child_only", "stops_at_seen", "follows_unbounded", "ignores_unknown",
         "float_compare", "ignores_units", "ignores_currency", "accepts_negative",
         "lenient_numbers", "ignores_standing_limit", "static_parent", "chain_before_fetch",
         "walks_supplied_only")
PULL_ONLY_FLAWS = ("chain_before_fetch",)
"""Flaws whose toy reads standing only by fetching, as ``pull-good`` does."""
FAILS = {"leaf_only": "wider_child", "ends_only": "middle_narrow",
         "absent_means_any": "dropped_constraint", "empty_means_any": "dropped_constraint",
         "glob_operations": "wildcard_default", "compares_backwards": "wildcard_default",
         "defaults_fill": "wildcard_default", "unions_grants": "combined",
         "ignores_depth": "delegation_exceeded", "maps_child_only": "translated_hop",
         "stops_at_seen": "cycle", "follows_unbounded": "cycle",
         "ignores_unknown": "unknown_constraint", "float_compare": "numeric",
         "ignores_units": "numeric", "ignores_currency": "numeric",
         "accepts_negative": "numeric", "lenient_numbers": "numeric",
         "ignores_standing_limit": "root_exceeds_standing", "static_parent": "narrowed_parent",
         "chain_before_fetch": "root_exceeds_standing", "walks_supplied_only": "incomplete_chain"}
FORM = {"absent_means_any": "omitted", "empty_means_any": "empty_list",
        "glob_operations": "wildcard_operation", "compares_backwards": "prefix_broader",
        "defaults_fill": "default_audience", "stops_at_seen": "id_cycle",
        "follows_unbounded": "too_deep", "float_compare": "precision", "ignores_units": "units",
        "ignores_currency": "currency", "accepts_negative": "negative",
        "lenient_numbers": "encoding", "maps_child_only": "mapping_widens",
        "chain_before_fetch": "before_first_fetch", "walks_supplied_only": "stops_before_root"}
INFO = ("hangs_on_cycle",)
PARTY = "did:web:b.example"
MAP_NAME = "kirkaldy.map/contacts-v1"
MAPPING = {"operations": {"contacts:write": ["crm.record.push", "crm.record.delete"]}}
"""B's name ``contacts:write`` means A's ``crm.record.push`` and ``crm.record.delete``."""
HOP_CHECKED = ("absent_means_any", "empty_means_any", "glob_operations", "compares_backwards",
               "defaults_fill")
LENIENT = ("float_compare", "lenient_numbers", "accepts_negative", "ignores_units",
           "ignores_currency")
LENIENT_PARSE = ("float_compare", "lenient_numbers")
"""Flaws that parse a chain whose payload the canonical form refuses (floats, big integers,
strings for numbers)."""
TOLERANCE_S = 5.0
DEPTH = 4
EXAMPLE_FLAWS = ("leaf_only",)
"""Flaws the known-bad gate also runs in the example delegation format
(``example-bad:<flaw>``)."""
UNANSWERED = object()
"""Pull only: A has not yet answered a fetch for the root principal."""


class ToyAttenuation:
    """A B that acts under delegation chains (P21's role-B adapter, in process)."""

    name = "toy-attenuation"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, *, T: float = 60.0,
                 clock: str = "virtual") -> None:
        if config == "bad" and flaw is None:
            flaw = "leaf_only"
        if flaw is not None and flaw not in FLAWS + INFO:
            raise ValueError(f"unknown flaw {flaw!r}")
        self.config = config if flaw is None else f"bad:{flaw}"
        self.depth = DEPTH
        self.flaw = flaw
        self.strict = config == "good-strict"
        self.no_control = config == "no-control"
        self.pull_only = config == "pull-good" or flaw in PULL_ONLY_FLAWS
        self.held: Dict[Tuple[str, str], Any] = {}
        """Pull only: (issuer, principal) -> the classes of the assertion fetched, or None when
        A answered 404 (it publishes none). Absent: A has not answered yet."""
        self.T = float(T)
        self.clock = clock
        self._clock: Any = None
        self.recorder = ""
        self.orgs: Dict[str, Dict[str, Any]] = {}
        self.snaps: Dict[str, Dict[str, Any]] = {}
        self._polls: List[int] = []

    # kit plumbing ---------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-attenuation {self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {"P21": "toy: 'a delegated grant can only narrow'"}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        c = self._clock
        for h in self._polls:
            if c is not None:
                c.cancel(h)
        self._polls = []

    def role(self) -> str:
        return "B"

    def withdrawal_bound(self) -> Dict[str, Any]:
        return {"T_s": self.T, "statistic": "max", "source": "documented",
                "quote": f"toy: 'a narrowing takes effect within {self.T:g} seconds'",
                "url": "known_bad/attenuation_toys.py", "setting": "", "recovery_s": self.T / 2,
                "clock_tolerance_s": TOLERANCE_S, "resolution_s": 0.001}

    def channels(self) -> List[str]:
        return ["pull-list"]

    def standing_channels(self) -> List[str]:
        """Standing evidence only as the agent staples it (`_standing`), or for ``pull-good``
        only by fetching it."""
        return ["pull"] if self.pull_only else ["stapled"]

    def keys_from(self) -> str:
        """Each organisation's key statement is read once, at bind (`_bind`)."""
        return "bind"

    def grant_profile(self) -> Optional[str]:
        return None

    def delegation_forms(self) -> List[str]:
        return ["a", "holder"]

    def constraint_profile(self) -> List[str]:
        return ["max_amount", "operations", "resources", "audience", "window", "delegation"]

    def format_features(self) -> List[str]:
        return ["operation-lists", "second-chain", "mappings", "stated-depth", "crit", "units",
                "currency", "standing-limits"]

    def constraint_bindings(self) -> Dict[str, Any]:
        return {}

    def accepts_holder_hops(self) -> bool:
        return True

    def max_depth(self) -> Optional[int]:
        return self.depth

    def issuers(self) -> int:
        return 2

    def mappings(self) -> Dict[str, Any]:
        return {MAP_NAME: MAPPING}

    def documents_attenuation(self) -> bool:
        return True

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": PARTY, "endpoints": ["e1", "e2"], "tenants": [],
                "max_validity_s": 3600, "clock_tolerance_s": TOLERANCE_S}

    def evidence_grade(self) -> str:
        return "recorder"

    def set_clock(self, clock: Any) -> None:
        self._clock = clock

    def _c(self) -> Any:
        if self._clock is None:
            from conformance.timing import RealClock
            self._clock = RealClock()
        return self._clock

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "accepted", "queued": "in-progress",
                "refused": "refused"}.get(code, "error")

    def reached_guarantee(self, variant: str, answer: Dict[str, Any]) -> bool:
        return True

    # binding and status ---------------------------------------------------------------------

    def _bind(self, anchor: Dict[str, Any]) -> str:
        from conformance import standing as st
        iss = anchor["issuer"]
        v = st.verify(anchor["keyset"], {k: bytes(x) for k, x in anchor["anchor"].items()},
                      st.KEYSET_TYP)
        self.orgs[iss] = {"base": anchor["base_url"], "keyset": v.claims if v.ok else None}
        return iss

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        iss = self._bind(anchor)
        c = self._c()
        self._polls.append(c.call_every(lambda: self.T / 4.0, self._poll))
        return f"pinned {iss}; polling its status list"

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        return f"pinned {self._bind(anchor)}"

    def bind_recorder(self, recorder_url: str) -> str:
        self.recorder = recorder_url.rstrip("/")
        return f"effects to {self.recorder}/effect/<id>"

    def _get(self, base: str, path: str) -> Tuple[int, str]:
        from conformance import requester
        src = requester.local_source(base + "/status/list")
        if self.clock == "virtual" and src is not None:
            return src.fetch_local(path, client="toy-attenuation")
        try:
            with urllib.request.urlopen(base + path, timeout=max(0.2, self.T / 8)) as r:
                return r.status, r.read().decode("ascii")
        except urllib.error.HTTPError as e:
            return e.code, ""

    def _poll(self) -> None:
        from conformance import standing as st, status
        for iss, o in self.orgs.items():
            try:
                code, tok = self._get(o["base"], "/status/list")
            except Exception:  # noqa: BLE001
                continue
            if code != 200 or not o["keyset"]:
                continue
            v = status.verify(tok, st.keys_of(o["keyset"]), status.STATUS_TYP)
            if v.ok and (iss not in self.snaps
                         or v.claims["version"] >= self.snaps[iss]["version"]):
                self.snaps[iss] = v.claims
            if self.pull_only and v.ok:
                for principal in (v.claims.get("standing") or {}):
                    self._fetch_standing(iss, o, principal)

    def _fetch_standing(self, iss: str, o: Dict[str, Any], principal: str) -> None:
        """Pull only: A's standing assertion for `principal`, verified under A's statement."""
        from conformance import standing as st
        try:
            code, tok = self._get(o["base"], "/standing/" + urllib.parse.quote(principal,
                                                                             safe=""))
        except Exception:  # noqa: BLE001 - no answer
            return
        if code == 404:
            self.held.setdefault((iss, principal), None)
            return
        if code != 200 or not o["keyset"]:
            return
        v = st.verify(tok, st.keys_of(o["keyset"]), st.STANDING_TYP)
        if v.ok and v.claims["issuer"] == iss and v.claims["principal"] == principal:
            self.held[(iss, principal)] = v.claims["classes"]

    def _narrowings(self, chain: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
        """(index in the chain, narrowed max_amount) for each hop A's status narrows."""
        out = []
        for i, g in enumerate(chain):
            if self.flaw == "static_parent" and i > 0:
                continue
            src = (g.get("status") or {}).get("source", "")
            for snap in self.snaps.values():
                if snap.get("source") != src:
                    continue
                e = (snap.get("entries") or {}).get(g.get("grant_id"))
                if e and e.get("state") == "narrowed":
                    out.append((i, e["ceiling"]["max_amount"]))
        return out

    # reading the chain ----------------------------------------------------------------------

    def _shape(self, c: Any) -> Optional[str]:
        from conformance import attenuation as att
        p = att.grant_v2_problem(c)
        if p is None:
            return None
        reason, detail = p
        if self.flaw == "ignores_unknown" and reason == att.UNKNOWN:
            return None
        if self.flaw == "unions_grants" and reason == att.TWO_PARENTS:
            return None
        if self.flaw == "glob_operations" and "wildcard" in detail:
            return None
        if self.flaw == "defaults_fill" and "missing claims: not_after" in detail:
            return None
        return f"{reason}: {detail}"

    def _normalise(self, x: Any) -> Any:
        """The lenient flaws' reading of amounts, applied to a copy of the claims."""
        if isinstance(x, dict):
            if set(x) == {"value", "currency", "minor_units"}:
                v, cur, mu = x["value"], x["currency"], x["minor_units"]
                if self.flaw == "lenient_numbers" and isinstance(v, str):
                    try:
                        v = int(float(v))
                    except ValueError:
                        pass
                if self.flaw == "float_compare" and isinstance(v, (int, float)):
                    v = int(round(float(v)))
                    v = min(v, 2 ** 53 - 1)
                if self.flaw == "ignores_units":
                    mu = 0
                if self.flaw == "ignores_currency":
                    cur = "EUR"
                if self.flaw == "accepts_negative" and isinstance(v, int) and v < 0:
                    v = 0
                return {"value": v, "currency": cur, "minor_units": mu}
            return {k: self._normalise(v) for k, v in x.items()}
        if isinstance(x, list):
            return [self._normalise(v) for v in x]
        return x

    def _strip_unknown(self, g: Dict[str, Any]) -> Dict[str, Any]:
        from conformance import attenuation as att
        c = {k: v for k, v in (g.get("constraints") or {}).items()
             if k in att.CONSTRAINT_MEMBERS}
        out = {**g, "constraints": c}
        out.pop("crit", None)
        return out

    def _map(self, g: Dict[str, Any]) -> Dict[str, Any]:
        c = dict(g.get("constraints") or {})
        if "operations" in c and isinstance(c["operations"], list):
            ops: List[str] = []
            for o in c["operations"]:
                for x in MAPPING["operations"].get(o, [o]):
                    if x not in ops:
                        ops.append(x)
            c["operations"] = ops
        return {**g, "constraints": c}

    def _chain(self, p: Any, grant_h: str, chain_h: str) -> Tuple[Optional[str], Any]:
        from conformance import standing as st
        toks = [p.headers.get(grant_h) or ""] + [
            t for t in (p.headers.get(chain_h) or "").split(",") if t]
        if not toks[0]:
            return "no grant", None
        ids = [st.peek(t).get("grant_id") for t in toks]
        cyc = len(set(ids)) != len(ids) or any(st.peek(t).get("parent") in ids[:i + 1]
                                               for i, t in enumerate(toks))
        if self.flaw == "hangs_on_cycle" and cyc:
            return "__hang__", None
        anchors = {iss: o["keyset"] for iss, o in self.orgs.items() if o["keyset"]}
        lenient = self.flaw in LENIENT_PARSE
        hops, problem = st.verify_holder_chain(toks, anchors, lenient=lenient,
                                               problem_of=self._shape)
        if problem:
            return f"grant chain: {problem}", None
        return None, [h.claims for h in hops]

    def _judge(self, chain: List[Dict[str, Any]], values: Dict[str, Any],
               standing: Optional[Dict[str, Any]]) -> Optional[str]:
        """Why `values` are refused under `chain` (claims, presented grant first)."""
        from conformance import attenuation as att
        now = self._c().wall()
        if self.flaw in LENIENT:
            chain = [self._normalise(g) for g in chain]
            values = self._normalise(values)
        if self.flaw == "ignores_unknown":
            chain = [self._strip_unknown(g) for g in chain]
        if self.flaw != "maps_child_only":
            chain = [self._map(g) for g in chain]
        for i, ceiling in self._narrowings(chain):
            g = chain[i]
            m = (g.get("constraints") or {}).get("max_amount") or {}
            chain[i] = {**g, "constraints": {**g["constraints"], "max_amount": {
                **m, "value": min(m.get("value", ceiling), ceiling)}}}
        depth_ok = self.flaw in ("ignores_depth", "follows_unbounded")
        if not depth_ok and len(chain) > self.depth:
            return "the chain is longer than the stated maximum"
        if self.flaw == "leaf_only":
            return att._inside_one(values, chain[0]["constraints"], {}, party=PARTY,
                                   where="the presented grant")
        if self.flaw == "maps_child_only":
            return att._inside_one(values, self._map(chain[0])["constraints"], {}, party=PARTY,
                                   where="the presented grant, mapped")
        if self.flaw == "ends_only":
            why = self._structure(chain, values, standing, now)
            if why:
                return why
            for g in (chain[0], chain[-1]):
                why = att._inside_one(values, g["constraints"], {}, party=PARTY, where="an end")
                if why:
                    return why
            return None
        if self.flaw == "stops_at_seen":
            ids = [g["grant_id"] for g in chain]
            if chain[0]["parent"] == chain[0]["grant_id"]:
                return "a grant names itself"
            if chain[-1]["parent"] in ids:
                chain = chain[:-1] + [{**chain[-1], "parent": None}]
        if self.flaw == "walks_supplied_only" and chain[-1].get("parent") is not None:
            # The last grant supplied is read as the root, whatever parent it names.
            chain = chain[:-1] + [{**chain[-1], "parent": None}]
        if self.flaw in HOP_CHECKED:
            return self._structure(chain, values, standing, now) or \
                self._hop_checked(chain, values, now)
        if self.flaw == "ignores_depth":
            chain = [{**g, "constraints": {k: v for k, v in g["constraints"].items()
                                           if k != "delegation"}} for g in chain]
        al = att.allowed(chain, None if self.flaw == "ignores_standing_limit" else standing)
        if isinstance(al, att.Refusal):
            return f"{al.reason}: {al.detail}"
        if self.strict and al.hops_wider:
            return f"a hop is wider than its parent: {al.hops_wider}"
        return att.inside(values, al, at=now, tolerance_s=TOLERANCE_S, party=PARTY)

    def _structure(self, chain: List[Dict[str, Any]], values: Dict[str, Any],
                   standing: Optional[Dict[str, Any]], now: float) -> Optional[str]:
        """What the partial checkers still get right: links, cycles, depth, every grant's
        window, and the root's standing limit."""
        from conformance import attenuation as att
        ids = [g["grant_id"] for g in chain]
        if len(set(ids)) != len(ids) or any(g["parent"] == g["grant_id"] for g in chain):
            return "a cycle"
        for i in range(len(chain) - 1):
            if chain[i]["parent"] != chain[i + 1]["grant_id"]:
                return "the chain does not link"
        if chain[-1]["parent"] is not None:
            return "the chain does not end at a root"
        for i, g in enumerate(chain):
            d = (g.get("constraints") or {}).get("delegation")
            if isinstance(d, dict) and i > d.get("max_depth", 99):
                return "deeper than a grant permits"
            nb, na = att._epoch_s(g.get("not_before")), att._epoch_s(g.get("not_after"))
            if nb is not None and now < nb - TOLERANCE_S:
                return "a grant is not yet valid"
            if na is not None and now > na + TOLERANCE_S:
                return "a grant has expired"
        if standing is not None:
            lim = standing.get(values.get("operation"), "__none__")
            if lim == "__none__":
                return "the standing does not cover this operation"
            if lim:
                return att._inside_one(values, lim, {}, party=PARTY, where="the standing")
        return None

    def _hop_checked(self, chain: List[Dict[str, Any]], values: Dict[str, Any], now: float
                     ) -> Optional[str]:
        """Every hop against its parent, then the request against the leaf, each with this
        flaw's reading."""
        from conformance import attenuation as att
        for i in range(len(chain) - 1):
            child, parent = chain[i], chain[i + 1]
            cc, pc = dict(child["constraints"]), parent["constraints"]
            if self.flaw == "glob_operations" and "*" in (cc.get("operations") or []):
                cc.pop("operations")
            if self.flaw == "compares_backwards" and "resources" in cc and "resources" in pc:
                if not all(any(att.covers(c, p) for c in cc["resources"])
                           for p in pc["resources"]):
                    return "resources wider than the parent's"
                cc.pop("resources")
            probe = {**child, "constraints": cc}
            if "not_after" not in probe:
                probe["not_after"] = parent["not_after"]
            w = att.wider(probe, parent)
            if w:
                return f"hop {i} is wider than its parent in {w}"
        leaf = chain[0]
        c = dict(leaf["constraints"])
        for i in range(1, len(chain)):                       # absent inherits from above
            for k, v in chain[i]["constraints"].items():
                if k not in c and self.flaw != "absent_means_any":
                    c[k] = v
        if self.flaw == "absent_means_any":
            pass                                             # absent read as any
        if self.flaw == "empty_means_any":
            c = {k: v for k, v in c.items() if v != []}
        if self.flaw == "defaults_fill" and "audience" not in leaf["constraints"]:
            c["audience"] = [PARTY]                          # B's own default
        if self.flaw == "glob_operations" and "*" in (c.get("operations") or []):
            c.pop("operations")
        if self.flaw == "compares_backwards":
            c["resources"] = leaf["constraints"].get("resources", c.get("resources"))
        why = att._inside_one(values, c, {}, party=PARTY, where="the presented grant")
        if why:
            return why
        nb = att._epoch_s(leaf.get("not_before"))
        na = att._epoch_s(leaf.get("not_after")) if leaf.get("not_after") else now + 86400
        if nb is None or now < nb - TOLERANCE_S or now > (na or 0) + TOLERANCE_S:
            return "outside the presented grant's window"
        return None

    def _standing(self, p: Any, root: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        from conformance import standing as st
        if self.pull_only:
            key = (root["issuer"], root["principal"])
            if key in self.held:
                return self.held[key]
            if self.flaw == "chain_before_fetch":
                return None                         # not yet answered: the chain alone
            return UNANSWERED
        tok = p.headers.get(st.STANDING_HEADER)
        if not tok:
            return None
        o = self.orgs.get(root["issuer"])
        if not o or not o["keyset"]:
            return None
        v = st.verify(tok, st.keys_of(o["keyset"]), st.STANDING_TYP)
        if not v.ok or v.claims["issuer"] != root["issuer"] or \
                v.claims["principal"] != root["principal"]:
            return None
        return v.claims["classes"]

    # the entry point ------------------------------------------------------------------------

    def _decide(self, p: Any) -> Optional[Dict[str, Any]]:
        from conformance import authz, requester
        from conformance.issuer import CHAIN2_HEADER, GRANT2_HEADER
        why, chain = self._chain(p, requester.GRANT_HEADER, requester.CHAIN_HEADER)
        if why == "__hang__":
            return None
        if why:
            return _answer("refused", why)
        leaf = chain[0]
        ak = leaf["agent_key"]
        kid, gid_want, chain = self._leaf_binding(p, chain)
        v = authz.verify_authorisation(p.authorisation, {kid: bytes.fromhex(ak["public_key"])})
        if not v.ok or v.claims["issuer"] != leaf["subject"] or \
                v.claims.get("grant_id") != gid_want or \
                v.claims["audience"]["counterparty"] != PARTY:
            return _answer("refused", f"authorisation: {v.reason or 'not under this grant'}")
        if v.claims["binding"]["request_digest"] != authz.binding_digest(
                p.request, v.claims["binding"]["basis"]):
            return _answer("refused", "payload-mismatch")
        values = json.loads(p.request.decode("utf-8"))
        standing = self._standing(p, chain[-1])
        if standing is UNANSWERED:
            return _answer("refused", "standing-unavailable: A has not yet answered for the "
                                      "root principal")
        why = self._judge([dict(g) for g in chain], values, standing)
        if why and self.flaw == "unions_grants" and p.headers.get(GRANT2_HEADER):
            why2, chain2 = self._chain(p, GRANT2_HEADER, CHAIN2_HEADER)
            if not why2:
                why = self._union(chain, chain2, values)
        if why and self.flaw == "unions_grants" and isinstance(leaf.get("parent"), list):
            why = None
        if why:
            return _answer("refused", why)
        return self._effect(values)

    def _leaf_binding(self, p: Any, chain: List[Dict[str, Any]]
                      ) -> Tuple[str, str, List[Dict[str, Any]]]:
        """(the kid the request's authorisation is verified under, the grant id it must name,
        the chain to judge). A reader of another format whose ids differ on the wire overrides
        it."""
        leaf = chain[0]
        return leaf["agent_key"]["kid"], leaf["grant_id"], chain

    def _union(self, c1: List[Dict[str, Any]], c2: List[Dict[str, Any]],
               values: Dict[str, Any]) -> Optional[str]:
        """`unions_grants`: each dimension from whichever leaf allows it; amounts added."""
        from conformance import attenuation as att
        a, b = c1[0]["constraints"], c2[0]["constraints"]
        merged: Dict[str, Any] = {}
        for k in ("operations", "resources", "audience"):
            if k in a or k in b:
                merged[k] = list(a.get(k, [])) + list(b.get(k, []))
        if "max_amount" in a and "max_amount" in b:
            merged["max_amount"] = {**a["max_amount"], "value": a["max_amount"]["value"]
                                    + b["max_amount"]["value"]}
        return att._inside_one(values, merged, {}, party=PARTY, where="the union")

    def present(self, p: Any, *, session: Optional[str] = None) -> Dict[str, Any]:
        ans = self._decide(p)
        if ans is None:
            return {"status": None, "raised": "no answer (hangs on a cyclic chain)"}
        return ans

    def present_deferred(self, p: Any, session: Optional[str], deliver: Any) -> None:
        ans = self._decide(p)
        if ans is not None:
            deliver(ans)

    def _effect(self, values: Dict[str, Any]) -> Dict[str, Any]:
        url = (f"{self.recorder}/effect/{secrets.token_hex(6)}" if not self.no_control
               else f"{self.recorder.rsplit('/p21/', 1)[0]}/elsewhere/{secrets.token_hex(4)}")
        try:
            code, _h = _KEEP.post(url, json.dumps(values).encode("utf-8"))
        except Exception as e:  # noqa: BLE001
            return _answer("refused", f"effect failed: {type(e).__name__}")
        return _answer("executed", "performed") if code == 200 else \
            _answer("refused", f"effect failed {code}")


class ToyExampleFormat(ToyAttenuation):
    """``good`` reading the example delegation format only (module docstring)."""

    name = "toy-attenuation"

    def __init__(self, flaw: Optional[str] = None, **kw: Any) -> None:
        if flaw is not None and flaw not in EXAMPLE_FLAWS:
            raise ValueError(f"flaw {flaw!r} has no example-format reading")
        super().__init__("good" if flaw is None else "bad", flaw, **kw)
        from conformance import delegation_formats as df
        self.config = "example-good" if flaw is None else f"example-bad:{flaw}"
        self.depth = df.EXAMPLE_MAX
        self.example_orgs: set = set()
        """Organisations whose anchor named the example format: the only root signers."""

    def grant_profile(self) -> Optional[str]:
        from conformance import delegation_formats as df
        return df.EXAMPLE_NAME

    def delegation_forms(self) -> List[str]:
        return ["holder"]

    def format_features(self) -> List[str]:
        """``crit`` is stated and the format cannot carry it; ``stated-depth`` is not stated
        and the format adds it (`max_depth` states none, so the format's limit applies)."""
        return ["operation-lists", "crit", "units", "currency", "standing-limits"]

    def max_depth(self) -> Optional[int]:
        return None

    def mappings(self) -> Dict[str, Any]:
        return {}

    def bind_requester(self, anchor: Dict[str, Any], source_url: str, *,
                       receiver: Optional[str] = None) -> str:
        from conformance import delegation_formats as df
        d = anchor.get("example_delegation") or {}
        if d.get("version") == df.EXAMPLE_NAME and d.get("org") == anchor.get("issuer"):
            self.example_orgs.add(d["org"])
        return super().bind_requester(anchor, source_url, receiver=receiver)

    def _chain(self, p: Any, grant_h: str, chain_h: str) -> Tuple[Optional[str], Any]:
        """The presented grant first, then each parent, read into grant 0.2 claims."""
        from conformance import attenuation as att, delegation_formats as df, standing as st
        toks = [p.headers.get(grant_h) or ""] + [
            t for t in (p.headers.get(chain_h) or "").split(",") if t]
        if not toks[0]:
            return "no grant", None
        peeked = [st.peek(t) for t in toks]
        out: List[Dict[str, Any]] = []
        for n, tok in enumerate(toks):
            c = peeked[n]
            kid = st.header_of(tok).get("kid", "")
            if n + 1 == len(toks):
                o = self.orgs.get(str(c.get("by")))
                if c.get("by") not in self.example_orgs or not o or not o["keyset"]:
                    return f"the root's signer {c.get('by')!r} is not an organisation B pins",                         None
                stt, why = st.key_state(o["keyset"], kid, "grant",
                                        att._epoch_s(c.get("at")))
                if stt != "a-key":
                    return f"the root: {stt}: {why}", None
                pinned = {kid: st.keys_of(o["keyset"])[kid]}
            else:
                parent = peeked[n + 1]
                tk = parent.get("to_key") if isinstance(parent, dict) else None
                if not isinstance(tk, dict) or c.get("by") != parent.get("to"):
                    return (f"grant {n} is signed by {c.get('by')!r}, not by its parent's "
                            f"subject {parent.get('to')!r}"), None
                try:
                    pinned = {str(tk["kid"]): bytes.fromhex(str(tk["x"]))}
                except (KeyError, ValueError, TypeError):
                    return f"grant {n + 1} has no readable to_key", None
            v = st.verify(tok, pinned, df.EXAMPLE_TYP, problem_of=self._example_shape)
            if not v.ok:
                return f"grant {n}: {v.reason}: {v.detail}", None
            claims = self._as_grant(v.claims)
            why = self._shape(claims)
            if why:
                return f"grant {n}: {why}", None
            out.append(claims)
        return None, out

    @staticmethod
    def _example_shape(c: Any) -> Optional[str]:
        from conformance import delegation_formats as df
        if not isinstance(c, dict):
            return "a grant is not a JSON object"
        if c.get("v") != df.EXAMPLE_NAME:
            return f"v must be {df.EXAMPLE_NAME!r}"
        missing = [m for m in df.EXAMPLE_MEMBERS if m not in c and m not in ("from", "until")]
        if missing:
            return f"missing members: {', '.join(missing)}"
        extra = sorted(set(c) - set(df.EXAMPLE_MEMBERS))
        if extra:
            return f"unknown members: {', '.join(extra)}"
        tk = c["to_key"]
        if not isinstance(tk, dict) or set(tk) != {"kid", "x"}:
            return "to_key must be {kid, x}"
        return None

    @staticmethod
    def _as_grant(c: Dict[str, Any]) -> Dict[str, Any]:
        """One example grant as grant 0.2 claims; a missing window member stays missing."""
        from conformance import attenuation as att, delegation_formats as df

        def gid(x: Any) -> Any:
            return x[len(df.EXAMPLE_PREFIX):] if isinstance(x, str) and \
                x.startswith(df.EXAMPLE_PREFIX) else x
        up = c["up"]
        out = {"schema": att.GRANT_V2_SCHEMA, "grant_id": gid(c["id"]), "issuer": c["by"],
               "subject": c["to"], "agent_key": {"kid": c["to_key"]["kid"],
                                                 "public_key": c["to_key"]["x"]},
               "principal": c["for"], "constraints": c["allow"],
               "parent": [gid(x) for x in up] if isinstance(up, list) else gid(up),
               "issued_at": c["at"], "status": {"source": "none:" + df.EXAMPLE_NAME, "index": 0}}
        for member, name in (("from", "not_before"), ("until", "not_after")):
            if member in c:
                out[name] = c[member]
        return out

    def _leaf_binding(self, p: Any, chain: List[Dict[str, Any]]
                      ) -> Tuple[str, str, List[Dict[str, Any]]]:
        """The authorisation names the presented grant's id as the format writes it."""
        from conformance import delegation_formats as df
        leaf = chain[0]
        return leaf["agent_key"]["kid"], df.example_id(leaf["grant_id"]), chain


def make(flaw: Optional[str] = None, **kw: Any) -> ToyAttenuation:
    return ToyAttenuation("bad" if flaw else "good", flaw, **kw)


def toy(config: str) -> ToyAttenuation:
    if config == "example-good":
        return ToyExampleFormat()
    if config.startswith("example-bad:"):
        return ToyExampleFormat(config.split(":", 1)[1])
    if config.startswith("bad:"):
        return make(config[4:])
    return ToyAttenuation(config)
