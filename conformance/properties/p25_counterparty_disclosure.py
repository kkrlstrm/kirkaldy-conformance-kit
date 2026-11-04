"""P25 — Counterparty disclosure (KRK-25, cross-organisation X6).

**Guarantee** (`X6-COUNTERPARTY-DISCLOSURE-DESIGN.md` §1.4). For every effect B commits for another
organisation's agent, B's record of it names, as separate facts, the agent that made the request
and the principal it acted for, at the level the agreement sets for the operation; each comes from
evidence bound to this request by the party entitled to state it, at a basis no stronger than that
evidence; the principal stays named after the delegation ends; nothing in B's records or answers
about the principal exceeds the agreed level for anyone but that principal and A; and where B
states that an operation needs a disclosure or bars agents, no effect is committed for a request
without a valid one. Five clauses, reported apart: (a) ``actor``, (b) ``principal``,
(c) ``basis`` and binding, (d) ``level``, (e) ``requirement``.

**This is the residue only**. Whether the principal had standing is
X1 (P20); whether the effect is the one authorised is X3 (P18), so every attribution form keeps the
effect equal to its sibling's and a fixture whose effect differs reads ``not_landed`` here
(KRK-M175); human against agent inside one product is KRK-7.

**Who is graded.** B, the organisation that commits the effect. The kit plays A, its agents and
principals (`discloser.StubDiscloser`), a second organisation A′ and a third C (``a-issued``), or
the stand-in agent and the person at B's page (``b-held``, the B-issuer modules, unchanged).

**Two profiles**, from the adapter's `disclosure_profile()`, checked against
`bissuer.authority_of`: ``a-issued`` (A's signed statement states the principal) and ``b-held``
(B minted the agent's identity from a consent the person gave at B).

**Reading B's record by value**: the adapter returns B's record through B's read
path (`attribution_record`) and, on a self-hosted target, B's store (`store_rows`), raw; the kit
searches the B-originated bytes for the identifiers it drew (`disclosure.find`) and infers the
fields that tell actors apart from interleaved runs (`disclosure.infer_fields`). The adapter never
names a field. The kit's own outgoing bytes are never searched (KRK-M181).

**Within each trial**: **W** (the fixture), **L** (the sibling, identical but for the one thing
under test, which B must accept and attribute) and, where B has a direct path, **D** (the
principal acting without an agent). Each trial draws fresh principals, agents and identifiers from
the operating system (KRK-M186).

**Control** (§4.1): every presentation of the control is accepted, lands exactly once at the
recorder, attributed to its request by B's operation id (KRK-M170), and B's read path returns a
record for it; the read of B's answers works. It never requires that B's record names the agent
or the principal, that B reads the disclosure, refuses anything, labels a basis or keeps a level
(KRK-M19).

**Outcomes** per trial: pass ``attributed``, ``refused_as_expected``; fail ``misattributed``,
``actor_not_shown``, ``unattributed``, ``over_disclosed``, ``performed_undisclosed``; information
``collateral_refusal``, ``not_landed``, ``format_gap``, ``stored_token``, ``record_late``,
``echoed``, ``no_attribution``, ``undeclared_normalisation``, ``no_sibling``, ``not_stated``.

**Result**: ``fail`` if any landed form fails; ``pass`` if the control held, every landed form
passed and every form in `MUST_LAND` for the profile read a verdict; else ``inconclusive``.
``extra["clauses"]`` gives the reading per clause, ``extra["forms"]`` per form,
``extra["disclosure_forms"]`` the class per failing form (§1.8).

Claim basis is the runner's (`conformance.claim_basis`), as for every property; the probe
reads every form the profile has. A must-land form a target does not claim and that did not land
leaves the result inconclusive (the fail-safe direction).
"""
from __future__ import annotations

import json
import os
import random
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .. import disclosure as dz
from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P25"
TITLE = "Counterparty disclosure"
FIXTURES = ("known_bad/disclosure_toys.py", "tests/test_p25_counterparty_disclosure.py",
            "tests/vectors/krk25/*.json")
ENVIRONMENT = ("python", "package:cryptography")
UNSEEDED = ("Principals, agents, organisations, keys, pairwise secrets, salts, request refs and "
            "authorisation ids come from the operating system, never from the seed (KRK-M36, "
            "KRK-M186).",
            "The seed draws the form order, the order of W, L and D within a trial, and amounts.")

PROFILES = ("a-issued", "b-held")
VARIANTS = ("actor_shown", "principal_shown", "asserted_principal", "foreign_disclosure",
            "self_asserted", "approval_basis", "missing_disclosure", "level_exceeded",
            "outlives_delegation", "chain")
FORMS = {"actor_shown": ("agent", "person_direct"),
         "principal_shown": ("named", "pairwise", "organisation"),
         "asserted_principal": ("header", "body_member", "query"),
         "foreign_disclosure": ("other_request", "other_agent", "other_issuer"),
         "self_asserted": ("agent_signed", "unsigned"),
         "approval_basis": ("agent_asserted", "standing_permission"),
         "missing_disclosure": ("required_absent", "agent_barred"),
         "level_exceeded": ("answer_to_other_agent", "answer_to_other_counterparty",
                            "pseudonym_linkable", "named_in_pairwise"),
         "outlives_delegation": ("grant_ended", "consent_revoked"),
         "chain": ("two_hops", "into_c")}
CLAUSE_OF = {"actor_shown": ("actor",), "approval_basis": ("actor",),
             "chain": ("actor", "principal"), "principal_shown": ("principal",),
             "outlives_delegation": ("principal",), "asserted_principal": ("basis",),
             "foreign_disclosure": ("basis",), "self_asserted": ("basis", "requirement"),
             "level_exceeded": ("level",), "missing_disclosure": ("requirement",)}
B_HELD_ONLY = {("approval_basis", "*"), ("level_exceeded", "pseudonym_linkable"),
               ("level_exceeded", "named_in_pairwise"), ("outlives_delegation", "consent_revoked")}
A_ISSUED_ONLY = {("foreign_disclosure", "*"), ("self_asserted", "*"),
                 ("outlives_delegation", "grant_ended"), ("chain", "*")}
MUST_LAND = {"a-issued": (("actor_shown", "agent"), ("asserted_principal", "header"),
                          ("foreign_disclosure", "other_request")),
             "b-held": (("actor_shown", "agent"),)}
"""Forms that must read a verdict (design §6.4 `NA_FORBIDDEN`), with the control and
``principal_shown`` at every level the agreement sets (`_must_land`)."""
NA_FORBIDDEN = ("control", "actor_shown", "principal_shown", "asserted_principal",
                "foreign_disclosure")
"""Variants an adapter may not declare not applicable (`variants_not_applicable`)."""
TRIALS = {"*": 5}
DEV_TRIALS = {"*": 3}
GRADES = ("b-store", "b-record", "b-signed", "b-response", "library-decision")
PLAN_ENV = "ACK_P25_PLAN"
VULNERABLE = {("asserted_principal", "*"), ("foreign_disclosure", "*"),
              ("missing_disclosure", "*"), ("level_exceeded", "*")}
"""Forms whose failure can be vulnerability class where the target documents the guarantee
(§1.8). The runner's claim-basis rule lowers the class of an unclaimed form."""
PASS = ("attributed", "refused_as_expected")
FAIL = ("misattributed", "actor_not_shown", "unattributed", "over_disclosed",
        "performed_undisclosed")
INFO = ("collateral_refusal", "not_landed", "format_gap", "stored_token", "record_late",
        "echoed", "no_attribution", "undeclared_normalisation", "no_sibling", "not_stated")
READ_WAIT_S = 10.0
"""How long the kit waits for B's read path to show an operation or a landed effect (KRK-M179)."""
STEP_S = 0.01
VALUE_MEMBERS = ("operation", "ref", "amount", "recipient", "note")
"""The members of a request the effect is made of. W's effect is compared with L's on every one
but ``ref`` (KRK-M175)."""
REUSE_AUTHORISATION = False
"""Only a test sets this: ``foreign_disclosure/other_request`` then presents W under R1's own
authorisation, as KRK-M183 describes, so the pin shows the guard refusing to read it."""


# --------------------------------------------------------------------------- small parts


def _jsonable(x: Any) -> Any:
    return json.loads(json.dumps(x, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))


def _is_toy(a: Any) -> bool:
    mod = type(a).__module__ or ""
    return mod.startswith(("known_bad.", "tests.", "test_")) or mod == "__main__"


def _plan_from_env() -> Optional[Dict[str, Any]]:
    raw = os.environ.get(PLAN_ENV)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return {"trials": raw}


class _Progress:
    """``NN-progress.jsonl``: one JSON line per event, synced as written."""

    def __init__(self, ev: Evidence) -> None:
        self.path = ev.write("progress.jsonl", "")
        self._lock = threading.Lock()

    def add(self, event: str, **doc: Any) -> None:
        rec = {"event": event, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **doc}
        line = json.dumps(_jsonable(rec), sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())


def _in(form: Tuple[str, str], spec: set) -> bool:
    return (form[0], "*") in spec or form in spec


@dataclass
class Principal:
    """One principal in one trial, with every identifier the kit can search for."""

    label: str
    named: str
    pairwise: Dict[str, str] = field(default_factory=dict)
    """Counterparty or tenant -> the pseudonym for it."""
    commitment: Optional[str] = None
    handle: Any = None
    """``b-held``: the adapter's handle for the test person; the hook acting as them."""
    hook: Any = None

    def needles(self) -> Dict[str, Tuple[str, str]]:
        out = {f"{self.label}:named": ("named", self.named),
               f"{self.label}:hash": ("hash", dz.plain_hash(self.named))}
        for k, v in self.pairwise.items():
            out[f"{self.label}:pairwise@{k}"] = ("pairwise", v)
        if self.commitment:
            out[f"{self.label}:commitment"] = ("commitment", self.commitment)
        return out


@dataclass
class Agent:
    """One agent in one trial."""

    label: str
    ids: List[str]
    """Every identifier that names it: its subject and key id (``a-issued``), or the identity B
    minted for it and its client id (``b-held``)."""
    org: str
    subject: str = ""
    holder: Any = None
    stand_in: Any = None
    tenant: Optional[str] = None
    principal: Optional[Principal] = None
    """``b-held``: the person whose consent the agent acts under."""


@dataclass
class Sent:
    label: str
    pid: str
    kind: str
    """``accepted`` | ``refused`` | ``error``, by the adapter's `classify`."""
    op_id: Optional[str]
    ref: Optional[str]
    values: Dict[str, Any]
    answer: Any = None
    landed: bool = True
    why: str = ""
    endpoint: str = ""


@dataclass
class Rec:
    """B's account of one operation, as the kit read it."""

    flat: Dict[str, str]
    echo: List[str]
    grade: str
    raw: Any = None

    def clean(self) -> Dict[str, str]:
        """The paths that are B's own account: not request content echoed back (KRK-M171), not
        inside a stored token (KRK-M188)."""
        e = set(self.echo)
        return {p: v for p, v in self.flat.items() if p not in e and not dz.in_token(p)}

    def token_only(self) -> Dict[str, str]:
        return {p: v for p, v in self.flat.items() if dz.in_token(p)}

    def echoed(self) -> Dict[str, str]:
        e = set(self.echo)
        return {p: v for p, v in self.flat.items() if p in e}


def _trial(outcome: str, detail: str = "", **extra: Any) -> Dict[str, Any]:
    ok = True if outcome in PASS else False if outcome in FAIL else None
    return {"outcome": outcome, "ok": ok, "detail": detail, "extra": _jsonable(extra)}


# --------------------------------------------------------------------------- the run


class _Run:
    """What one probe run shares: the transport, the recorder, B's statements, the stubs."""

    def __init__(self, a: Any, ev: Evidence, *, profile: str, st: Dict[str, Any],
                 rng: random.Random, recorder: Any, prefix: str, plan: Dict[str, Any]) -> None:
        from ..requester import Transport
        self.a, self.ev, self.profile, self.st, self.rng = a, ev, profile, st, rng
        self.recorder, self.prefix, self.plan = recorder, prefix, plan
        self.tr = Transport(a.present)
        self.progress: Optional[_Progress] = None
        self.cp = st["agreement"]["counterparty"]
        self.endpoints = list(st["agreement"].get("endpoints") or ["default"])
        self.endpoint = self.endpoints[0]
        self.tenants = list(st["agreement"].get("tenants") or [None])
        self.norm = dz.normaliser(st.get("normalisation"))
        self.labels = dict((st.get("labels_basis") or {}).get("labels") or {})
        self._eidx = 0
        self._effects: Dict[str, List[Dict[str, Any]]] = {}
        self._elock = threading.Lock()
        self.A: Any = None
        self.A2: Any = None
        self.C: Any = None
        self.objs: Any = None
        self.published: Dict[Any, Any] = {}
        self.n = 0
        self.findings: List[str] = []
        self.used_authorisations: set = set()

    # logging ---------------------------------------------------------------------------------

    def log(self, event: str, **doc: Any) -> None:
        if self.progress is not None:
            self.progress.add(event, **doc)

    # operations from B's statements ------------------------------------------------------------

    def op_at(self, level: str) -> Optional[str]:
        """An operation whose agreed level is `level` and that has no requirement."""
        for op, d in sorted((self.st.get("levels") or {}).items()):
            if d.get("agreed") == level and not self.req_of(op):
                return op
        return None

    def op_plain(self) -> Optional[Tuple[str, str]]:
        """The operation the attribution forms use: the first with no requirement, preferring a
        named level. Returns (operation, its agreed level)."""
        for level in ("named", "pairwise", "organisation", "none"):
            op = self.op_at(level)
            if op:
                return op, level
        return None

    def req_of(self, op: str) -> Optional[str]:
        r = (self.st.get("requirements") or {}).get(op)
        return (r or {}).get("requirement") if isinstance(r, dict) else r

    def op_with(self, requirement: str) -> Optional[Tuple[str, str]]:
        for op, d in sorted((self.st.get("requirements") or {}).items()):
            if (d or {}).get("requirement") == requirement:
                lv = ((self.st.get("levels") or {}).get(op) or {}).get("agreed", "named")
                return op, lv
        return None

    # values and presentations -----------------------------------------------------------------

    def values(self, op: str, *, like: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fresh values: a ``ref`` from the operating system; the rest drawn from the seed, or
        copied from `like` (W and L share every value but ``ref``). Resources are neutral: they
        name neither principal (KRK-M172)."""
        if like is not None:
            v = dict(like)
            v["ref"] = f"r-{secrets.token_hex(8)}"
            return v
        return {"operation": op, "ref": f"r-{secrets.token_hex(8)}",
                "amount": self.rng.randrange(100, 99_999),
                "recipient": f"acct-{secrets.token_hex(5)}@neutral.test",
                "note": f"n{self.rng.getrandbits(32):08x}"}

    def audience(self, endpoint: Optional[str] = None, tenant: Any = None) -> Dict[str, Any]:
        return {"counterparty": self.cp, "endpoint": endpoint or self.endpoint, "tenant": tenant}

    def send(self, p: Any, label: str, values: Dict[str, Any], *,
             principals: Sequence[Principal] = ()) -> Sent:
        """Present once. A drawn principal identifier in the request bytes or the endpoint means
        the fixture would read B's echo as attribution: it is not presented (KRK-M171)."""
        body = p.request.decode("utf-8", "replace") + "|" + str(p.endpoint)
        for pr in principals:
            if pr.named and pr.named in body:
                return Sent(label, p.pid, "not_sent", None, values.get("ref"), values,
                            landed=False, why=f"{pr.label}'s identifier is in the request "
                                              f"(KRK-M171)")
        if self.profile == "a-issued" and isinstance(p.authorisation, str):
            if p.authorisation in self.used_authorisations:
                return Sent(label, p.pid, "not_sent", None, values.get("ref"), values,
                            landed=False, why="the authorisation was presented before "
                                              "(KRK-M183)")
            self.used_authorisations.add(p.authorisation)
        ans = self.tr.send(p)
        try:
            kind = self.a.classify(ans)
        except Exception as e:  # noqa: BLE001
            kind = "error"
            ans = {"raised": f"{type(e).__name__}: {e}"}
        op = None
        if kind == "accepted":
            try:
                op = self.a.operation_of(ans)
            except Exception:  # noqa: BLE001
                op = None
        s = Sent(label, p.pid, kind, op, values.get("ref"), values, answer=ans,
                 endpoint=str(p.endpoint))
        got = getattr(self.a, "received", None)
        if callable(got):
            r = got(p.pid)
            if r is not None and (r.get("headers") != dict(p.headers)
                                  or r.get("request") not in (None, p.request)):
                s.landed = False
                s.why = "B received other headers or bytes than the kit sent (KRK-M182)"
        self.n += 1
        self.log("present", label=label, pid=p.pid, kind=kind, op_id=op, ref=s.ref,
                 headers=sorted(p.headers), landed=s.landed)
        return s

    # the recorder -----------------------------------------------------------------------------

    def _refresh(self) -> None:
        with self._elock:
            got, self._eidx = self.recorder.effects_after(self._eidx, self.prefix)
            for e in got:
                ref = (e.get("effect") or {}).get("ref")
                if ref is not None:
                    self._effects.setdefault(str(ref), []).append(e)

    def effects(self, ref: Optional[str]) -> List[Dict[str, Any]]:
        self._refresh()
        with self._elock:
            return list(self._effects.get(str(ref), [])) if ref else []

    def wait_effect(self, ref: Optional[str], limit_s: float = READ_WAIT_S) -> List[Dict[str, Any]]:
        end = time.monotonic() + limit_s
        while True:
            got = self.effects(ref)
            if got or time.monotonic() > end:
                return got
            time.sleep(STEP_S)

    # B's record -------------------------------------------------------------------------------

    def record(self, s: Sent, *, wait: bool = True) -> Optional[Rec]:
        """B's record of `s`'s operation, read by B's operation id only (KRK-M170), once B's read
        path shows it (KRK-M179). None if nothing is readable within `READ_WAIT_S`."""
        if not s.op_id:
            return None
        end = time.monotonic() + (READ_WAIT_S if wait else 0.0)
        while True:
            rec = self._read(s)
            if rec is not None or time.monotonic() > end:
                return rec
            time.sleep(STEP_S)

    def _read(self, s: Sent) -> Optional[Rec]:
        r = st = None
        try:
            r = self.a.attribution_record(s.op_id)
        except Exception:  # noqa: BLE001
            r = None
        if callable(getattr(self.a, "store_rows", None)):
            try:
                st = self.a.store_rows(s.op_id)
            except Exception:  # noqa: BLE001
                st = None
        if r in (None, {}, [], b"") and not st:
            return None
        doc: Dict[str, Any] = {}
        grade = self.st["grade"]
        if r not in (None, {}, [], b""):
            doc["record"] = r
        if st:
            doc["store"] = st
        flat = dz.flatten(doc)
        toks = [s.ref, str(s.values.get("recipient") or ""), str(s.values.get("note") or "")]
        return Rec(flat, dz.echo_paths(flat, toks), grade, _jsonable(doc))

    def answer_flat(self, caller: Any, op_id: str) -> Tuple[Optional[Dict[str, str]], Any]:
        """B's answer to `caller` about `op_id`, flattened: B-originated bytes only (KRK-M181)."""
        try:
            ans = self.a.answer_as(caller, op_id)
        except Exception as e:  # noqa: BLE001
            return None, f"{type(e).__name__}: {e}"
        if ans is None:
            return None, None
        return dz.flatten({"answer": ans}), _jsonable(ans)

    # readings ---------------------------------------------------------------------------------

    def hits(self, rec: Rec, needles: Dict[str, str]) -> Dict[str, List[str]]:
        return dz.find(rec.clean(), needles, normalise=self.norm)

    def principal_reading(self, rec: Optional[Rec], want: str, level: str,
                          pr: Principal) -> Tuple[str, str]:
        """Whether `rec` names `pr` by `want` (the identifier at `level`), as B's own fact."""
        if rec is None:
            return "record_late", "B's read path showed nothing for the operation in time"
        if self.hits(rec, {"want": want}):
            over = dz.over_level(rec.clean(), level, pr.needles(), normalise=self.norm) \
                if self.profile == "a-issued" else []
            if over:
                return "over_disclosed", f"the record carries {over} above level {level}"
            return "attributed", f"{want} is in the record"
        if dz.find(rec.token_only(), {"want": want}):
            return "stored_token", "the principal is only inside a token B stored (KRK-M188)"
        if dz.find(rec.echoed(), {"want": want}):
            return "echoed", "the principal is only in request content B echoed (KRK-M171)"
        if dz.find_folded(rec.clean(), {"want": want}):
            return "undeclared_normalisation", ("the principal appears only after case-folding, "
                                                "which B did not declare (KRK-M187)")
        return "unattributed", f"no {level} identifier of the principal in B's record"

    def label_on(self, rec: Rec, which: str) -> Optional[bool]:
        """Whether B's record carries B's declared word for `which` as a leaf value; None when B
        declared no word for it."""
        word = self.labels.get(which)
        if not word:
            return None
        return any(v == word for v in rec.clean().values())

    def attested(self, rec: Rec) -> bool:
        """Whether the record states the a-attested basis. A B that declares no basis labels
        records every attribution as plain fact, so a recorded principal counts as attested
        (clause c)."""
        a = self.label_on(rec, "a-attested")
        if a is None:
            return True
        weaker = any(self.label_on(rec, b) for b in ("agent-asserted", "unattested"))
        return bool(a) and not weaker

    def same_effect(self, w: Sent, l: Sent) -> bool:
        """KRK-M175: W's effect equals L's in every member but ``ref``."""
        we, le = self.effects(w.ref), self.effects(l.ref)
        if len(we) != 1 or len(le) != 1:
            return False
        a = {k: v for k, v in (we[0].get("effect") or {}).items() if k != "ref"}
        b = {k: v for k, v in (le[0].get("effect") or {}).items() if k != "ref"}
        return a == b


# --------------------------------------------------------------------------- the two profiles


class _AIssued:
    """``a-issued``: A states the principal in its signed disclosure."""

    def __init__(self, run: _Run) -> None:
        self.run = run

    def principal(self, label: str, org: Any = None) -> Principal:
        A = org or self.run.A
        p = A.principal()
        return Principal(label, p, {self.run.cp: A.pseudonym(p, self.run.cp)}, A.commit(p))

    def agent(self, label: str, org: Any = None) -> Agent:
        A = org or self.run.A
        sub = f"agent-{secrets.token_hex(5)}"
        k = A.agent(sub)
        return Agent(label, [sub, k.kid], A.issuer, subject=sub, holder=A)

    def want(self, pr: Principal, level: str) -> Optional[str]:
        return {"named": pr.named, "pairwise": pr.pairwise.get(self.run.cp),
                "organisation": pr.commitment}.get(level)

    def act(self, ag: Agent, pr: Principal, op: str, level: str, label: str, *,
            values: Optional[Dict[str, Any]] = None, asserted: Optional[Tuple[str, str]] = None,
            signer: Optional[str] = "a", disclosure: Any = None, issuer: Any = None,
            endpoint: Optional[str] = None) -> Sent:
        """A request by `ag` for `pr`: A's disclosure at `level` (``signer`` ``a``, ``agent``,
        ``none``; None sends no disclosure, or `disclosure` sends the one given), with an
        asserted member ``(where, value)`` where a fixture adds one."""
        run = self.run
        v = dict(values or run.values(op))
        extra: Dict[str, str] = {}
        if asserted:
            where, val = asserted
            if where == "body_member":
                v[dz.ASSERT_MEMBER] = val
            elif where == "header":
                extra[dz.ASSERT_HEADER] = val
            elif where == "query":
                extra[dz.QUERY + dz.ASSERT_MEMBER] = val
        raw = ag.holder.request_raw(v)
        aud = run.audience(endpoint)
        d = disclosure
        if d is None and signer is not None and level != "none":
            d = (issuer or run.A).disclose(raw, agent=ag.subject, principal=pr.named,
                                           level=level, audience=run.cp, signer=signer,
                                           holder=ag.holder)
        p, _c = run.A.presentation(raw, subject=ag.subject, audience=aud, operation=op,
                                   disclosure=d, extra_headers=extra, holder=ag.holder)
        return run.send(p, label, v, principals=[pr])

    def direct(self, pr: Principal, op: str, label: str, *,
               values: Optional[Dict[str, Any]] = None) -> Optional[Sent]:
        run = self.run
        if not run.st.get("direct_path"):
            return None
        v = dict(values or run.values(op))
        raw = run.A.request_raw(v)
        key = run.A.person(pr.named)
        p = run.a.direct_presentation(pr.named, raw, key=key, pid=f"d{secrets.token_hex(6)}",
                                      endpoint=run.endpoint)
        if p.headers.get(dz.HEADER) or _signed_by_agent(p, run):
            return Sent(label, p.pid, "not_sent", None, v.get("ref"), v, landed=False,
                        why="the direct request carries an agent credential (KRK-M178)")
        return run.send(p, label, v)

    def reader(self, ag: Agent, op_id: str) -> Any:
        return self.run.A.read_request(ag.subject, op_id, audience=self.run.audience(),
                                       holder=ag.holder)

    def end(self, ag: Agent) -> Dict[str, Any]:
        """A ends `ag`'s delegation: its key is retired in A's key statement (A's own act); the
        adapter then makes B pick it up, in whatever form B takes it."""
        ch = ag.holder.retire_key(ag.ids[1])
        # The statement gives the end to the millisecond; a request inside that millisecond is
        # signed before the end. Confirm only once A's clock is past it (KRK-M180).
        while ag.holder.now() <= ch.since + 0.005:
            time.sleep(0.002)
        how = self.run.a.end_delegation(ag.subject, by="a")
        return {"retired": ag.ids[1], "keyset_version": ch.version, "how": _jsonable(how)}


def _signed_by_agent(p: Any, run: _Run) -> bool:
    from .. import standing
    kid = standing.header_of(p.authorisation).get("kid") if p.authorisation else None
    agents = set()
    for org in (run.A, run.A2, run.C):
        if org is not None:
            agents.update(org.agent_kids())
    return kid in agents


class _BHeld:
    """``b-held``: B minted the agent's identity from a consent the person gave at B's page
    (the B-issuer modules, `stand_in` and `bissuer`, unchanged)."""

    def __init__(self, run: _Run) -> None:
        from ..bissuer import BObjectLog
        self.run = run
        run.objs = BObjectLog()

    def principal(self, label: str, org: Any = None) -> Principal:
        from ..bissuer import authority_of
        from ..stand_in import hook_problem
        a = self.run.a
        h = a.new_person()
        hook = a.hook(person=h)
        why = hook_problem(hook, (authority_of(a).hook or {}).get("kind"))
        if why:
            raise RuntimeError(f"the person hook may not be used: {why} (B-issuer design §2.3)")
        return Principal(label, "", {}, None, handle=h, hook=hook)

    def agent(self, label: str, org: Any = None, *, principal: Optional[Principal] = None,
              tenant: Any = None) -> Agent:
        run = self.run
        (si,) = run.a.agent(1)
        tenant = tenant if tenant is not None else run.tenants[0]
        ag = Agent(label, [si.identity().client_id], str(tenant), stand_in=si, tenant=tenant,
                   principal=principal)
        if principal is not None:
            self.consent(ag, principal)
        return ag

    def consent(self, ag: Agent, pr: Principal) -> None:
        """The pair's one consent through the hook (B-issuer design §2.3), and the identities B
        minted, read from B's own signed object (the adapter names them; the kit checks each is
        in the object it verified)."""
        from .. import bissuer
        run = self.run
        rec = ag.stand_in.consent(pr.hook, tenant=ag.tenant, pair=f"p25-{run.n}")
        cred = rec.credential
        if cred is None:
            raise RuntimeError("B issued no credential on the consent")
        keys = run.a.published_keys(ag.tenant)
        run.published[ag.tenant] = keys
        v = bissuer.verify_b_object(cred.raw, keys)
        cred.verified = v.ok
        run.objs.add(cred)
        if not v.ok:
            raise RuntimeError(f"B's consent object does not verify: {v.detail}")
        ids = dict(run.a.identities(rec) or {})
        flat = dz.flatten(v.claims)
        for k, val in ids.items():
            if val and not dz.find(flat, {k: str(val)}):
                raise RuntimeError(f"identity {k}={val!r} is not in B's signed consent object")
        if ids.get("agent"):
            ag.ids.insert(0, str(ids["agent"]))
        if ids.get("principal_named"):
            if pr.named and pr.named != ids["principal_named"]:
                raise RuntimeError("B names the person differently in two consents")
            pr.named = str(ids["principal_named"])
        if ids.get("principal_pairwise"):
            pr.pairwise[str(ag.tenant)] = str(ids["principal_pairwise"])
        ag.principal = pr
        run.log("consent", agent=ag.label, tenant=ag.tenant, identities=ids,
                credential=cred.doc())

    def want(self, pr: Principal, level: str, tenant: Any = None) -> Optional[str]:
        if level == "named":
            return pr.named or None
        if level == "pairwise":
            return pr.pairwise.get(str(tenant if tenant is not None else self.run.tenants[0]))
        return None

    def act(self, ag: Agent, pr: Principal, op: str, level: str, label: str, *,
            values: Optional[Dict[str, Any]] = None, asserted: Optional[Tuple[str, str]] = None,
            signer: Optional[str] = "a", disclosure: Any = None, issuer: Any = None,
            endpoint: Optional[str] = None) -> Sent:
        """A request by `ag` under its consent; ``signer=None`` presents it without the consent
        (``missing_disclosure/required_absent``), through the adapter's `undisclosed_use`."""
        run = self.run
        v = dict(values or run.values(op))
        extra: Dict[str, str] = {}
        if asserted:
            where, val = asserted
            if where == "body_member":
                v[dz.ASSERT_MEMBER] = val
            elif where == "header":
                extra[dz.ASSERT_HEADER] = val
            elif where == "query":
                extra[dz.QUERY + dz.ASSERT_MEMBER] = val
        body = json.dumps(ag.stand_in.class_body(v), sort_keys=True,
                          separators=(",", ":")).encode()
        pid = f"h{secrets.token_hex(6)}"
        ep = endpoint or run.endpoint
        if signer is None:
            p = run.a.undisclosed_use(ag.stand_in, body, pid=pid, tenant=ag.tenant, endpoint=ep)
        else:
            p = ag.stand_in.class_use(body, pid=pid, tenant=ag.tenant, endpoint=ep,
                                      headers=extra or None)
        return run.send(p, label, v, principals=[pr])

    def direct(self, pr: Principal, op: str, label: str, *,
               values: Optional[Dict[str, Any]] = None) -> Optional[Sent]:
        run = self.run
        if not run.st.get("direct_path"):
            return None
        v = dict(values or run.values(op))
        raw = json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
        p = run.a.direct_presentation(pr.handle, raw, key=None, pid=f"d{secrets.token_hex(6)}",
                                      endpoint=run.endpoint)
        return run.send(p, label, v)

    def reader(self, ag: Agent, op_id: str) -> Any:
        return ag.stand_in

    def end(self, ag: Agent) -> Dict[str, Any]:
        how = self.run.a.end_delegation(ag.stand_in, by="person", hook=ag.principal.hook,
                                        tenant=ag.tenant)
        return {"how": _jsonable(how)}


# --------------------------------------------------------------------------- the forms


class _Forms:
    """One method per variant; each returns ``{form: [trial, ...]}``."""

    def __init__(self, run: _Run, prof: Any) -> None:
        self.run, self.P = run, prof

    # helpers ----------------------------------------------------------------------------------

    def _fresh(self, n_principals: int = 2, n_agents: int = 2) -> Tuple[List[Principal],
                                                                        List[Agent]]:
        prs = [self.P.principal(f"P{i + 1}") for i in range(n_principals)]
        if self.run.profile == "a-issued":
            ags = [self.P.agent(f"a{i + 1}") for i in range(n_agents)]
            if self.run.st.get("direct_path"):
                for pr in prs:
                    k = self.run.A.person(pr.named)
                    self.run.a.enrol_person(pr.named, k.kid, k.public_bytes())
        else:
            ags = [self.P.agent(f"a{i + 1}", principal=prs[min(i, len(prs) - 1)])
                   for i in range(n_agents)]
        return prs, ags

    def _want(self, pr: Principal, level: str, ag: Optional[Agent] = None) -> Optional[str]:
        if self.run.profile == "b-held":
            return self.P.want(pr, level, ag.tenant if ag else None)
        return self.P.want(pr, level)

    def _order(self, *items: Any) -> List[Any]:
        xs = list(items)
        self.run.rng.shuffle(xs)
        return xs

    def _accepted(self, *ss: Optional[Sent]) -> Optional[Dict[str, Any]]:
        """The information trial when a sibling or the person was refused, or a presentation did
        not land; None when every one landed and was accepted."""
        for s in ss:
            if s is None:
                continue
            if not s.landed:
                return _trial("not_landed", f"{s.label}: {s.why}")
            if s.kind != "accepted":
                return _trial("collateral_refusal", f"{s.label} was {s.kind} (KRK-M174)",
                              answer=s.answer)
        return None

    # (a) actor_shown ----------------------------------------------------------------------------

    def actor_shown(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {"agent": [], "person_direct": []}
        plain = run.op_plain()
        if plain is None:
            na = _trial("format_gap", "B states no operation without a requirement")
            return {"agent": [na], "person_direct": [na]}
        op, level = plain
        direct = bool(run.st.get("direct_path"))
        for _ in range(n):
            prs, ags = self._fresh(1, 1)
            pr, ag = prs[0], ags[0]
            start = run.rng.random() < 0.5
            seq = ["agent", "person"] * 2 if start else ["person", "agent"] * 2
            if not direct:
                seq = ["agent", "agent"]
            sent: List[Tuple[str, Sent]] = []
            for who in seq:
                s = (P.act(ag, pr, op, level, f"{who}") if who == "agent"
                     else P.direct(pr, op, "person"))
                sent.append((who, s))
            bad = self._accepted(*[s for _w, s in sent])
            if bad:
                out["agent"].append(bad)
                out["person_direct"].append(bad)
                continue
            recs = [(who, run.record(s), s) for who, s in sent]
            if any(r is None for _w, r, _s in recs):
                late = _trial("record_late", "a record did not appear in time (KRK-M179)")
                out["agent"].append(late)
                out["person_direct"].append(late)
                continue
            rows = [(who, r.clean()) for who, r, _s in recs]
            trans = dz.transport_paths([(r.clean(), _transport(s, run)) for _w, r, s in recs])
            inferred = dz.infer_fields(rows, exclude=trans) if direct else []
            ag_ids = {f"id{i}": x for i, x in enumerate(ag.ids)}
            agent_rows = [r for who, r, _s in recs if who == "agent"]
            person_rows = [r for who, r, _s in recs if who == "person"]
            on_agent = [run.hits(r, ag_ids) for r in agent_rows]
            detail = {"inferred": inferred, "transport_excluded": trans,
                      "agent_hits": on_agent}
            # agent
            if not all(on_agent):
                imp = _impersonated(pr, person_rows, agent_rows) if person_rows else \
                    bool(pr.named) and all(run.hits(r, {"p": pr.named}) for r in agent_rows)
                out["agent"].append(_trial(
                    "misattributed" if imp else "actor_not_shown",
                    "the agent's rows name the principal and not the agent" if imp else
                    "the agent's rows carry no identifier of the agent", **detail))
            elif direct:
                if inferred:
                    out["agent"].append(_trial("attributed", "the agent is named on its rows, and "
                                               f"{inferred} tell it from the person", **detail))
                else:
                    out["agent"].append(_trial(
                        "actor_not_shown", "the agent is named, but no field stable within "
                        "each actor tells the agent from the person", **detail))
            else:
                ag_paths = set().union(*(set(sum(h.values(), [])) for h in on_agent))
                pr_paths = set(sum(run.hits(agent_rows[0], {"p": pr.named}).values(), [])) \
                    if pr.named else set()
                if pr_paths and pr_paths <= ag_paths:
                    out["agent"].append(_trial("misattributed", "the agent and the principal "
                                               "share one field", **detail))
                else:
                    out["agent"].append(_trial("attributed", "agent and principal are distinct "
                                               "values on the row (no direct path, question "
                                               "342)", **detail))
            # person_direct
            if not direct:
                out["person_direct"].append(_trial("format_gap", "B states no direct path for "
                                                   "the principal"))
                continue
            p_ids = {"p": pr.named} if pr.named else {}
            on_person_agent = [run.hits(r, ag_ids) for r in person_rows]
            on_person = [run.hits(r, p_ids) if p_ids else {} for r in person_rows]
            if any(on_person_agent):
                out["person_direct"].append(_trial(
                    "misattributed", "the principal's own request is recorded with an agent's "
                    "identifier", person_agent_hits=on_person_agent, **detail))
            elif not inferred:
                out["person_direct"].append(_trial(
                    "actor_not_shown", "no field stable within each actor differs between the "
                    "agent and the person", **detail))
            elif p_ids and not all(on_person):
                out["person_direct"].append(_trial(
                    "actor_not_shown", "the principal's own request does not name them",
                    **detail))
            else:
                out["person_direct"].append(_trial("attributed", "the person and the agent are "
                                                   "told apart", **detail))
        return out

    # (b) principal_shown ----------------------------------------------------------------------

    def principal_shown(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {}
        for level in FORMS["principal_shown"]:
            op = run.op_at(level)
            if op is None:
                out[level] = [_trial("format_gap", f"no operation's agreed level is {level} "
                                     f"(KRK-M173)")]
                continue
            out[level] = []
            for _ in range(n):
                prs, ags = self._fresh(1, 1)
                pr, ag = prs[0], ags[0]
                want = self._want(pr, level, ag)
                if not want:
                    out[level].append(_trial("format_gap", f"B gave no {level} identifier for "
                                             f"the person (KRK-M173)"))
                    continue
                s = P.act(ag, pr, op, level, "W")
                bad = self._accepted(s)
                if bad:
                    out[level].append(bad)
                    continue
                rec = run.record(s)
                outcome, why = run.principal_reading(rec, want, level, pr)
                extra = {}
                if rec is not None and dz.find(rec.clean(), {"h": dz.plain_hash(pr.named)}):
                    extra["plain_hash"] = "the record holds the kit's own SHA-256 of the " \
                                          "named identifier (KRK-M184)"
                out[level].append(_trial(outcome, why, op=op, **extra))
        return out

    # (c) asserted_principal ---------------------------------------------------------------------

    def asserted_principal(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        plain = run.op_plain()
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["asserted_principal"]}
        if plain is None:
            return {f: [_trial("format_gap", "no operation without a requirement")] for f in out}
        op, level = plain
        for form in FORMS["asserted_principal"]:
            for _ in range(n):
                prs, ags = self._fresh(2, 2)
                p1, p2 = prs
                ag = ags[0]
                if run.profile == "b-held" and not p2.named:
                    out[form].append(_trial("not_landed", "B named no second person"))
                    continue
                want = self._want(p1, level, ag)
                lv = run.values(op)
                wv = run.values(op, like=lv)
                pair = self._order(("W", form), ("L", None))
                sent: Dict[str, Sent] = {}
                for lab, where in pair:
                    if lab == "W":
                        sent["W"] = P.act(ag, p1, op, level, "W", values=wv,
                                          asserted=(form, p2.named))
                    else:
                        sent["L"] = P.act(ag, p1, op, level, "L", values=lv)
                w, l = sent["W"], sent["L"]
                bad = self._accepted(l)
                if bad:
                    out[form].append(bad)
                    continue
                if not w.landed:
                    out[form].append(_trial("not_landed", w.why))
                    continue
                lrec = run.record(l)
                lo, lwhy = run.principal_reading(lrec, want, level, p1) if want else \
                    ("unattributed", "no identifier at the level")
                if w.kind != "accepted":
                    if run.effects(w.ref):
                        out[form].append(_trial("not_landed", "W was answered refused but its "
                                                "effect landed; that is X3's question"))
                    else:
                        out[form].append(_trial("attributed", "W refused; L accepted"))
                    continue
                run.wait_effect(w.ref)
                if not run.same_effect(w, l):
                    out[form].append(_trial("not_landed", "W's effect differs from L's: the "
                                            "member changed the effect, which is X3's "
                                            "question (KRK-M175)"))
                    continue
                wrec = run.record(w)
                if wrec is None:
                    out[form].append(_trial("record_late", "W's record did not appear"))
                    continue
                if run.hits(wrec, {"p2": p2.named}):
                    out[form].append(_trial("misattributed", "B recorded the principal the "
                                            "request member named", hits=run.hits(
                                                wrec, {"p2": p2.named})))
                    continue
                if lo != "attributed":
                    out[form].append(_trial("no_attribution", f"L: {lwhy}; B records no "
                                            f"principal, so there is no basis to test"))
                    continue
                wo, wwhy = run.principal_reading(wrec, want, level, p1)
                out[form].append(_trial("attributed" if wo == "attributed" else
                                        ("unattributed" if wo == "unattributed" else wo),
                                        f"W: {wwhy}"))
        return out

    # (c) foreign_disclosure ---------------------------------------------------------------------

    def foreign_disclosure(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["foreign_disclosure"]}
        plain = run.op_plain()
        if plain is None or plain[1] == "none":
            return {f: [_trial("format_gap", "no operation with a disclosed level")] for f in out}
        op, level = plain
        for form in FORMS["foreign_disclosure"]:
            for _ in range(n):
                if form == "other_issuer" and run.A2 is None:
                    out[form].append(_trial("format_gap", "B pins one organisation "
                                            "(KRK-M177)"))
                    continue
                prs, ags = self._fresh(2, 2)
                p1, p2 = prs
                a1, a2 = ags
                lv = run.values(op)
                wv = run.values(op, like=lv)
                foreign_pr = p1
                if form == "other_request":
                    r1 = run.values(op, like=lv)
                    raw1 = run.A.request_raw(r1)
                    d = run.A.disclose(raw1, agent=a1.subject, principal=p1.named, level=level,
                                       audience=run.cp, holder=a1.holder, broken="request")
                    if REUSE_AUTHORISATION:
                        p_r1, _ = run.A.presentation(raw1, subject=a1.subject,
                                                     audience=run.audience(), operation=op,
                                                     disclosure=d, holder=a1.holder)
                        run.used_authorisations.add(p_r1.authorisation)
                        mk = lambda: run.send(p_r1, "W", r1, principals=[p1])  # noqa: E731
                    else:
                        mk = lambda: P.act(a1, p1, op, level, "W", values=wv,  # noqa: E731
                                           disclosure=d)
                    wagent = a1
                elif form == "other_agent":
                    raw_w = run.A.request_raw(wv)
                    d = run.A.disclose(raw_w, agent=a1.subject, principal=p1.named, level=level,
                                       audience=run.cp, holder=a1.holder, broken="agent")
                    mk = lambda: P.act(a2, p1, op, level, "W", values=wv,  # noqa: E731
                                       disclosure=d)
                    wagent = a2
                else:
                    p3 = self.P.principal("P3", org=run.A2)
                    foreign_pr = p3
                    raw_w = run.A.request_raw(wv)
                    d = run.A2.disclose(raw_w, agent=a1.subject, principal=p3.named,
                                        level=level, audience=run.cp, holder=a1.holder,
                                        broken="issuer")
                    mk = lambda: P.act(a1, p1, op, level, "W", values=wv,  # noqa: E731
                                       disclosure=d)
                    wagent = a1
                order = self._order("W", "L")
                sent: Dict[str, Sent] = {}
                for lab in order:
                    sent[lab] = mk() if lab == "W" else P.act(a1, p1, op, level, "L", values=lv)
                w, l = sent["W"], sent["L"]
                bad = self._accepted(l)
                if bad:
                    out[form].append(bad)
                    continue
                if not w.landed:
                    out[form].append(_trial("not_landed", w.why))
                    continue
                if w.kind != "accepted":
                    out[form].append(_trial("attributed", "W refused; L accepted"))
                    continue
                wrec = run.record(w)
                if wrec is None:
                    out[form].append(_trial("record_late", "W's record did not appear"))
                    continue
                want_f = self._want(foreign_pr, level)
                named = run.hits(wrec, {"p": want_f}) if want_f else {}
                agent_named = run.hits(wrec, {"a1": a1.subject}) if form == "other_agent" else {}
                if (named or agent_named) and run.attested(wrec):
                    out[form].append(_trial("misattributed", "B recorded the foreign "
                                            "disclosure's principal or agent as A's statement",
                                            hits={**named, **agent_named}, agent=wagent.label))
                else:
                    out[form].append(_trial("attributed", "the foreign disclosure is not "
                                            "recorded as A's statement"))
        return out

    # (c)(e) self_asserted -------------------------------------------------------------------------

    def self_asserted(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["self_asserted"]}
        plain = run.op_plain()
        req = run.op_with("disclosure-required")
        if plain is None or plain[1] == "none":
            return {f: [_trial("format_gap", "no operation with a disclosed level")] for f in out}
        op, level = plain
        for form in FORMS["self_asserted"]:
            signer = "agent" if form == "agent_signed" else "none"
            for _ in range(n):
                prs, ags = self._fresh(1, 1)
                p1, a1 = prs[0], ags[0]
                lv = run.values(op)
                wv = run.values(op, like=lv)
                sent: Dict[str, Sent] = {}
                for lab in self._order("W", "L"):
                    sent[lab] = (P.act(a1, p1, op, level, "W", values=wv, signer=signer)
                                 if lab == "W" else P.act(a1, p1, op, level, "L", values=lv))
                w, l = sent["W"], sent["L"]
                bad = self._accepted(l)
                if bad:
                    out[form].append(bad)
                    continue
                if not w.landed:
                    out[form].append(_trial("not_landed", w.why))
                    continue
                verdict_w = None
                if w.kind == "accepted":
                    wrec = run.record(w)
                    if wrec is None:
                        out[form].append(_trial("record_late", "W's record did not appear"))
                        continue
                    want = self._want(p1, level)
                    if run.hits(wrec, {"p": want}) and run.attested(wrec):
                        verdict_w = _trial("misattributed", "the agent's own statement is "
                                           "recorded at the a-attested basis")
                if verdict_w is None and req is not None:
                    rop, rlevel = req
                    rl = P.act(a1, p1, rop, rlevel, "L-required")
                    rw = P.act(a1, p1, rop, rlevel, "W-required", signer=signer)
                    bad = self._accepted(rl)
                    if bad:
                        verdict_w = bad
                    else:
                        run.wait_effect(rl.ref)
                        if run.effects(rw.ref):
                            verdict_w = _trial("performed_undisclosed", f"an effect for {rop}, "
                                               "which B says needs disclosure, on the agent's "
                                               "own statement")
                out[form].append(verdict_w or _trial("attributed", "the agent's statement is "
                                                     "not recorded as A's"))
        return out

    # (a) approval_basis (b-held) ------------------------------------------------------------------

    def approval_basis(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run = self.run
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["approval_basis"]}
        appr = run.op_with("approval-required")
        if appr is None:
            return {f: [_trial("format_gap", "B states no operation that needs approval")]
                    for f in out}
        if not all(run.labels.get(x) for x in ("person", "agent-asserted")):
            return {f: [_trial("not_stated", "B declares no approval labels")]
                    for f in out}
        op = appr[0]
        for form in FORMS["approval_basis"]:
            how = "agent" if form == "agent_asserted" else "standing"
            for _ in range(n):
                prs, ags = self._fresh(1, 1)
                p1, a1 = prs[0], ags[0]
                lv = run.values(op)
                wv = run.values(op, like=lv)
                res: Dict[str, Tuple[Optional[Sent], str]] = {}
                for lab in self._order("W", "L"):
                    res[lab] = self._approve(a1, p1, op, wv if lab == "W" else lv, lab,
                                             "person" if lab == "L" else how)
                (l, lwhy), (w, wwhy) = res["L"], res["W"]
                if l is None or l.kind != "accepted":
                    out[form].append(_trial("collateral_refusal", f"L: {lwhy}"))
                    continue
                lrec = run.record(l)
                if lrec is None or not run.label_on(lrec, "person"):
                    out[form].append(_trial("no_attribution", "L, approved at B's page, is not "
                                            "labelled as the person's"))
                    continue
                if w is None or w.kind != "accepted":
                    out[form].append(_trial("attributed", f"W refused ({wwhy}); P20B grades "
                                            "that decision"))
                    continue
                wrec = run.record(w)
                if wrec is None:
                    out[form].append(_trial("record_late", "W's record did not appear"))
                    continue
                if run.label_on(wrec, "person"):
                    out[form].append(_trial("misattributed", "an approval the agent asserted is "
                                            "labelled as the person's"))
                else:
                    out[form].append(_trial("attributed", "labelled as not the person's"))
        return out

    def _approve(self, ag: Agent, pr: Principal, op: str, values: Dict[str, Any], label: str,
                 how: str) -> Tuple[Optional[Sent], str]:
        """B's approval flow (the stand-in protocol, unchanged): ask for B's object; the person
        approves at B's page (``how="person"``), or nobody does and the agent asserts it
        (``agent``) or relies on a standing permission (``standing``); then accept."""
        run = self.run
        si = ag.stand_in
        raw = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        first = run.send(si.request(raw, pid=f"q{secrets.token_hex(6)}", tenant=ag.tenant,
                                    endpoint=run.endpoint), f"{label}-request", values,
                         principals=[pr])
        if first.kind not in ("accepted",) and not first.answer:
            return None, f"B refused the request ({first.kind})"
        objs = si.read(first.answer, endpoint=run.endpoint)
        if not objs:
            return None, "B issued no object"
        obj = objs[-1]
        run.objs.add(obj)
        if how == "person":
            handle = si.person_needed(obj)
            if handle:
                pr.hook.approve(handle, pair=f"p25-{run.n}")
        body = json.dumps(si.acceptance_body(obj, approval=how), sort_keys=True,
                          separators=(",", ":")).encode()
        s = run.send(si.accept(obj, body, pid=f"x{secrets.token_hex(6)}", tenant=ag.tenant,
                               endpoint=run.endpoint), label, values, principals=[pr])
        return s, s.kind

    # (e) missing_disclosure ---------------------------------------------------------------------

    def missing_disclosure(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["missing_disclosure"]}
        for form in FORMS["missing_disclosure"]:
            want_req = "disclosure-required" if form == "required_absent" else "agents-barred"
            spec = run.op_with(want_req)
            if spec is None:
                out[form] = [_trial("not_stated", f"B states no operation as {want_req} "
                                    f"")]
                continue
            if form == "required_absent" and run.profile == "b-held" and \
                    not callable(getattr(run.a, "undisclosed_use", None)):
                out[form] = [_trial("format_gap", "B has no path for an agent's credential "
                                    "without its consent")]
                continue
            op, level = spec
            for _ in range(n):
                prs, ags = self._fresh(1, 1)
                p1, a1 = prs[0], ags[0]
                sent: Dict[str, Optional[Sent]] = {}
                labs = ["W", "L", "D"] if form == "required_absent" else ["W", "D"]
                for lab in self._order(*labs):
                    if lab == "W":
                        sent["W"] = (P.act(a1, p1, op, level, "W", signer=None)
                                     if form == "required_absent"
                                     else P.act(a1, p1, op, level, "W"))
                    elif lab == "L":
                        sent["L"] = P.act(a1, p1, op, level, "L")
                    else:
                        sent["D"] = P.direct(p1, op, "D")
                w = sent["W"]
                if form == "agent_barred" and sent.get("D") is None:
                    out[form].append(_trial("no_sibling", "no direct path: a bar cannot be told "
                                            "from refusing everyone (KRK-M185)"))
                    continue
                bad = self._accepted(sent.get("L"), sent.get("D"))
                if bad:
                    out[form].append(bad)
                    continue
                if not w.landed:
                    out[form].append(_trial("not_landed", w.why))
                    continue
                for k in ("L", "D"):
                    if sent.get(k) is not None:
                        run.wait_effect(sent[k].ref)
                if run.effects(w.ref):
                    out[form].append(_trial("performed_undisclosed", f"W's effect landed for "
                                            f"{op} ({want_req})", answer=w.kind))
                else:
                    out[form].append(_trial("refused_as_expected", "no effect for W; the "
                                            "siblings were accepted"))
        return out

    # (d) level_exceeded -----------------------------------------------------------------------

    def level_exceeded(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["level_exceeded"]}
        plain = run.op_plain()
        if plain is None:
            return {f: [_trial("format_gap", "no operation without a requirement")] for f in out}
        op, level = plain
        for form in FORMS["level_exceeded"]:
            if run.profile == "a-issued" and _in(("level_exceeded", form), B_HELD_ONLY):
                continue
            for _ in range(n):
                if form in ("answer_to_other_agent", "answer_to_other_counterparty"):
                    out[form].append(self._answer_to_other(form, op, level))
                elif form == "pseudonym_linkable":
                    out[form].append(self._linkable())
                else:
                    out[form].append(self._named_in_pairwise())
        return out

    def _answer_to_other(self, form: str, op: str, level: str) -> Dict[str, Any]:
        run, P = self.run, self.P
        prs, ags = self._fresh(1, 1)
        p1, a1 = prs[0], ags[0]
        if form == "answer_to_other_agent":
            other = (P.agent("a2") if run.profile == "a-issued"
                     else P.agent("a2", principal=self.P.principal("P2")))
        else:
            if run.profile == "a-issued":
                if run.A2 is None:
                    return _trial("format_gap", "B pins one organisation")
                other = P.agent("a'1", org=run.A2)
            else:
                if len(run.tenants) < 2:
                    return _trial("format_gap", "B states one counterparty")
                other = P.agent("a'1", principal=self.P.principal("P2"), tenant=run.tenants[1])
        w = P.act(a1, p1, op, level, "W")
        bad = self._accepted(w)
        if bad:
            return bad
        if run.record(w) is None:
            return _trial("record_late", "W's record did not appear")
        own, _ = run.answer_flat(P.reader(a1, w.op_id), w.op_id)
        flat, doc = run.answer_flat(P.reader(other, w.op_id), w.op_id)
        if flat is None:
            return _trial("attributed", "B gave the other party no answer about the operation",
                          own_answer_read=own is not None)
        over = dz.over_level(flat, "none", p1.needles(), normalise=run.norm)
        if over:
            return _trial("over_disclosed", f"B's answer to {other.label} carries {over}",
                          answer=doc)
        return _trial("attributed", f"B's answer to {other.label} carries nothing about the "
                      f"principal")

    def _linkable(self) -> Dict[str, Any]:
        from .. import bissuer
        run, P = self.run, self.P
        ps = run.st.get("pseudonyms") or {}
        if ps.get("scope") != "per-counterparty":
            return _trial("not_stated", "B does not state per-counterparty pseudonyms "
                          "")
        if len(run.tenants) < 2:
            return _trial("format_gap", "B states one counterparty")
        t1, t2 = run.tenants[:2]
        p1 = P.principal("P1")
        a1 = P.agent("a1", principal=p1, tenant=t1)
        a3 = P.agent("a3", principal=p1, tenant=t2)
        k1 = bissuer.thumbprints(run.published.get(t1))
        k2 = bissuer.thumbprints(run.published.get(t2))
        if not k1 or set(k1) & set(k2):
            return _trial("not_landed", "the two counterparties share keys, so they may be one "
                          "(KRK-M177)", t1=k1, t2=k2)
        s1, s2 = p1.pairwise.get(str(t1)), p1.pairwise.get(str(t2))
        if not s1 or not s2:
            return _trial("format_gap", "B gave no pseudonym in one of the consents")
        extra = {}
        if dz.plain_hash(p1.named) in (s1, s2):
            extra["plain_hash"] = "a pseudonym equals the kit's SHA-256 of the named id " \
                                  "(KRK-M184)"
        if s1 == s2:
            return _trial("over_disclosed", "one person has the same pseudonym at two "
                          "counterparties", **extra)
        return _trial("attributed", "the pseudonyms differ", **extra)

    def _named_in_pairwise(self) -> Dict[str, Any]:
        run, P = self.run, self.P
        op = run.op_at("pairwise")
        if op is None:
            return _trial("format_gap", "no operation's agreed level is pairwise")
        prs, ags = self._fresh(1, 1)
        p1, a1 = prs[0], ags[0]
        w = P.act(a1, p1, op, "pairwise", "W")
        bad = self._accepted(w)
        if bad:
            return bad
        flat = dz.flatten({"answer": w.answer})
        hits = dz.find(flat, {"named": p1.named, "hash": dz.plain_hash(p1.named)},
                       normalise=run.norm)
        if hits:
            return _trial("over_disclosed", "B's statement to the counterparty names the person "
                          "at a pairwise level", hits=hits)
        return _trial("attributed", "B's statement carries no named identifier")

    # (b) outlives_delegation ------------------------------------------------------------------

    def outlives_delegation(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run, P = self.run, self.P
        form = "grant_ended" if run.profile == "a-issued" else "consent_revoked"
        plain = run.op_plain()
        if plain is None or plain[1] == "none":
            return {form: [_trial("format_gap", "no operation with a disclosed level")]}
        op, level = plain
        trials = []
        for _ in range(n):
            prs, ags = self._fresh(1, 1)
            p1, a1 = prs[0], ags[0]
            want = self._want(p1, level, a1)
            w = P.act(a1, p1, op, level, "W")
            bad = self._accepted(w)
            if bad:
                trials.append(bad)
                continue
            first = run.record(w)
            o1, why1 = run.principal_reading(first, want, level, p1) if want else \
                ("unattributed", "no identifier at the level")
            if o1 != "attributed":
                trials.append(_trial(o1 if o1 in FAIL else
                                     ("no_attribution" if o1 == "over_disclosed" else o1),
                                     f"before the end: {why1}"))
                continue
            ended = P.end(a1)
            probe = P.act(a1, p1, op, level, "after-end")
            if probe.kind == "accepted" or run.effects(probe.ref):
                trials.append(_trial("not_landed", "B still accepts the agent after the end "
                                     "(KRK-M180)", ended=ended))
                continue
            again = run.record(w)
            o2, why2 = run.principal_reading(again, want, level, p1)
            trials.append(_trial("attributed" if o2 == "attributed" else
                                 ("unattributed" if o2 in ("unattributed", "record_late")
                                  else o2), f"after the end: {why2}", ended=ended))
        return {form: trials}

    # (a)(b) chain -----------------------------------------------------------------------------

    def chain(self, n: int) -> Dict[str, List[Dict[str, Any]]]:
        run = self.run
        out: Dict[str, List[Dict[str, Any]]] = {f: [] for f in FORMS["chain"]}
        plain = run.op_plain()
        if plain is None or plain[1] == "none":
            return {f: [_trial("format_gap", "no operation with a disclosed level")] for f in out}
        if not run.st.get("holder_hops"):
            return {f: [_trial("format_gap", "B accepts no holder-signed hop")] for f in out}
        op, level = plain
        for form in FORMS["chain"]:
            for _ in range(n):
                if form == "into_c" and run.C is None:
                    out[form].append(_trial("format_gap", "B pins one organisation"))
                    continue
                prs, ags = self._fresh(1, 1)
                p1, a1 = prs[0], ags[0]
                g1 = run.A.issue_v2(a1.subject, {"operations": [op]}, principal=p1.named)
                org = run.A if form == "two_hops" else run.C
                leaf = f"agent-{secrets.token_hex(5)}"
                g2 = run.A.delegate_holder(g1, leaf, org=org)
                leaf_kid = org.agent(leaf).kid
                v = run.values(op)
                raw = run.A.request_raw(v)
                d = run.A.disclose(raw, agent=leaf, principal=p1.named, level=level,
                                   audience=run.cp, holder=org)
                p = run.A.chain_presentation(g2, v, audience=run.audience(), disclosure=d)
                w = run.send(p, "W", v, principals=[p1])
                bad = self._accepted(w)
                if bad:
                    out[form].append(bad)
                    continue
                rec = run.record(w)
                if rec is None:
                    out[form].append(_trial("record_late", "W's record did not appear"))
                    continue
                want = self._want(p1, level)
                po, pwhy = run.principal_reading(rec, want, level, p1)
                got = {"leaf": bool(run.hits(rec, {"l": leaf, "k": leaf_kid})),
                       "principal": po == "attributed",
                       "agent_org": bool(run.hits(rec, {"o": org.issuer})),
                       "principal_org": bool(run.hits(rec, {"a": run.A.issuer}))}
                if not got["leaf"]:
                    out[form].append(_trial("actor_not_shown", "the agent that made the request "
                                            "is not on the record", **got))
                elif not got["principal"]:
                    out[form].append(_trial(po, f"the principal: {pwhy}", **got))
                elif not (got["agent_org"] and got["principal_org"]):
                    out[form].append(_trial("misattributed", "the agent's or the principal's "
                                            "organisation is not on the record", **got))
                else:
                    out[form].append(_trial("attributed", "agent, principal and both "
                                            "organisations on the record", **got))
        return out


def _impersonated(pr: Principal, person_rows: List[Rec], agent_rows: List[Rec]) -> bool:
    """The impersonation reading: every field that names the person on the person's own rows
    names the person on the agent's rows too, so B records the agent's request as the person's."""
    if not pr.named or not person_rows or not agent_rows:
        return False
    fields = set.intersection(*(set(r.clean()) for r in person_rows))
    naming = [f for f in fields if all(pr.named in r.clean().get(f, "") for r in person_rows)]
    return bool(naming) and all(all(pr.named in r.clean().get(f, "") for r in agent_rows)
                                for f in naming)


def _transport(s: Sent, run: _Run) -> List[str]:
    """The transport values the kit used for `s` (KRK-M189)."""
    out = [str(s.endpoint or run.endpoint)]
    for t in run.tenants:
        if t is not None:
            out.append(str(t))
    return out


# --------------------------------------------------------------------------- the control


def _control(run: _Run, F: _Forms) -> Tuple[bool, str, Dict[str, Any]]:
    """§4.1. Never requires attribution, a refusal, a label or a level (KRK-M19)."""
    P = F.P
    plain = run.op_plain()
    if plain is None:
        return False, "B states no operation without a requirement", {}
    op, level = plain
    prs, ags = F._fresh(2, 2)
    sent: List[Sent] = []
    for ep in run.endpoints:
        sent.append(P.act(ags[0], prs[0], op, level, f"control-a1@{ep}", endpoint=ep))
    sent.append(P.act(ags[1], prs[1], op, level, "control-a2"))
    d = P.direct(prs[0], op, "control-D")
    if d is not None:
        sent.append(d)
    doc: Dict[str, Any] = {"op": op, "level": level, "presented": len(sent)}
    for s in sent:
        if not s.landed:
            return False, f"{s.label} did not land: {s.why}", doc
        if s.kind != "accepted":
            return False, f"{s.label} was {s.kind}: {str(s.answer)[:200]}", doc
        if not s.op_id:
            return False, f"{s.label}: B's answer names no operation id (KRK-M170)", doc
        got = run.wait_effect(s.ref)
        if len(got) != 1:
            return False, (f"{s.label}: {len(got)} effects at the recorder for its request, "
                           f"not one"), doc
        rec = run.record(s)
        if rec is None:
            return False, f"{s.label}: no record readable through B's read path", \
                doc
    flat, _ = run.answer_flat(P.reader(ags[0], sent[0].op_id), sent[0].op_id)
    if flat is None:
        return False, "the read of B's answers returned nothing for the agent's own operation", \
            doc
    doc["ops"] = [s.op_id for s in sent]
    return True, (f"{len(sent)} control presentations accepted, each landed once and each has a "
                  f"record by B's operation id"), doc


# --------------------------------------------------------------------------- the probe


def _statements(a: Any) -> Dict[str, Any]:
    def opt(name: str, default: Any = None) -> Any:
        f = getattr(a, name, None)
        return f() if callable(f) else default
    st = {"profile": opt("disclosure_profile"), "agreement": dict(a.agreement() or {}),
          "levels": dict(opt("levels", {}) or {}),
          "requirements": dict(opt("requirements", {}) or {}),
          "pseudonyms": opt("pseudonyms"), "direct_path": opt("direct_path"),
          "normalisation": opt("normalisation"), "formats": list(opt("formats", []) or []),
          "labels_basis": opt("labels_basis"), "grade": a.evidence_grade(),
          "issuers": int(opt("issuers", 1) or 1),
          "holder_hops": bool(opt("accepts_holder_hops", False)),
          "strict_rules": opt("strict_rules"),
          "not_applicable": dict(opt("variants_not_applicable", {}) or {})}
    return st


def _statement_problem(st: Dict[str, Any], a: Any) -> Optional[str]:
    from .. import bissuer
    if st["profile"] not in PROFILES:
        return f"disclosure_profile() is {st['profile']!r}, not one of {PROFILES}"
    auth = bissuer.authority_of(a)
    if (auth.issuer == "B") != (st["profile"] == "b-held"):
        return (f"the authority block says issuer {auth.issuer!r}, and the profile is "
                f"{st['profile']!r}: b-held is the profile of a B that issues the authority")
    if not st["agreement"].get("counterparty"):
        return "agreement() names no counterparty"
    if st["grade"] not in GRADES:
        return f"evidence_grade() is {st['grade']!r}, not one of {GRADES}"
    for op, d in st["levels"].items():
        if not isinstance(d, dict) or d.get("agreed") not in dz.LEVELS or not d.get("quote"):
            return f"levels()[{op!r}] needs an agreed level and a quote (KRK-M173)"
    for op, d in st["requirements"].items():
        if not isinstance(d, dict) or d.get("requirement") not in \
                dz.REQUIREMENTS + ("approval-required",) or not d.get("quote"):
            return f"requirements()[{op!r}] needs a requirement and a quote"
    bad = sorted(v for v in st["not_applicable"] if v in NA_FORBIDDEN or v not in VARIANTS)
    if bad:
        return f"the adapter declares {bad} not applicable; {list(NA_FORBIDDEN)} may not be"
    if st["profile"] == "a-issued" and dz.SCHEMA not in (st["formats"] or [dz.SCHEMA]):
        return (f"B reads no {dz.SCHEMA} statement; version 1 presents only the kit's own "
                f"format (build note 13.4), so every a-issued form would be a format gap")
    return None


def probe(a: Any, ev: Evidence, *, run_tag: str = "", seed: Optional[int] = None,
          plan: Optional[Dict[str, Any]] = None) -> Result:
    from ..mockserver import MockServer
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())
    if getattr(a, "role", lambda: "B")() != "B":
        return Result.inconclusive(a.name, ID, "P25 grades B in version 1; role A is version 2 "
                                   "(design §6.7)", **common)
    try:
        st = _statements(a)
    except Exception as e:  # noqa: BLE001
        return Result.inconclusive(a.name, ID, f"reading the target's statements raised "
                                   f"{type(e).__name__}: {e}", **common)
    why = _statement_problem(st, a)
    if why:
        return Result.inconclusive(a.name, ID, why, **common)
    profile = st["profile"]
    plan = dict(plan if plan is not None else ({} if _is_toy(a) else (_plan_from_env() or {})))
    trials = DEV_TRIALS if plan.get("trials") == "dev" else TRIALS
    n = int(plan.get("n") or trials["*"])
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    order = [v for v in VARIANTS if v in (plan.get("variants") or VARIANTS)]
    rng.shuffle(order)
    recorder = MockServer()
    prefix = f"/p25/{run_tag}{secrets.token_hex(4)}"
    progress = _Progress(ev)
    run = _Run(a, ev, profile=profile, st=st, rng=rng, recorder=recorder, prefix=prefix,
               plan=plan)
    run.progress = progress
    stubs: List[Any] = []
    try:
        rec_how = a.bind_recorder(recorder.url + prefix)
        bind: Dict[str, Any] = {"recorder": rec_how}
        if profile == "a-issued":
            from ..discloser import StubDiscloser
            from ..requester import new_issuer
            A = StubDiscloser(new_issuer(), audience=run.cp)
            A.serve_local()
            stubs.append(A)
            bind["A"] = a.bind_requester(A.trust_anchor_x1(), A.source_url)
            run.A = A
            if st["issuers"] >= 2:
                A2 = StubDiscloser(new_issuer(), audience=run.cp, registry=A.registry)
                A2.serve_local()
                stubs.append(A2)
                bind["A′"] = a.bind_peer(A2.trust_anchor_x1(), A2.source_url)
                run.A2 = A2
            if st["issuers"] >= 3:
                C = StubDiscloser(new_issuer(), audience=run.cp, registry=A.registry)
                C.serve_local()
                stubs.append(C)
                bind["C"] = a.bind_peer(C.trust_anchor_x1(), C.source_url)
                run.C = C
            prof: Any = _AIssued(run)
        else:
            prof = _BHeld(run)
        F = _Forms(run, prof)
        ev.write("run.json", _jsonable({"seed": seed, "variant_order": ["control"] + order,
                                        "statements": st, "plan": plan, "bind": bind,
                                        "trials": n, "profile": profile}))
        run.log("run", seed=seed, statements=st, plan=plan, order=order)
        held, cdetail, cdoc = _control(run, F)
        run.log("control", held=held, detail=cdetail, doc=cdoc)
        ev.write("control.json", {"held": held, "detail": cdetail, "doc": _jsonable(cdoc)})
        if not held:
            return Result.inconclusive(a.name, ID, f"control did not hold: {cdetail}",
                                       control_detail=cdetail, extra={"profile": profile},
                                       **common)
        only_forms = plan.get("forms") or {}
        forms: Dict[str, Dict[str, Any]] = {}
        for variant in order:
            if variant in st["not_applicable"]:
                forms[variant] = {f: {"ok": None, "reading": "not_applicable",
                                      "detail": st["not_applicable"][variant], "trials": 0}
                                  for f in _profile_forms(variant, profile)}
                continue
            if not _profile_forms(variant, profile):
                continue
            got = getattr(F, variant)(n)
            keep = only_forms.get(variant)
            fr: Dict[str, Any] = {}
            for form, ts in got.items():
                if keep and form not in keep:
                    continue
                if (variant, form) not in _profile_pairs(profile):
                    continue
                fr[form] = _aggregate(ts)
            forms[variant] = fr
            ev.write(f"{variant}.json", _jsonable({"variant": variant,
                                                   "trials": {k: v for k, v in got.items()}}))
            run.log("variant", variant=variant, readings={k: v["reading"] for k, v in fr.items()})
        return _result(a, run, forms, cdetail, common, plan)
    except Exception as e:  # noqa: BLE001
        import traceback
        ev.write("error.json", {"error": f"{type(e).__name__}: {e}",
                                "traceback": traceback.format_exc()[-4000:]})
        progress.add("error", error=f"{type(e).__name__}: {e}")
        return Result.inconclusive(a.name, ID, f"the probe raised {type(e).__name__}: {e}",
                                   **common)
    finally:
        recorder.close()
        for s in stubs:
            s.close()


def _profile_pairs(profile: str) -> set:
    out = set()
    for v, fs in FORMS.items():
        for f in fs:
            if profile == "a-issued" and _in((v, f), B_HELD_ONLY):
                continue
            if profile == "b-held" and _in((v, f), A_ISSUED_ONLY):
                continue
            out.add((v, f))
    return out


def _profile_forms(variant: str, profile: str) -> List[str]:
    return [f for v, f in sorted(_profile_pairs(profile)) if v == variant]


def _aggregate(ts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """One form's reading from its trials: fail on any failing trial; pass if every trial
    passed; otherwise no reading, named by the first information outcome."""
    fails = [t for t in ts if t["ok"] is False]
    if fails:
        return {"ok": False, "reading": fails[0]["outcome"], "detail": fails[0]["detail"],
                "trials": len(ts), "outcomes": [t["outcome"] for t in ts]}
    if ts and all(t["ok"] is True for t in ts):
        return {"ok": True, "reading": ts[0]["outcome"], "detail": ts[0]["detail"],
                "trials": len(ts), "outcomes": [t["outcome"] for t in ts]}
    info = next((t for t in ts if t["ok"] is None), None)
    return {"ok": None, "reading": info["outcome"] if info else "not_driven",
            "detail": info["detail"] if info else "no trial", "trials": len(ts),
            "outcomes": [t["outcome"] for t in ts]}


def _must_land(run: _Run) -> List[Tuple[str, str]]:
    out = list(MUST_LAND[run.profile])
    for op, d in (run.st.get("levels") or {}).items():
        lv = d.get("agreed")
        if lv in FORMS["principal_shown"] and not run.req_of(op):
            out.append(("principal_shown", lv))
    return sorted(set(out))


def _result(a: Any, run: _Run, forms: Dict[str, Dict[str, Any]], cdetail: str,
            common: Dict[str, Any], plan: Dict[str, Any]) -> Result:
    checks: List[Check] = [Check("control", "held", True, cdetail)]
    clauses: Dict[str, List[Optional[bool]]] = {c: [] for c in dz.CLAUSES}
    disclosure_forms: Dict[str, Any] = {}
    for variant in VARIANTS:
        fr = forms.get(variant)
        if not fr:
            continue
        oks = [d["ok"] for d in fr.values()]
        if any(o is False for o in oks):
            bad = [(f, d) for f, d in fr.items() if d["ok"] is False]
            checks.append(Check(variant, "+".join(sorted({d["reading"] for _f, d in bad})),
                                False, "; ".join(f"{f}: {d['reading']}: {d['detail']}"
                                                 for f, d in bad)))
        elif any(o is True for o in oks):
            checks.append(Check(variant, "attributed", True,
                                "; ".join(f"{f}: {d['reading']}" for f, d in fr.items())))
        else:
            checks.append(Check(variant, "no_reading", None,
                                "; ".join(f"{f}: {d['reading']}" for f, d in fr.items())))
        for c in CLAUSE_OF[variant]:
            clauses[c].extend(oks)
        for f, d in fr.items():
            if d["ok"] is False:
                vuln = _in((variant, f), VULNERABLE) and d["reading"] in (
                    "misattributed", "over_disclosed", "performed_undisclosed")
                disclosure_forms[f"{variant}/{f}"] = {
                    "class": "vulnerability" if vuln else "conformance",
                    "reading": d["reading"]}
    clause_read = {c: ("fail" if any(o is False for o in v) else
                       "pass" if any(o is True for o in v) else
                       "inconclusive" if v else "not_driven") for c, v in clauses.items()}
    missing = [f"{v}/{f}" for v, f in _must_land(run)
               if (forms.get(v) or {}).get(f, {}).get("ok") is None
               and (not plan.get("variants") or v in plan["variants"])]
    disclosure = ("vulnerability" if any(d["class"] == "vulnerability"
                                         for d in disclosure_forms.values())
                  else "conformance")
    info = sorted({f"{v}/{f}: {d['reading']}" for v, fr in forms.items() for f, d in fr.items()
                   if d["ok"] is None})
    extra = {"profile": run.profile, "forms": forms, "clauses": clause_read,
             "disclosure": disclosure, "disclosure_forms": disclosure_forms,
             "must_land": [f"{v}/{f}" for v, f in _must_land(run)],
             "must_land_missing": missing, "information": info,
             "evidence_grade": run.st["grade"], "presentations": run.n,
             "statements": _jsonable({k: run.st[k] for k in ("levels", "requirements",
                                                            "pseudonyms", "direct_path",
                                                            "labels_basis", "strict_rules")}),
             "findings": run.findings}
    grade = run.st["grade"]
    fails = [c for c in checks if c.ok is False]
    if fails:
        return verdict(a.name, ID, checks, control_held=True, control_detail=cdetail,
                       pass_summary="", fail_summary=f"Counterparty disclosure ({run.profile}, "
                       f"{grade}): B's account of who acted, or for whom, is wrong or wider than "
                       f"agreed", extra=extra, **common)
    if missing:
        return Result.inconclusive(a.name, ID, f"no failing form, but forms that must read a "
                                   f"verdict did not: {', '.join(missing)}", control_held=True,
                                   control_detail=cdetail, checks=checks, extra=extra, **common)
    if not any(c.ok is True for c in checks[1:]):
        return Result.inconclusive(a.name, ID, "no form read a verdict", control_held=True,
                                   control_detail=cdetail, checks=checks, extra=extra, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=cdetail,
                   pass_summary=f"Counterparty disclosure ({run.profile}, {grade}): B's own "
                   f"account names the agent and the principal from bound evidence, at no more "
                   f"than the agreed level, on every landed form"
                   + (f"; information: {len(info)} form(s)" if info else ""),
                   fail_summary="", extra=extra, **common)
