"""The B-issuer toy core: an in-process B that issues the authority it honours, in the three shapes
of the profile (design §1.5, §6.6), and the stand-in agent and person hook that drive it.

**The correct B** (``good``). It registers each agent identity's key when the person consents at
its page, issues a class credential on that consent, and signs every exact object with its own
Ed25519 key, which it publishes as a JWKS. It keeps credentials, objects, use records, effects and
the tenants' ledgers in one SQLite file shared by its two endpoints (``api-2`` is an alias of
``api-1``) and its two instances. For each acceptance it checks, in this order: the credential is
its own and current and the presenter's proof is the credential's client's; the object is in its
own store; the object was issued to the presenting identity; the object's tenant, the credential's
tenant and the presentation's tenant agree; the object is current (not superseded); it is inside
its stated expiry plus the stated tolerance; the person approved it at the page where the object
needs that (a class operation may be accepted on a standing permission); the presented terms equal
the object's (consent-id and rar-token); a declared part is one of the object's parts and the
whole is refused after any part; then its ledger dependency is up. Only then does it mark the use,
with an insert that refuses a duplicate key, execute the object's signed terms, record the effect
and the ledger change, and mark the use done. A repeat is answered from the use record
(``duplicate``, or ``in-progress`` while it runs). It refuses a request or acceptance with a
member twice. It restates every request faithfully.

**Shapes.** ``revision``: B signs a revision of the proposal (``rev-…``); the agent accepts by
naming it, with ``approved_by``; a counter-proposal issues the next revision, which supersedes the
last. ``consent-id``: B registers a consent (``cns-…``) with its terms; the person authorises it at
B's page; the agent submits naming it and repeating its terms; a consent may list instalments.
``rar-token``: the agent pushes an authorization request; the person consents at B's page; B
issues a token (``tok-…``) carrying the one transaction's details; the agent presents the request
with the token. In consent-id and rar-token B states a use-record retention (``memory_horizon_s``)
and caps each new object's validity at it; in revision it keeps objects and uses together, for
good.

Each toy is a flawed copy of this B in one shape; the flaws are in
`known_bad.bissuer_binding_toys`. It is in process and speaks no HTTP: the stand-in's
presentations are `authz.Presentation` objects whose ``X-Toy-Route`` header names the route.

Knobs for the failure-mode pins (``tests/test_failure_modes_bissuer.py``):
``reset_effects_on_restart`` (a restart rebuilds the effect store and use records from start-up
data, KRK-M134), ``no_counter`` (a counter-proposal opens a new proposal, so the revision it was
made on stays current, KRK-M141),
``peer_shares_keys`` (the second instance is started with this one's key, KRK-M142),
``background`` (``"declared"`` or ``"undeclared"``: a settlement job writes the tenants' ledgers,
KRK-M147), ``prior_history`` (a ledger change before the run), ``driver_reconsents`` (the stand-in
asks the hook again before every acceptance, KRK-M139), ``reset_between_pairs`` (the adapter calls
B's reset aid at each new pair, KRK-M145), ``signs_with_unpublished_key`` (B signs with a key it
does not publish, KRK-M140), ``issues_on_decline`` (B issues a credential on a declined consent,
KRK-M133).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from conformance import authz, bissuer
from conformance.stand_in import AgentIdentity, ConsentRecord

SHAPES = bissuer.SHAPES
ENDPOINTS = ("api-1", "api-2")
ALIASES = {"api-2": "api-1"}
TENANTS = ("t-1", "t-2")
INSTANCES = ("i-1", "i-2")
OPERATIONS = {"crm.record.push": "exact", "notes.append": "class"}
OBJECT_LIFETIME_S = 900
CREDENTIAL_LIFETIME_S = 4 * 3600
TOLERANCE_S = 60
RETENTION_S = 3600
EFFECT_S = 0.03
"""How long the executor takes before its ledger write, so presentations overlap."""
SLOW_S = 0.12
ROUTE, CLIENT, PROOF = "X-Toy-Route", "X-Toy-Client", "X-Toy-Proof"
PERSON = "toy-person-1 (fictitious test data the toy ships)"
SETTLEMENT = "settlement-job"
VALUE_MEMBERS = ("ref", "operation", "recipient", "amount", "items")

_NAMESPACE: Dict[str, "ToyIssuerB"] = {}
"""Object id -> the toy instance that issued it, across every instance of the product. A correct
B never reads it; ``accepts_foreign_object`` resolves ids through it."""
_NS_LOCK = threading.Lock()


class ToyCrash(BaseException):
    """B's process dying between two writes."""


class Refused(Exception):
    pass


def _b64e(b: bytes) -> str:
    return bissuer.b64e(b)


def _json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _strict(raw: bytes) -> Any:
    def pairs(ps):
        out = {}
        for k, v in ps:
            if k in out:
                raise Refused(f"member {k!r} twice")
            out[k] = v
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(f"not JSON: {e}") from None


def _lenient(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))           # the last duplicate wins
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(f"not JSON: {e}") from None


def _decode(token: str) -> Dict[str, Any]:
    """The payload of a compact JWS, unverified (the stand-in's reading; the kit verifies)."""
    seg = token.split(".")[1]
    return json.loads(bissuer.b64d(seg))


def _digest(terms: Dict[str, Any]) -> Optional[str]:
    try:
        return bissuer.terms_digest(terms)
    except bissuer.NotIJSON:
        return None


def _values(terms: Dict[str, Any]) -> Dict[str, Any]:
    return {k: terms[k] for k in VALUE_MEMBERS if k in terms}


class ToyHook:
    """The person at the toy's page, ``driven-page``: it posts the page's approve or decline
    form for the test person, and records what the page showed."""

    kind = "driven-page"

    def __init__(self, b: "ToyIssuerB") -> None:
        self.b = b
        self.log: List[ConsentRecord] = []

    def _decide(self, handle: Dict[str, Any], decision: str, pair: str) -> ConsentRecord:
        shown, steps = self.b._page(handle, decision)
        rec = ConsentRecord(pair=pair, identity=str(handle.get("client") or ""), hook=self.kind,
                            person=PERSON, decision=decision, handle=dict(handle), shown=shown,
                            steps=steps, at=time.time())
        self.log.append(rec)
        return rec

    def approve(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord:
        return self._decide(handle, "approved", pair)

    def decline(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord:
        return self._decide(handle, "declined", pair)


class ToyAgent:
    """The stand-in agent at the toy B (`stand_in.StandInAgent`): it builds the toy's protocol
    bytes and decides nothing."""

    def __init__(self, b: "ToyIssuerB", ident: AgentIdentity) -> None:
        self.b, self.ident = b, ident
        self.creds: Dict[Optional[str], str] = {}

    def identity(self) -> AgentIdentity:
        return self.ident

    def consent(self, hook: Any, *, tenant: Optional[str], pair: str,
                decision: str = "approve") -> ConsentRecord:
        cid = self.b._start_consent(self.ident, tenant)
        handle = {"consent": cid, "client": self.ident.client_id, "tenant": tenant}
        rec = (hook.approve if decision == "approve" else hook.decline)(handle, pair=pair)
        tok = self.b._redeem_consent(cid)
        if tok:
            self.creds[tenant] = tok
            rec.credential = bissuer.BObject("credential", _decode(tok)["jti"], tok.encode(),
                                             True, tenant=tenant, issued_to=self.ident.client_id)
        return rec

    # presentations ------------------------------------------------------------------------

    def _pres(self, route: str, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
              authorisation: Optional[str], headers: Optional[Dict[str, str]] = None
              ) -> authz.Presentation:
        h = dict(headers or {})
        sig = self.ident.sign(f"{route}|{endpoint}|{tenant}|".encode()
                              + hashlib.sha256(body).hexdigest().encode())
        h.update({ROUTE: route, CLIENT: self.ident.client_id, PROOF: _b64e(sig)})
        return authz.Presentation(pid=pid, endpoint=endpoint, tenant=tenant, request=body,
                                  authorisation=authorisation, headers=h)

    def request(self, raw: bytes, *, pid: str, tenant: Optional[str], endpoint: str):
        route = {"revision": "propose", "consent-id": "consent", "rar-token": "par"}[self.b.shape]
        body = b'{"authorization_details":' + raw + b"}" if self.b.shape == "rar-token" else raw
        return self._pres(route, body, pid=pid, tenant=tenant, endpoint=endpoint,
                          authorisation=self.creds.get(tenant))

    def counter(self, obj, raw: bytes, *, pid: str, tenant: Optional[str], endpoint: str):
        if self.b.shape != "revision":
            raise NotImplementedError("counter-proposals are the revision shape's")
        body = b'{"revision":' + json.dumps(obj.id).encode() + b',"terms":' + raw + b"}"
        return self._pres("counter", body, pid=pid, tenant=tenant, endpoint=endpoint,
                          authorisation=self.creds.get(tenant))

    def read(self, answer: Dict[str, Any], *, endpoint: str) -> List[bissuer.BObject]:
        body = (answer or {}).get("body") or {}
        out = []
        if isinstance(body.get("pending"), dict):
            pend = body["pending"]
            out.append(bissuer.BObject("pending", pend["request_uri"], _json(pend), False,
                                       endpoint=endpoint))
        tok = body.get("object")
        if isinstance(tok, str):
            c = _decode(tok)
            out.append(bissuer.BObject(
                "exact", c.get("id"), tok.encode(), True, kid=None, alg=None,
                terms=c.get("terms"), terms_digest=c.get("terms_digest"),
                issued_to=c.get("issued_to"), tenant=c.get("tenant"), endpoint=endpoint,
                instance=c.get("instance"), expires_at=c.get("exp"), issued_at=c.get("iat"),
                supersedes=c.get("supersedes"), counter_proposal=bool(c.get("counter_proposal")),
                claims=c))
        return out

    def person_needed(self, obj) -> Optional[Dict[str, Any]]:
        if obj is None:
            return None
        if obj.kind == "pending":
            return {"object": obj.id, "client": self.ident.client_id}
        c = obj.claims or {}
        if self.b.shape == "revision" and c.get("approval") == "user":
            return {"object": obj.id, "client": self.ident.client_id}
        if self.b.shape == "consent-id" and c.get("status") == "awaiting-authorisation":
            return {"object": obj.id, "client": self.ident.client_id}
        return None

    def complete(self, obj, *, pid: str, tenant: Optional[str], endpoint: str):
        if self.b.shape != "rar-token" or obj is None or obj.kind != "pending":
            return None
        return self._pres("token", _json({"request_uri": obj.id}), pid=pid, tenant=tenant,
                          endpoint=endpoint, authorisation=self.creds.get(tenant))

    def acceptance_body(self, obj, *, approval: str = "person") -> Dict[str, Any]:
        if self.b.shape == "revision":
            return {"revision": obj.id,
                    "approved_by": "user" if approval == "person" else "standing_permission"}
        vals = _values(obj.terms or {})
        if self.b.shape == "consent-id":
            return {"consent_id": obj.id, **vals}
        return vals

    def accept(self, obj, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
               headers: Optional[Dict[str, str]] = None,
               credential_tenant: Optional[str] = None):
        if self.b.driver_reconsents:               # KRK-M139: a driver acting on its own
            self.b.hook().approve({"consent": "refresh", "client": self.ident.client_id},
                                  pair="driver")
        ct = tenant if credential_tenant is None else credential_tenant
        if self.b.shape == "rar-token":
            auth = obj.raw.decode()
            route = "submit"
        else:
            auth = self.creds.get(ct)
            route = "accept" if self.b.shape == "revision" else "submit"
        return self._pres(route, body, pid=pid, tenant=tenant, endpoint=endpoint,
                          authorisation=auth, headers=headers)

    def class_body(self, values: Dict[str, Any]) -> Dict[str, Any]:
        return dict(values)

    def class_use(self, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
                  headers: Optional[Dict[str, str]] = None):
        return self._pres("class", body, pid=pid, tenant=tenant, endpoint=endpoint,
                          authorisation=self.creds.get(tenant), headers=headers)


class ToyIssuerB:
    name = "toy-b-issuer"

    def __init__(self, shape: str = "revision", variant: str = "good",
                 flaw: Optional[str] = None, *, org: Optional[str] = None,
                 key: Any = None) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        assert shape in SHAPES, shape
        assert variant in ("good", "slow-good", "bad", "no-control"), variant
        if variant == "bad" and flaw is None:
            flaw = "no_check"
        self.shape, self.variant, self.flaw = shape, variant, flaw
        self.config = f"{shape}:bad:{flaw}" if flaw and flaw != "no_check" else \
            f"{shape}:{variant}"
        self.org = org or f"did:web:b-{secrets.token_hex(3)}.example"
        self.key = key or Ed25519PrivateKey.generate()
        self.kid = f"b-{secrets.token_hex(4)}"
        self.unpublished = Ed25519PrivateKey.generate()
        # knobs
        self.reset_effects_on_restart = False
        self.no_counter = False
        self.peer_shares_keys = False
        self.background: Optional[str] = None
        self.prior_history = False
        self.driver_reconsents = False
        self.reset_between_pairs = False
        self.signs_with_unpublished_key = False
        self.issues_on_decline = False
        # state
        self.dir: Optional[Path] = None
        self.db_path: Optional[Path] = None
        self.active = INSTANCES[0]
        self.boot = {i: secrets.token_hex(4) for i in INSTANCES}
        self.proc_uses: Dict[str, Dict[str, str]] = {i: {} for i in INSTANCES}
        self.inst_uses: Dict[str, Dict[str, str]] = {i: {} for i in INSTANCES}
        self.skew = 0.0
        self.retention = RETENTION_S
        self.dep_ok = True
        self.crash_armed = False
        self.crashed_flag = False
        self.lock = threading.Lock()
        self._hook: Optional[ToyHook] = None
        self._peer: Optional["ToyIssuerB"] = None
        self._clock: Optional["ToyIssuerB"] = None
        """The instance whose virtual clock this one reads (a peer reads its target's), so the
        two organisations agree on the time and only the issuer differs."""
        self._resets: List[Dict[str, Any]] = []
        self._presented = 0
        self.verify_calls = 0

    # target ---------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def implements(self):
        return ["P18B"]

    def start(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="toy-p18b-"))
        self.db_path = self.dir / "b.sqlite"
        with self._db() as db:
            db.executescript("""
                CREATE TABLE clients (client_id TEXT PRIMARY KEY, jwk TEXT);
                CREATE TABLE consents (id TEXT PRIMARY KEY, client_id TEXT, tenant TEXT,
                                       state TEXT);
                CREATE TABLE credentials (jti TEXT PRIMARY KEY, client_id TEXT, tenant TEXT,
                                          exp REAL);
                CREATE TABLE objects (id TEXT PRIMARY KEY, claims TEXT, approved INTEGER,
                                      superseded_by TEXT, raw TEXT);
                CREATE TABLE pending (uri TEXT PRIMARY KEY, client_id TEXT, tenant TEXT,
                                      details TEXT, approved INTEGER);
                CREATE TABLE proposals (id TEXT PRIMARY KEY, latest TEXT);
                CREATE TABLE uses (key TEXT PRIMARY KEY, state TEXT, at REAL);
                CREATE TABLE effects (op_id TEXT PRIMARY KEY, ref TEXT, tenant TEXT,
                                      vals TEXT, at REAL, began_at REAL);
                CREATE TABLE ledger (seq INTEGER PRIMARY KEY AUTOINCREMENT, resource TEXT,
                                     op_id TEXT, ref TEXT, writer TEXT, at REAL);
            """)
            if self.prior_history:
                db.execute("INSERT INTO ledger (resource, op_id, ref, writer, at) VALUES "
                           "(?, ?, NULL, 'migration', ?)",
                           (f"ledger:{TENANTS[0]}", f"op-{secrets.token_hex(6)}", time.time()))

    def stop(self) -> None:
        if self._peer is not None:
            self._peer.stop()
            self._peer = None
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), timeout=30, isolation_level=None,
                             check_same_thread=False)
        return db

    # the P18B adapter -----------------------------------------------------------------------

    def authority(self) -> Dict[str, Any]:
        exact = {"revision": {"kind": "revision", "id_member": "id", "terms_member": "terms",
                              "terms_digest": {"member": "terms_digest", "basis": "jcs"},
                              "signed": "jws", "expiry_member": "exp", "parts": False},
                 "consent-id": {"kind": "consent", "id_member": "id", "terms_member": "terms",
                                "terms_digest": {"member": "terms_digest", "basis": "jcs"},
                                "signed": "jws", "expiry_member": "exp", "parts": True},
                 "rar-token": {"kind": "transaction-token", "id_member": "id",
                               "terms_member": "terms",
                               "terms_digest": {"member": "terms_digest", "basis": "jcs"},
                               "signed": "jws", "expiry_member": "exp", "parts": True}}[self.shape]
        acc = {"revision": {"route": "accept", "names": "id", "carries_digest": False,
                            "approval_methods": ["user", "standing_permission"]},
               "consent-id": {"route": "submit", "names": "consent_id", "repeats_terms": True},
               "rar-token": {"route": "submit", "names": "the token", "repeats_terms": True}}
        return {"issuer": "B", "shape": self.shape,
                "class_credential": {"kind": "toy-access-token", "binding": "client-proof",
                                     "consent": "toy-page", "lifetime_s": CREDENTIAL_LIFETIME_S},
                "exact_object": exact, "acceptance": acc[self.shape],
                "hook": {"kind": ToyHook.kind, "routes": ["page approve", "page decline"],
                         "quote": "the toy's module docstring (known_bad/bissuer_core.py)"},
                "revocation": [], "agent_keys_from": "bind",
                "keys": {"published": "published_keys()", "trusted_as": "live"}}

    def agreement(self) -> Dict[str, Any]:
        writers = [SETTLEMENT] if self.background == "declared" else []
        return {"counterparty": self.org, "endpoints": list(ENDPOINTS), "aliases": dict(ALIASES),
                "tenants": list(TENANTS), "operations": dict(OPERATIONS),
                "binding_basis": "jcs", "mappings": {},
                "max_validity_s": OBJECT_LIFETIME_S,
                "memory_horizon_s": "permanent" if self.shape == "revision" else RETENTION_S,
                "clock_tolerance_s": TOLERANCE_S,
                "answer_codes": {"executed": "200 {code: executed}", "proposed": "201",
                                 "duplicate": "409 {code: duplicate}",
                                 "in-progress": "409 {code: in-progress}",
                                 "refused": "422 {code: refused}"},
                "claims_replay_protection": True,
                "test_resources": [f"ledger:{t}" for t in TENANTS],
                "background_writers": writers, "instances": list(INSTANCES),
                "store_survives_restart": not self.reset_effects_on_restart,
                "quotes": {"*": "the toy's module docstring (known_bad/bissuer_core.py)"}}

    def agent(self, n: int, identities: Optional[List[AgentIdentity]] = None) -> List[ToyAgent]:
        if self.reset_between_pairs and identities is None:
            self._reset("between pairs")
        ids = identities or [AgentIdentity.fresh() for _ in range(n)]
        return [ToyAgent(self, i) for i in ids]

    def hook(self) -> ToyHook:
        if self._hook is None:
            self._hook = ToyHook(self)
        return self._hook

    def evidence_grade(self) -> str:
        return "B-store-read"

    def published_keys(self) -> Dict[str, Any]:
        from cryptography.hazmat.primitives import serialization
        x = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64e(x), "kid": self.kid,
                          "use": "sig", "alg": "EdDSA"}]}

    def verify(self, token: str) -> bool:
        """B's own verifier, which the kit must never use (KRK-M140)."""
        self.verify_calls += 1
        return True

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "executed", "duplicate": "duplicate", "in-progress": "in-progress",
                "refused": "refused", "proposed": "original"}.get(code, "error")

    def store(self, since: float) -> List[Dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT op_id, ref, tenant, vals, at, began_at FROM effects "
                              "ORDER BY at").fetchall()
        out = []
        for op, ref, tenant, vals, at, began in rows:
            out.append({"op_id": op, **json.loads(vals), "tenant": tenant, "at": at,
                        "began_at": began})
        return out

    def resource_history(self, resources: List[str]) -> List[Dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT seq, resource, op_id, ref, writer, at FROM ledger "
                              "ORDER BY seq").fetchall()
        return [{"seq": s, "resource": r, "op_id": o, "ref": ref, "writer": w, "at": at}
                for s, r, o, ref, w, at in rows if r in resources]

    def resets(self) -> List[Dict[str, Any]]:
        return list(self._resets)

    def _reset(self, why: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM uses")
        self._resets.append({"at": time.time(), "why": why})

    def peer(self) -> "ToyIssuerB":
        """A second instance of the product run by another organisation: correct, its own key
        (or this one's, with ``peer_shares_keys``)."""
        if self._peer is None:
            self._peer = ToyIssuerB(self.shape, "good",
                                    key=self.key if self.peer_shares_keys else None)
            if self.peer_shares_keys:
                self._peer.kid = self.kid
            self._peer._clock = self
            self._peer.start()
        return self._peer

    def now(self) -> float:
        return time.time() + (self._clock.skew if self._clock is not None else self.skew)

    def elapse(self, seconds: float) -> None:
        self.skew += seconds

    def instances(self) -> List[str]:
        return list(INSTANCES)

    def restart(self, kind: str) -> Dict[str, str]:
        before = f"{self.active}:{self.boot[self.active]}"
        if kind == "process":
            self.boot[self.active] = secrets.token_hex(4)
            self.proc_uses[self.active] = {}
            if self.reset_effects_on_restart:
                with self._db() as db:
                    db.execute("DELETE FROM effects")
                    db.execute("DELETE FROM uses")
            how = "the toy's state-holding process replaced"
        elif kind == "failover":
            self.active = INSTANCES[1] if self.active == INSTANCES[0] else INSTANCES[0]
            how = "requests now go to the other instance"
        else:
            raise ValueError(kind)
        return {"before": before, "after": f"{self.active}:{self.boot[self.active]}", "how": how}

    def dependency(self, available: bool) -> str:
        self.dep_ok = bool(available)
        return f"the toy's ledger service {'up' if available else 'down'}"

    def crash_between(self, step: str) -> str:
        self.crash_armed = True
        return ("armed: B's process dies after the first of its two writes (the use record and "
                "the effect); in process, milder than a process death")

    def crashed(self) -> bool:
        return self.crashed_flag

    def variants_not_applicable(self) -> Dict[str, str]:
        if self.shape == "revision":
            return {"validity_beyond_memory": "the toy keeps revisions and their use records in "
                                              "one store, for good (rule 6)"}
        return {}

    def set_memory_horizon(self, seconds: Optional[int]) -> str:
        if self.shape == "revision":
            raise NotImplementedError("revision: objects and uses are kept together")
        self.retention = RETENTION_S if seconds is None else int(seconds)
        return f"use-record retention {self.retention} s"

    # B's page (driven by the hook) ----------------------------------------------------------

    def _start_consent(self, ident: AgentIdentity, tenant: Optional[str]) -> str:
        cid = f"dev-{secrets.token_hex(6)}"
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO clients VALUES (?, ?)",
                       (ident.client_id, json.dumps(ident.jwk())))
            db.execute("INSERT INTO consents VALUES (?, ?, ?, 'pending')",
                       (cid, ident.client_id, tenant))
        return cid

    def _page(self, handle: Dict[str, Any], decision: str
              ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        state = "approved" if decision == "approved" else "declined"
        steps = []
        with self._db() as db:
            if "consent" in handle:
                db.execute("UPDATE consents SET state = ? WHERE id = ?", (state, handle["consent"]))
                steps.append({"route": f"GET /device/{handle['consent']}", "status": 200})
                steps.append({"route": f"POST /device/{handle['consent']}/{decision}",
                              "status": 200})
                return {"consent": "class credential for this agent"}, steps
            oid = handle.get("object")
            row = db.execute("SELECT claims FROM objects WHERE id = ?", (oid,)).fetchone()
            if row:
                db.execute("UPDATE objects SET approved = ? WHERE id = ?",
                           (1 if state == "approved" else -1, oid))
                shown = json.loads(row[0]).get("terms")
            else:
                db.execute("UPDATE pending SET approved = ? WHERE uri = ?",
                           (1 if state == "approved" else -1, oid))
                r = db.execute("SELECT details FROM pending WHERE uri = ?", (oid,)).fetchone()
                shown = json.loads(r[0]) if r else None
            steps.append({"route": f"GET /approve/{oid}", "status": 200})
            steps.append({"route": f"POST /approve/{oid}/{decision}", "status": 200})
        return shown, steps

    def _redeem_consent(self, cid: str) -> Optional[str]:
        with self._db() as db:
            row = db.execute("SELECT client_id, tenant, state FROM consents WHERE id = ?",
                             (cid,)).fetchone()
            if not row:
                return None
            client, tenant, state = row
            if state != "approved" and not (self.issues_on_decline and state == "declined"):
                return None
            jti = f"at-{secrets.token_hex(8)}"
            exp = self.now() + CREDENTIAL_LIFETIME_S
            db.execute("INSERT INTO credentials VALUES (?, ?, ?, ?)", (jti, client, tenant, exp))
        return self._sign({"typ": "credential", "jti": jti, "client_id": client,
                           "tenant": tenant, "iss": self.org, "iat": self.now(), "exp": exp,
                           "scope": "class"})

    # signing --------------------------------------------------------------------------------

    def _sign(self, claims: Dict[str, Any]) -> str:
        key = self.unpublished if self.signs_with_unpublished_key else self.key
        h = _b64e(_json({"alg": "EdDSA", "kid": self.kid, "typ": "toy-b+jws"}))
        p = _b64e(_json(claims))
        sig = key.sign(f"{h}.{p}".encode("ascii"))
        return f"{h}.{p}.{_b64e(sig)}"

    def _issue(self, kind: str, client: str, tenant: Optional[str], terms: Dict[str, Any],
               **more: Any) -> str:
        prefix = {"revision": "rev", "consent": "cns", "transaction-token": "tok"}[kind]
        oid = more.pop("oid", None) or f"{prefix}-{secrets.token_hex(8)}"
        life = OBJECT_LIFETIME_S
        if self.shape != "revision" and self.flaw != "forgets_before_expiry":
            life = min(life, self.retention)
        iat = self.now()
        claims = {"typ": kind, "id": oid, "iss": self.org, "terms": terms,
                  "terms_digest": _digest(terms), "issued_to": client, "tenant": tenant,
                  "instance": self.active, "iat": iat, "exp": iat + life, **more}
        if self.flaw == "restates_silently":
            claims["terms"] = dict(terms, amount=terms.get("amount", 0) + 1)
            claims["terms_digest"] = _digest(claims["terms"])
        tok = self._sign(claims)
        with self._db() as db:
            db.execute("INSERT INTO objects VALUES (?, ?, 0, NULL, ?)",
                       (oid, json.dumps(claims), tok))
        with _NS_LOCK:
            _NAMESPACE[oid] = self
        return tok

    # the entry point ------------------------------------------------------------------------

    def present(self, p: authz.Presentation) -> Dict[str, Any]:
        began = time.time()
        self._presented += 1
        if self.background and self._presented % 3 == 0:
            with self._db() as db:
                db.execute("INSERT INTO ledger (resource, op_id, ref, writer, at) VALUES "
                           "(?, ?, NULL, ?, ?)", (f"ledger:{TENANTS[0]}",
                                                  f"op-{secrets.token_hex(6)}", SETTLEMENT,
                                                  self.now()))
        try:
            code, why, extra = self._route(p)
        except Refused as e:
            code, why, extra = "refused", str(e), {}
        except ToyCrash:
            self.boot[self.active] = secrets.token_hex(4)
            self.proc_uses[self.active] = {}
            self.crash_armed = False
            self.crashed_flag = True
            raise ConnectionError("connection reset: B's process died")
        if self.variant == "slow-good" and code == "executed":
            time.sleep(SLOW_S)
        status = {"executed": 200, "proposed": 201, "duplicate": 409,
                  "in-progress": 409}.get(code, 422)
        return {"status": status, "body": {"code": code, "reason": why, **extra},
                "began_at": began, "ended_at": time.time()}

    def _route(self, p: authz.Presentation) -> Tuple[str, str, Dict[str, Any]]:
        route = p.headers.get(ROUTE)
        if p.endpoint not in ENDPOINTS:
            raise Refused(f"no endpoint {p.endpoint!r}")
        if route == "propose" and self.shape == "revision":
            return self._propose(p)
        if route == "counter" and self.shape == "revision":
            return self._counter(p)
        if route == "consent" and self.shape == "consent-id":
            return self._register(p)
        if route == "par" and self.shape == "rar-token":
            return self._par(p)
        if route == "token" and self.shape == "rar-token":
            return self._token(p)
        if route in ("accept", "submit"):
            return self._accept(p)
        if route == "class":
            return self._class(p)
        raise Refused(f"no route {route!r} in the {self.shape} shape")

    # authentication -------------------------------------------------------------------------

    def _client(self, p: authz.Presentation, token: Optional[str], *,
                txn: bool = False) -> Tuple[str, Optional[str]]:
        """The presenting client, after its credential and proof check. For a rar-token
        submission the token is the transaction token and the client is its holder."""
        client = p.headers.get(CLIENT)
        if not token or not client:
            raise Refused("no credential")
        try:
            claims = _decode(token)
        except Exception:  # noqa: BLE001
            raise Refused("unreadable credential") from None
        with self._db() as db:
            if txn:
                row = db.execute("SELECT 1 FROM objects WHERE id = ?",
                                 (claims.get("id"),)).fetchone()
                tenant = claims.get("tenant")
                if not row and self.flaw not in ("no_check", "accepts_foreign_object"):
                    raise Refused("token not issued here")
            else:
                row = db.execute("SELECT client_id, tenant, exp FROM credentials WHERE jti = ?",
                                 (claims.get("jti"),)).fetchone()
                if not row:
                    raise Refused("credential not issued here")
                if row[0] != client and self.flaw != "no_check":
                    raise Refused("credential belongs to another client")
                if row[2] < self.now() - TOLERANCE_S:
                    raise Refused("credential expired")
                tenant = row[1]
            jrow = db.execute("SELECT jwk FROM clients WHERE client_id = ?", (client,)).fetchone()
        if not jrow:
            raise Refused("unknown client")
        jwk = json.loads(jrow[0])
        sig_ok = False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(bissuer.b64d(jwk["x"])).verify(
                bissuer.b64d(p.headers.get(PROOF, "")),
                f"{p.headers.get(ROUTE)}|{p.endpoint}|{p.tenant}|".encode()
                + hashlib.sha256(p.request).hexdigest().encode())
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        if not sig_ok:
            raise Refused("the client's proof does not verify")
        return client, tenant

    def _parse(self, raw: bytes) -> Any:
        return _lenient(raw) if self.flaw in ("last_member_wins",) else _strict(raw)

    @staticmethod
    def _check_values(v: Any) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise Refused("the request is not an object")
        if v.get("operation") not in OPERATIONS:
            raise Refused(f"unknown operation {v.get('operation')!r}")
        for k in ("ref", "recipient", "amount", "items"):
            if k not in v:
                raise Refused(f"missing {k}")
        return v

    # issuing --------------------------------------------------------------------------------

    def _propose(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        v = self._check_values(self._parse(p.request))
        prop = f"prop-{secrets.token_hex(6)}"
        approval = "user" if OPERATIONS[v["operation"]] == "exact" else "standing"
        tok = self._issue("revision", client, tenant, v, proposal=prop, rev=1,
                          approval=approval, supersedes=None)
        with self._db() as db:
            db.execute("INSERT INTO proposals VALUES (?, ?)", (prop, json.dumps(v)))
        return "proposed", "revision issued", {"object": tok}

    def _counter(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        body = self._parse(p.request)
        rid = body.get("revision")
        new = self._check_values(body.get("terms"))
        with self._db() as db:
            row = db.execute("SELECT claims, raw, superseded_by FROM objects WHERE id = ?",
                             (rid,)).fetchone()
        if not row:
            raise Refused("unknown revision")
        old = json.loads(row[0])
        if old["issued_to"] != client or row[2]:
            raise Refused("not this client's current revision")
        if self.no_counter:     # KRK-M141: a new proposal, so the old revision stays current
            tok = self._issue("revision", client, tenant, new,
                              proposal=f"prop-{secrets.token_hex(6)}", rev=1,
                              approval=old["approval"], supersedes=None)
            return "proposed", "new proposal issued", {"object": tok}
        tok = self._issue("revision", client, tenant, new, proposal=old["proposal"],
                          rev=old["rev"] + 1, approval=old["approval"], supersedes=rid)
        nid = _decode(tok)["id"]
        with self._db() as db:
            db.execute("UPDATE objects SET superseded_by = ? WHERE id = ?", (nid, rid))
            db.execute("UPDATE proposals SET latest = ? WHERE id = ?",
                       (json.dumps(new), old["proposal"]))
        return "proposed", "next revision issued", {"object": tok}

    def _register(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        v = self._check_values(self._parse(p.request))
        tok = self._issue("consent", client, tenant, v, status="awaiting-authorisation")
        return "proposed", "consent registered", {"object": tok}

    def _par(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        body = self._parse(p.request)
        v = self._check_values(body.get("authorization_details"))
        uri = f"urn:toy:par:{secrets.token_hex(8)}"
        with self._db() as db:
            db.execute("INSERT INTO pending VALUES (?, ?, ?, ?, 0)",
                       (uri, client, tenant, json.dumps(v)))
        return "proposed", "authorization request pushed", \
            {"pending": {"request_uri": uri, "expires_in": 60}}

    def _token(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        uri = self._parse(p.request).get("request_uri")
        with self._db() as db:
            row = db.execute("SELECT client_id, tenant, details, approved FROM pending "
                             "WHERE uri = ?", (uri,)).fetchone()
            if not row or row[0] != client:
                raise Refused("unknown request_uri")
            if row[3] != 1:
                raise Refused("the person has not consented")
            db.execute("DELETE FROM pending WHERE uri = ?", (uri,))
        tok = self._issue("transaction-token", client, row[1], json.loads(row[2]))
        return "proposed", "token issued", {"object": tok}

    # accepting ------------------------------------------------------------------------------

    def _object(self, oid: Any) -> Tuple[Dict[str, Any], Dict[str, Any], "ToyIssuerB"]:
        """B's own record of object `oid`: (claims, row, issuing toy)."""
        f = self.flaw
        with self._db() as db:
            row = db.execute("SELECT claims, approved, superseded_by FROM objects WHERE id = ?",
                             (oid,)).fetchone()
        owner = self
        if not row and f == "accepts_foreign_object":
            with _NS_LOCK:
                owner = _NAMESPACE.get(oid)
            if owner is not None:
                with owner._db() as db:
                    row = db.execute("SELECT claims, approved, superseded_by FROM objects "
                                     "WHERE id = ?", (oid,)).fetchone()
        if not row:
            raise Refused(f"no object {oid!r} issued here")
        return json.loads(row[0]), {"approved": row[1], "superseded_by": row[2]}, owner

    def _accept(self, p) -> Tuple[str, str, Dict[str, Any]]:
        f, shape = self.flaw, self.shape
        body = self._parse(p.request)
        if not isinstance(body, dict):
            raise Refused("the body is not an object")
        if shape == "rar-token":
            token = p.authorisation or ""
            client, _ = self._client(p, token, txn=True)
            try:
                oid = _decode(token).get("id")
            except Exception:  # noqa: BLE001
                raise Refused("unreadable token") from None
        else:
            client, cred_tenant = self._client(p, p.authorisation)
            oid = body.get("revision") if shape == "revision" else body.get("consent_id")
        claims, row, owner = self._object(oid)
        terms = claims["terms"]
        if shape == "rar-token":
            cred_tenant = claims.get("tenant")
        checks = f != "no_check"
        if checks and f != "holder_not_checked" and claims.get("issued_to") != client:
            raise Refused("the object was issued to another agent")
        if checks and f != "tenant_not_checked" and not (
                claims.get("tenant") == p.tenant == cred_tenant):
            raise Refused("tenant mismatch")
        if checks and f not in ("terms_not_compared", "executes_request_not_terms") and \
                row["superseded_by"]:
            raise Refused(f"revision superseded by {row['superseded_by']}")
        if checks and f != "ignores_expiry" and self.now() > claims["exp"] + TOLERANCE_S:
            raise Refused("the object has expired")
        part = body.get("part")
        vals = _values(terms)
        if shape == "revision":
            by = body.get("approved_by")
            if checks and claims.get("approval") == "user" and f != "class_suffices":
                if by != "user":
                    raise Refused("this revision needs the person's approval")
                if row["approved"] != 1:
                    raise Refused("the person has not approved this revision")
            if checks and by not in ("user", "standing_permission"):
                raise Refused("unknown approval method")
        else:
            if shape == "consent-id" and checks and row["approved"] != 1:
                raise Refused("the consent is not authorised")
            presented = {k: body[k] for k in VALUE_MEMBERS if k in body}
            if part is not None:
                parts = terms.get("parts") or []
                if not isinstance(part, int) or not 0 <= part < len(parts):
                    raise Refused("no such part")
                want = dict(vals, items=parts[part])
            else:
                want = vals
            if f in ("terms_not_compared", "no_check"):
                vals = dict(vals, **presented)
            elif presented != want:
                same_but_items = {k: v for k, v in presented.items() if k != "items"} == \
                    {k: v for k, v in want.items() if k != "items"}
                if f == "accepts_subset" and same_but_items and \
                        set(presented.get("items") or []) < set(want.get("items") or []):
                    vals = dict(vals, items=list(presented["items"]))
                else:
                    raise Refused("the presented terms differ from the object's")
            else:
                vals = dict(want)
        if f == "executes_request_not_terms":
            vals = self._latest(claims, body, vals)
        key = str(oid) if part is None else f"{oid}#part{part}"
        if f == "per_endpoint_use":
            key = f"{key}@{p.endpoint}"
        if f == "dedupes_on_client_key":
            key = p.headers.get("Idempotency-Key") or key
        whole_key = str(oid)
        return self._use(key, whole_key, part, vals, claims, p)

    def _latest(self, claims: Dict[str, Any], body: Dict[str, Any],
                vals: Dict[str, Any]) -> Dict[str, Any]:
        """``executes_request_not_terms``: the values of the latest request body for the
        object's thread, overlaid by any ``instruction`` the acceptance carries."""
        out = dict(vals)
        if self.shape == "revision" and claims.get("proposal"):
            with self._db() as db:
                row = db.execute("SELECT latest FROM proposals WHERE id = ?",
                                 (claims["proposal"],)).fetchone()
            if row:
                out.update(_values(json.loads(row[0])))
        if isinstance(body.get("instruction"), dict):
            out.update({k: v for k, v in body["instruction"].items() if k in VALUE_MEMBERS})
        return out

    def _class(self, p) -> Tuple[str, str, Dict[str, Any]]:
        client, tenant = self._client(p, p.authorisation)
        v = self._check_values(self._parse(p.request))
        if OPERATIONS[v["operation"]] == "exact" and self.flaw not in ("class_suffices",
                                                                       "no_check"):
            raise Refused(f"{v['operation']} needs an exact object, not the class credential")
        return self._use(f"class:{v['ref']}", f"class:{v['ref']}", None, _values(v),
                         {"tenant": tenant}, p)

    # use records and the effect -------------------------------------------------------------

    def _get_use(self, key: str) -> Optional[str]:
        f = self.flaw
        if f == "use_record_in_memory":
            return self.proc_uses[self.active].get(key)
        if f == "per_instance_use":
            return self.inst_uses[self.active].get(key)
        with self._db() as db:
            if f == "forgets_before_expiry":
                db.execute("DELETE FROM uses WHERE at < ?", (self.now() - self.retention,))
            row = db.execute("SELECT state FROM uses WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def _claim(self, key: str, state: str) -> bool:
        """Mark the use; False when it was already there."""
        f = self.flaw
        if f == "use_record_in_memory":
            with self.lock:
                if key in self.proc_uses[self.active]:
                    return False
                self.proc_uses[self.active][key] = state
                return True
        if f == "per_instance_use":
            with self.lock:
                if key in self.inst_uses[self.active]:
                    return False
                self.inst_uses[self.active][key] = state
                return True
        try:
            with self._db() as db:
                db.execute("INSERT INTO uses VALUES (?, ?, ?)", (key, state, self.now()))
            return True
        except sqlite3.IntegrityError:
            return False

    def _set(self, key: str, state: str) -> None:
        f = self.flaw
        if f == "use_record_in_memory":
            self.proc_uses[self.active][key] = state
        elif f == "per_instance_use":
            self.inst_uses[self.active][key] = state
        else:
            with self._db() as db:
                db.execute("INSERT OR REPLACE INTO uses VALUES (?, ?, ?)",
                           (key, state, self.now()))

    def _repeat(self, state: str) -> Tuple[str, str, Dict[str, Any]]:
        if state == "done":
            if self.flaw == "duplicate_as_refusal":
                return "refused", "already used", {}
            return "duplicate", "already executed", {}
        return "in-progress", "being executed", {}

    def _parts_used(self, whole_key: str) -> bool:
        """Whether any part of `whole_key` was used, read from wherever this B keeps uses."""
        pre = f"{whole_key}#part"
        if self.flaw == "use_record_in_memory":
            return any(k.startswith(pre) for k in self.proc_uses[self.active])
        if self.flaw == "per_instance_use":
            return any(k.startswith(pre) for k in self.inst_uses[self.active])
        with self._db() as db:
            return bool(db.execute("SELECT 1 FROM uses WHERE key LIKE ?",
                                   (f"{pre}%",)).fetchone())

    def _use(self, key: str, whole_key: str, part: Optional[int], vals: Dict[str, Any],
             claims: Dict[str, Any], p) -> Tuple[str, str, Dict[str, Any]]:
        f = self.flaw
        if f == "forgets_before_expiry":
            with self._db() as db:
                db.execute("DELETE FROM uses WHERE at < ?", (self.now() - self.retention,))
        if part is None and f not in ("parts_and_whole", "every_acceptance_runs", "no_check") \
                and self._parts_used(whole_key):
            raise Refused("this object was used in parts")
        if f == "consumes_on_refusal":
            if not self._claim(key, "in-progress"):
                return self._repeat(self._get_use(key) or "in-progress")
            if not self.dep_ok:
                raise Refused("the ledger service is down")
            return self._run(key, vals, claims, p, marked=True)
        if not self.dep_ok:
            raise Refused("the ledger service is down")
        if f in ("every_acceptance_runs", "no_check"):
            return self._run(None, vals, claims, p, marked=False)
        if f == "check_then_set":
            st = self._get_use(key)
            if st:
                return self._repeat(st)
            out = self._run(None, vals, claims, p, marked=False)
            self._set(key, "done")
            return out
        if f == "effect_before_mark":
            with self.lock:
                st = self._get_use(key)
                if st:
                    return self._repeat(st)
                out = self._run(None, vals, claims, p, marked=False)
                self._set(key, "done")
                return out
        if f == "mark_before_effect_says_done":
            if not self._claim(key, "done"):
                return self._repeat(self._get_use(key) or "done")
            return self._run(None, vals, claims, p, marked=True)
        if not self._claim(key, "in-progress"):
            return self._repeat(self._get_use(key) or "in-progress")
        return self._run(key, vals, claims, p, marked=True)

    def _run(self, key: Optional[str], vals: Dict[str, Any], claims: Dict[str, Any],
             p, *, marked: bool) -> Tuple[str, str, Dict[str, Any]]:
        """Execute `vals`: the effect record and its ledger change, then the use marked done.
        A crash armed by `crash_between` dies after the first of the two writes: after the
        use mark where B marks first (`marked`), after the effect where it acts first."""
        if self.crash_armed and marked:
            raise ToyCrash()
        began = time.time()
        time.sleep(EFFECT_S)
        f = self.flaw
        v = dict(vals)
        if f == "member_outside_terms" and p.headers.get("X-Recipient"):
            v["recipient"] = p.headers["X-Recipient"]
        if f == "float_terms" and isinstance(v.get("amount"), int):
            v["amount"] = int(float(v["amount"]))
        if f == "fold_at_execution" and isinstance(v.get("recipient"), str):
            v["recipient"] = unicodedata.normalize("NFKC", v["recipient"])
        op = f"op-{secrets.token_hex(8)}"
        tenant = claims.get("tenant") or p.tenant
        if self.variant != "no-control":
            with self._db() as db:
                db.execute("INSERT INTO effects VALUES (?, ?, ?, ?, ?, ?)",
                           (op, str(v.get("ref")), tenant, json.dumps(v), self.now(), began))
                db.execute("INSERT INTO ledger (resource, op_id, ref, writer, at) VALUES "
                           "(?, ?, ?, 'b-core', ?)", (f"ledger:{tenant}", op, str(v.get("ref")),
                                                      self.now()))
                if f == "writes_unaccepted":
                    db.execute("INSERT INTO ledger (resource, op_id, ref, writer, at) VALUES "
                               "(?, ?, ?, 'b-core', ?)",
                               (f"ledger:{tenant}", f"op-{secrets.token_hex(8)}",
                                f"fee-{secrets.token_hex(4)}", self.now()))
        if self.crash_armed and not marked:
            raise ToyCrash()
        if key is not None:
            self._set(key, "done")
        return "executed", "executed", {"op_id": op,
                                        "proof": {"executed": True, "op_id": op, "values": v}}


def make(shape: str, flaw: Optional[str] = None, **knobs: Any) -> ToyIssuerB:
    t = ToyIssuerB(shape, "bad" if flaw else "good", flaw)
    for k, val in knobs.items():
        assert hasattr(t, k), k
        setattr(t, k, val)
    return t
