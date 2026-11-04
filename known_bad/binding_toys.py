"""P18 (KRK-18) toys: a receiving organisation B that performs an effect only for the exact,
addressed, valid request A authorised, at most once, and copies of it that each have one flaw.
Also a requesting organisation A for the role-A family, with its flawed copies (`ToyRequesterA`).

**The correct B** (``good``) verifies A's authorisation against the key pinned for its issuer,
checks the audience (counterparty, endpoint, tenant), the window (B's clock, with a stated
tolerance) and that the window does not outlive its memory, refuses a class authorisation for an
operation the agreement marks exact, refuses ambiguous bytes, translates a request in its own
vocabulary only through the mapping the pair's agreement declares, and compares the digest of
the bytes it acts on with the authorisation's (or with a declared part's). It keeps use records
in one SQLite file shared by its two endpoints, two tenants and two instances, marks a use with
an insert that refuses a duplicate key, after every check and before the effect, records the
outcome after it, and answers a repeat with the stored outcome (``duplicate``), or
``in-progress`` while it runs. A crash between the mark and the effect leaves the use
``in-progress`` and B never says done. It implements every check itself; it uses `authz`'s
verifier and digest functions, the shared specification, and none of the probe's judging.

**Role-B flaws** (`FLAWS`), each failing the variants named (``tests/test_p18_payload_bound.py``
holds the exact sets):

| Flaw | What it does | Fails |
|---|---|---|
| ``signature_only`` | verifies signature, audience and window; never the digest | ``body_changed``, ``split_undeclared``, ``duplicate_key``, ``number_precision``, ``unicode_fold`` |
| ``header_recipient`` | binds the body, takes the recipient from a header | ``unbound_member`` |
| ``last_key_wins`` | parses leniently (the last duplicate wins) for the check and the act | ``duplicate_key`` |
| ``float_amounts`` | parses numbers as floats for the check, acts on the raw text | ``number_precision`` |
| ``nfkc_before_check`` | NFKC-normalises before the digest, acts on the raw value | ``unicode_fold`` |
| ``accepts_scope`` | accepts a class authorisation for any operation | ``class_for_exact`` |
| ``no_memory`` | keeps no use records | the replay family, ``race_same``, ``crash_between_use_and_effect`` |
| ``duplicate_as_refusal`` | answers a repeat of a done request with a refusal | the replay family, ``race_same`` (``denied_done``) |
| ``dedupes_on_client_key`` | keys single use on the client's idempotency key | ``replay_new_key`` |
| ``memory_only`` | keeps use records in process memory | ``replay_after_restart``, ``replay_after_failover`` |
| ``per_replica_memory`` | one use store per instance | ``replay_after_failover`` |
| ``per_endpoint_memory`` | one use store per endpoint, and no endpoint audience check | ``replay_other_endpoint`` |
| ``ignores_tenant`` | no tenant audience check | ``replay_other_tenant`` |
| ``ignores_audience`` | no counterparty audience check | ``replay_other_counterparty`` |
| ``check_then_set`` | reads its use set, acts, then writes | ``race_same``, ``crash_between_use_and_effect`` |
| ``accepts_subset`` | on a digest mismatch, accepts a request whose items are inside the approver's summary | ``split_undeclared`` |
| ``parts_and_whole`` | counts uses per digest, so the whole runs after its parts | ``split_declared`` |
| ``ignores_not_after`` | checks only ``not_before`` | ``expired`` |
| ``forgets_before_expiry`` | accepts any validity and forgets uses after its horizon | ``validity_beyond_memory`` |
| ``consumes_on_refusal`` | marks the use, then checks its dependency | ``refused_then_retry`` |
| ``effect_before_mark`` | acts, then marks (under a lock, so races are safe) | ``crash_between_use_and_effect`` |
| ``mark_before_effect_says_done`` | marks the use as done before the effect | ``crash_between_use_and_effect`` (``claims_done``) |
| ``matches_by_shape`` | with no declared mapping, applies the one it uses for other counterparties | ``mapping_undeclared`` |

``check_then_set`` also fails the crash variant, and ``no_memory`` the crash and race variants,
because acting before marking is the same flaw at a crash as at a race.

``bad`` is ``no_check``: it executes whatever arrives. It must **fail**, not be inconclusive,
which shows the control does not demand the guarantee (KRK-M19). ``no-control``: its executor
never reaches the recorder, so the control cannot hold and the probe must give no verdict.

Knobs for the failure-mode pins: ``restart_wrapper_only`` (the restart hook restarts a wrapper and
reports the same boot id, KRK-M44), ``no_timing`` (answers carry no start time measured inside
B, KRK-M39), ``serialise`` (a front end that hands B's handler one presentation at a time, so a
race never overlaps inside B, KRK-M39), ``unrecorded_endpoint`` (that endpoint's executor posts
somewhere the recorder is not, KRK-M40), ``clock_ahead_s`` (B's clock runs ahead, KRK-M41),
``grade`` (the evidence grade the adapter reports).
"""
from __future__ import annotations

import json
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import unicodedata
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from conformance import authz, receipts

FLAWS = ("signature_only", "header_recipient", "last_key_wins", "float_amounts",
         "nfkc_before_check", "accepts_scope", "no_memory", "duplicate_as_refusal",
         "dedupes_on_client_key", "memory_only", "per_replica_memory", "per_endpoint_memory",
         "ignores_tenant", "ignores_audience", "check_then_set", "accepts_subset",
         "parts_and_whole", "ignores_not_after", "forgets_before_expiry", "consumes_on_refusal",
         "effect_before_mark", "mark_before_effect_says_done", "matches_by_shape")
BAD_DEFAULT = "no_check"

B_ID = "did:web:b.example"
ENDPOINTS = ("orders", "orders-eu")
TENANTS = ("t-17", "t-18")
INSTANCES = ("i-1", "i-2")
OPERATIONS = {"crm.record.push": "exact", "notes.append": "class"}
MAPPING_NAME = "kirkaldy.map/crm-v1"
DEFAULT_MAPPING = {"fields": {"op": "operation", "to": "recipient", "value": "amount",
                              "lines": "items", "ref": "ref"},
                   "values": {"operation": {"people.upsert": "crm.record.push"}}}
TOLERANCE_S = 60
HORIZON_S = 3600
MAX_VALIDITY_S = 3600
EFFECT_S = 0.03
"""How long the toy's executor takes before its downstream call, so presentations overlap."""


class ToyCrash(BaseException):
    """B's process dying between two writes."""


def _nfkc(x: Any) -> Any:
    if isinstance(x, str):
        return unicodedata.normalize("NFKC", x)
    if isinstance(x, list):
        return [_nfkc(v) for v in x]
    if isinstance(x, dict):
        return {k: _nfkc(v) for k, v in x.items()}
    return x


def _ints(x: Any) -> Any:
    if isinstance(x, float) and x.is_integer():
        return int(x)
    if isinstance(x, list):
        return [_ints(v) for v in x]
    if isinstance(x, dict):
        return {k: _ints(v) for k, v in x.items()}
    return x


def _loose_sha(obj: Any) -> str:
    return receipts.sha256_ref(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8"))


class Refused(Exception):
    pass


class ToyBinding:
    name = "toy-payload-binding"

    def __init__(self, variant: str = "good", flaw: Optional[str] = None,
                 grade: str = "recorder") -> None:
        assert variant in ("good", "bad", "no-control"), variant
        if variant == "bad" and flaw is None:
            flaw = BAD_DEFAULT
        assert flaw is None or flaw == BAD_DEFAULT or (variant == "bad" and flaw in FLAWS), flaw
        self.variant, self.flaw, self.grade = variant, flaw, grade
        self.config = f"bad:{flaw}" if flaw and flaw != BAD_DEFAULT else variant
        self.restart_wrapper_only = False
        self.no_timing = False
        self.serialise = False
        self.unrecorded_endpoint: Optional[str] = None
        self.clock_ahead_s = 0.0
        self.dir: Optional[Path] = None
        self.pinned: Dict[str, Dict[str, bytes]] = {}
        self.mappings: Dict[str, Optional[Dict[str, Any]]] = {}
        self.recorder_url: Optional[str] = None
        self.local_effects: List[Dict[str, Any]] = []
        self.received_log: Dict[str, bytes] = {}
        self.active = INSTANCES[0]
        self.boot = {i: secrets.token_hex(4) for i in INSTANCES}
        self.proc_mem: Dict[str, Dict[str, Dict[str, Any]]] = {i: {} for i in INSTANCES}
        self.skew = 0.0
        self.horizon = HORIZON_S
        self.dep_ok = True
        self.crash_armed = False
        self.crashed_flag = False
        self.lock = threading.Lock()
        self.serial = threading.Lock()

    # Target -----------------------------------------------------------------------------------

    def version(self) -> str:
        return f"toy-{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def implements(self):
        return ["P18"]

    def start(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="toy-p18-"))

    def stop(self) -> None:
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)

    # P18 adapter (role B) ---------------------------------------------------------------------

    def role(self) -> str:
        return "B"

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": B_ID, "endpoints": list(ENDPOINTS), "aliases": {},
                "tenants": list(TENANTS), "operations": dict(OPERATIONS),
                "binding_basis": authz.CANONICAL, "mappings": {MAPPING_NAME: DEFAULT_MAPPING},
                "max_validity_s": MAX_VALIDITY_S, "memory_horizon_s": HORIZON_S,
                "clock_tolerance_s": TOLERANCE_S,
                "answer_codes": {"executed": "200 {code: executed}",
                                 "duplicate": "409 {code: duplicate}",
                                 "in-progress": "409 {code: in-progress}",
                                 "refused": "422 {code: refused}"},
                "claims_replay_protection": True,
                "quotes": {"*": "the toy's module docstring (known_bad/binding_toys.py)"}}

    def pin_requester_key(self, issuer: str, kid: str, public_key: bytes,
                          mapping: Optional[Dict[str, Any]] = None) -> None:
        self.pinned.setdefault(issuer, {})[kid] = bytes(public_key)
        self.mappings[issuer] = mapping

    def bind_recorder(self, recorder_url: str) -> str:
        if self.variant == "no-control":
            return "not bound: this toy's executor posts to its own list"
        self.recorder_url = recorder_url.rstrip("/")
        return f"the toy's executor POSTs each effect to {self.recorder_url}/effect/<id>"

    def evidence_grade(self) -> str:
        return self.grade

    def classify(self, answer: Dict[str, Any]) -> str:
        code = (answer.get("body") or {}).get("code") if isinstance(answer, dict) else None
        return {"executed": "executed", "duplicate": "duplicate", "in-progress": "in-progress",
                "refused": "refused"}.get(code, "error")

    def received(self, pid: str) -> Optional[bytes]:
        return self.received_log.get(pid)

    def now(self) -> float:
        return time.time() + self.skew + self.clock_ahead_s

    def elapse(self, seconds: float) -> None:
        self.skew += seconds

    def instances(self) -> List[str]:
        return list(INSTANCES)

    def restart(self, kind: str) -> Dict[str, str]:
        before = f"{self.active}:{self.boot[self.active]}"
        if self.restart_wrapper_only:
            return {"before": before, "after": before, "how": "restarted the wrapper only"}
        if kind == "process":
            self._die()
            how = "the toy's state-holding process replaced"
        elif kind == "failover":
            self.active = INSTANCES[1] if self.active == INSTANCES[0] else INSTANCES[0]
            how = "requests now go to the other instance"
        else:
            raise ValueError(kind)
        return {"before": before, "after": f"{self.active}:{self.boot[self.active]}", "how": how}

    def _die(self) -> None:
        self.boot[self.active] = secrets.token_hex(4)
        self.proc_mem[self.active] = {}

    def dependency(self, available: bool) -> str:
        self.dep_ok = bool(available)
        return f"the toy's ledger service {'up' if available else 'down'}"

    def crash_between(self, step: str) -> str:
        self.crash_armed = True
        return ("armed: B's process dies after the first of its two writes (the use record and "
                "the effect); in process, milder than a process death")

    def crashed(self) -> bool:
        return self.crashed_flag

    def set_memory_horizon(self, seconds: Optional[int]) -> str:
        self.horizon = HORIZON_S if seconds is None else int(seconds)
        return f"memory horizon {self.horizon} s"

    def present(self, p: authz.Presentation) -> Dict[str, Any]:
        if self.serialise:          # a front end that queues: B's handler sees one at a time
            with self.serial:
                return self._present(p)
        return self._present(p)

    def _present(self, p: authz.Presentation) -> Dict[str, Any]:
        began = time.time()
        self.received_log[p.pid] = bytes(p.request)
        try:
            code, why = self._handle(p)
        except ToyCrash:
            self._die()
            self.crash_armed = False
            self.crashed_flag = True
            raise ConnectionError("connection reset: B's process died")
        status = {"executed": 200, "duplicate": 409, "in-progress": 409}.get(code, 422)
        ans: Dict[str, Any] = {"status": status, "body": {"code": code, "reason": why}}
        if not self.no_timing:
            ans.update(began_at=began, ended_at=time.time())
        return ans

    # the toy's own checks ---------------------------------------------------------------------

    def _handle(self, p: authz.Presentation) -> Tuple[str, str]:
        try:
            return self._checked(p)
        except Refused as e:
            return "refused", str(e)

    def _checked(self, p: authz.Presentation) -> Tuple[str, str]:
        f = self.flaw
        if f == BAD_DEFAULT:
            vals = json.loads(p.request.decode("utf-8"))
            if isinstance(vals, dict) and "op" in vals:
                vals = self._untranslate(vals, DEFAULT_MAPPING)
            self._effect(vals, p)
            return "executed", "no checks"
        tok = p.authorisation
        issuer = (authz.claims_of(tok) or {}).get("issuer")
        v = authz.verify_authorisation(tok, self.pinned.get(str(issuer), {}))
        if not v.ok:
            raise Refused(f"authorisation not verified: {v.reason}")
        c = v.claims
        aud = c["audience"]
        if f != "ignores_audience" and aud["counterparty"] != B_ID:
            raise Refused("audience-mismatch: another organisation")
        if f != "per_endpoint_memory" and aud["endpoint"] != p.endpoint:
            raise Refused("audience-mismatch: another endpoint")
        if f != "ignores_tenant" and aud["tenant"] != p.tenant:
            raise Refused("audience-mismatch: another tenant")
        now = self.now()
        nb, na = authz.epoch(c["not_before"]), authz.epoch(c["not_after"])
        if now < nb - TOLERANCE_S:
            raise Refused("not-yet-valid")
        if f != "ignores_not_after" and now > na + TOLERANCE_S:
            raise Refused("expired")
        if f != "forgets_before_expiry" and na - now > self.horizon:
            raise Refused("validity-exceeds-memory")
        b = c["binding"]
        raw = p.request
        if b["kind"] == "class":
            if f != "accepts_scope" and OPERATIONS.get(c["operation"]) != "class":
                raise Refused("class-not-allowed")
            try:
                vals = authz.parse(raw)
            except authz.NotBindable as e:
                raise Refused(f"ambiguous-input: {e.reason}")
            if int(vals.get("amount", 0)) > int((b["ceiling"] or {}).get("max_amount", 0)):
                raise Refused("over-ceiling")
            digest, part = authz.binding_digest(raw), None
        else:
            vals, digest, part = self._exact(raw, b, str(issuer), p)
        if f == "header_recipient" and "X-Recipient" in p.headers:
            vals = {**vals, "recipient": p.headers["X-Recipient"]}
        key = f"{issuer}::{c['authorisation_id']}"
        if part is not None:
            key += f"::{part}"
        if f == "dedupes_on_client_key":
            key = f"client::{p.headers.get('Idempotency-Key')}"
        return self._use(key, digest, na, vals, p)

    def _exact(self, raw: bytes, b: Dict[str, Any], issuer: str,
               p: authz.Presentation) -> Tuple[Dict[str, Any], str, Optional[str]]:
        f = self.flaw
        try:
            loose = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise Refused("ambiguous-input: not-json")
        check = raw
        if isinstance(loose, dict) and "op" in loose:     # B's own vocabulary
            declared = self.mappings.get(issuer)
            if declared is None:
                if f != "matches_by_shape":
                    raise Refused("mapping-undeclared")
                declared = DEFAULT_MAPPING
            elif b["mapping"] != MAPPING_NAME:
                raise Refused("mapping-mismatch: the authorisation names no declared mapping")
            if authz.ambiguous(raw):
                raise Refused(f"ambiguous-input: {authz.ambiguous(raw)}")
            loose = self._untranslate(authz.parse(raw), declared)
            check = receipts.canonical_json(loose)
        vals = loose
        if f == "signature_only":
            digest = authz.binding_digest(check, authz.RAW)
        elif f == "last_key_wins":
            digest = authz.lenient_digest(check)
        elif f == "float_amounts":
            found = authz.explain_ambiguity(check)
            if "duplicate-key" in found or "not-json" in found:
                raise Refused("ambiguous-input")
            digest = _loose_sha(_ints(json.loads(check.decode("utf-8"), parse_int=float,
                                                 parse_float=float)))
        else:
            amb = authz.ambiguous(check)
            if amb:
                raise Refused(f"ambiguous-input: {amb}")
            if f == "nfkc_before_check":
                digest = receipts.sha256_ref(receipts.canonical_json(_nfkc(authz.parse(check))))
            else:
                digest = authz.binding_digest(check, b["basis"])
        if f == "signature_only":
            return vals, digest, None
        if b["parts"]:
            if digest in b["parts"]:
                return vals, digest, f"part{b['parts'].index(digest)}"
            if f == "parts_and_whole" and digest == b["request_digest"]:
                return vals, digest, "whole"
            raise Refused("parts-declared: only a declared part may run")
        if digest != b["request_digest"]:
            if f == "accepts_subset" and self._inside(vals, b.get("summary")):
                return vals, digest, None
            raise Refused("payload-mismatch")
        return vals, digest, None

    @staticmethod
    def _inside(vals: Dict[str, Any], summary: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(summary, dict):
            return False
        same = all(vals.get(k) == summary.get(k) for k in summary if k != "items")
        return same and set(vals.get("items") or []) <= set(summary.get("items") or [])

    @staticmethod
    def _untranslate(vals: Dict[str, Any], mapping: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        for k, v in vals.items():
            a = mapping["fields"].get(k, k)
            table = mapping.get("values", {}).get(a, {})
            out[a] = table.get(v, v) if isinstance(v, str) else v
        return out

    # use records ------------------------------------------------------------------------------

    def _db(self, p: authz.Presentation) -> sqlite3.Connection:
        assert self.dir is not None
        name = "uses.sqlite"
        if self.flaw == "per_replica_memory":
            name = f"uses-{self.active}.sqlite"
        elif self.flaw == "per_endpoint_memory":
            name = f"uses-{p.endpoint}.sqlite"
        db = sqlite3.connect(self.dir / name, timeout=30, isolation_level=None)
        db.execute("CREATE TABLE IF NOT EXISTS uses (key TEXT PRIMARY KEY, digest TEXT, "
                   "state TEXT, recorded_at REAL, not_after REAL)")
        return db

    def _purge(self, db: sqlite3.Connection) -> None:
        now = self.now()
        if self.flaw == "forgets_before_expiry":
            db.execute("DELETE FROM uses WHERE recorded_at < ?", (now - self.horizon,))
        else:
            db.execute("DELETE FROM uses WHERE not_after + ? < ?", (TOLERANCE_S, now))

    def _get(self, key: str, p: authz.Presentation) -> Optional[Dict[str, Any]]:
        if self.flaw == "memory_only":
            return self.proc_mem[self.active].get(key)
        db = self._db(p)
        try:
            self._purge(db)
            row = db.execute("SELECT digest, state FROM uses WHERE key = ?", (key,)).fetchone()
        finally:
            db.close()
        return {"digest": row[0], "state": row[1]} if row else None

    def _claim(self, key: str, digest: str, na: float, state: str,
               p: authz.Presentation) -> bool:
        """Insert the use record; False if one is already there (the insert refused it)."""
        if self.flaw == "memory_only":
            with self.lock:
                mem = self.proc_mem[self.active]
                if key in mem:
                    return False
                mem[key] = {"digest": digest, "state": state}
                return True
        db = self._db(p)
        try:
            self._purge(db)
            cur = db.execute("INSERT OR IGNORE INTO uses VALUES (?, ?, ?, ?, ?)",
                             (key, digest, state, self.now(), na))
            return cur.rowcount == 1
        finally:
            db.close()

    def _set(self, key: str, state: str, p: authz.Presentation) -> None:
        if self.flaw == "memory_only":
            with self.lock:
                if key in self.proc_mem[self.active]:
                    self.proc_mem[self.active][key]["state"] = state
            return
        db = self._db(p)
        try:
            db.execute("UPDATE uses SET state = ? WHERE key = ?", (state, key))
        finally:
            db.close()

    def _repeat(self, row: Dict[str, Any], digest: str) -> Tuple[str, str]:
        if row["digest"] != digest:
            raise Refused("authorisation-reused: another request under this authorisation")
        if row["state"] == "refused":
            raise Refused("authorisation-used")
        if self.flaw == "duplicate_as_refusal":
            raise Refused("already used")
        if row["state"] == "done":
            return "duplicate", "already performed under this authorisation"
        return "in-progress", "the first presentation is still running"

    def _use(self, key: str, digest: str, na: float, vals: Dict[str, Any],
             p: authz.Presentation) -> Tuple[str, str]:
        f = self.flaw
        if f == "no_memory":
            self._dep()
            self._effect(vals, p)
            self._maybe_crash()
            return "executed", "performed"
        if f == "consumes_on_refusal":
            if not self._claim(key, digest, na, "in-progress", p):
                return self._repeat(self._get(key, p), digest)
            self._maybe_crash()
            if not self.dep_ok:
                self._set(key, "refused", p)
                raise Refused("dependency-unavailable")
            self._effect(vals, p)
            self._set(key, "done", p)
            return "executed", "performed"
        self._dep()
        if f in ("check_then_set", "effect_before_mark"):
            ctx = self.lock if f == "effect_before_mark" else _Null()
            with ctx:
                row = self._get(key, p)
                if row is not None:
                    return self._repeat(row, digest)
                self._effect(vals, p)
                self._maybe_crash()
                if not self._claim(key, digest, na, "done", p):
                    return self._repeat(self._get(key, p), digest)
            return "executed", "performed"
        first = "done" if f == "mark_before_effect_says_done" else "in-progress"
        if not self._claim(key, digest, na, first, p):
            return self._repeat(self._get(key, p), digest)
        self._maybe_crash()
        self._effect(vals, p)
        self._set(key, "done", p)
        return "executed", "performed"

    def _dep(self) -> None:
        if not self.dep_ok:
            raise Refused("dependency-unavailable")

    def _maybe_crash(self) -> None:
        if self.crash_armed:
            raise ToyCrash()

    def _effect(self, vals: Dict[str, Any], p: authz.Presentation) -> None:
        began = time.time()
        time.sleep(EFFECT_S)
        body = {k: vals.get(k) for k in ("ref", "operation", "recipient", "amount", "items")}
        body.update(endpoint=p.endpoint, tenant=p.tenant, instance=self.active, began_at=began)
        if not self.recorder_url or p.endpoint == self.unrecorded_endpoint:
            self.local_effects.append(body)
            return
        req = urllib.request.Request(f"{self.recorder_url}/effect/{secrets.token_hex(6)}",
                                     data=json.dumps(body).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make(flaw: Optional[str] = None, **kw: Any) -> ToyBinding:
    """The correct toy (no flaw) or the copy with one flaw."""
    return ToyBinding("bad", flaw, **kw) if flaw else ToyBinding("good", **kw)


# =========================================================================== role A

A_FLAWS = ("no_authorisation", "rebuilds_on_retry", "reuses_id", "any_audience",
           "duplicate_as_not_executed", "refusal_as_outcome")
"""Role-A flaws, each failing the role-A checks named:

| Flaw | What it does | Fails |
|---|---|---|
| ``no_authorisation`` | sends the request with no authorisation | ``authorisation_present`` |
| ``rebuilds_on_retry`` | rebuilds the request on every send (a fresh ``sent_nonce`` member) and signs it again | ``retry_same`` |
| ``reuses_id`` | binds a correlation id again for a new decision and derives the authorisation id from it | ``fresh_per_decision``, ``one_audience`` |
| ``any_audience`` | keeps one authorisation per correlation id and presents it to any counterparty | ``one_audience`` |
| ``duplicate_as_not_executed`` | reads B's "already performed" answer as not executed | ``honours_duplicate`` |
| ``refusal_as_outcome`` | rebuilds the bytes on a retry (a fresh ``sent_checkpoint`` member) under the same authorisation id, and records B's signed refusal of that retry as the outcome: "refused" while B performed the first send | ``retry_same``, ``record_matches_effect`` |

``reuses_id`` fails both checks because one id per request, reused, is the same flaw whether the
second presentation goes to a new decision or a new counterparty. ``refusal_as_outcome`` fails
``retry_same`` too because a strict B refuses a repeat only when its bytes differ; the knob
``careful_reading`` makes the same toy read that refusal, after a lost answer, as disputed, and
then it fails ``retry_same`` alone (``record_matches_effect`` reads ``disputed_held``)."""
A_BAD_DEFAULT = "no_authorisation"


class ToyRequesterA:
    """A requesting organisation A for the role-A family. ``good``: binds each correlation id to
    one decision and one counterparty, freezes the request's bytes and a signed authorisation (a
    fresh id from the operating system, the digest of those bytes, B as audience, a window) at
    the first send, resends exactly those on a retry, completes only on B's verified receipt for
    those bytes, and reads B's "already performed" answer as awaiting a receipt."""

    name = "toy-payload-binding-a"

    def __init__(self, variant: str = "good", flaw: Optional[str] = None) -> None:
        assert variant in ("good", "bad", "no-control"), variant
        if variant == "bad" and flaw is None:
            flaw = A_BAD_DEFAULT
        assert flaw is None or (variant == "bad" and flaw in A_FLAWS), flaw
        self.variant, self.flaw = variant, flaw
        self.config = f"a-bad:{flaw}" if flaw else f"a-{variant}"
        self.key = receipts.Keypair.generate(f"a-authz-toy-{secrets.token_hex(3)}")
        self.peers: Dict[str, Any] = {}
        self.b_keys: Dict[str, Dict[str, bytes]] = {}
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.bound_cids: Dict[str, str] = {}
        self.per_cid_token: Dict[str, str] = {}
        self.careful_reading = False
        """Knob: read B's ``authorisation-reused`` refusal of a retry after a lost answer as
        disputed (the first send may have run), not as the outcome."""

    def version(self) -> str:
        return f"toy-{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def implements(self):
        return ["P18"]

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def role(self) -> str:
        return "A"

    def authorisation_key(self):
        return self.key.kid, self.key.public_bytes()

    def bind_counterparty(self, peer: str, send: Any, receipt_key: Tuple[str, bytes]) -> str:
        self.peers[peer] = send
        self.b_keys[peer] = {receipt_key[0]: bytes(receipt_key[1])}
        return f"send path and receipt key for {peer}"

    def pin_counterparty_key(self, kid: str, public_key: bytes) -> None:
        pass

    def submit(self, envelope: Dict[str, Any], expected: Any) -> str:
        cid = envelope["correlation_id"]
        if cid in self.bound_cids and self.flaw != "reuses_id":
            held = self.cases[self.bound_cids[cid]]
            if not (self.flaw == "any_audience"
                    and held["envelope"]["counterparty"] != envelope["counterparty"]):
                raise ValueError(f"correlation id {cid!r} is already bound to a decision")
        case_id = f"case-{len(self.cases) + 1}"
        self.cases[case_id] = {"envelope": dict(envelope), "expected": expected,
                               "status": "authorized", "raw": None, "token": None,
                               "lost": False}
        self.bound_cids.setdefault(cid, case_id)
        return case_id

    def _frozen(self, c: Dict[str, Any]) -> Tuple[bytes, Optional[str]]:
        env = c["envelope"]
        if self.flaw == "refusal_as_outcome" and c["raw"] is not None:
            # A fresh member on every send after the first (as an envelope carrying a fresh
            # checkpoint has), signed again under the first authorisation's id.
            az = (authz.claims_of(c["token"]) or {}).get("authorisation_id")
            c["raw"] = receipts.canonical_json(dict(env, sent_checkpoint=secrets.randbits(32)))
            c["token"] = self._authorise(c["raw"], env, authorisation_id=az)
            return c["raw"], c["token"]
        if self.flaw == "rebuilds_on_retry" or c["raw"] is None:
            body = dict(env, sent_nonce=secrets.randbits(32)) if self.flaw == "rebuilds_on_retry" else env
            c["raw"] = receipts.canonical_json(body)
            c["token"] = self._authorise(c["raw"], env)
        return c["raw"], c["token"]

    def _authorise(self, raw: bytes, env: Dict[str, Any], *,
                   authorisation_id: Optional[str] = None) -> Optional[str]:
        if self.flaw == "no_authorisation":
            return None
        cid = env["correlation_id"]
        if self.flaw == "any_audience" and cid in self.per_cid_token:
            return self.per_cid_token[cid]
        az = authorisation_id or (f"az-{receipts.sha256_ref(cid.encode())[7:23]}"
                                  if self.flaw == "reuses_id" else None)
        now = time.time()
        claims = authz.authorisation_claims(
            issuer="did:web:a.example",
            audience={"counterparty": env["counterparty"], "endpoint": None, "tenant": None},
            operation=env["operation"], binding=authz.exact_binding(raw), max_uses=1,
            not_before=authz.utc(now - 60), not_after=authz.utc(now + 900),
            decision_digest=None, authorisation_id=az)
        tok = authz.sign_authorisation(claims, self.key)
        self.per_cid_token.setdefault(cid, tok)
        return tok

    def send(self, case_id: str) -> str:
        c = self.cases[case_id]
        if self.variant == "no-control":
            return "this toy has no path to B"
        raw, tok = self._frozen(c)
        try:
            ans = self.peers[c["envelope"]["counterparty"]](raw, tok, {})
        except Exception as e:  # noqa: BLE001  (the answer was lost)
            c["status"] = "outcome-unknown"
            c["lost"] = True
            return f"answer lost: {e}"
        self._read(c, raw, ans)
        return f"B answered {ans.get('answer')!r}"

    def retry(self, case_id: str) -> str:
        return "resent: " + self.send(case_id)

    def _read(self, c: Dict[str, Any], raw: bytes, ans: Dict[str, Any]) -> None:
        tok = ans.get("receipt")
        if tok is None:
            if ans.get("answer") == "duplicate":
                c["status"] = ("not-executed" if self.flaw == "duplicate_as_not_executed"
                               else "awaiting-receipt")
            return
        v = receipts.verify_receipt(tok, self.b_keys[c["envelope"]["counterparty"]])
        if not v.ok or v.claims["request_digest"] != receipts.sha256_ref(raw):
            c["status"] = "blocked"
            return
        c["status"] = {"executed": "done", "refused": "refused"}.get(v.claims["verdict"],
                                                                      "blocked")
        if (c["status"] == "refused" and self.careful_reading and c["lost"]
                and ans.get("code") == "authorisation-reused"):
            c["status"] = "disputed"

    def status(self, case_id: str) -> str:
        return self.cases[case_id]["status"]

    def outcome(self, case_ref: str) -> str:
        s = self.cases[case_ref]["status"]
        return {"done": "done", "not-executed": "not-done", "refused": "not-done",
                "disputed": "disputed"}.get(s, "open")


def make_a(flaw: Optional[str] = None) -> ToyRequesterA:
    return ToyRequesterA("bad", flaw) if flaw else ToyRequesterA("good")
