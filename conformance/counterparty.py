"""A stub counterparty B for KRK-16 (P16): a real SQLite store and a real Ed25519 receipt key.

B applies the effect to its own store, one row per item, and builds each receipt from what the
store holds after the commit, never from the request. The variants change what B writes and
what it answers, and nothing else:

- a negative receipt is a genuine signature over content that does not match what A expected,
  or is unsigned. Signed bytes are never altered and nothing is forged;
- `store_counts` reads B's store directly, so the probe has ground truth that does not depend
  on any receipt.

The receipt's ``items_digest`` names the item set of the request it answers, as B received it
and logged it; the outcome counts say what B committed out of that set. So a receipt for a short
or partial write differs from the expectation in its counts only, and each variant isolates one
check. (Were the digest over the committed keys alone, the item check would also catch every
short write and a target that ignores counts could not be told from one that does not.)

The request envelope must carry ``correlation_id`` (a string) and the item keys as a list of
distinct strings, under ``items`` or ``payload.items``; `make_envelope` builds one. If it
carries ``expected_effect_digest``, that must equal the expectation passed alongside.

**Wire profiles (for outside targets).** A target that reads another receipt
format cannot parse B's claims, so it would reject every receipt as malformed and every variant
would read as "not done" for that reason alone. A profile (`PROFILES`) adds, to the claims B
signs, the members another format requires, each derived from the same committed log entry as
the kit's own claims. B still signs once, with its own key; the kit's claims are unchanged and
the kit's verifier ignores the added members. A profile never overwrites a kit claim and never
looks at the variant: it reads only what B's store says (the verdict, the request digest, the log
sequence). A verdict the format has no way to say gets no added members, so the target sees a
receipt it cannot parse; P16 lets the adapter declare such a variant not applicable instead of
counting that rejection (see `p16_effect_receipt.py`). The kit holds only a made-up example
profile; an adapter adds the format its product reads with `register_profile`, from its own
directory, so the format's code is hashed with the adapter (`conformance.versions`).

**Strict single-use mode (added for KRK-18's role-A family).** ``StubCounterparty(...,
single_use=True)`` adds `receive`, the path a target in role A sends its raw request bytes to,
with any authorisation and headers. B keeps every presentation as received
(`received_requests`) and remembers each use key: the authorisation's id when one is presented,
else the request's correlation id. The same key with the same request digest is a repeat:
nothing runs again, and B answers with the receipt it issued (``repeat_answer="original"``) or
with "already performed" and no receipt (``"duplicate"``). The same key with another digest is
refused with a signed refusal, reason ``authorisation-reused``. Nothing in the KRK-16 or KRK-17
paths changes when the mode is off.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import json
import random
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import books, receipts
from .receipts import ExpectedEffect, Keypair

VARIANTS = ("honest", "wrong_request", "unsigned", "unpinned_key", "count_mismatch",
            "honest_partial", "missing", "agent_report", "signed_refusal", "signed_no_record",
            "disputed_no_record", "sibling_request")
"""`signed_no_record` and `disputed_no_record`: B writes nothing and signs a
permanent "no record of this request". In the first the executor reports that it could not
confirm the send (``"sent": false``), so A may close the attempt as not executed; in the second
the executor reports success, so the two sides disagree and a person decides.

`wrong_request` and `sibling_request` both answer with B's genuine receipt for another request
that has the same items and expectation. They differ in whose request that is. In
`wrong_request` it is a request B received that A never made: B applies it beside A's and
answers with its receipt. In `sibling_request` it is one of A's own earlier
requests, passed as ``earlier=``: B executes it honestly (once, if it has not already), then
executes A's current request in full and answers it with the receipt it issued for the earlier
one. The token is replayed exactly as B signed it. A target that checks only whether a receipt
names a request it knows refuses the first and accepts the second (KRK-M20)."""

REPLAYS = ("sibling_request",)
"""Variants whose answer is a receipt B issued earlier for another request, sent again as it was
signed."""

K_MAX = 15
"""Upper bound for k, the number of items short in count_mismatch and honest_partial."""

REFUSAL_REASON = "outside-mandate"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log (
    log_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    pair_seq INTEGER NOT NULL,
    prev_digest TEXT,
    kind TEXT NOT NULL,
    correlation_id TEXT,
    request_digest TEXT,
    body TEXT NOT NULL,
    raw_sha256 TEXT,
    recorded_at TEXT NOT NULL,
    entry_digest TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS log_pair ON log (requester, pair_seq);
CREATE TABLE IF NOT EXISTS requests (
    log_seq INTEGER PRIMARY KEY REFERENCES log(log_seq),
    requester TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    variant TEXT NOT NULL,
    verdict TEXT NOT NULL,
    failed INTEGER NOT NULL DEFAULT 0,
    items_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS answers (
    answer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_seq INTEGER NOT NULL REFERENCES log(log_seq),
    token TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS holdings (
    holding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    token TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    container TEXT NOT NULL,
    item_key_hash TEXT NOT NULL,
    verb TEXT NOT NULL CHECK (verb IN ('create', 'update', 'delete')),
    log_seq INTEGER NOT NULL REFERENCES log(log_seq)
);
"""
"""B's store. `log` is B's log, in the kit's reading format (one row per entry, numbered per
requester, chained); it is append-only (`_TRIGGERS`). `requests` and `answers` are B's own
bookkeeping of what it was asked and what it sent back, written once per row and never changed
either; they are not part of the log B shows anyone. `items` is B's state, which a read API
serves and an ordinary write may change."""

APPEND_ONLY = ("log", "requests", "answers", "holdings")
_TRIGGERS = "".join(
    f"""
CREATE TRIGGER IF NOT EXISTS {t}_no_update BEFORE UPDATE ON {t}
BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END;
CREATE TRIGGER IF NOT EXISTS {t}_no_delete BEFORE DELETE ON {t}
BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END;""" for t in APPEND_ONLY)
_TRIGGER_STATEMENTS = [t.strip() + " END;" for t in _TRIGGERS.split("END;") if t.strip()]
"""Refuse UPDATE and DELETE on B's log and bookkeeping (KRK-M35, KRK-M35). The only way past
them is `StubCounterparty._tamper`, the kit-only path that plays an insider at B with owner
rights, which drops the triggers for one transaction and puts them back."""

_VERB_FIELD = {"create": "created", "update": "updated", "delete": "deleted"}


def make_envelope(correlation_id: str, expected: ExpectedEffect, items: List[str],
                  **extra: Any) -> Dict[str, Any]:
    """A request envelope in the shape the stub reads. `extra` adds members (requester, batch)."""
    env: Dict[str, Any] = {
        "schema": "kirkaldy.effect-request/0.1",
        "correlation_id": correlation_id,
        "operation": expected.operation,
        "counterparty": expected.counterparty,
        "container": expected.container,
        "items": list(items),
        "expected_effect_digest": expected.digest(),
    }
    env.update(extra)
    return env


def envelope_items(envelope: Dict[str, Any]) -> List[str]:
    for holder in (envelope, envelope.get("payload")):
        if isinstance(holder, dict) and "items" in holder:
            items = holder["items"]
            if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
                raise ValueError("envelope items must be a list of strings")
            return items
    raise ValueError("envelope carries no item keys (expected 'items' or 'payload.items')")


def _now(skew_s: int = 0) -> str:
    t = datetime.now(timezone.utc).timestamp() + skew_s
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def example_reference(request_digest: str) -> str:
    """The example profile's encoding of B's digest of the request it received: base64url (no
    padding) of the raw SHA-256. The kit writes the same digest as ``sha256:<hex>``; only the
    encoding differs."""
    algo, _, hexdigest = request_digest.partition(":")
    if algo != "sha256" or len(hexdigest) != 64:
        raise ValueError(f"not a sha256 digest: {request_digest!r}")
    return _b64url(bytes.fromhex(hexdigest))


def _example_receipt(claims: Dict[str, Any]) -> Dict[str, Any]:
    """A made-up wire profile that exercises the hook; it is no product's format. B restates its
    verdict as ``outcome_code`` (``done`` or ``refused``), the committed item count as
    ``outcome_items`` and its digest of the request as ``request_ref``. The format has no way to
    say a no-record, so a no-record gets nothing and is a format gap."""
    verdict = claims["verdict"]
    base = {"request_ref": example_reference(claims["request_digest"])}
    if verdict == "executed":
        o = claims["outcome"]
        done = sum(int(o[f]) for f in o if f != "failed")
        return {**base, "outcome_code": "done", "outcome_items": done}
    if verdict == "refused":
        return {**base, "outcome_code": "refused",
                "outcome_reason": str(claims["refusal_reason"])}
    return {}


PROFILES: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "example-receipt": _example_receipt,
}
"""Wire profiles by name (module docstring). The function maps B's claims to the members it
adds; it must not return a member the kit's claims already have."""


def register_profile(name: str, fn: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
    """Add the wire profile `name` (module docstring), for an adapter's `receipt_profile()`.
    Registering the same function again (a module imported twice) is a no-op; any other function
    under a name already taken raises ValueError, so two adapters can never share a name with
    different formats."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"a wire profile needs a name, not {name!r}")
    if not callable(fn):
        raise ValueError(f"wire profile {name!r}: {fn!r} is not callable")
    have = PROFILES.get(name)
    if have is not None and have is not fn and \
            (getattr(have, "__module__", None), getattr(have, "__qualname__", None)) != \
            (getattr(fn, "__module__", None), getattr(fn, "__qualname__", None)):
        raise ValueError(f"wire profile {name!r} is already registered by "
                         f"{getattr(have, '__module__', '?')}")
    PROFILES[name] = fn


class StubCounterparty:
    def __init__(self, db_path: str, key: Keypair, salt: bytes, *,
                 counterparty_id: str = "did:web:b.example",
                 profile: Optional[str] = None,
                 checkpoint_key: Optional[Keypair] = None,
                 single_use: bool = False, repeat_answer: str = "original",
                 requester_keys: Optional[Dict[str, bytes]] = None) -> None:
        if profile is not None and profile not in PROFILES:
            raise ValueError(f"unknown wire profile {profile!r}; one of {sorted(PROFILES)}")
        self.profile = profile
        self.db_path = db_path
        self.format_gaps: List[Dict[str, Any]] = []
        """Receipts B built whose verdict the wire profile cannot express (module docstring)."""
        self.key = key
        self.salt = bytes(salt)
        self.counterparty_id = counterparty_id
        # A second genuine key of B's, never published, for the unpinned_key variant. Its kid
        # differs, so a verifier that looks the kid up finds nothing pinned under it.
        self.other_key = Keypair.generate(f"{key.kid}-unpinned")
        # B's checkpoint key (KRK-17): separate from the receipt key, so a checkpoint can never be
        # read as a receipt or the reverse.
        self.checkpoint_key = checkpoint_key or Keypair.generate(f"{key.kid}-checkpoints")
        self.modes: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        """correlation id -> (record mode, parameters), set by `set_record_mode` (KRK-17)."""
        self.leaks: Dict[str, str] = {}
        """correlation id -> another requester whose entries under it B's record for this
        requester also shows (`join_collision`)."""
        self.deferred: Dict[str, Tuple[Dict[str, Any], ExpectedEffect]] = {}
        """Requests B has received and not yet acted on (`late_entry`), by correlation id."""
        self.tamper_log: List[Dict[str, Any]] = []
        """Every change made through the kit-only tamper path, in order. The honest path never
        adds to it (KRK-M35)."""
        self.checkpoints_issued: List[Dict[str, Any]] = []
        if repeat_answer not in REPEAT_ANSWERS:
            raise ValueError(f"repeat_answer must be one of {REPEAT_ANSWERS}")
        self.single_use = bool(single_use)
        self.repeat_answer = repeat_answer
        self.requester_keys: Dict[str, bytes] = dict(requester_keys or {})
        """A's authorisation keys (kid -> raw public key), for recording whether a presented
        authorisation verifies (strict mode)."""
        self.expectations: Dict[str, ExpectedEffect] = {}
        self.received_requests: List[Dict[str, Any]] = []
        """Every presentation `receive` was given, in order, as received (strict mode)."""
        self._refusal_reason: Optional[str] = None
        receipts.item_key_hash(self.salt, "")  # refuses a short salt now, not mid-run
        with self._db() as db:
            db.executescript(_SCHEMA + _TRIGGERS)
            if self.single_use:
                db.executescript(_SINGLE_USE)

    @contextlib.contextmanager
    def _db(self):
        """One transaction: committed on a clean exit, rolled back on an exception, and the
        connection closed either way."""
        db = sqlite3.connect(self.db_path)
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextlib.contextmanager
    def _tamper(self, what: Dict[str, Any]):
        """The kit-only path: an insider at B with owner rights. Drops the append-only triggers,
        yields a connection, and puts them back, all in one transaction. Used by the KRK-17
        tamper fixtures only; every use is recorded in `tamper_log`."""
        db = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            for t in APPEND_ONLY:
                db.execute(f"DROP TRIGGER IF EXISTS {t}_no_update")
                db.execute(f"DROP TRIGGER IF EXISTS {t}_no_delete")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            for stmt in _TRIGGER_STATEMENTS:     # one by one: executescript would commit first
                db.execute(stmt)
            db.execute("COMMIT")
            self.tamper_log.append(dict(what))
        finally:
            db.close()

    def public_key(self) -> Tuple[str, bytes]:
        return self.key.kid, self.key.public_bytes()

    def checkpoint_public_key(self) -> Tuple[str, bytes]:
        return self.checkpoint_key.kid, self.checkpoint_key.public_bytes()

    # ----------------------------------------------------------------------- the log

    def _entry(self, requester: str, pair_seq: int, prev: Optional[str], kind: str,
               cid: Optional[str], rd: Optional[str], body: Dict[str, Any],
               raw: Optional[str], at: str) -> Dict[str, Any]:
        return {"schema": books.SCHEMA, "side": "B", "party": self.counterparty_id,
                "peer": requester, "pair_seq": pair_seq, "prev_digest": prev, "kind": kind,
                "correlation_id": cid, "request_digest": rd, "answers": None, "body": body,
                "raw_sha256": raw, "recorded_at": at}

    def _append(self, db: sqlite3.Connection, requester: str, kind: str, cid: Optional[str],
                rd: Optional[str], body: Dict[str, Any], raw: Optional[str] = None,
                skew_s: int = 0) -> int:
        """Append one entry to B's log for `requester`, numbered and chained in the caller's
        transaction. Returns its global `log_seq` (the number KRK-16 receipts name)."""
        row = db.execute("SELECT pair_seq, entry_digest FROM log WHERE requester = ? "
                         "ORDER BY pair_seq DESC LIMIT 1", (requester,)).fetchone()
        n, prev = (row[0] + 1, row[1]) if row else (1, None)
        at = _now(skew_s)
        e = self._entry(requester, n, prev, kind, cid, rd, body, raw, at)
        cur = db.execute(
            "INSERT INTO log (requester, pair_seq, prev_digest, kind, correlation_id, "
            "request_digest, body, raw_sha256, recorded_at, entry_digest) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (requester, n, prev, kind, cid, rd, receipts.canonical_json(body).decode("utf-8"),
             raw, at, books.entry_digest(e)))
        return int(cur.lastrowid)

    def _next_log_seq(self, db: sqlite3.Connection) -> int:
        row = db.execute("SELECT seq FROM sqlite_sequence WHERE name = 'log'").fetchone()
        return (int(row[0]) if row else 0) + 1

    @staticmethod
    def _rows_to_entries(rows, party: str) -> List[Dict[str, Any]]:
        out = []
        for (req, n, prev, kind, cid, rd, body, raw, at) in rows:
            out.append({"schema": books.SCHEMA, "side": "B", "party": party, "peer": req,
                        "pair_seq": n, "prev_digest": prev, "kind": kind, "correlation_id": cid,
                        "request_digest": rd, "answers": None, "body": json.loads(body),
                        "raw_sha256": raw, "recorded_at": at})
        return out

    _COLS = ("requester, pair_seq, prev_digest, kind, correlation_id, request_digest, body, "
             "raw_sha256, recorded_at")

    # ----------------------------------------------------------------------- the effect

    @staticmethod
    def _verb(expected: ExpectedEffect) -> str:
        verbs = set(expected.verbs)
        if verbs == {"create", "update"}:
            return "upsert"
        if len(verbs) != 1:
            raise ValueError(f"the stub applies one verb (or create+update); got {sorted(verbs)}")
        return verbs.pop()

    def _apply(self, db: sqlite3.Connection, envelope: Dict[str, Any], expected: ExpectedEffect,
               keys: List[str], variant: str, verdict: str, failed: int,
               rng: random.Random, *, vocabulary: Optional[Dict[str, Dict[str, str]]] = None,
               skew_s: int = 0, requester: Optional[str] = None) -> int:
        """Write one request's effect and its log entries in the caller's transaction: the
        request as received, then the effect committed. Returns the effect entry's log
        sequence number, which the receipt names."""
        requester = requester or _requester(envelope)
        cid, rd = envelope["correlation_id"], receipts.request_digest(envelope)
        requested = receipts.items_digest(self.salt, envelope_items(envelope))
        said = {"operation": expected.operation, "container": expected.container,
                "count": len(envelope_items(envelope)), "items_digest": requested,
                "expected_effect_digest": expected.digest()}
        for f, table in (vocabulary or {}).items():
            said[f] = table.get(said[f], said[f])
        self._append(db, requester, "request-received", cid, rd, said, skew_s=skew_s)
        seq = self._next_log_seq(db)
        rows: List[Tuple[str, str]] = []
        verb = self._verb(expected)
        for key in keys:
            h = receipts.item_key_hash(self.salt, key)
            if verb == "none":
                continue
            row_verb = verb
            if verb == "upsert":
                last = db.execute(
                    "SELECT verb FROM items WHERE container = ? AND item_key_hash = ? "
                    "ORDER BY row_id DESC LIMIT 1", (expected.container, h)).fetchone()
                done = {x for x, _ in rows if x == h}
                row_verb = ("update" if (last and last[0] in ("create", "update")) or done
                            else "create")
            rows.append((h, row_verb))
        outcome = {f: 0 for f in receipts.OUTCOME_FIELDS}
        for _, v in rows:
            outcome[_VERB_FIELD[v]] += 1
        outcome["failed"] = int(failed)
        got = self._append(db, requester, "effect-committed", cid, rd,
                           {"verdict": verdict, **outcome, "items_digest": requested,
                            "log_seq": seq}, skew_s=skew_s)
        assert got == seq, (got, seq)
        for h, row_verb in rows:
            db.execute(
                "INSERT INTO items (record_id, correlation_id, container, item_key_hash, verb, "
                "log_seq) VALUES (?, ?, ?, ?, ?, ?)",
                (f"rec-{rng.getrandbits(48):012x}", cid, expected.container, h, row_verb, seq))
        db.execute("INSERT INTO requests (log_seq, requester, correlation_id, request_digest, "
                   "variant, verdict, failed, items_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (seq, requester, cid, rd, variant, verdict, failed, requested))
        return seq

    def _claims_from_store(self, db: sqlite3.Connection, seq: int, envelope: Dict[str, Any],
                           expected: ExpectedEffect, rng: random.Random) -> Dict[str, Any]:
        """The receipt's claims, read back from the committed rows under this log entry."""
        cid, req, verdict, failed, requested = db.execute(
            "SELECT correlation_id, request_digest, verdict, failed, items_digest FROM requests "
            "WHERE log_seq = ?", (seq,)).fetchone()
        outcome = {f: 0 for f in receipts.OUTCOME_FIELDS}
        for verb, n in db.execute("SELECT verb, COUNT(*) FROM items WHERE log_seq = ? "
                                  "GROUP BY verb", (seq,)):
            outcome[_VERB_FIELD[verb]] = int(n)
        outcome["failed"] = int(failed)
        claims = {
            "receipt_id": f"rcpt-{rng.getrandbits(64):016x}",
            "correlation_id": cid,
            "request_digest": req,
            "expected_effect_digest": expected.digest(),
            "verdict": verdict,
            "refusal_reason": (self._refusal_reason or REFUSAL_REASON) if verdict == "refused"
            else None,
            **({"refuses_permanently": True} if verdict == "no-record" else {}),
            "outcome": outcome,
            "items_digest": requested,
            "counterparty": self.counterparty_id,
            "executed_at": _now(),
            "log_seq": seq,
        }
        if self.profile is not None:
            added = PROFILES[self.profile](claims)
            clash = sorted(set(added) & set(claims))
            if clash:
                raise ValueError(f"profile {self.profile!r} would overwrite kit claims {clash}")
            if not added:
                # The target's format has no way to say this verdict, so the target will see a
                # receipt it cannot parse. P16 records the variant as information, not as the
                # target's rejection (KRK-M21).
                self.format_gaps.append({"correlation_id": cid, "verdict": verdict,
                                         "profile": self.profile})
            claims.update(added)
        return claims

    def _record_receipt(self, seq: int, token: Optional[str]) -> None:
        """B's record of what it sent for the request whose effect entry is `seq`: a new
        `receipt-issued` entry naming the token's digest, and the token in B's bookkeeping. No
        token, no entry: B sent nothing. Nothing earlier is changed (KRK-M35)."""
        if token is None:
            return
        with self._db() as db:
            requester, cid, rd = db.execute("SELECT requester, correlation_id, request_digest "
                                            "FROM requests WHERE log_seq = ?", (seq,)).fetchone()
            sha = receipts.sha256_ref(token.encode("utf-8"))
            claims = _claims_of(token) or {}
            skew = self._skew(cid)
            self._append(db, requester, "receipt-issued", cid, rd,
                         {"receipt_id": claims.get("receipt_id"), "token_sha256": sha,
                          "verdict": claims.get("verdict"), "outcome": claims.get("outcome"),
                          "log_seq": claims.get("log_seq")}, raw=sha, skew_s=skew)
            db.execute("INSERT INTO answers (log_seq, token) VALUES (?, ?)", (seq, token))

    def execute(self, envelope: Dict[str, Any], expected: ExpectedEffect,
                variant: str = "honest", *, rng: random.Random,
                earlier: Optional[Dict[str, Any]] = None
                ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Apply the effect as `variant` implies and answer. Returns (receipt token or None,
        executor report or None). The report is the executor's own account: a claim of success
        for `agent_report` and `disputed_no_record`, an unconfirmed send (``"sent": false``) for
        `signed_no_record`, and None otherwise.

        `earlier` is required for `sibling_request` and refused otherwise: the envelope of one of
        A's own earlier requests, with the same items and expectation and another correlation
        id. B answers this request with the receipt it issued for that one.

        On `honest`, a record mode set for this correlation id (`set_record_mode`, KRK-17)
        decides what B records and answers instead."""
        if variant not in VARIANTS:
            raise ValueError(f"unknown variant {variant!r}; one of {VARIANTS}")
        if not isinstance(rng, random.Random):
            raise TypeError("rng must be a random.Random, so every draw is reproducible")
        if (earlier is not None) != (variant in REPLAYS):
            raise ValueError(f"earlier= is required for {REPLAYS} and only for them; "
                             f"variant {variant!r}")
        if variant in REPLAYS:
            return self._replay_earlier(envelope, expected, earlier, rng)
        cid = envelope.get("correlation_id")
        if not isinstance(cid, str) or not cid:
            raise ValueError("envelope has no correlation_id")
        keys = envelope_items(envelope)
        if len(keys) != expected.count:
            raise ValueError(f"envelope has {len(keys)} items, the expectation {expected.count}; "
                             f"the fixture is inconsistent")
        if receipts.items_digest(self.salt, keys) != expected.items_digest:
            raise ValueError("expected.items_digest is not the digest of the envelope's items "
                             "under this agreement's salt; the fixture is inconsistent")
        stated = envelope.get("expected_effect_digest")
        if stated is not None and stated != expected.digest():
            raise ValueError("the envelope's expected_effect_digest is not expected.digest()")
        if variant == "honest" and cid in self.modes:
            return self._execute_mode(envelope, expected, rng)
        return self._execute(envelope, expected, variant, rng)

    def _execute(self, envelope: Dict[str, Any], expected: ExpectedEffect, variant: str,
                 rng: random.Random, *, label: Optional[str] = None,
                 answer_with: Optional[str] = None, lie_k: int = 0,
                 vocabulary: Optional[Dict[str, Dict[str, str]]] = None
                 ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        cid = envelope["correlation_id"]
        keys = envelope_items(envelope)
        written = list(keys)
        failed = 0
        verdict = "executed"
        if variant in ("count_mismatch", "honest_partial"):
            if expected.count < 1:
                raise ValueError(f"{variant} needs at least one item")
            k = rng.randint(1, min(K_MAX, expected.count))
            dropped = set(rng.sample(range(expected.count), k))
            written = [key for i, key in enumerate(keys) if i not in dropped]
            if variant == "honest_partial":
                failed = k
        elif variant == "signed_refusal":
            written = []
            verdict = "refused"
        elif variant in ("signed_no_record", "disputed_no_record"):
            written = []
            verdict = "no-record"
        if lie_k:
            written = written[:len(written) - lie_k]

        skew = self._skew(cid)
        with self._db() as db:
            seq = self._apply(db, envelope, expected, written, label or variant, verdict, failed,
                              rng, vocabulary=vocabulary, skew_s=skew)
            sibling_seq = None
            if variant == "wrong_request":
                # A sibling request B also received: same items and expectation, a different
                # correlation id, so a different request digest. B applies it too and answers
                # with the receipt it issued for it.
                sibling = copy.deepcopy(envelope)
                sibling["correlation_id"] = f"{cid}/sibling-{rng.getrandbits(32):08x}"
                sibling_seq = self._apply(db, sibling, expected, keys, "wrong_request:sibling",
                                          "executed", 0, rng)
        if answer_with is not None:
            self._record_receipt(seq, answer_with)
            return answer_with, None
        # Committed. Every receipt below is built from the store, not from the request.
        with self._db() as db:
            claims = self._claims_from_store(db, sibling_seq or seq, envelope, expected, rng)
        if lie_k:
            # receipt_contradicts_log (KRK-17): B signs the full count its log contradicts.
            field = "created" if claims["outcome"]["created"] or not claims["outcome"]["updated"] \
                else "updated"
            claims["outcome"] = dict(claims["outcome"], **{field: claims["outcome"][field] + lie_k})

        token: Optional[str]
        report: Optional[Dict[str, Any]] = None
        if variant in ("honest", "wrong_request", "count_mismatch", "honest_partial",
                       "signed_refusal", "signed_no_record", "disputed_no_record"):
            token = receipts.sign_receipt(claims, self.key)
            if variant == "signed_no_record":
                report = {"by": "executor", "correlation_id": cid, "sent": False,
                          "status": "unknown", "error": "timed out waiting for B's response"}
            elif variant == "disputed_no_record":
                report = {"by": "executor", "correlation_id": cid, "success": True,
                          "sent": True, "status": "done", "count": expected.count}
        elif variant == "unsigned":
            token = receipts.unsigned_receipt(claims)
        elif variant == "unpinned_key":
            token = receipts.sign_receipt(claims, self.other_key)
        else:  # missing, agent_report
            token = None
            if variant == "agent_report":
                report = {"by": "executor", "correlation_id": cid, "success": True,
                          "status": "done", "count": expected.count}
        self._record_receipt(sibling_seq or seq, token)
        return token, report

    def _replay_earlier(self, envelope: Dict[str, Any], expected: ExpectedEffect,
                        earlier: Dict[str, Any], rng: random.Random
                        ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """`sibling_request`: B's genuine receipt for A's earlier request, sent as the answer to
        this one. B executes the earlier request honestly if it has not already, then executes
        this request in full, and records that it answered it with the earlier token."""
        cid, ecid = envelope.get("correlation_id"), earlier.get("correlation_id")
        if not isinstance(ecid, str) or not ecid or ecid == cid:
            raise ValueError("the earlier request needs its own correlation id")
        if (sorted(envelope_items(earlier)) != sorted(envelope_items(envelope))
                or earlier.get("expected_effect_digest", expected.digest()) != expected.digest()):
            raise ValueError("the earlier request must have the same items and expectation, so "
                             "the replayed receipt differs from an honest one in the request it "
                             "names only")
        token = self._executed_receipt(ecid)
        if token is None:
            token, _ = self.execute(earlier, expected, "honest", rng=rng)
        # B's log for this request carries the token it actually sent: the earlier one.
        return self._execute(envelope, expected, "honest", rng, label="sibling_request",
                             answer_with=token)

    def _executed_receipt(self, correlation_id: str) -> Optional[str]:
        """The signed receipt B issued for the last executed entry under `correlation_id`."""
        with self._db() as db:
            row = db.execute("SELECT a.token FROM answers a JOIN requests r USING (log_seq) "
                             "WHERE r.correlation_id = ? AND r.verdict = 'executed' "
                             "ORDER BY a.answer_id DESC LIMIT 1", (correlation_id,)).fetchone()
        return row[0] if row else None

    # ----------------------------------------------------------------------- ground truth

    def store_counts(self, correlation_id: str) -> Dict[str, Any]:
        """What B's store holds for this correlation id, read from the rows themselves:
        created/updated/deleted item rows, their total (also as `written`), the item digest over
        the stored hashes, and how many requests B logged under it."""
        out: Dict[str, Any] = {"created": 0, "updated": 0, "deleted": 0}
        hashes = []
        with self._db() as db:
            for verb, h in db.execute(
                    "SELECT verb, item_key_hash FROM items WHERE correlation_id = ?",
                    (correlation_id,)):
                out[_VERB_FIELD[verb]] += 1
                hashes.append(h)
            out["requests_logged"] = db.execute(
                "SELECT COUNT(*) FROM requests WHERE correlation_id = ?",
                (correlation_id,)).fetchone()[0]
        out["total"] = out["written"] = len(hashes)
        out["items_digest"] = receipts.digest_of_hashes(sorted(set(hashes)))
        return out

    def issued(self) -> List[Dict[str, Any]]:
        """Every request B logged, with the receipt token B returned for it (None if it returned
        none)."""
        with self._db() as db:
            rows = db.execute(
                "SELECT r.log_seq, r.correlation_id, r.request_digest, r.variant, r.verdict, "
                "r.failed, (SELECT a.token FROM answers a WHERE a.log_seq = r.log_seq "
                "ORDER BY a.answer_id DESC LIMIT 1) FROM requests r ORDER BY r.log_seq").fetchall()
        cols = ("log_seq", "correlation_id", "request_digest", "variant", "verdict", "failed",
                "receipt")
        return [dict(zip(cols, r)) for r in rows]

    def log_truth(self) -> List[Dict[str, Any]]:
        """Every row of B's log, every requester, as stored, with its global `log_seq` (kit-only
        ground truth; never offered to a target)."""
        with self._db() as db:
            rows = db.execute(f"SELECT log_seq, entry_digest, {self._COLS} FROM log "
                              "ORDER BY log_seq").fetchall()
        out = []
        for row in rows:
            e = self._rows_to_entries([row[2:]], self.counterparty_id)[0]
            out.append({"log_seq": row[0], "stored_digest": row[1], **e})
        return out

    # ----------------------------------------------------------------------- KRK-17 read side

    def record(self, peer: str) -> List[Dict[str, Any]]:
        """B's log for `peer`, in the kit's reading format, ordered by B's numbering. Under
        `join_collision` it also holds another requester's entries under the leaked correlation
        id, as a B whose export is not scoped to the pair would show them."""
        with self._db() as db:
            rows = db.execute(f"SELECT {self._COLS} FROM log WHERE requester = ? "
                              "ORDER BY pair_seq, log_seq", (peer,)).fetchall()
            leaked = []
            for cid, other in self.leaks.items():
                leaked += db.execute(f"SELECT {self._COLS} FROM log WHERE requester = ? AND "
                                     "correlation_id = ? ORDER BY pair_seq", (other, cid)).fetchall()
        return self._rows_to_entries(rows + leaked, self.counterparty_id)

    def checkpoint(self, peer: str) -> Optional[str]:
        """B's signed checkpoint of its record for `peer`, at its latest entry, or None if B has
        none for `peer` yet."""
        with self._db() as db:
            row = db.execute("SELECT pair_seq, entry_digest FROM log WHERE requester = ? "
                             "ORDER BY pair_seq DESC LIMIT 1", (peer,)).fetchone()
        if not row:
            return None
        claims = books.checkpoint_claims(self.counterparty_id, peer, int(row[0]), row[1], _now())
        tok = books.sign_checkpoint(claims, self.checkpoint_key)
        self.checkpoints_issued.append(dict(claims, token=tok))
        return tok

    def hold(self, peer: str, commitment: str) -> None:
        """What A sends B to hold: A's checkpoint of its record for B, raw. B keeps the bytes
        and logs a `checkpoint-received` entry with the checkpoint's number and head. B does not
        judge it; a third party verifies it against A's key."""
        if not isinstance(commitment, str):
            raise TypeError("a commitment is a compact JWS string")
        c = _claims_of(commitment) or {}
        with self._db() as db:
            db.execute("INSERT INTO holdings (requester, token, received_at) VALUES (?, ?, ?)",
                       (peer, commitment, _now()))
            if isinstance(c.get("pair_seq"), int) and isinstance(c.get("head"), str):
                self._append(db, peer, "checkpoint-received", None, None,
                             {"pair_seq": c["pair_seq"], "head": c["head"]},
                             raw=receipts.sha256_ref(commitment.encode("utf-8")))

    def holdings(self, peer: str) -> List[Dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT token FROM holdings WHERE requester = ? ORDER BY holding_id",
                              (peer,)).fetchall()
        return [{"type": "checkpoint", "token": t} for (t,) in rows]

    def read_state(self, peer: str, correlation_id: str) -> Dict[str, Any]:
        """B's read API over its store, for one of `peer`'s actions: honest in every mode. Item
        keys are salted hashes, so a reader learns digests and counts, never identifiers."""
        out = self.store_counts(correlation_id)
        return {k: out[k] for k in ("created", "updated", "deleted", "written", "items_digest")}

    # ----------------------------------------------------------------------- KRK-17 modes

    def set_record_mode(self, correlation_id: str, mode: str, **params: Any) -> None:
        """Make B record and answer the request with this correlation id as `mode` says, when it
        arrives with variant `honest`. Modes are in `RECORD_MODES`."""
        if mode not in RECORD_MODES:
            raise ValueError(f"unknown record mode {mode!r}; one of {RECORD_MODES}")
        self.modes[correlation_id] = (mode, dict(params))

    def _skew(self, cid: Optional[str]) -> int:
        mode = self.modes.get(cid or "")
        return int(mode[1].get("skew_s", 0)) if mode and mode[0] == "clock_skew" else 0

    def _execute_mode(self, envelope: Dict[str, Any], expected: ExpectedEffect,
                      rng: random.Random) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        cid = envelope["correlation_id"]
        mode, params = self.modes[cid]
        success = {"by": "executor", "correlation_id": cid, "success": True, "sent": True,
                   "status": "done", "count": expected.count}
        if mode == "receipt_contradicts_log":
            return self._execute(envelope, expected, "honest", rng, label=mode,
                                 lie_k=int(params["k"]))
        if mode == "receipt_contradicts_state":
            token, report = self._execute(envelope, expected, "honest", rng, label=mode)
            with self._db() as db:              # B's state loses k items after the receipt
                db.execute("DELETE FROM items WHERE row_id IN (SELECT row_id FROM items WHERE "
                           "correlation_id = ? ORDER BY row_id LIMIT ?)", (cid, int(params["k"])))
            return token, report
        if mode == "drop_request":
            return None, success                # B logs nothing, changes nothing, answers nothing
        if mode == "compensating_pair":
            other = dict(envelope, correlation_id=params["other_cid"])
            with self._db() as db:
                self._apply(db, other, expected, envelope_items(envelope), mode, "executed", 0,
                            rng, requester=_requester(envelope))
            return None, success
        if mode == "join_collision":
            token, report = self._execute(envelope, expected, "honest", rng, label=mode)
            foreign = dict(envelope, requester=params["other_requester"])
            with self._db() as db:
                self._apply(db, foreign, expected, envelope_items(envelope), "foreign",
                            "executed", 0, rng, requester=params["other_requester"])
            self.leaks[cid] = params["other_requester"]
            return token, report
        if mode == "seq_duplicate":
            token, report = self._execute(envelope, expected, "honest", rng, label=mode)
            with self._db() as db:              # the same request, executed a second time
                self._apply(db, envelope, expected, envelope_items(envelope), mode + ":again",
                            "executed", 0, rng)
            return token, report
        if mode == "clock_skew":
            return self._execute(envelope, expected, "honest", rng, label=mode)
        if mode == "late_entry":
            self.deferred[cid] = (envelope, expected)
            return None, success
        if mode == "b_vocabulary":
            return self._execute(envelope, expected, "honest", rng, label=mode,
                                 vocabulary=params["vocabulary"])
        if mode == "declared_void":
            with self._db() as db:
                req = _requester(envelope)
                said = {"operation": expected.operation, "container": expected.container,
                        "count": expected.count,
                        "items_digest": receipts.items_digest(self.salt, envelope_items(envelope)),
                        "expected_effect_digest": expected.digest()}
                self._append(db, req, "request-received", cid, receipts.request_digest(envelope),
                             said)
                head = db.execute("SELECT entry_digest FROM log WHERE requester = ? ORDER BY "
                                  "pair_seq DESC LIMIT 1", (req,)).fetchone()[0]
                self._append(db, req, "void", cid, receipts.request_digest(envelope),
                             {"voids": head, "reason": "aborted before commit"})
            return None, None
        raise AssertionError(mode)

    def release(self, correlation_id: str, rng: random.Random) -> Optional[str]:
        """`late_entry`: B acts on a request it received earlier, honestly, now, and returns the
        receipt it then sends."""
        envelope, expected = self.deferred.pop(correlation_id)
        token, _ = self._execute(envelope, expected, "honest", rng, label="late_entry")
        return token

    def out_of_band(self, requester: str, expected: ExpectedEffect, items: List[str],
                    rng: random.Random) -> str:
        """`unbacked_on_b`: B records and applies an effect for `requester` under a correlation
        id the requester never used, and tells nobody. Returns that correlation id."""
        cid = f"oob-{rng.getrandbits(64):016x}"
        env = {"schema": "kirkaldy.effect-request/0.1", "correlation_id": cid,
               "operation": expected.operation, "counterparty": self.counterparty_id,
               "container": expected.container, "items": list(items),
               "expected_effect_digest": expected.digest(), "requester": requester}
        with self._db() as db:
            self._apply(db, env, expected, list(items), "unbacked_on_b", "executed", 0, rng,
                        requester=requester)
        return cid

    def void(self, peer: str, correlation_id: str) -> str:
        """`void_over_receipt`: B appends a `void` entry naming the effect it committed for this
        request, after it has sent the receipt. Append-only; nothing earlier changes."""
        with self._db() as db:
            row = db.execute("SELECT entry_digest, request_digest FROM log WHERE requester = ? "
                             "AND correlation_id = ? AND kind = 'effect-committed' "
                             "ORDER BY pair_seq LIMIT 1", (peer, correlation_id)).fetchone()
            self._append(db, peer, "void", correlation_id, row[1],
                         {"voids": row[0], "reason": "reversed"})
        return row[0]

    # ----------------------------------------------------------------------- KRK-17 tamper

    def _rechain(self, db: sqlite3.Connection, peer: str) -> None:
        prev = None
        for (log_seq, *rest) in db.execute(f"SELECT log_seq, {self._COLS} FROM log WHERE "
                                           "requester = ? ORDER BY pair_seq", (peer,)).fetchall():
            e = self._rows_to_entries([rest], self.counterparty_id)[0]
            e["prev_digest"] = prev
            d = books.entry_digest(e)
            db.execute("UPDATE log SET prev_digest = ?, entry_digest = ? WHERE log_seq = ?",
                       (prev, d, log_seq))
            prev = d

    def tamper_edit(self, peer: str, correlation_id: str, kind: str,
                    change: Dict[str, Any]) -> Dict[str, Any]:
        """`b_edit_after_ack`: an insider at B changes the body of one entry and re-chains every
        entry after it, so B's own chain is whole again. No signature is made: the checkpoints B
        already gave stay as they were."""
        what = {"op": "edit", "peer": peer, "correlation_id": correlation_id, "kind": kind,
                "change": dict(change)}
        with self._tamper(what) as db:
            log_seq, body = db.execute("SELECT log_seq, body FROM log WHERE requester = ? AND "
                                       "correlation_id = ? AND kind = ? ORDER BY pair_seq LIMIT 1",
                                       (peer, correlation_id, kind)).fetchone()
            new = dict(json.loads(body), **change)
            db.execute("UPDATE log SET body = ? WHERE log_seq = ?",
                       (receipts.canonical_json(new).decode("utf-8"), log_seq))
            self._rechain(db, peer)
        return what

    def tamper_delete(self, peer: str, correlation_id: str, kind: str) -> Dict[str, Any]:
        """`b_delete_after_ack`: an insider at B deletes one entry and leaves the rest as they
        were."""
        what = {"op": "delete", "peer": peer, "correlation_id": correlation_id, "kind": kind}
        with self._tamper(what) as db:
            db.execute("DELETE FROM log WHERE log_seq = (SELECT log_seq FROM log WHERE "
                       "requester = ? AND correlation_id = ? AND kind = ? ORDER BY pair_seq "
                       "LIMIT 1)", (peer, correlation_id, kind))
        return what

    def tamper_swap(self, peer: str, correlation_id: str) -> Dict[str, Any]:
        """`seq_reorder`: an insider at B swaps the numbers of this action's effect entry and the
        entry after it, and changes nothing else."""
        what = {"op": "swap", "peer": peer, "correlation_id": correlation_id}
        with self._tamper(what) as db:
            a_seq, a_n = db.execute("SELECT log_seq, pair_seq FROM log WHERE requester = ? AND "
                                    "correlation_id = ? AND kind = 'effect-committed' ORDER BY "
                                    "pair_seq LIMIT 1", (peer, correlation_id)).fetchone()
            b_seq = db.execute("SELECT log_seq FROM log WHERE requester = ? AND pair_seq = ?",
                               (peer, a_n + 1)).fetchone()[0]
            db.execute("UPDATE log SET pair_seq = -1 WHERE log_seq = ?", (a_seq,))
            db.execute("UPDATE log SET pair_seq = ? WHERE log_seq = ?", (a_n, b_seq))
            db.execute("UPDATE log SET pair_seq = ? WHERE log_seq = ?", (a_n + 1, a_seq))
            for seq in (a_seq, b_seq):            # the stored digest follows the row's content
                row = db.execute(f"SELECT {self._COLS} FROM log WHERE log_seq = ?",
                                 (seq,)).fetchone()
                e = self._rows_to_entries([row], self.counterparty_id)[0]
                db.execute("UPDATE log SET entry_digest = ? WHERE log_seq = ?",
                           (books.entry_digest(e), seq))
        return what


    # ----------------------------------------------------------------------- KRK-18 strict mode

    def expect(self, correlation_id: str, expected: ExpectedEffect) -> None:
        """What the request with this correlation id will do, as B's side of the agreement
        knows it (strict mode: `receive` executes against it)."""
        self.expectations[correlation_id] = expected

    def receive(self, raw: bytes, authorisation: Optional[str] = None,
                headers: Optional[Dict[str, str]] = None, *,
                rng: random.Random) -> Dict[str, Any]:
        """One presentation from a target in role A (module docstring, strict mode). Returns
        ``{"receipt": token or None, "answer": "executed" | "original" | "duplicate" | "refused" |
        "error", "code": ..., "use_key": ...}``."""
        if not self.single_use:
            raise RuntimeError("receive() is the strict single-use path; construct with "
                               "single_use=True")
        from . import authz
        raw = bytes(raw)
        entry: Dict[str, Any] = {"n": len(self.received_requests) + 1, "raw": raw,
                                 "raw_sha256": receipts.sha256_ref(raw),
                                 "authorisation": authorisation, "headers": dict(headers or {}),
                                 "received_at": _now()}
        self.received_requests.append(entry)
        claims = authz.claims_of(authorisation) if isinstance(authorisation, str) else None
        if isinstance(authorisation, str):
            v = authz.verify_authorisation(authorisation, self.requester_keys)
            entry["authorisation_verified"] = v.ok
            entry["authorisation_reason"] = v.reason
        try:
            envelope = json.loads(raw.decode("utf-8"))
            cid = envelope["correlation_id"]
            expected = self.expectations[cid]
        except Exception as e:  # noqa: BLE001
            entry["answer"] = "error"
            return {"receipt": None, "answer": "error", "code": f"unreadable: {e}"[:200],
                    "use_key": None}
        digest = receipts.request_digest(envelope)
        key = (f"authz::{claims.get('issuer')}::{claims.get('authorisation_id')}"
               if isinstance(claims, dict) and claims.get("authorisation_id")
               else f"correlation::{_requester(envelope)}::{cid}")
        entry.update(correlation_id=cid, request_digest=digest, use_key=key)
        with self._db() as db:
            row = db.execute("SELECT request_digest, token, receipt_id FROM single_use "
                             "WHERE use_key = ?", (key,)).fetchone()
        if row and row[0] == digest:
            entry["answer"] = self.repeat_answer
            if self.repeat_answer == "original":
                return {"receipt": row[1], "answer": "original", "code": "repeat",
                        "use_key": key}
            return {"receipt": None, "answer": "duplicate", "code": "already-performed",
                    "first_receipt_id": row[2], "use_key": key}
        if row:
            self._refusal_reason = "authorisation-reused"
            try:
                token, _ = self._execute(envelope, expected, "signed_refusal", rng,
                                         label="authorisation-reused")
            finally:
                self._refusal_reason = None
            entry["answer"] = "refused"
            return {"receipt": token, "answer": "refused", "code": "authorisation-reused",
                    "use_key": key}
        token, _ = self.execute(envelope, expected, "honest", rng=rng)
        with self._db() as db:
            db.execute("INSERT INTO single_use (use_key, request_digest, token, receipt_id) "
                       "VALUES (?, ?, ?, ?)",
                       (key, digest, token, (_claims_of(token) or {}).get("receipt_id")))
        entry["answer"] = "executed"
        return {"receipt": token, "answer": "executed", "code": "executed", "use_key": key}


REPEAT_ANSWERS = ("original", "duplicate")
_SINGLE_USE = """
CREATE TABLE IF NOT EXISTS single_use (
    use_key TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    token TEXT,
    receipt_id TEXT
);
"""
"""B's use records in strict mode (KRK-18): one row per use key, inserted once."""


RECORD_MODES = ("receipt_contradicts_log", "receipt_contradicts_state", "drop_request",
                "compensating_pair", "join_collision", "seq_duplicate", "clock_skew",
                "late_entry", "b_vocabulary", "declared_void")
"""What B can be told to do with one request (`set_record_mode`). The KRK-17 variants that are
not a mode are B acting on its own outside a request (`out_of_band`, `void`), an insider at B
(`tamper_edit`, `tamper_delete`, `tamper_swap`), or B acting late (`release`)."""


def _requester(envelope: Dict[str, Any]) -> str:
    r = envelope.get("requester")
    return r if isinstance(r, str) and r else "anonymous:requester"


def _claims_of(token: str) -> Optional[Dict[str, Any]]:
    """The payload of a compact JWS, read without checking anything: what B itself said."""
    try:
        seg = token.split(".")[1]
        out = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        return out if isinstance(out, dict) else None
    except Exception:
        return None
