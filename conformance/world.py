"""The world for KRK-23 (P23): the system where B's effects land, owned and read by the kit
(`X10-REVERSIBILITY-DESIGN.md` §2.4).

The world is the recorder for X10. It knows nothing about reversibility classes. B is bound to it
with a credential (`credential`), and every change B makes is written to an append-only history
with B's credential label and the kit-clock time of the commit. The kit reads the world through
its own interface (`mark`, `diff`, `changes`, `entity_at`, `holdings`, `snapshot`), which never
changes anything (KRK-M116): a kit read of a message does not set ``read_at``.

**Resources** (B-facing; each change is recorded with its caller):

| Resource | Calls | Consequence the kit can plant | What B can observe |
|---|---|---|---|
| objects | create, create_many, update, delete (soft: it also removes the object's links), restore (existence only), link, unlink | another object links to it | ``get_object`` shows links |
| mail | deliver to a mailbox; recall (only while unread) | the recipient reads it (`read_message`) | ``get_mail`` shows ``read_at`` |
| ledger | transfer in integer minor units; reverse (only while the payee covers it and the funds have not moved on) | the payee moves the funds on (`spend`) | ``get_transfer`` shows ``moved_on`` |
| topics | publish; retract | delivery to a subscriber (`deliver_fanout`) | ``get_item`` shows ``delivered_to`` |

**Entities** are keyed ``(kind, id)``: ``object``, ``edge`` (``src->dst``), ``mail``,
``transfer``, ``account``, ``item`` and ``copy`` (a subscriber's copy of an item, a downstream
holding). The diff between two marks covers every entity changed between them, whoever changed it
and whether or not it carries a trial's tag (KRK-M114).

**Faults** are induced on the world only, never on B: ``down`` (the call fails as unreachable),
``hang`` (the call waits `hang_s` on the kit clock and then times out), ``error`` (a server
error), ``slow`` (the call waits `slow_s` and then commits), and ``refuse_item:<id>`` (the next
call that touches that object is refused once). `hold` answers the next write whose payload carries
a token with "held, retry after", committing nothing (`MockServer.hold`'s behaviour). Faults and
held calls are logged in `attempts`, never in the history.

**No expiry.** Nothing in the world expires or is cleaned up (KRK-M117).

Served in process to toys (``world://`` URLs, `connect`) and over HTTP to a self-hosted target
(`serve`), standard library only. The HTTP interface carries the same calls; the kit-facing
interface is never served to B.
"""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

KINDS = ("object", "edge", "mail", "transfer", "account", "item", "copy")
FAULTS = ("down", "hang", "error", "slow")
KIT = "kit"
"""The caller label of the kit's own setup changes (accounts, objects, topics)."""
PLANT = "kit-plant"
"""The caller label of a consequence the kit plants at a downstream party."""

Key = Tuple[str, str]


class WorldError(Exception):
    """A call the world did not commit. ``code`` is the world's own reason."""

    code = "error"

    def __init__(self, code: Optional[str] = None, detail: str = "") -> None:
        self.code = code or type(self).code
        super().__init__(f"{self.code}: {detail}" if detail else self.code)


class Unavailable(WorldError):
    code = "down"


class TimedOut(WorldError):
    code = "hang"


class ServerError(WorldError):
    code = "error"


class Refused(WorldError):
    code = "refused"


class NotFound(WorldError):
    code = "not_found"


class Held(WorldError):
    code = "held"

    def __init__(self, retry_after_s: float) -> None:
        self.retry_after_s = float(retry_after_s)
        super().__init__("held", f"retry after {retry_after_s:g} s")


@dataclass(frozen=True)
class Mark:
    """A point in the world's history: everything up to `seq` has happened, at kit time `t`."""

    seq: int
    t: float


_LOCAL: Dict[str, "World"] = {}


def local(url: str) -> Optional["World"]:
    """The in-process world served at a ``world://`` URL, or None."""
    return _LOCAL.get(url)


def _monotonic() -> float:
    import time
    return time.monotonic()


class World:
    """One world partition. B is bound to it with a credential; the kit reads it directly."""

    def __init__(self, clock: Any = None, *, hang_s: float = 5.0, slow_s: float = 2.0) -> None:
        self.clock = clock
        self._now: Callable[[], float] = clock.now if clock is not None else _monotonic
        self._lock = threading.RLock()
        self.state: Dict[Key, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []
        self._by_key: Dict[Key, List[int]] = {}
        self._times: List[float] = []
        self.attempts: List[Dict[str, Any]] = []
        """Calls the world did not commit (faults, holds, refusals), with their caller and time."""
        self.credentials: Dict[str, str] = {}
        self.mailboxes: Dict[str, str] = {}
        """address -> party."""
        self.subscribers: Dict[str, List[str]] = {}
        """topic -> parties."""
        self._faults: List[Dict[str, Any]] = []
        self._holds: Dict[str, float] = {}
        self.hang_s = float(hang_s)
        self.slow_s = float(slow_s)
        self._ids = 0
        self.url = f"world://{secrets.token_hex(6)}"
        _LOCAL[self.url] = self
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.http_url: Optional[str] = None

    # ------------------------------------------------------------------ plumbing

    def now(self) -> float:
        return self._now()

    def _sleep(self, s: float) -> None:
        if self.clock is not None:
            self.clock.sleep(s)
        else:
            import time
            time.sleep(s)

    def _new_id(self, prefix: str) -> str:
        with self._lock:
            self._ids += 1
            return f"{prefix}-{self._ids:05d}-{secrets.token_hex(3)}"

    def credential(self, label: str = "b") -> str:
        """A fresh credential for a caller labelled `label` (B's is ``b``; A′'s B is ``b``
        too). The kit never uses one: its own calls carry `KIT` or `PLANT`."""
        tok = f"wc-{secrets.token_hex(12)}"
        with self._lock:
            self.credentials[tok] = label
        return tok

    def _record(self, caller: str, op: str, key: Key, after: Optional[Dict[str, Any]],
                **meta: Any) -> None:
        """Change one entity and append the change to the history. Caller holds the lock."""
        before = copy.deepcopy(self.state.get(key))
        if after is None:
            self.state.pop(key, None)
        else:
            self.state[key] = copy.deepcopy(after)
        seq = len(self.history) + 1
        t = self.now()
        self._times.append(t)
        self.history.append({"seq": seq, "t": t, "caller": caller, "op": op,
                             "key": list(key), "before": before,
                             "after": copy.deepcopy(after), **meta})
        self._by_key.setdefault(key, []).append(seq)

    def _attempt(self, caller: str, op: str, outcome: str, **more: Any) -> None:
        with self._lock:
            self.attempts.append({"t": self.now(), "caller": caller, "op": op,
                                  "outcome": outcome, **more})

    def _get(self, kind: str, eid: str) -> Dict[str, Any]:
        cur = self.state.get((kind, str(eid)))
        if cur is None:
            raise NotFound("not_found", f"no {kind} {eid}")
        return cur

    # ------------------------------------------------------------------ faults and holds

    def fault(self, mode: str, *, until: Optional[float] = None, item: Optional[str] = None,
              slow_s: Optional[float] = None, hang_s: Optional[float] = None) -> Dict[str, Any]:
        """Induce a fault on B's calls from now until kit time `until` (None: until cleared).
        ``refuse_item`` refuses the next call that touches object `item` once."""
        if mode not in FAULTS and mode != "refuse_item":
            raise ValueError(f"unknown fault {mode!r}")
        f = {"mode": mode, "from": self.now(), "until": until, "item": item,
             "slow_s": slow_s, "hang_s": hang_s}
        with self._lock:
            self._faults.append(f)
        return dict(f)

    def clear_faults(self) -> None:
        with self._lock:
            self._faults.clear()

    def hold(self, token: str, retry_after_s: float) -> None:
        """Answer the next B write whose payload carries `token` with `Held`, committing nothing."""
        with self._lock:
            self._holds[str(token)] = float(retry_after_s)

    def _active(self) -> List[Dict[str, Any]]:
        t = self.now()
        return [f for f in self._faults if f["until"] is None or t < f["until"]]

    def _gate(self, caller: str, op: str, payload: Dict[str, Any], touches: Iterable[str]) -> None:
        """Apply any fault or hold to one of B's calls before it commits."""
        touches = [str(x) for x in touches]
        with self._lock:
            active = self._active()
        for f in active:
            m = f["mode"]
            if m == "down":
                self._attempt(caller, op, "down")
                raise Unavailable("down", "the world is unreachable")
            if m == "error":
                self._attempt(caller, op, "error")
                raise ServerError("error", "the world answered 503")
            if m == "hang":
                self._attempt(caller, op, "hang")
                self._sleep(float(f.get("hang_s") or self.hang_s))
                raise TimedOut("hang", "no answer from the world")
            if m == "refuse_item" and f["item"] in touches:
                with self._lock:
                    if f in self._faults:
                        self._faults.remove(f)
                self._attempt(caller, op, "refused_item", item=f["item"])
                raise Refused("refused_item", f"the world refused the call on {f['item']}")
        for f in active:
            if f["mode"] == "slow":
                self._attempt(caller, op, "slow")
                self._sleep(float(f.get("slow_s") or self.slow_s))
        if op in WRITES:
            blob = json.dumps(payload, sort_keys=True, default=str)
            with self._lock:
                hit = next((tok for tok in self._holds if tok in blob), None)
                ra = self._holds.pop(hit) if hit is not None else None
            if hit is not None:
                self._attempt(caller, op, "held", token=hit, retry_after_s=ra)
                raise Held(ra)

    def held_attempts(self, token: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [a for a in self.attempts if a["outcome"] == "held" and a.get("token") == token]

    # ------------------------------------------------------------------ B-facing calls

    def call(self, credential: str, op: str, **kw: Any) -> Dict[str, Any]:
        """One of B's calls. Raises a `WorldError` when the world does not commit it."""
        with self._lock:
            caller = self.credentials.get(credential)
        if caller is None:
            raise Refused("unauthorised", "unknown credential")
        fn = _OPS.get(op)
        if fn is None:
            raise NotFound("no_such_call", op)
        touches = [kw.get(k) for k in ("object_id", "src", "dst") if kw.get(k)]
        if op == "update" or op == "delete" or op == "restore":
            touches.append(kw.get("object_id"))
        self._gate(caller, op, kw, touches)
        return fn(self, caller, **kw)

    def _create(self, caller: str, fields: Dict[str, Any], email: Optional[str] = None,
                note: Optional[str] = None, links: Optional[List[str]] = None) -> Dict[str, Any]:
        oid = self._new_id("obj")
        with self._lock:
            self._record(caller, "create", ("object", oid),
                         {"id": oid, "fields": dict(fields or {}), "email": email, "note": note,
                          "deleted": False})
            for dst in links or []:
                self._link_locked(caller, oid, str(dst))
        return {"id": oid}

    def _create_many(self, caller: str, items: List[Dict[str, Any]],
                     note: Optional[str] = None) -> Dict[str, Any]:
        ids = [self._create(caller, it.get("fields") or {}, it.get("email"),
                            it.get("note") or note)["id"] for it in items]
        return {"ids": ids}

    def _update(self, caller: str, object_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            cur = copy.deepcopy(self._get("object", object_id))
            if cur["deleted"]:
                raise Refused("deleted", f"object {object_id} is deleted")
            cur["fields"] = {**cur["fields"], **dict(fields or {})}
            for k, v in list(cur["fields"].items()):
                if v is None:
                    cur["fields"].pop(k)
            self._record(caller, "update", ("object", object_id), cur)
        return {"id": object_id}

    def _delete(self, caller: str, object_id: str) -> Dict[str, Any]:
        with self._lock:
            cur = copy.deepcopy(self._get("object", object_id))
            if cur["deleted"]:
                raise Refused("deleted", f"object {object_id} is already deleted")
            for (kind, eid), e in list(self.state.items()):
                if kind == "edge" and e["live"] and object_id in (e["src"], e["dst"]):
                    self._record(caller, "unlink", (kind, eid), {**e, "live": False},
                                 cause="delete")
            cur["deleted"] = True
            self._record(caller, "delete", ("object", object_id), cur)
        return {"id": object_id}

    def _restore(self, caller: str, object_id: str) -> Dict[str, Any]:
        """Existence only: links removed by the delete are not restored by this call."""
        with self._lock:
            cur = copy.deepcopy(self._get("object", object_id))
            if not cur["deleted"]:
                raise Refused("not_deleted", f"object {object_id} is not deleted")
            cur["deleted"] = False
            self._record(caller, "restore", ("object", object_id), cur)
        return {"id": object_id}

    def _link_locked(self, caller: str, src: str, dst: str) -> None:
        for oid in (src, dst):
            o = self.state.get(("object", oid))
            if o is None or o["deleted"]:
                raise Refused("no_object", f"cannot link {src}->{dst}: {oid} missing or deleted")
        self._record(caller, "link", ("edge", f"{src}->{dst}"),
                     {"src": src, "dst": dst, "live": True})

    def _link(self, caller: str, src: str, dst: str) -> Dict[str, Any]:
        with self._lock:
            self._link_locked(caller, str(src), str(dst))
        return {"edge": f"{src}->{dst}"}

    def _unlink(self, caller: str, src: str, dst: str) -> Dict[str, Any]:
        with self._lock:
            e = copy.deepcopy(self._get("edge", f"{src}->{dst}"))
            if not e["live"]:
                raise Refused("not_linked", f"{src}->{dst} is not linked")
            self._record(caller, "unlink", ("edge", f"{src}->{dst}"), {**e, "live": False})
        return {"edge": f"{src}->{dst}"}

    def _deliver(self, caller: str, to: str, subject: str = "", body: str = "") -> Dict[str, Any]:
        mid = self._new_id("msg")
        with self._lock:
            party = self.mailboxes.get(str(to), f"external:{to}")
            self._record(caller, "deliver", ("mail", mid),
                         {"id": mid, "to": to, "party": party, "subject": subject, "body": body,
                          "recalled": False, "read_at": None})
        return {"id": mid}

    def _recall(self, caller: str, message_id: str) -> Dict[str, Any]:
        with self._lock:
            m = copy.deepcopy(self._get("mail", message_id))
            if m["read_at"] is not None:
                raise Refused("already_read", f"message {message_id} was read")
            if m["recalled"]:
                raise Refused("recalled", f"message {message_id} is already recalled")
            m["recalled"] = True
            self._record(caller, "recall", ("mail", message_id), m)
        return {"id": message_id}

    def _transfer_locked(self, caller: str, frm: str, to: str, amount: int,
                         memo: Optional[str], op: str = "transfer") -> str:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise Refused("bad_amount", "amounts are positive integers in minor units")
        src = copy.deepcopy(self._get("account", frm))
        dst = copy.deepcopy(self._get("account", to))
        if src["balance"] < amount:
            raise Refused("insufficient_funds", f"{frm} holds {src['balance']}")
        tid = self._new_id("trf")
        self._record(caller, op, ("transfer", tid),
                     {"id": tid, "from": frm, "to": to, "amount": amount, "memo": memo,
                      "voided": False, "moved_on": False})
        src["balance"] -= amount
        self._record(caller, op, ("account", frm), src, transfer=tid)
        dst["balance"] += amount
        self._record(caller, op, ("account", to), dst, transfer=tid)
        return tid

    def _transfer(self, caller: str, frm: str, to: str, amount: int,
                  memo: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            return {"id": self._transfer_locked(caller, frm, to, amount, memo)}

    def _reverse_transfer(self, caller: str, transfer_id: str) -> Dict[str, Any]:
        """A void: the entry is marked voided and both balances return. Allowed only while the
        funds have not moved on and the payee's balance covers the amount."""
        with self._lock:
            t = copy.deepcopy(self._get("transfer", transfer_id))
            if t["voided"]:
                raise Refused("voided", f"transfer {transfer_id} is already voided")
            if t["moved_on"]:
                raise Refused("funds_moved", f"the payee moved the funds of {transfer_id} on")
            payee = copy.deepcopy(self._get("account", t["to"]))
            payer = copy.deepcopy(self._get("account", t["from"]))
            if payee["balance"] < t["amount"]:
                raise Refused("insufficient_funds", f"{t['to']} no longer covers the amount")
            t["voided"] = True
            self._record(caller, "void", ("transfer", transfer_id), t)
            payee["balance"] -= t["amount"]
            self._record(caller, "void", ("account", t["to"]), payee, transfer=transfer_id)
            payer["balance"] += t["amount"]
            self._record(caller, "void", ("account", t["from"]), payer, transfer=transfer_id)
        return {"id": transfer_id}

    def _publish(self, caller: str, topic: str, body: str = "") -> Dict[str, Any]:
        iid = self._new_id("itm")
        with self._lock:
            self._record(caller, "publish", ("item", iid),
                         {"id": iid, "topic": topic, "body": body, "retracted": False,
                          "delivered_to": []})
        return {"id": iid}

    def _retract(self, caller: str, item_id: str) -> Dict[str, Any]:
        with self._lock:
            it = copy.deepcopy(self._get("item", item_id))
            if it["retracted"]:
                raise Refused("retracted", f"item {item_id} is already retracted")
            it["retracted"] = True
            self._record(caller, "retract", ("item", item_id), it)
        return {"id": item_id}

    def _read(self, caller: str, kind: str, eid: str) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._get(kind, eid))

    def _find(self, caller: str, kind: str, **match: Any) -> List[Dict[str, Any]]:
        """B's search: every entity of `kind` whose members equal `match` (a read)."""
        with self._lock:
            return [copy.deepcopy(e) for (k, _i), e in self.state.items()
                    if k == kind and all(e.get(m) == v for m, v in match.items())]

    # ------------------------------------------------------------------ the kit's interface

    def mark(self) -> Mark:
        with self._lock:
            return Mark(len(self.history), self.now())

    def snapshot(self) -> Dict[str, Any]:
        """A full copy of the partition with its digest (used by the control and the tests;
        the trials use marks and `diff`, which read the same history)."""
        with self._lock:
            state = {f"{k}:{i}": copy.deepcopy(v) for (k, i), v in sorted(self.state.items())}
            seq = len(self.history)
        blob = json.dumps(state, sort_keys=True, default=str).encode()
        return {"seq": seq, "t": self.now(), "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
                "state": state}

    def entity_at(self, key: Key, seq: int) -> Optional[Dict[str, Any]]:
        """The entity as it was once the first `seq` history entries had happened."""
        key = (key[0], str(key[1]))
        with self._lock:
            seqs = self._by_key.get(key, [])
            later = next((s for s in seqs if s > seq), None)
            if later is not None:
                return copy.deepcopy(self.history[later - 1]["before"])
            return copy.deepcopy(self.state.get(key))

    def seq_at(self, t: float) -> int:
        """How many history entries were committed at or before kit time `t`."""
        import bisect
        with self._lock:
            return bisect.bisect_right(self._times, t)

    def entity_at_time(self, key: Key, t: float) -> Optional[Dict[str, Any]]:
        """The entity as committed at kit time `t` (every change with time <= t applied)."""
        return self.entity_at(key, self.seq_at(t))

    def changes(self, since: Optional[Mark] = None, until: Optional[Mark] = None,
                caller: Optional[str] = None) -> List[Dict[str, Any]]:
        lo = since.seq if since else 0
        with self._lock:
            hi = until.seq if until else len(self.history)
            out = [copy.deepcopy(e) for e in self.history[lo:hi]]
        return [e for e in out if caller is None or e["caller"] == caller]

    def diff(self, a: Mark, b: Optional[Mark] = None) -> Dict[Key, Tuple[Any, Any]]:
        """Every entity whose state differs between `a` and `b` (now when None), whoever changed
        it: ``{key: (state at a, state at b)}``."""
        with self._lock:
            hi = b.seq if b else len(self.history)
            keys = {tuple(e["key"]) for e in self.history[a.seq:hi]}
        out: Dict[Key, Tuple[Any, Any]] = {}
        for k in sorted(keys):
            x, y = self.entity_at(k, a.seq), self.entity_at(k, hi)
            if x != y:
                out[k] = (x, y)
        return out

    def find(self, kind: str, pred: Callable[[Dict[str, Any]], bool]) -> List[Tuple[Key, Dict[str, Any]]]:
        with self._lock:
            return [((k, i), copy.deepcopy(e)) for (k, i), e in self.state.items()
                    if k == kind and pred(e)]

    def holdings(self, party: str) -> Dict[str, Any]:
        """What downstream party `party` holds: its messages (with reads), subscriber copies and
        account balances."""
        with self._lock:
            return {"mail": [copy.deepcopy(e) for (k, _i), e in self.state.items()
                             if k == "mail" and e["party"] == party],
                    "copies": [copy.deepcopy(e) for (k, _i), e in self.state.items()
                               if k == "copy" and e["party"] == party],
                    "accounts": [copy.deepcopy(e) for (k, _i), e in self.state.items()
                                 if k == "account" and e["owner"] == party]}

    # kit setup (caller KIT): never one of B's calls

    def kit_account(self, owner: str, balance: int, *, account_id: Optional[str] = None) -> str:
        aid = account_id or self._new_id(f"acct-{owner.split(':')[-1][:8]}")
        with self._lock:
            self._record(KIT, "open", ("account", aid), {"id": aid, "owner": owner,
                                                         "balance": int(balance)})
        return aid

    def kit_mailbox(self, address: str, party: str) -> None:
        with self._lock:
            self.mailboxes[address] = party

    def kit_topic(self, topic: str, subscribers: List[str]) -> None:
        with self._lock:
            self.subscribers[topic] = list(subscribers)

    def kit_object(self, fields: Dict[str, Any], *, email: Optional[str] = None,
                   note: Optional[str] = None) -> str:
        return self._create(KIT, fields, email, note)["id"]

    def kit_link(self, src: str, dst: str) -> None:
        with self._lock:
            self._link_locked(KIT, src, dst)

    def kit_call(self, op: str, **kw: Any) -> Dict[str, Any]:
        """One B-facing call made by the kit with its own label (the control, step 1)."""
        return _OPS[op](self, KIT, **kw)

    # planted consequences (caller PLANT)

    def read_message(self, message_id: str) -> Dict[str, Any]:
        """The recipient reads the message."""
        with self._lock:
            m = copy.deepcopy(self._get("mail", message_id))
            if m["read_at"] is None:
                m["read_at"] = self.now()
                self._record(PLANT, "read", ("mail", message_id), m)
            return copy.deepcopy(m)

    def deliver_fanout(self, item_id: str, party: str) -> Dict[str, Any]:
        """The world delivers the item to subscriber `party`, who keeps a copy."""
        with self._lock:
            it = copy.deepcopy(self._get("item", item_id))
            if it["retracted"]:
                raise Refused("retracted", "a retracted item is not delivered")
            if party not in it["delivered_to"]:
                it["delivered_to"].append(party)
                self._record(PLANT, "fanout", ("item", item_id), it)
                self._record(PLANT, "fanout", ("copy", f"{item_id}@{party}"),
                             {"item": item_id, "party": party, "body": it["body"]})
            return copy.deepcopy(it)

    def spend(self, transfer_id: str, to_account: str) -> Dict[str, Any]:
        """The payee moves the funds of `transfer_id` on to `to_account`."""
        with self._lock:
            t = copy.deepcopy(self._get("transfer", transfer_id))
            onward = self._transfer_locked(PLANT, t["to"], to_account, t["amount"],
                                           f"onward {transfer_id}", op="spend")
            t["moved_on"] = True
            self._record(PLANT, "spend", ("transfer", transfer_id), t, onward=onward)
            return {"onward": onward, "transfer": copy.deepcopy(t)}

    # ------------------------------------------------------------------ HTTP

    def serve(self, host: str = "127.0.0.1", port: int = 0) -> str:
        """Serve the B-facing calls over HTTP (for a self-hosted target)."""
        world = self

        class H(_Handler):
            pass
        H.world = world
        self._httpd = ThreadingHTTPServer((host, port), H)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        self.http_url = f"http://{host}:{self._httpd.server_address[1]}"
        return self.http_url

    def close(self) -> None:
        _LOCAL.pop(self.url, None)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


WRITES = ("create", "create_many", "update", "delete", "restore", "link", "unlink", "deliver",
          "recall", "transfer", "reverse_transfer", "publish", "retract")
_OPS: Dict[str, Callable[..., Any]] = {
    "create": World._create, "create_many": World._create_many, "update": World._update,
    "delete": World._delete, "restore": World._restore, "link": World._link,
    "unlink": World._unlink, "deliver": World._deliver, "recall": World._recall,
    "transfer": World._transfer, "reverse_transfer": World._reverse_transfer,
    "publish": World._publish, "retract": World._retract, "read": World._read,
    "find": World._find}


# --------------------------------------------------------------------------- B's clients


class LocalClient:
    """B's client to an in-process world. Every call goes through `World.call` with B's
    credential, so faults, holds and the history apply exactly as over HTTP."""

    def __init__(self, world: World, credential: str) -> None:
        self.world = world
        self.credential = credential

    def call(self, op: str, **kw: Any) -> Dict[str, Any]:
        return self.world.call(self.credential, op, **kw)

    def __getattr__(self, op: str) -> Callable[..., Any]:
        if op in _OPS:
            return lambda **kw: self.call(op, **kw)
        raise AttributeError(op)


class HttpClient:
    """B's client to a world served over HTTP: the same calls, the world's errors re-raised."""

    def __init__(self, url: str, credential: str, timeout_s: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.credential = credential
        self.timeout_s = timeout_s

    def call(self, op: str, **kw: Any) -> Any:
        req = urllib.request.Request(f"{self.url}/call/{op}", method="POST",
                                     data=json.dumps(kw).encode(),
                                     headers={"Authorization": f"Bearer {self.credential}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            doc = json.loads(e.read() or b"{}")
            code = doc.get("error", "error")
            if code == "held":
                raise Held(float(doc.get("retry_after_s", 1.0))) from None
            cls = {"down": Unavailable, "hang": TimedOut, "not_found": NotFound,
                   "error": ServerError}.get(code, Refused)
            raise cls(code, doc.get("detail", "")) from None
        except (urllib.error.URLError, OSError) as e:
            raise Unavailable("down", str(e)) from None

    def __getattr__(self, op: str) -> Callable[..., Any]:
        if op in _OPS:
            return lambda **kw: self.call(op, **kw)
        raise AttributeError(op)


def connect(url: str, credential: str) -> Any:
    """B's client for the world at `url` (``world://`` in process, ``http://`` otherwise)."""
    w = local(url)
    if w is not None:
        return LocalClient(w, credential)
    return HttpClient(url, credential)


class _Handler(BaseHTTPRequestHandler):
    world: World

    def log_message(self, *a: Any) -> None:
        pass

    def _send(self, code: int, doc: Any, headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(doc, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/call/"):
            self._send(404, {"error": "not_found"})
            return
        op = self.path[len("/call/"):]
        auth = self.headers.get("Authorization", "")
        cred = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            kw = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            self._send(200, self.world.call(cred, op, **kw))
        except Held as e:
            self._send(503, {"error": "held", "retry_after_s": e.retry_after_s},
                       {"Retry-After": str(max(1, int(e.retry_after_s)))})
        except WorldError as e:
            code = {"down": 503, "hang": 504, "error": 503, "not_found": 404}.get(e.code, 409)
            self._send(code, {"error": e.code, "detail": str(e)})
        except TypeError as e:
            self._send(400, {"error": "bad_call", "detail": str(e)})
