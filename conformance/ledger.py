"""The kit's correct holder and spender for KRK-22 (P22, cumulative ceiling across
counterparties): `StubHolder` plays H in a role-B run, `StubSpender` plays every B the kit owns
(all of them in a role-A run, stub B2 in a role-B run). `X9-CUMULATIVE-CEILING-DESIGN.md` §6.3.

Both are correct by construction and pinned by the vectors and tests: a stub spender executes
exactly what the holder's issuance allows, read by the kit's profile (KRK-M99), and nothing
else; a refusal the issuance did not require is reported as ``stub_refused`` so the trial gives
no reading. Each stub spender has its own key, its own store, its own recorder prefix and no
channel to any other spender. Fresh identifiers (ceiling ids, reservation ids, share ids, keys)
come from the operating system (KRK-M36).

**The holder's interface** (the shape a holder adapter maps onto, and `StubHolder.serve`'s HTTP
routes): ``POST /reserve {chain, spender, values, request_id, digest}`` returns a signed
reservation or a refusal and is idempotent by ``request_id`` (the same request id with other
bytes is refused); ``POST /authorise`` (``online``) charges at once; ``POST /capture``,
``/release``, ``/reverse`` take a spender's signed statement; ``GET /account/<ceiling_id>``
returns the stub's own account (information only). The stub counts every reservation until its
spender's capture or release, or until its expiry plus its tolerance plus the agreed capture lag; frees headroom only on the spender's signed statement and, for reversals, only
under ``net-recorded``; charges every ceiling id on the presented chain; and checks and records
each charge under one lock.

Nothing here imports a target. P16 to P21 do not import this module.
"""
from __future__ import annotations

import http.client
import json
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import ceiling, receipts, standing, status
from .receipts import Keypair

PROFILES = ("kirkaldy", "forwarding")
"""How a stub spender reads a holder's issuance. One profile per outside format is added with
its target, in the kit, never in the adapter (KRK-M25, M99)."""
REPORT_MODES = ("deliver", "drop", "hold-until-heal")
REACH_MODES = ("up", "down", "hang", "error")
HOLDER = "did:web:holder.example"
LIFETIME_S = 12 * 3600

LOCAL_HOLDERS: Dict[str, "StubHolder"] = {}
LOCAL_SPENDERS: Dict[str, "StubSpender"] = {}


def local_holder(url: str) -> Optional["StubHolder"]:
    return LOCAL_HOLDERS.get(url.rstrip("/"))


def local_spender(url: str) -> Optional["StubSpender"]:
    return LOCAL_SPENDERS.get(url.rstrip("/"))


def new_ceiling_id() -> str:
    return f"cl-{secrets.token_hex(8)}"


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def request_digest(values: Any) -> str:
    """The digest a reservation binds (X3's rule): over the canonical JSON of the request's
    values, or over a sorted compact serialisation where the canonical form refuses them."""
    try:
        raw = receipts.canonical_json(values)
    except Exception:  # noqa: BLE001
        raw = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return receipts.sha256_ref(raw)


class Unreachable(ConnectionError):
    """The kit made the holder unreachable for this spender (`StubHolder.set_reachable`)."""


# --------------------------------------------------------------------------- grant 0.3


@dataclass(frozen=True)
class Grant3:
    """One grant 0.3 the kit signed: a root, a delegated child, or a holder's share."""

    id: str
    token: str
    claims: Dict[str, Any]
    ceiling_ids: Tuple[str, ...]
    """This grant's own ceiling and every ancestor's (the kit's issuance log, KRK-M111)."""
    limits: Tuple[Dict[str, Any], ...]
    """The limits of this grant's own ceiling (a share: the share's limits)."""
    subject: str
    principal: str
    chain: Tuple[str, ...]
    """This grant's token and each parent's, the presented grant first."""
    signer: str
    holder: Any = field(default=None, compare=False, repr=False)


def cumulative(ceiling_id: str, limits: Sequence[Dict[str, Any]], *, window: Any = None,
               rule: str = "gross", holder: Optional[Dict[str, str]] = None,
               share: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"ceiling_id": ceiling_id, "limits": [dict(x) for x in limits], "window": window,
            "reversals": rule, "holder": holder, "share": share}


def _claims(*, issuer: str, subject: str, agent: Keypair, principal: str, constraints: Dict,
            parent: Optional[str], now: float, source: str) -> Dict[str, Any]:
    return {"schema": ceiling.GRANT_V3_SCHEMA, "grant_id": status.new_grant_id(),
            "issuer": issuer, "subject": subject,
            "agent_key": {"kid": agent.kid, "public_key": agent.public_bytes().hex()},
            "principal": principal, "constraints": constraints, "parent": parent,
            "issued_at": status.utc_ms(now), "not_before": status.utc_s(now - 3600),
            "not_after": status.utc_s(now + LIFETIME_S),
            "status": {"source": source, "index": 0}}


def issue_root(A: Any, subject: str, cum: Dict[str, Any], *, principal: str,
               per_request: Optional[Dict[str, Any]] = None) -> Grant3:
    """A root grant 0.3, signed by A's grant key (`issuer.StubIssuer`), for agent `subject`."""
    agent = A.agent(subject)
    cons: Dict[str, Any] = {"cumulative": cum}
    if per_request is not None:
        cons["max_amount"] = per_request
    c = _claims(issuer=A.issuer, subject=subject, agent=agent, principal=principal,
                constraints=cons, parent=None, now=A.clock.wall(), source=A.source_url)
    tok = standing.sign(c, A.key, ceiling.GRANT_TYP)
    return Grant3(c["grant_id"], tok, c, (cum["ceiling_id"],), tuple(cum["limits"]), subject,
                  principal, (tok,), f"org:{A.issuer}", A)


def delegate(A: Any, parent: Grant3, subject: str, *, own: Optional[Dict[str, Any]] = None,
             holder_hop: bool = False, org: Any = None) -> Grant3:
    """A child of `parent`, genuinely signed and never wider (its ``max_amount`` is its
    parent's): by A (``holder_hop`` false) or by the parent's agent key into `org`'s agent (a
    holder hop, `StubIssuer.delegate_holder`'s shape). `own` is the child's own ``cumulative``
    member (its own ceiling), or None: it then carries its parent's ceiling member unchanged.
    Its effects count against every ceiling on the chain."""
    pc = parent.claims["constraints"]
    cons = {k: v for k, v in pc.items() if k != "cumulative"}
    cons["cumulative"] = own if own is not None else pc["cumulative"]
    signer_org = parent.holder or A
    new_org = org or signer_org
    sub_key = new_org.agent(subject)
    issuer = parent.subject if holder_hop else A.issuer
    c = _claims(issuer=issuer, subject=subject, agent=sub_key, principal=parent.principal,
                constraints=cons, parent=parent.id, now=A.clock.wall(),
                source=signer_org.source_url)
    key = signer_org.agent(parent.subject) if holder_hop else A.key
    tok = standing.sign(c, key, ceiling.GRANT_TYP)
    cids = tuple(dict.fromkeys(parent.ceiling_ids + (cons["cumulative"]["ceiling_id"],)))
    return Grant3(c["grant_id"], tok, c, cids, tuple(cons["cumulative"]["limits"]), subject,
                  parent.principal, (tok,) + parent.chain,
                  f"holder:{parent.subject}" if holder_hop else f"org:{A.issuer}", new_org)


def reissue(A: Any, root: Grant3) -> Grant3:
    """The root again (a renewal or key rotation), with the same ``ceiling_id`` and a new grant
    id (``redelegated/reissued_root``)."""
    cons = root.claims["constraints"]
    return issue_root(A, root.subject, cons["cumulative"], principal=root.principal,
                      per_request=cons.get("max_amount"))


def chain_ceilings(hops: Sequence[Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    """(ceiling_id, cumulative member) for each distinct ceiling a verified chain names, the
    presented grant's first."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for h in hops:
        cm = (h.get("constraints") or {}).get("cumulative")
        if isinstance(cm, dict) and cm.get("ceiling_id") not in [x[0] for x in out]:
            out.append((cm["ceiling_id"], cm))
    return out


def verify_chain(tokens: Sequence[str], anchors: Dict[str, Dict[str, Any]], *,
                 extra_keys: Optional[Dict[str, bytes]] = None
                 ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """A grant 0.3 chain's signatures (`standing.verify_holder_chain` with grant 0.3's shape),
    or a single share signed by a holder whose key is in `extra_keys`."""
    toks = list(tokens)
    if len(toks) == 1 and extra_keys:
        v = standing.verify(toks[0], extra_keys, ceiling.GRANT_TYP,
                            problem_of=ceiling.PROBLEMS[ceiling.GRANT_TYP])
        if v.ok:
            return [v.claims], None
    hops, why = standing.verify_holder_chain(toks, anchors,
                                             problem_of=ceiling.PROBLEMS[ceiling.GRANT_TYP])
    if why:
        return None, why
    return [h.claims for h in hops], None


# --------------------------------------------------------------------------- plumbing


class _KeepAlive:
    """One kept-alive connection per host (the recorder, a served holder). A request is sent
    again only if the connection failed before it was sent, never after."""

    def __init__(self) -> None:
        self.conns: Dict[Tuple[int, str], http.client.HTTPConnection] = {}
        self.lock = threading.Lock()

    def post(self, url: str, body: bytes) -> Tuple[int, bytes]:
        u = urllib.parse.urlsplit(url)
        key = (threading.get_ident(), u.netloc)
        for attempt in (1, 2):
            with self.lock:
                c = self.conns.get(key)
                if c is None:
                    c = self.conns[key] = http.client.HTTPConnection(u.hostname, u.port,
                                                                     timeout=30)
            try:
                c.request("POST", u.path, body=body, headers={"Content-Type":
                                                              "application/json"})
            except (ConnectionError, http.client.HTTPException, OSError):
                c.close()
                with self.lock:
                    self.conns.pop(key, None)
                if attempt == 2:
                    raise
                continue
            try:
                r = c.getresponse()
                data = r.read()
            except Exception:
                c.close()
                with self.lock:
                    self.conns.pop(key, None)
                raise
            return r.status, data
        raise RuntimeError("unreachable")


KEEP = _KeepAlive()


def _serve(obj: Any, routes: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
           get: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None) -> Tuple[Any, str]:
    from . import netbind

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:  # noqa: D401
            pass

        def _send(self, code: int, doc: Dict[str, Any]) -> None:
            raw = json.dumps(doc).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            try:
                doc = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._send(400, {"code": "malformed"})
            fn = routes.get(self.path)
            if fn is None:
                return self._send(404, {"code": "no-route"})
            try:
                ans = fn(doc)
            except Unreachable:
                return self._send(503, {"code": "unreachable"})
            return self._send(int(ans.get("status") or 200), ans.get("body") or {})

        def do_GET(self) -> None:  # noqa: N802
            ans = get(self.path) if get else None
            return self._send(200 if ans is not None else 404, ans or {})

    host = netbind.bind_host(None)
    httpd = netbind.server_class(host)((host, 0), H)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    h, p = httpd.server_address[:2]
    return httpd, f"http://{netbind.url_host(netbind.advertise_host(h))}:{p}"


def _answer(code: str, reason: str = "", status_code: Optional[int] = None,
            **more: Any) -> Dict[str, Any]:
    st = status_code or {"authorised": 200, "executed": 200, "accepted": 200, "queued": 202,
                         "refused": 403, "conflict": 409, "unreachable": 503,
                         "rate-limited": 429}.get(code, 500)
    return {"status": st, "body": {"code": code, "reason": reason, **more}}


def _clock(clock: Any) -> Any:
    if clock is None:
        from .timing import RealClock
        return RealClock()
    return clock


# --------------------------------------------------------------------------- the holder


@dataclass
class _Entry:
    """One charge the holder keeps against a set of ceilings."""

    id: str
    kind: str                      # reservation | online | share | forward
    spender: str
    ceiling_ids: Tuple[str, ...]
    q: Dict[str, List[int]]        # ceiling_id -> per limit, kit units
    t_h: float                     # the holder's wall clock at the charge (s)
    not_after: Optional[float]     # the holder's wall clock (s), or None
    state: str = "held"            # held | captured | released | expired
    request_id: str = ""
    digest: str = ""
    token: str = ""
    reversed: Dict[str, List[int]] = field(default_factory=dict)


class StubHolder:
    """H, correct (module docstring)."""

    def __init__(self, issuer: Any, *, mechanism: str = "reservation", expiry_s: float = 20.0,
                 tolerance_s: float = 1.0, capture_lag_s: float = 2.0, rule: str = "gross",
                 clock: Any = None, name: str = HOLDER) -> None:
        if mechanism not in ("allocation", "reservation", "online"):
            raise ValueError(f"the stub holder drives allocation, reservation and online, "
                             f"not {mechanism!r}")
        self.A = issuer
        self.mechanism = mechanism
        self.expiry_s = float(expiry_s)
        self.tolerance_s = float(tolerance_s)
        self.capture_lag_s = float(capture_lag_s)
        self.rule = rule
        self.clock = _clock(clock)
        self.name = name
        self.key = Keypair.generate(f"holder-{secrets.token_hex(3)}")
        self.offset_s = 0.0
        self.url = ""
        self._httpd: Any = None
        self._lock = threading.RLock()
        self.ceilings: Dict[str, Dict[str, Any]] = {}
        self.entries: Dict[str, _Entry] = {}
        self.by_request: Dict[str, str] = {}
        self.spender_keys: Dict[str, Dict[str, bytes]] = {}
        self.reach: Dict[str, str] = {}
        self._log: List[Dict[str, Any]] = []
        self._conf: List[Dict[str, Any]] = []
        self.capture_failures: Dict[str, int] = {}
        """spender -> how many of its next captures to answer 503 (``release_after_commit``)."""

    # identity and set-up ---------------------------------------------------------------------

    def anchor(self) -> Dict[str, bytes]:
        return {self.key.kid: self.key.public_bytes()}

    def holder_ref(self) -> Dict[str, str]:
        return {"source": self.url or f"local:{self.name}", "kid": self.key.kid}

    def wall(self) -> float:
        return self.clock.wall() + self.offset_s

    def set_clock_offset(self, seconds: float) -> None:
        self.offset_s = float(seconds)

    def bind_spender(self, name: str, keys: Dict[str, bytes]) -> None:
        with self._lock:
            self.spender_keys[name] = dict(keys)

    def set_reachable(self, spender: str, mode: str) -> None:
        if mode not in REACH_MODES:
            raise ValueError(mode)
        self.reach[spender] = mode

    def fail_next_captures(self, spender: str, n: int = 1) -> None:
        self.capture_failures[spender] = n

    def _gate(self, spender: str, what: str) -> None:
        mode = self.reach.get(spender, "up")
        self._note(what, spender=spender, reach=mode)
        if mode in ("down", "hang"):
            raise Unreachable(f"the holder is unreachable for {spender} ({mode})")
        if mode == "error":
            raise Unreachable(f"the holder answers {spender} with an error")

    def _note(self, kind: str, **doc: Any) -> None:
        with self._lock:
            self._log.append({"kind": kind, "t_kit": self.clock.now(), **doc})

    def log(self, since: float = 0.0) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self._log if e["t_kit"] >= since]

    def confirmations(self, spender: str) -> List[Dict[str, Any]]:
        with self._lock:
            self._sweep()
            return [dict(c) for c in self._conf if c["spender"] == spender]

    # roots --------------------------------------------------------------------------------

    def open_root(self, principal: str, limits: List[Dict[str, Any]], *, window: Any = None,
                  rule: Optional[str] = None, agent: Optional[str] = None,
                  per_request: Optional[Dict[str, Any]] = None,
                  anchor_kit: Optional[float] = None) -> Grant3:
        cid = new_ceiling_id()
        cum = cumulative(cid, limits, window=window, rule=rule or self.rule,
                         holder=self.holder_ref())
        g = issue_root(self.A, agent or f"agent-{secrets.token_hex(4)}", cum,
                       principal=principal, per_request=per_request)
        self._register(cum, anchor_kit)
        return g

    def _register(self, cum: Dict[str, Any], anchor_kit: Optional[float] = None) -> None:
        with self._lock:
            self.ceilings.setdefault(cum["ceiling_id"], {
                "limits": list(cum["limits"]), "window": cum["window"],
                "rule": cum["reversals"], "anchor_kit": anchor_kit})

    def learn(self, g: Grant3) -> None:
        """Register a child's own ceiling (the kit delegated it; a target holder learns it from
        the chain it is shown)."""
        for cid, cm in chain_ceilings([g.claims]):
            self._register(cm)

    def allocate(self, root: Grant3, spender: str, limits: List[Dict[str, Any]]
                 ) -> Optional[Grant3]:
        """A share of `root` for `spender`, a grant 0.3 signed by the holder, counted in full
        against every ceiling of the root at issue; None if it does not fit."""
        with self._lock:
            self._sweep()
            cum = root.claims["constraints"]["cumulative"]
            q = {cid: self._q_of(cid, limits) for cid in root.ceiling_ids}
            if not self._fits(root.ceiling_ids, q):
                self._note("allocate-refused", spender=spender)
                return None
            sid = new_id("sh")
            share = {"spender": spender, "share_id": sid, "limits": [dict(x) for x in limits]}
            cons = {k: v for k, v in root.claims["constraints"].items() if k != "cumulative"}
            cons["cumulative"] = {**cum, "share": share, "holder": self.holder_ref()}
            agent = self.A.agent(root.subject)
            c = _claims(issuer=self.name, subject=root.subject, agent=agent,
                        principal=root.principal, constraints=cons, parent=root.id,
                        now=self.wall(), source=self.holder_ref()["source"])
            tok = standing.sign(c, self.key, ceiling.GRANT_TYP)
            e = _Entry(sid, "share", spender, root.ceiling_ids, q, self.wall(), None,
                       state="held", token=tok)
            self.entries[sid] = e
            self._conf.append({"kind": "share", "spender": spender, "ref": sid,
                               "ceiling_ids": list(root.ceiling_ids), "quantity": limits})
            self._note("allocate", spender=spender, share_id=sid)
            return Grant3(c["grant_id"], tok, c, root.ceiling_ids, tuple(limits),
                          root.subject, root.principal, (tok,), f"holder:{self.name}", None)

    # accounting -----------------------------------------------------------------------------

    def _q_of(self, cid: str, qty: Sequence[Dict[str, Any]]) -> List[int]:
        lims = self.ceilings[cid]["limits"]
        out = []
        for lim in lims:
            v = ceiling.quantity_of_limits(qty, lim)
            out.append(0 if v is None else v)
        return out

    def _sweep(self) -> None:
        now = self.wall()
        for e in self.entries.values():
            if e.state == "held" and e.not_after is not None and \
                    now > e.not_after + self.tolerance_s + self.capture_lag_s:
                e.state = "expired"
                self._conf.append({"kind": "expired", "spender": e.spender, "ref": e.id,
                                   "ceiling_ids": list(e.ceiling_ids),
                                   "quantity": self._qty_back(e)})
                self._note("expired", ref=e.id, spender=e.spender)

    def _qty_back(self, e: _Entry) -> List[Dict[str, Any]]:
        cid = e.ceiling_ids[0]
        out = []
        for lim, v in zip(self.ceilings[cid]["limits"], e.q[cid]):
            if lim["kind"] == "amount":
                out.append({"kind": "amount", "value": v // 10 ** (ceiling.SCALE
                                                                    - lim["minor_units"]),
                            "currency": lim["currency"], "minor_units": lim["minor_units"]})
            else:
                out.append({"kind": "count", "value": v, "unit": lim["unit"]})
        return out

    def _window_of(self, cid: str, t_h: float) -> Optional[Tuple[float, float]]:
        w = self.ceilings[cid].get("window")
        if not w:
            return None
        P = float(w["period_s"])
        if w["kind"] == "fixed":
            a = w["anchor_ms"] / 1000.0
            k = (t_h - a) // P
            return a + k * P, a + (k + 1) * P
        return t_h - P, t_h + 1e-9

    def used(self, cid: str, *, at: Optional[float] = None) -> List[int]:
        """What counts against `cid` now (or in the window containing `at`)."""
        lims = self.ceilings[cid]["limits"]
        rule = self.ceilings[cid]["rule"]
        tot = [0] * len(lims)
        win = self._window_of(cid, at) if at is not None else None
        for e in self.entries.values():
            if cid not in e.ceiling_ids or e.state in ("released", "expired"):
                continue
            if win is not None and not (win[0] <= e.t_h < win[1]):
                continue
            for i in range(len(lims)):
                tot[i] += e.q[cid][i]
                if rule == "net-recorded":
                    tot[i] -= (e.reversed.get(cid) or [0] * len(lims))[i]
        return tot

    def _fits(self, cids: Sequence[str], q: Dict[str, List[int]]) -> bool:
        now = self.wall()
        for cid in cids:
            lims = self.ceilings[cid]["limits"]
            u = self.used(cid, at=now if self.ceilings[cid].get("window") else None)
            for i, lim in enumerate(lims):
                if q[cid][i] < 0 or u[i] + q[cid][i] > ceiling.limit_value(lim):
                    return False
        return True

    def account(self, ceiling_id: str) -> Dict[str, Any]:
        with self._lock:
            self._sweep()
            return {"ceiling_id": ceiling_id, "used": self.used(ceiling_id)}

    # the routes -----------------------------------------------------------------------------

    def _chain(self, req: Dict[str, Any]) -> Tuple[Optional[List[Tuple[str, Dict]]], str]:
        anchors = {self.A.issuer: self.A.trust_anchor_x1()["keyset_claims"]}
        for p in getattr(self.A, "peers", []) or []:
            anchors[p.issuer] = p.trust_anchor_x1()["keyset_claims"]
        hops, why = verify_chain(req.get("chain") or [], anchors)
        if why:
            return None, f"chain: {why}"
        cs = chain_ceilings(hops)
        for cid, cm in cs:
            if cid not in self.ceilings:
                self._register(cm)
        return cs, ""

    def reserve(self, req: Dict[str, Any], *, kind: str = "reservation") -> Dict[str, Any]:
        spender = str(req.get("spender") or "")
        self._gate(spender, kind)
        with self._lock:
            self._sweep()
            rid = str(req.get("request_id") or "")
            dig = str(req.get("digest") or request_digest(req.get("values")))
            if rid in self.by_request:
                e = self.entries[self.by_request[rid]]
                if e.digest != dig or e.spender != spender:
                    self._note("conflict", request_id=rid, spender=spender)
                    return _answer("conflict", "the same request id with other bytes")
                return _answer("authorised", "the same request again", issuance=e.token)
            cs, why = self._chain(req)
            if cs is None:
                return _answer("refused", why)
            cids = tuple(c for c, _ in cs)
            lims0 = self.ceilings[cids[0]]["limits"]
            qty = ceiling.values_quantity(req.get("values") or {}, lims0)
            if qty is None:
                return _answer("refused", "the request cannot be counted against the ceiling")
            q = {cid: self._q_of(cid, qty) for cid in cids}
            for cid in cids:
                vq = ceiling.values_quantity(req.get("values") or {},
                                             self.ceilings[cid]["limits"])
                if vq is None:
                    return _answer("refused", f"the request cannot be counted against {cid}")
                q[cid] = self._q_of(cid, vq)
            if not self._fits(cids, q):
                self._note("refused", spender=spender, request_id=rid)
                return _answer("refused", "over the ceiling")
            now = self.wall()
            res_id = new_id("rs")
            na = None if kind == "online" else now + self.expiry_s
            claims = ceiling.reservation_claims(
                holder=self.name, ceiling_ids=cids, spender=spender, quantity=qty,
                request_id=rid, not_after=None if na is None else int(na * 1000),
                issued_at=int(now * 1000), reservation_id=res_id, digest=dig, kind=kind)
            tok = standing.sign(claims, self.key, ceiling.RESERVATION_TYP)
            e = _Entry(res_id, kind, spender, cids, q, now, na,
                       state="captured" if kind == "online" else "held", request_id=rid,
                       digest=dig, token=tok)
            self.entries[res_id] = e
            self.by_request[rid] = res_id
            self._conf.append({"kind": "authorisation" if kind == "online" else "reservation",
                               "spender": spender, "ref": res_id, "ceiling_ids": list(cids),
                               "quantity": qty})
            self._note("reserved", spender=spender, request_id=rid, reservation_id=res_id)
            return _answer("authorised", "reserved", issuance=tok)

    def authorise(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self.reserve(req, kind="online")

    def _statement(self, tok: str) -> Tuple[Optional[Dict[str, Any]], str]:
        peek = standing.peek(tok)
        keys = self.spender_keys.get(str(peek.get("spender")), {})
        v = standing.verify(tok, keys, ceiling.SPEND_TYP, problem_of=ceiling.spend_problem)
        if not v.ok:
            return None, f"statement: {v.reason}: {v.detail}"
        return v.claims, ""

    def capture(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._apply(req, "captured")

    def release(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._apply(req, "released")

    def reverse(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._apply(req, "reversed")

    def _apply(self, req: Dict[str, Any], kind: str) -> Dict[str, Any]:
        tok = str(req.get("statement") or "")
        spender = str(standing.peek(tok).get("spender") or "")
        self._gate(spender, kind)
        with self._lock:
            if kind == "captured" and self.capture_failures.get(spender):
                self.capture_failures[spender] -= 1
                self._note("capture-503", spender=spender)
                return _answer("unreachable", "try again", status_code=503)
            c, why = self._statement(tok)
            if c is None or c["kind"] != kind:
                return _answer("refused", why or "wrong kind")
            e = self.entries.get(c["ref"])
            if e is None or e.spender != c["spender"]:
                return _answer("refused", "no such reservation or share for this spender")
            if kind == "captured":
                if e.kind in ("reservation",) and e.state == "held":
                    e.state = "captured"
                self._note("captured", ref=e.id, spender=e.spender)
            elif kind == "released":
                if e.state in ("held", "captured"):
                    e.state = "released"
                    self._conf.append({"kind": "release", "spender": e.spender, "ref": e.id,
                                       "ceiling_ids": list(e.ceiling_ids),
                                       "quantity": self._qty_back(e)})
                self._note("released", ref=e.id, spender=e.spender)
            else:
                for cid in e.ceiling_ids:
                    q = self._q_of(cid, c["quantity"])
                    cur = e.reversed.get(cid) or [0] * len(q)
                    e.reversed[cid] = [min(a + b, m) for a, b, m in zip(cur, q, e.q[cid])]
                self._note("reversed", ref=e.id, spender=e.spender)
            return _answer("accepted", kind)

    # serving -------------------------------------------------------------------------------

    def routes(self) -> Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]]:
        return {"/reserve": self.reserve, "/authorise": self.authorise, "/capture": self.capture,
                "/release": self.release, "/reverse": self.reverse}

    def serve(self) -> str:
        if self._httpd is None:
            self._httpd, base = _serve(self, self.routes(), self._get)
            self.url = base
        LOCAL_HOLDERS[self.url] = self
        return self.url

    def serve_local(self) -> str:
        self.url = self.url or f"http://holder-{secrets.token_hex(4)}.invalid"
        LOCAL_HOLDERS[self.url] = self
        return self.url

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        if path.startswith("/account/"):
            return self.account(path.rsplit("/", 1)[1])
        return None

    def close(self) -> None:
        LOCAL_HOLDERS.pop(self.url, None)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def call_holder(url: str, route: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """A spender's call to a holder: in process for a local one, else over HTTP. Raises
    `Unreachable` when the holder cannot be reached."""
    h = local_holder(url)
    if h is not None:
        return h.routes()[route](doc)
    try:
        code, data = KEEP.post(url.rstrip("/") + route, json.dumps(doc).encode("utf-8"))
    except OSError as e:
        raise Unreachable(str(e))
    if code == 503:
        body = json.loads(data or b"{}")
        if body.get("code") == "unreachable" and route != "/capture":
            raise Unreachable("503")
    return {"status": code, "body": json.loads(data or b"{}")}


# --------------------------------------------------------------------------- a spender


class StubSpender:
    """A B the kit owns: it executes exactly what the holder's issuance allows, read by its
    profile (KRK-M99), posts each effect to its own recorder prefix, and reports to the holder
    as its report mode says."""

    def __init__(self, name: str, *, recorder_url: str, profile: str = "kirkaldy",
                 clock: Any = None, effect_delay_s: float = 0.0) -> None:
        if profile not in PROFILES:
            raise ValueError(f"profile is one of {PROFILES}")
        self.name = name
        self.recorder_url = recorder_url.rstrip("/")
        self.profile = profile
        self.clock = _clock(clock)
        self.effect_delay_s = float(effect_delay_s)
        self.key = Keypair.generate(f"spender-{secrets.token_hex(3)}")
        self.holder_keys: Dict[str, bytes] = {}
        self.holder_url: Optional[str] = None
        self.deliver_fn: Optional[Callable[[str, str], Any]] = None
        self.report = "deliver"
        self.report_delay_s = 0.0
        self.offset_s = 0.0
        self.used: Dict[str, List[int]] = {}
        """reservation, share or forward id -> what this spender committed under it."""
        self.received: List[Dict[str, Any]] = []
        self.refused: List[Dict[str, Any]] = []
        self.statements: List[str] = []
        self.held: List[Tuple[str, str]] = []
        self.dropped: List[str] = []
        self._lock = threading.RLock()
        self.url = ""
        self._httpd: Any = None

    def anchor(self) -> Dict[str, bytes]:
        return {self.key.kid: self.key.public_bytes()}

    def bind_holder(self, anchor: Dict[str, bytes], url: Optional[str],
                    deliver: Optional[Callable[[str, str], Any]] = None) -> None:
        """Pin the holder's key; reports go to `deliver(route, statement)` when given (a role-A
        run, through the holder adapter), else to the holder at `url`."""
        self.holder_keys = dict(anchor)
        self.holder_url = url
        self.deliver_fn = deliver

    def set_report(self, mode: str, delay_s: float = 0.0) -> None:
        """``deliver``, ``drop`` or ``hold-until-heal``; `delay_s` delays each delivery."""
        if mode not in REPORT_MODES:
            raise ValueError(mode)
        self.report = mode
        self.report_delay_s = float(delay_s)
        if mode == "deliver":
            held, self.held = self.held, []
            for route, st in held:
                self._send(route, st)

    def set_clock_offset(self, seconds: float) -> None:
        self.offset_s = float(seconds)

    def wall_ms(self) -> int:
        return int((self.clock.wall() + self.offset_s) * 1000)

    # reading the issuance -------------------------------------------------------------------

    def _limits_of(self, claims: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        if "quantity" in claims:
            return claims["quantity"]
        sh = ((claims.get("constraints") or {}).get("cumulative") or {}).get("share")
        return sh["limits"] if sh else None

    def _allows(self, p: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]], str]:
        """(why the issuance does not allow this spend, or None; its claims; its id)."""
        values = p.get("values") or {}
        if self.profile == "forwarding" or p.get("forward"):
            v = standing.verify(p.get("forward"), self.holder_keys, ceiling.FORWARD_TYP,
                                problem_of=ceiling.forward_problem)
            if not v.ok:
                return f"forward: {v.reason}", None, ""
            c = v.claims
            if c["spender"] != self.name:
                return "forwarded to another spender", c, c["forward_id"]
            if c["request_digest"] != request_digest(values):
                return "the request is not the one forwarded", c, c["forward_id"]
            if c["forward_id"] in self.used:
                return "forwarded once, already performed", c, c["forward_id"]
            return None, c, c["forward_id"]
        tok = p.get("issuance")
        typ = standing.header_of(tok).get("typ")
        if typ == ceiling.RESERVATION_TYP:
            v = standing.verify(tok, self.holder_keys, typ, problem_of=ceiling.reservation_problem)
            if not v.ok:
                return f"reservation: {v.reason}", None, ""
            c = v.claims
            rid = c["reservation_id"]
            if c["spender"] != self.name:
                return "addressed to another spender", c, rid
            if c["not_after"] is not None and self.wall_ms() > c["not_after"]:
                return "the reservation has expired", c, rid
            if rid in self.used:
                return "the reservation was already used", c, rid
        elif typ == ceiling.GRANT_TYP:
            v = standing.verify(tok, self.holder_keys, typ,
                                problem_of=ceiling.PROBLEMS[ceiling.GRANT_TYP])
            if not v.ok:
                return f"share: {v.reason}", None, ""
            c = v.claims
            sh = ((c.get("constraints") or {}).get("cumulative") or {}).get("share")
            if not sh:
                return "a grant with no share", c, ""
            rid = sh["share_id"]
            if sh["spender"] != self.name:
                return "a share addressed to another spender", c, rid
        else:
            return f"an issuance this profile does not read ({typ!r})", None, ""
        lims = self._limits_of(c) or []
        q = ceiling.values_quantity(values, lims)
        if q is None:
            return "the spend cannot be counted against the issuance", c, rid
        used = self.used.get(rid) or [0] * len(lims)
        for i, lim in enumerate(lims):
            if used[i] + ceiling.limit_value(q[i]) > ceiling.limit_value(lim):
                return "beyond what the issuance allows", c, rid
        return None, c, rid

    def present(self, p: Dict[str, Any]) -> Dict[str, Any]:
        """``{"issuance" | "forward": token, "values", "ref"}``: execute iff the issuance
        allows it (KRK-M99)."""
        with self._lock:
            self.received.append({"ref": p.get("ref"), "t_kit": self.clock.now()})
            why, c, rid = self._allows(p)
            if why:
                self.refused.append({"ref": p.get("ref"), "why": why, "t_kit": self.clock.now()})
                return _answer("refused", why, stub_refused=False)
            lims = self._limits_of(c) or [] if c and "forward_id" not in c else []
            q = ceiling.values_quantity(p.get("values") or {}, lims) if lims else []
            used = self.used.get(rid) or [0] * len(lims)
            self.used[rid] = [u + ceiling.limit_value(x) for u, x in zip(used, q)] if lims \
                else [1]
        if self.effect_delay_s > 0:
            t = self.clock.now() + self.effect_delay_s
            self.clock.call_at(t, lambda: self._commit(p, c, rid))
            return _answer("queued", f"committing in {self.effect_delay_s:g} s")
        return self._commit(p, c, rid)

    def _commit(self, p: Dict[str, Any], c: Dict[str, Any], rid: str) -> Dict[str, Any]:
        body = {"ref": p.get("ref"), "spender": self.name, "kind": "spend",
                "values": p.get("values")}
        try:
            code, _ = KEEP.post(f"{self.recorder_url}/effect/{p.get('ref')}",
                                json.dumps(body).encode("utf-8"))
        except OSError as e:
            with self._lock:
                self.refused.append({"ref": p.get("ref"), "why": f"recorder: {e}",
                                     "stub_refused": True})
            return _answer("refused", "the recorder could not be reached", stub_refused=True)
        if code != 200:
            with self._lock:
                self.refused.append({"ref": p.get("ref"), "why": f"recorder {code}",
                                     "stub_refused": True})
            return _answer("refused", f"recorder answered {code}", stub_refused=True)
        if c is not None and "forward_id" not in c:
            cids = c.get("ceiling_ids") or [((c.get("constraints") or {}).get("cumulative")
                                             or {}).get("ceiling_id")]
            q = ceiling.values_quantity(p.get("values") or {}, self._limits_of(c) or [])
            st = standing.sign(ceiling.spend_claims(
                spender=self.name, kind="captured", ref=rid, ceiling_ids=[x for x in cids if x],
                quantity=q or [], effect_ref=str(p.get("ref")), at=self.wall_ms()),
                self.key, ceiling.SPEND_TYP)
            self._report("/capture", st)
        return _answer("executed", "performed")

    def reverse(self, effect_ref: str, values: Dict[str, Any], *, ref: str,
                ceiling_ids: Sequence[str], quantity: List[Dict[str, Any]]) -> str:
        """Reverse part of an effect this spender performed: a reversal at the recorder and a
        signed statement to the holder. Returns the reversal's own recorder reference."""
        rref = f"rv-{secrets.token_hex(6)}"
        body = {"ref": rref, "spender": self.name, "kind": "reversal",
                "reverses": effect_ref, "values": values}
        KEEP.post(f"{self.recorder_url}/effect/{rref}", json.dumps(body).encode("utf-8"))
        st = standing.sign(ceiling.spend_claims(
            spender=self.name, kind="reversed", ref=ref, ceiling_ids=list(ceiling_ids),
            quantity=quantity, effect_ref=effect_ref, at=self.wall_ms()), self.key,
            ceiling.SPEND_TYP)
        self._report("/reverse", st)
        return rref

    def _report(self, route: str, st: str) -> None:
        with self._lock:
            self.statements.append(st)
            if self.report == "drop":
                self.dropped.append(st)
                return
            if self.report == "hold-until-heal":
                self.held.append((route, st))
                return
        if self.report_delay_s > 0:
            self.clock.call_at(self.clock.now() + self.report_delay_s,
                               lambda: self._send(route, st))
            return
        self._send(route, st)

    def _send(self, route: str, st: str) -> None:
        try:
            if self.deliver_fn is not None:
                self.deliver_fn(route, st)
            elif self.holder_url:
                call_holder(self.holder_url, route, {"statement": st})
        except Exception:  # noqa: BLE001 - a lost report is the fixture's, recorded as sent
            pass

    # serving -------------------------------------------------------------------------------

    def serve(self) -> str:
        if self._httpd is None:
            self._httpd, self.url = _serve(self, {"/present": self.present})
        LOCAL_SPENDERS[self.url] = self
        return self.url

    def serve_local(self) -> str:
        self.url = self.url or f"http://spender-{secrets.token_hex(4)}.invalid"
        LOCAL_SPENDERS[self.url] = self
        return self.url

    def close(self) -> None:
        LOCAL_SPENDERS.pop(self.url, None)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def call_spender(url: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """A forwarding holder's call to a spender: in process for a local one, else over HTTP."""
    s = local_spender(url)
    if s is not None:
        return s.present(doc)
    code, data = KEEP.post(url.rstrip("/") + "/present", json.dumps(doc).encode("utf-8"))
    return {"status": code, "body": json.loads(data or b"{}")}


def now_ms(clock: Any, offset_s: float = 0.0) -> int:
    return int((clock.wall() + offset_s) * 1000)


__all__ = ["StubHolder", "StubSpender", "Grant3", "PROFILES", "issue_root", "delegate",
           "reissue", "cumulative", "verify_chain", "call_holder", "call_spender",
           "request_digest", "new_ceiling_id", "new_id", "Unreachable", "time"]
